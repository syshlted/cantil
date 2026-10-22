/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/usb/usbd.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>

#include "transport.h"

LOG_MODULE_REGISTER(transport_usb, LOG_LEVEL_INF);

/*
 * USB device support — the usbd_* ("device_next") stack.
 *
 * The legacy <zephyr/usb/usb_device.h> stack this file used to target is
 * deprecated upstream and pins the tree to v4.3.1; see
 * docs/roadmap/zephyr-upstream.md. Unlike the legacy stack, device_next is not
 * enabled at SYS_INIT: the whole device is built and enabled from
 * transport_usb_init() below, which runs from main() after every SYS_INIT
 * (NRF_SECURITY, QSPI) has completed. That deferral is what the legacy port
 * had to arrange by hand — calling usb_enable() explicitly rather than at boot
 * to avoid a SET_ADDRESS race — and here it falls out of the stack's shape.
 *
 * VID/PID and the manufacturer/product strings are declared in C here rather
 * than in Kconfig (CONFIG_USB_DEVICE_VID/PID/…), which the legacy stack read.
 * The serial-number string is taken from HWINFO (the FICR device ID), matching
 * the legacy build's runtime-filled iSerial byte for byte, so udev-based tools
 * such as scripts/capture_boot_log.sh keep matching a unit by its FICR serial.
 *
 * Two CDC ACM functions are registered, in devicetree-instance order:
 *   board_cdc_acm_uart (instance 0) → interface 0 → protocol / Noise bytes
 *   cdc_acm_uart1      (instance 1) → interface 2 → console + log backend
 * The host (libcantil/src/discover_usb.c) selects the protocol port by
 * interface number (:1.0), so that order is load-bearing.
 *
 * Protocol UART selected via chosen `cantil,protocol-uart` (per-board overlay).
 */
#define CDC_NODE DT_CHOSEN(cantil_protocol_uart)

static const struct device *cdc_dev = DEVICE_DT_GET(CDC_NODE);
static bool connected;

/* pid.codes-registered Cantil identity (https://pid.codes/1209/00CA/). */
#define CANTIL_USB_VID 0x1209
#define CANTIL_USB_PID 0x00CA

USBD_DEVICE_DEFINE(cantil_usbd, DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)), CANTIL_USB_VID,
		   CANTIL_USB_PID);

USBD_DESC_LANG_DEFINE(cantil_lang);
USBD_DESC_MANUFACTURER_DEFINE(cantil_mfr, "Cantil");
USBD_DESC_PRODUCT_DEFINE(cantil_product, "Cantil Hardware CA");
USBD_DESC_SERIAL_NUMBER_DEFINE(cantil_sn);

USBD_DESC_CONFIG_DEFINE(cantil_fs_cfg_desc, "Cantil");

/* Bus-powered, no remote wakeup. bMaxPower in 2 mA units. */
USBD_CONFIGURATION_DEFINE(cantil_fs_config, 0, 125, &cantil_fs_cfg_desc);

/*
 * RX must be interrupt-driven on the device_next CDC ACM class: the class only
 * arms the host→device (OUT) endpoint read when the application has enabled
 * interrupt RX (usbd_cdc_acm_enable() re-arms only if CDC_ACM_IRQ_RX_ENABLED is
 * set; see usbd_cdc_acm.c). With the legacy stack a bare uart_poll_in() loop
 * sufficed; here it never sees a byte because nothing arms the endpoint, so the
 * ISR below drains the class FIFO into a ring buffer that usb_recv() empties.
 * TX stays on uart_poll_out() — the class arms IN transfers from poll_out.
 */
#define USB_RX_RING_BYTES 4096
RING_BUF_DECLARE(usb_rx_ring, USB_RX_RING_BYTES);

static void usb_uart_isr(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
		uint8_t chunk[64];
		int n;

		if (!uart_irq_rx_ready(dev)) {
			continue;
		}
		n = uart_fifo_read(dev, chunk, sizeof(chunk));
		if (n <= 0) {
			continue;
		}
		/* On overflow the excess is dropped; the session framing layer
		 * detects the short/garbled frame and the peer retries. */
		(void)ring_buf_put(&usb_rx_ring, chunk, (uint32_t)n);
	}
}

static int usb_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(t);
	for (size_t i = 0; i < len; i++) {
		uart_poll_out(cdc_dev, buf[i]);
	}
	return 0;
}

static int usb_recv(cantil_transport_t *t, uint8_t *buf, size_t max_len, size_t *received)
{
	ARG_UNUSED(t);

	*received = ring_buf_get(&usb_rx_ring, buf, (uint32_t)max_len);
	return 0;
}

static bool usb_connected(cantil_transport_t *t)
{
	ARG_UNUSED(t);
	return connected;
}

static cantil_transport_t usb_transport = {
	.send = usb_send,
	.recv = usb_recv,
	.connected = usb_connected,
};

/*
 * Track the host DTR line as the "client attached" signal. This is read by
 * usb_connected(), which the session recv loop polls so it can abort a dead
 * session the instant the client disconnects (see usb_connected() and the
 * RECV_TIMEOUT_MS note in session.c). Detection must be prompt: a client that
 * reconnects and sends its Noise msg1 while the previous session is still
 * blocked in recv has those bytes consumed as a command frame, desyncing every
 * following frame. So this is driven two ways — event-first, poll as backstop.
 */
static void update_connected(void)
{
	uint32_t dtr = 0;

	uart_line_ctrl_get(cdc_dev, UART_LINE_CTRL_DTR, &dtr);

	if ((bool)dtr != connected) {
		connected = (bool)dtr;
		LOG_INF("USB CDC/ACM %s", connected ? "connected" : "disconnected");
	}
}

static void dtr_check(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(dtr_work, dtr_check);

static void dtr_check(struct k_work *work)
{
	ARG_UNUSED(work);
	update_connected();
	k_work_reschedule(&dtr_work, K_MSEC(100));
}

/*
 * The nRF UDC reports it can detect VBUS, so the stack does not enable itself:
 * we enable on VBUS_READY and disable on VBUS_REMOVED. Without this callback
 * the device would init but never come up on the bus.
 */
static void usbd_msg_cb(struct usbd_context *const ctx, const struct usbd_msg *const msg)
{
	/*
	 * The host toggles DTR on open/close; catching the control-line-state
	 * change here updates `connected` immediately, without waiting up to a
	 * full dtr_work poll interval. That promptness is what lets a dead
	 * session be torn down before a fast-reconnecting client's msg1
	 * arrives. Only the protocol port (cdc_dev) matters; the console port
	 * raises DTR too but drives no session.
	 */
	if (msg->type == USBD_MSG_CDC_ACM_CONTROL_LINE_STATE && msg->dev == cdc_dev) {
		update_connected();
		return;
	}

	if (!usbd_can_detect_vbus(ctx)) {
		return;
	}

	if (msg->type == USBD_MSG_VBUS_READY) {
		if (usbd_enable(ctx)) {
			LOG_ERR("usbd_enable (VBUS ready) failed");
		}
	} else if (msg->type == USBD_MSG_VBUS_REMOVED) {
		connected = false;
		if (usbd_disable(ctx)) {
			LOG_ERR("usbd_disable (VBUS removed) failed");
		}
	}
}

static int cantil_usbd_setup(void)
{
	int err;

	err = usbd_add_descriptor(&cantil_usbd, &cantil_lang);
	if (err) {
		LOG_ERR("add language descriptor: %d", err);
		return err;
	}

	err = usbd_add_descriptor(&cantil_usbd, &cantil_mfr);
	if (err) {
		LOG_ERR("add manufacturer descriptor: %d", err);
		return err;
	}

	err = usbd_add_descriptor(&cantil_usbd, &cantil_product);
	if (err) {
		LOG_ERR("add product descriptor: %d", err);
		return err;
	}

	err = usbd_add_descriptor(&cantil_usbd, &cantil_sn);
	if (err) {
		LOG_ERR("add serial-number descriptor: %d", err);
		return err;
	}

	err = usbd_add_configuration(&cantil_usbd, USBD_SPEED_FS, &cantil_fs_config);
	if (err) {
		LOG_ERR("add FS configuration: %d", err);
		return err;
	}

	err = usbd_register_all_classes(&cantil_usbd, USBD_SPEED_FS, 1, NULL);
	if (err) {
		LOG_ERR("register classes: %d", err);
		return err;
	}

	/*
	 * Two CDC ACM functions each carry an Interface Association Descriptor,
	 * so the device class triple must advertise IAD (MISC / common / IAD)
	 * rather than defer to the interface descriptors.
	 */
	usbd_device_set_code_triple(&cantil_usbd, USBD_SPEED_FS, USB_BCC_MISCELLANEOUS, 0x02, 0x01);

	err = usbd_msg_register_cb(&cantil_usbd, usbd_msg_cb);
	if (err) {
		LOG_ERR("register message callback: %d", err);
		return err;
	}

	return usbd_init(&cantil_usbd);
}

int transport_usb_init(void)
{
	if (!device_is_ready(cdc_dev)) {
		LOG_ERR("CDC/ACM device not ready");
		return -ENODEV;
	}

	int ret = cantil_usbd_setup();

	if (ret) {
		LOG_ERR("USB device setup failed: %d", ret);
		return ret;
	}

	/*
	 * Register the RX ISR and enable interrupt RX now, before the host sets
	 * the configuration. Enabling here sets CDC_ACM_IRQ_RX_ENABLED so the
	 * class arms the OUT endpoint from usbd_cdc_acm_enable(); if the class
	 * is already enabled, uart_irq_rx_enable() arms it directly.
	 */
	uart_irq_rx_disable(cdc_dev);
	uart_irq_tx_disable(cdc_dev);
	uart_irq_callback_user_data_set(cdc_dev, usb_uart_isr, NULL);
	uart_irq_rx_enable(cdc_dev);

	/*
	 * On a controller without VBUS detection the stack must be enabled
	 * here; on the nRF UDC (which detects VBUS) usbd_msg_cb() does it on
	 * VBUS_READY instead.
	 */
	if (!usbd_can_detect_vbus(&cantil_usbd)) {
		ret = usbd_enable(&cantil_usbd);
		if (ret) {
			LOG_ERR("usbd_enable failed: %d", ret);
			return ret;
		}
	}

	LOG_INF("USB CDC/ACM transport ready");
	k_work_schedule(&dtr_work, K_MSEC(100));
	return 0;
}

cantil_transport_t *transport_usb_get(void)
{
	return connected ? &usb_transport : NULL;
}

void transport_usb_flush_rx(void)
{
	/* Mask the RX IRQ across the reset: ring_buf_reset() rewrites head and
	 * tail non-atomically, so a usb_uart_isr() ring_buf_put() landing in the
	 * middle would corrupt the buffer. */
	uart_irq_rx_disable(cdc_dev);
	ring_buf_reset(&usb_rx_ring);
	uart_irq_rx_enable(cdc_dev);
}
