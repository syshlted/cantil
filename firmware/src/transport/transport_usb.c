#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/logging/log.h>

#include "transport.h"

LOG_MODULE_REGISTER(transport_usb, LOG_LEVEL_INF);

/*
 * Protocol UART selected via chosen `cantil,protocol-uart` (per-board overlay).
 * The board overlay routes zephyr,console to a different CDC ACM endpoint so
 * log output cannot interleave with the Noise byte stream on this one.
 *
 * USB_DEVICE_STACK + USB_DEVICE_INITIALIZE_AT_BOOT are enabled by the board;
 * USB is initialized at POST_KERNEL before main() runs.
 */
#define CDC_NODE DT_CHOSEN(cantil_protocol_uart)

static const struct device *cdc_dev = DEVICE_DT_GET(CDC_NODE);
static bool connected;

static int usb_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(t);
	for (size_t i = 0; i < len; i++) {
		uart_poll_out(cdc_dev, buf[i]);
	}
	return 0;
}

static int usb_recv(cantil_transport_t *t, uint8_t *buf,
		    size_t max_len, size_t *received)
{
	ARG_UNUSED(t);
	size_t n = 0;

	while (n < max_len) {
		if (uart_poll_in(cdc_dev, &buf[n]) == 0) {
			n++;
		} else {
			break;
		}
	}
	*received = n;
	return 0;
}

static cantil_transport_t usb_transport = {
	.send = usb_send,
	.recv = usb_recv,
};

static void dtr_check(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(dtr_work, dtr_check);

static void dtr_check(struct k_work *work)
{
	ARG_UNUSED(work);
	uint32_t dtr = 0;

	uart_line_ctrl_get(cdc_dev, UART_LINE_CTRL_DTR, &dtr);

	if ((bool)dtr != connected) {
		connected = (bool)dtr;
		LOG_INF("USB CDC/ACM %s", connected ? "connected" : "disconnected");
	}

	k_work_reschedule(&dtr_work, K_MSEC(100));
}

int transport_usb_init(void)
{
	if (!device_is_ready(cdc_dev)) {
		LOG_ERR("CDC/ACM device not ready");
		return -ENODEV;
	}

	/*
	 * Call usb_enable() explicitly rather than relying on
	 * USB_DEVICE_INITIALIZE_AT_BOOT. The auto-init fires during SYS_INIT
	 * at APPLICATION level, before main() runs, which races with
	 * NRF_SECURITY and QSPI driver init and leaves the USBD unable to
	 * respond to SET_ADDRESS. By calling it here (after all SYS_INITs are
	 * done) we guarantee the stack is fully ready before D+ goes high.
	 */
	int ret = usb_enable(NULL);

	if (ret && ret != -EALREADY) {
		LOG_ERR("usb_enable failed: %d", ret);
		return ret;
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
	uint8_t discard;

	while (uart_poll_in(cdc_dev, &discard) == 0) {}
}
