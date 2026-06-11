#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <bluetooth/services/nus.h>
#include <zephyr/logging/log.h>

#include "transport.h"

LOG_MODULE_REGISTER(transport_ble, LOG_LEVEL_INF);

#define BLE_RX_BUF_SIZE 512

static struct bt_conn *active_conn;
static bool connected;

static uint8_t rx_buf[BLE_RX_BUF_SIZE];
static size_t rx_len;
static K_SEM_DEFINE(rx_sem, 0, 1);
static K_MUTEX_DEFINE(rx_mutex);

static void nus_received(struct bt_conn *conn,
			 const uint8_t *data, uint16_t len)
{
	ARG_UNUSED(conn);

	k_mutex_lock(&rx_mutex, K_FOREVER);
	size_t space = BLE_RX_BUF_SIZE - rx_len;

	if (len <= space) {
		memcpy(rx_buf + rx_len, data, len);
		rx_len += len;
	}
	k_mutex_unlock(&rx_mutex);
	k_sem_give(&rx_sem);
}

static struct bt_nus_cb nus_cb = {
	.received = nus_received,
};

static int ble_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(t);

	if (!active_conn) {
		return -ENOTCONN;
	}
	return bt_nus_send(active_conn, buf, len);
}

static int ble_recv(cantil_transport_t *t, uint8_t *buf,
		    size_t max_len, size_t *received)
{
	ARG_UNUSED(t);

	k_sem_take(&rx_sem, K_MSEC(100));

	k_mutex_lock(&rx_mutex, K_FOREVER);
	size_t n = MIN(rx_len, max_len);

	memcpy(buf, rx_buf, n);
	rx_len -= n;
	if (rx_len) {
		memmove(rx_buf, rx_buf + n, rx_len);
	}
	k_mutex_unlock(&rx_mutex);

	*received = n;
	return 0;
}

static cantil_transport_t ble_transport = {
	.send = ble_send,
	.recv = ble_recv,
};

static void conn_connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		LOG_WRN("BLE connect failed: %u", err);
		return;
	}
	active_conn = bt_conn_ref(conn);
	connected = true;
	LOG_INF("BLE connected");
}

static void conn_disconnected(struct bt_conn *conn, uint8_t reason)
{
	ARG_UNUSED(reason);
	if (active_conn == conn) {
		bt_conn_unref(active_conn);
		active_conn = NULL;
		connected = false;
		LOG_INF("BLE disconnected: %u", reason);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected    = conn_connected,
	.disconnected = conn_disconnected,
};

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
};

int transport_ble_init(void)
{
	int ret;

	ret = bt_enable(NULL);
	if (ret) {
		LOG_ERR("bt_enable failed: %d", ret);
		return ret;
	}

	ret = bt_nus_init(&nus_cb);
	if (ret) {
		LOG_ERR("bt_nus_init failed: %d", ret);
		return ret;
	}

	ret = bt_le_adv_start(BT_LE_ADV_CONN_ONE_TIME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (ret) {
		LOG_ERR("bt_le_adv_start failed: %d", ret);
		return ret;
	}

	LOG_INF("BLE advertising started");
	return 0;
}

cantil_transport_t *transport_ble_get(void)
{
	return connected ? &ble_transport : NULL;
}
