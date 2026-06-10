#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "transport.h"

LOG_MODULE_REGISTER(transport, LOG_LEVEL_INF);

#if defined(CONFIG_CANTIL_TRANSPORT_USB)
extern int transport_usb_init(void);
extern cantil_transport_t *transport_usb_get(void);
#endif

#if defined(CONFIG_CANTIL_TRANSPORT_BLE)
extern int transport_ble_init(void);
extern cantil_transport_t *transport_ble_get(void);
#endif

int transport_init(void)
{
	int ret = 0;

#if defined(CONFIG_CANTIL_TRANSPORT_USB)
	ret = transport_usb_init();
	if (ret) {
		LOG_ERR("USB transport init failed: %d", ret);
		return ret;
	}
#endif

#if defined(CONFIG_CANTIL_TRANSPORT_BLE)
	ret = transport_ble_init();
	if (ret) {
		LOG_ERR("BLE transport init failed: %d", ret);
		return ret;
	}
#endif

	return ret;
}

cantil_transport_t *transport_get_active(void)
{
#if defined(CONFIG_CANTIL_TRANSPORT_USB)
	cantil_transport_t *t = transport_usb_get();

	if (t != NULL) {
		return t;
	}
#endif

#if defined(CONFIG_CANTIL_TRANSPORT_BLE)
	return transport_ble_get();
#endif

	return NULL;
}
