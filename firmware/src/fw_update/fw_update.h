#pragma once

#include <stdint.h>
#include <stddef.h>

/* Sub-operations for CMD_UPDATE_FIRMWARE (CBOR map key 0 in the data field). */
#define FW_UPDATE_OP_BEGIN  0U  /* {0:0, 1:total_size}               */
#define FW_UPDATE_OP_CHUNK  1U  /* {0:1, 1:offset, 2:<bstr data>}    */
#define FW_UPDATE_OP_COMMIT 2U  /* {0:2}                             */

/*
 * Open the MCUboot secondary slot and erase it in preparation for streaming.
 * total_size must be > 0 and ≤ CONFIG_CANTIL_FW_SLOT_SIZE.
 *
 * Returns 0 on success.
 * -EBUSY   another update is already in progress
 * -EFBIG   total_size exceeds the secondary slot
 * -EIO     flash erase error
 */
int fw_update_begin(uint32_t total_size);

/*
 * Write one image chunk to the secondary slot.
 * offset + len must not exceed the total_size from fw_update_begin().
 * Chunks must be a multiple of the flash write alignment (4 bytes on nRF52840)
 * except for the final chunk, which may be any length.
 *
 * Returns 0 on success.
 * -ENODEV  fw_update_begin() has not been called
 * -ERANGE  offset + len exceeds declared total_size
 * -EIO     flash write error
 */
int fw_update_chunk(uint32_t offset, const uint8_t *data, size_t len);

/*
 * Close the flash area after all chunks have been written.  Does not set the
 * MCUboot pending flag; call fw_update_set_pending() after user confirms.
 *
 * Returns 0 on success, -ENODEV if no update is in progress.
 */
int fw_update_close(void);

/*
 * Write the fw_pending sentinel to storage and set the MCUboot upgrade flag so
 * the next reboot validates and swaps the new image.  Caller must call
 * fw_update_close() first.
 *
 * Returns 0 on success, negative errno otherwise.
 */
int fw_update_set_pending(void);

/*
 * Abort an in-progress update: erase the secondary slot and close.
 * Safe to call even if no update is in progress.
 */
void fw_update_abort(void);

/*
 * Boot-time outcome check — call from main() after storage_init() and
 * gesture_init().  Inspects the fw_pending sentinel and MCUboot image state:
 *
 *   Sentinel present + image unconfirmed:
 *     New image is running in test mode.  Confirm it, clear sentinel,
 *     play LED_PATTERN_FW_APPLIED.
 *
 *   Sentinel present + image already confirmed (MCUboot rejected the staged image):
 *     Play LED_PATTERN_FW_INVALID and wait up to
 *     CONFIG_CANTIL_FW_INVALID_CONFIRM_TIMEOUT_SEC for a tap-confirm.
 *     Tap accepted: erase secondary slot; if CONFIG_CANTIL_FW_UPDATE_WIPE_ON_INVALID
 *       perform a secure storage wipe, then boot_set_pending() + reboot anyway
 *       so the (now-wiped) device installs the untrusted image.
 *     Tap denied / timeout: erase secondary slot, continue normal boot.
 *
 *   No sentinel: returns immediately.
 */
void fw_update_boot_check(void);
