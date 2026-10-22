/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <zephyr/storage/flash_map.h>

/*
 * Where the Cantil filesystem lives. Private to src/storage/ and to the
 * step-1 factory image, which must create the volume at exactly the offset
 * production will later mount — that agreement is the whole basis of the
 * volume identity marker, so both sides read it from here rather than each
 * naming a partition of their own.
 */

#define MOUNT_POINT "/lfs"

/* Which flash partition backs the LittleFS key/cert store.
 *
 * Under NCS this was always FIXED_PARTITION_ID(storage_partition): Partition
 * Manager synthesised that label and, when
 * CONFIG_PM_PARTITION_REGION_LITTLEFS_EXTERNAL was set, pointed it at the
 * external QSPI device named by the `nordic,pm-ext-flash` chosen node.
 *
 * Upstream Zephyr has no Partition Manager, so the two cases are now distinct
 * devicetree nodes and the board overlay must declare the one it uses:
 *
 *   EXTERNAL — `cantil_storage`, a fixed-partition on the QSPI part
 *              (xiao_ble: the full 2 MB of p25q16h).
 *   INTERNAL — `storage_partition`, the partition the board's own DTS
 *              already carves out of internal flash.
 *
 * A board that sets CANTIL_STORAGE_EXTERNAL without declaring cantil_storage
 * fails at build time with an unresolved-node error, which is the intended
 * behaviour — it used to succeed silently against a PM-invented default.
 */
#if defined(CONFIG_CANTIL_STORAGE_EXTERNAL)
#define LFS_PARTITION      FIXED_PARTITION_ID(cantil_storage)
#define LFS_PARTITION_OFF  FIXED_PARTITION_OFFSET(cantil_storage)
#define LFS_PARTITION_SIZE FIXED_PARTITION_SIZE(cantil_storage)
#else
#define LFS_PARTITION      FIXED_PARTITION_ID(storage_partition)
#define LFS_PARTITION_OFF  FIXED_PARTITION_OFFSET(storage_partition)
#define LFS_PARTITION_SIZE FIXED_PARTITION_SIZE(storage_partition)
#endif
