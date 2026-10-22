/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * The last format route, closed at link time.
 *
 * CONFIG_FILE_SYSTEM_MKFS=n removes fs_mkfs() and littlefs_mkfs() from the
 * production image, so nothing can ask the *filesystem layer* to format. It
 * does not remove littlefs's own formatter: littlefs_mount() calls
 * lfs_format() from a branch that is compiled unconditionally and guarded only
 * at runtime, by FS_MOUNT_FLAG_NO_FORMAT on the mount point. No Kconfig symbol
 * gates that branch.
 *
 *     ret = lfs_mount(&fs->lfs, &fs->cfg);
 *     if (ret < 0 && (mountp->flags & FS_MOUNT_FLAG_NO_FORMAT) == 0) {
 *             ...
 *             ret = lfs_format(&fs->lfs, &fs->cfg);     <-- 200 bytes, live
 *
 * That is the exact code that erased unit #2 on 2026-07-22, in a build written
 * to be incapable of formatting. Its residual presence is not a technicality:
 * one cleared flag stands between it and an unexportable CA key.
 *
 * So the build links with -Wl,--wrap=lfs_format and defines the wrapper below.
 * Every reference from littlefs_mount() resolves here instead, and because
 * nothing references __real_lfs_format, --gc-sections drops the real
 * formatter's 200 bytes from the image entirely. The guarantee stops being "a
 * runtime flag is set correctly" and becomes "the code is not there", which is
 * the property assert_no_mkfs.cmake can actually check.
 *
 * Why a link-time wrap and not a patched Zephyr: the west workspace lives
 * outside this repository and `west update` would silently revert a patch to
 * it, restoring the erase path with nothing in the build log. A Kconfig gate
 * upstream is still the right end state and is worth proposing; this does not
 * depend on it landing.
 *
 * This file is compiled only when the wrap is active — see the guard in
 * firmware/CMakeLists.txt, which is the same predicate that arms the post-link
 * assertion. Builds that legitimately format (the step-1 factory image, the
 * ztest suites) set CONFIG_FILE_SYSTEM_MKFS=y, take neither, and are
 * unaffected.
 */

#include <zephyr/kernel.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(no_format, LOG_LEVEL_INF);

int __wrap_lfs_format(lfs_t *lfs, const struct lfs_config *cfg);

int __wrap_lfs_format(lfs_t *lfs, const struct lfs_config *cfg)
{
	ARG_UNUSED(lfs);
	ARG_UNUSED(cfg);

	/*
	 * Reaching this is a bug, not a recoverable condition: the mount point
	 * sets FS_MOUNT_FLAG_NO_FORMAT whenever this build cannot format, so
	 * littlefs_mount() should never take the branch that calls here. Say so
	 * loudly — a device that refuses to mount is recoverable, and the log is
	 * the only thing telling the operator which of the two it is.
	 */
	LOG_ERR("lfs_format called in a build that cannot format — refused");
	LOG_ERR("the volume is intact; nothing was erased");
	LOG_ERR("check the storage partition definition for this board");
	LOG_ERR("a genuinely blank device is initialised by the factory image");

	/* -> -EINVAL via lfs_to_errno(), which storage_init() reports as a
	 * configuration error rather than a filesystem one. */
	return LFS_ERR_INVAL;
}
