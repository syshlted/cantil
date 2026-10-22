/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Phase-1 Bazel smoke test: proves the xiao_ble board package + arm-zephyr
 * toolchain build and link under Bazel, isolated from Cantil's own modules.
 * Delete once the real app builds (docs/roadmap/bazel-migration.md).
 */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/devicetree.h>

int main(void)
{
	printk("Cantil Bazel smoke: hello from %s\n", DT_PROP_BY_IDX(DT_ROOT, compatible, 0));
	return 0;
}
