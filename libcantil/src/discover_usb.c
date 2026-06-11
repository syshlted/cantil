/*
 * USB device discovery for Cantil hardware.
 *
 * Linux implementation walks /sys/bus/usb/devices and matches VID:PID.
 * For each match it finds the two CDC-ACM interfaces:
 *   - interface :1.0 → protocol port (ACM #0)
 *   - interface :1.2 → console port  (ACM #1)
 * and reads the ttyACMx node name from <iface>/tty/.
 *
 * Other platforms: return CANTIL_ERR_NOT_SUPPORTED for now. macOS would use
 * IOKit (IOServiceMatching("IOUSBDevice")); Windows would use SetupDi*.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cantil.h"

#if defined(__linux__)

#define SYSFS_USB "/sys/bus/usb/devices"

/* Read a small one-line sysfs attribute; trim trailing newline. */
static int read_attr(const char *dir, const char *name, char *out, size_t cap)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    if (!fgets(out, (int)cap, f)) { fclose(f); out[0] = 0; return -1; }
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = 0;
    return 0;
}

static unsigned parse_hex(const char *s)
{
    return (unsigned)strtoul(s, NULL, 16);
}

/* Find the first ttyACMx node under <iface>/tty/. */
static int find_tty(const char *iface_dir, char *out, size_t cap)
{
    char tty_dir[512];
    snprintf(tty_dir, sizeof(tty_dir), "%s/tty", iface_dir);
    DIR *d = opendir(tty_dir);
    if (!d) return -1;

    int found = -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, "tty", 3) != 0) continue;
        snprintf(out, cap, "/dev/%s", de->d_name);
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

int cantil_list_usb_devices(cantil_usb_device_t **out)
{
    if (!out) return CANTIL_ERR_INVALID_ARG;
    *out = NULL;

    DIR *root = opendir(SYSFS_USB);
    if (!root) return CANTIL_ERR_IO;

    /* Two-pass-free single growing buffer. Cantil devices on a host count
     * in the single digits; realloc per match is fine. */
    cantil_usb_device_t *list = NULL;
    size_t count = 0;

    struct dirent *de;
    while ((de = readdir(root))) {
        /* Top-level USB devices have names like "1-2"; interfaces look like
         * "1-2:1.0" — skip those, we recurse into them below. */
        if (de->d_name[0] == '.') continue;
        if (strchr(de->d_name, ':'))  continue;

        char dev_dir[512];
        snprintf(dev_dir, sizeof(dev_dir), "%s/%s", SYSFS_USB, de->d_name);

        char vid_s[16], pid_s[16];
        if (read_attr(dev_dir, "idVendor",  vid_s, sizeof(vid_s)) < 0) continue;
        if (read_attr(dev_dir, "idProduct", pid_s, sizeof(pid_s)) < 0) continue;
        unsigned vid = parse_hex(vid_s), pid = parse_hex(pid_s);
        if (vid != CANTIL_USB_VID || pid != CANTIL_USB_PID) continue;

        cantil_usb_device_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.vid = (uint16_t)vid;
        entry.pid = (uint16_t)pid;
        read_attr(dev_dir, "serial", entry.serial, sizeof(entry.serial));

        /* CDC-ACM interfaces. CDC composite devices put the abstract control
         * model on the even interface; the paired data interface is one above.
         * Cantil exposes two ACMs → control interfaces at .0 and .2. */
        char iface[512];
        snprintf(iface, sizeof(iface), "%s/%s:1.0", SYSFS_USB, de->d_name);
        find_tty(iface, entry.protocol_port, sizeof(entry.protocol_port));
        snprintf(iface, sizeof(iface), "%s/%s:1.2", SYSFS_USB, de->d_name);
        find_tty(iface, entry.console_port,  sizeof(entry.console_port));

        cantil_usb_device_t *grown = realloc(list,
                                             (count + 1) * sizeof(*list));
        if (!grown) {
            free(list);
            closedir(root);
            return CANTIL_ERR_NO_MEMORY;
        }
        list = grown;
        list[count++] = entry;
    }
    closedir(root);

    *out = list;
    return (int)count;
}

#else  /* !__linux__ */

int cantil_list_usb_devices(cantil_usb_device_t **out)
{
    if (out) *out = NULL;
    return CANTIL_ERR_NOT_SUPPORTED;
}

#endif
