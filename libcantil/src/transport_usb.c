#define _DEFAULT_SOURCE  /* cfmakeraw, cfsetspeed */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/select.h>
#include "internal.h"

struct usb_transport {
    struct cantil_transport base;
    int fd;
};

static int usb_send(struct cantil_transport *t,
                    const uint8_t *buf, size_t len)
{
    struct usb_transport *u = (struct usb_transport *)t;
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(u->fd, buf + off, len - off);
        if (n < 0)  return -errno;
        if (n == 0) return -EIO;
        off += (size_t)n;
    }
    return 0;
}

static int usb_recv(struct cantil_transport *t,
                    uint8_t *buf, size_t max_len,
                    size_t *received, int timeout_ms)
{
    struct usb_transport *u = (struct usb_transport *)t;
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(u->fd, &rfds);
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(u->fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0)  return -errno;
    if (ret == 0) { *received = 0; return -ETIMEDOUT; }

    ssize_t n = read(u->fd, buf, max_len);
    if (n < 0)  return -errno;
    if (n == 0) return -EIO;
    *received = (size_t)n;
    return 0;
}

static void usb_close(struct cantil_transport *t)
{
    struct usb_transport *u = (struct usb_transport *)t;
    close(u->fd);
}

cantil_transport_t *cantil_transport_open_usb(const char *port)
{
    struct usb_transport *u = calloc(1, sizeof(*u));
    if (!u)
        return NULL;

    /* O_NONBLOCK on open() avoids hanging if the port has no carrier.
     * We switch back to blocking after open. */
    u->fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (u->fd < 0) {
        free(u);
        return NULL;
    }

    int fl = fcntl(u->fd, F_GETFL);
    fcntl(u->fd, F_SETFL, fl & ~O_NONBLOCK);

    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    tcgetattr(u->fd, &tty);
    cfmakeraw(&tty);
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 0;
    tcsetattr(u->fd, TCSANOW, &tty);
    tcflush(u->fd, TCIOFLUSH);

    /* Wait for the device to exit any stale session from the previous
     * connection. The device's first-frame recv timeout is 2000ms; 700ms
     * here gives a generous safety margin while keeping reconnect snappy.
     * Without this delay msg1 can arrive while a stale session is still
     * draining its command loop, corrupting the Noise handshake. */
    usleep(700000);

    u->base.send  = usb_send;
    u->base.recv  = usb_recv;
    u->base.close = usb_close;

    return (cantil_transport_t *)u;
}
