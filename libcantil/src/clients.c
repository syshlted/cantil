/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/* Client bond management — cantil_list_clients / cantil_unpair_client /
 * cantil_set_client_name  (transport + pairing T-15). */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../include/cantil.h"
#include "internal.h"
#include "cantil_cbor.h"

#define CLIENTS_SCRATCH_SZ 4096

cantil_err_t cantil_list_clients(cantil_session_t *s,
                                 int (*cb)(const cantil_client_info_t *, void *),
                                 void *userdata)
{
    if (!s || !cb) return CANTIL_ERR_INVALID_ARG;

    static uint8_t scratch[CLIENTS_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_LIST_CLIENTS, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen == 0) return CANTIL_ERR_PROTOCOL;

    size_t off = 0;
    uint8_t mt; uint64_t v;
    if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0)
        return CANTIL_ERR_PROTOCOL;
    if (mt != CANTIL_CBOR_MT_ARRAY) return CANTIL_ERR_PROTOCOL;
    uint32_t count = (uint32_t)v;

    for (uint32_t i = 0; i < count; i++) {
        if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0 ||
            mt != CANTIL_CBOR_MT_MAP || v != 4)
            return CANTIL_ERR_PROTOCOL;

        cantil_client_info_t info = {0};

        for (int k = 0; k < 4; k++) {
            const uint8_t *key; size_t klen;
            if (cantil_cbor_read_tstr(d, dlen, &off, &key, &klen) != 0 ||
                klen != 1)
                return CANTIL_ERR_PROTOCOL;
            char kc = (char)key[0];

            if (kc == 'k' || kc == 'n') {
                uint32_t u;
                if (cantil_cbor_read_uint32(d, dlen, &off, &u) != 0)
                    return CANTIL_ERR_PROTOCOL;
                if (kc == 'k') info.kind = (cantil_client_kind_t)u;
                else           info.created_at = u;
            } else if (kc == 'p') {
                /* bstr(32) — raw pubkey */
                const uint8_t *bval; size_t blen;
                if (cantil_cbor_read_bstr(d, dlen, &off, &bval, &blen) != 0 ||
                    blen != 32)
                    return CANTIL_ERR_PROTOCOL;
                memcpy(info.pubkey, bval, 32);
            } else if (kc == 't') {
                /* tstr — friendly name */
                const uint8_t *tval; size_t tlen;
                if (cantil_cbor_read_tstr(d, dlen, &off, &tval, &tlen) != 0)
                    return CANTIL_ERR_PROTOCOL;
                if (tlen >= CANTIL_CLIENT_NAME_MAX)
                    tlen = CANTIL_CLIENT_NAME_MAX - 1;
                memcpy(info.friendly_name, tval, tlen);
                info.friendly_name[tlen] = '\0';
            } else {
                return CANTIL_ERR_PROTOCOL;
            }
        }

        int stop = cb(&info, userdata);
        if (stop) return (cantil_err_t)stop;
    }
    return CANTIL_OK;
}

cantil_err_t cantil_unpair_client(cantil_session_t *s, const uint8_t pubkey[32])
{
    if (!s || !pubkey) return CANTIL_ERR_INVALID_ARG;

    static uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    /* Tap-confirm opcode — device blocks on gesture before replying. */
    cantil_err_t rc = cantil_do_request_to(s, CMD_UNPAIR_CLIENT, 0x01,
                                           pubkey, 32,
                                           scratch, sizeof(scratch),
                                           &d, &dlen,
                                           CANTIL_TAP_CONFIRM_TIMEOUT_MS);
    return rc;
}

cantil_err_t cantil_set_client_name(cantil_session_t *s,
                                    const uint8_t pubkey[32],
                                    const char *name)
{
    if (!s || !pubkey || !name) return CANTIL_ERR_INVALID_ARG;
    size_t name_len = strlen(name);
    if (name_len >= CANTIL_CLIENT_NAME_MAX) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[32 + CANTIL_CLIENT_NAME_MAX];
    memcpy(req, pubkey, 32);
    memcpy(req + 32, name, name_len);

    static uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_SET_CLIENT_NAME, 0x01,
                             req, 32 + name_len,
                             scratch, sizeof(scratch),
                             &d, &dlen);
}
