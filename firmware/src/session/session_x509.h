/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Build-time session X.509 identity constant (transport + pairing task T-01).
 *
 * Generated from firmware/session_x509.toml (path overridable via
 * CONFIG_CANTIL_SESSION_X509_TOML) by scripts/encode_session_x509.py and
 * compiled into the firmware. The bytes are a packed x509_data_t blob in the
 * exact wire format x509_parse() in firmware/src/ca/ca.c accepts, so
 * session_init() can hand the constant straight to the self-signed cert
 * builder at first boot. The CN field is a placeholder ("Cantil") that
 * session_init() overrides with the FICR-derived per-device serial.
 */
extern const uint8_t cantil_session_x509_constant[];
extern const size_t cantil_session_x509_constant_len;
