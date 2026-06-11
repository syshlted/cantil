/*
 * cantil — CLI tool for the Cantil hardware CA
 *
 * Usage:
 *   cantil pair   [--force] [--passkey <digits>]     <port>
 *   cantil status [--trust <tier>] [trust-opts...]  <port>
 *   (other commands — see usage())
 *
 * Trust tiers (--trust):
 *   none    Tier 1 — Noise encrypts; cert accepted without inspection.
 *   pin     Tier 2 — SHA-256 fingerprint of leaf cert must match stored value.
 *             This is the default when a fingerprint has been saved by 'pair'.
 *   ca      Tier 3 — Cert must chain to a CA in the trust store.
 *             Requires --ca-dir or --ca-cert.
 *   ca+cn   Tier 4 — Tier 3 + leaf CN must equal stored or --cn value.
 *             Requires --ca-dir or --ca-cert.
 *
 * Trust options:
 *   --ca-dir <path>   Load all *.der CA certs from a directory (Tier 3/4).
 *   --ca-cert <file>  Load a single CA cert DER file (Tier 3/4).
 *   --cn <value>      Override the expected leaf CN (Tier 4; default: stored CN).
 *
 * Keys are persisted in ${XDG_CONFIG_HOME:-$HOME/.config}/cantil/:
 *   client_priv.bin           — Curve25519 private key (mode 0600)
 *   client_pub.bin            — Curve25519 public key
 *   client_cert.der           — client certificate (Method 4, optional)
 *   client_chain.der          — client certificate chain (optional)
 *   devices/<fp16>/           — one subdir per paired device
 *     device_pub.bin          — pinned device Noise static public key
 *     session_fp.bin          — SHA-256 fingerprint of device session cert leaf
 *     session_cn.bin          — CN from the device session cert (for Tier 4 default)
 *
 * fp16 = SHA-256(device_noise_static_pubkey)[0:8] as 16 lowercase hex chars.
 * Multiple devices are supported; each gets its own subdir.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime / CLOCK_MONOTONIC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <glob.h>
#include <sys/stat.h>
#include <sodium.h>
#include "../include/cantil.h"
#include "../src/key_store.h"
#include "../src/internal.h"


/* ── Module-level CLI cert paths (populated from argv in main) ───────────── */

static const char *g_cert_file  = NULL;
static const char *g_chain_file = NULL;

/* ── Trust policy helpers ───────────────────────────────────────────────── */

/* Parsed CLI trust flags. */
typedef struct {
    int         mode_set;           /* 1 if --trust was given explicitly    */
    cantil_trust_mode_t mode;       /* effective mode (only valid if set)   */
    const char *ca_dir;             /* --ca-dir path, or NULL               */
    const char *ca_cert;            /* --ca-cert file, or NULL              */
    const char *cn_override;        /* --cn value, or NULL                  */
} trust_opts_t;

/*
 * Holds all memory owned on behalf of a cantil_trust_policy_t.
 * Call policy_ctx_free() after the session is done.
 */
typedef struct {
    cantil_trust_policy_t policy;
    cantil_trust_store_t *store;    /* non-NULL for Tier 3/4 */
    uint8_t fp[32];                 /* fingerprint buffer for Tier 2 */
    char    cn[128];                /* CN buffer for Tier 4 */
} policy_ctx_t;

static void policy_ctx_free(policy_ctx_t *ctx)
{
    if (ctx->store) {
        cantil_trust_store_free(ctx->store);
        ctx->store = NULL;
    }
}

/* Read an entire binary file into a malloc'd buffer. Caller frees *out.
 * Returns 0 on success, negative errno on failure. */
static int slurp_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -errno;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -EIO; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -EIO; }
    rewind(f);

    uint8_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return -ENOMEM; }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -EIO; }

    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

/*
 * Build a cantil_trust_policy_t from parsed CLI flags and key-store state.
 *
 * Auto mode (no --trust): Tier 2 if a fingerprint is stored, else Tier 1.
 * Explicit --trust overrides that.
 *
 * Returns 0 on success, 1 on error (message already printed to stderr).
 */
static int build_policy_ctx(const trust_opts_t *opts, policy_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    cantil_trust_mode_t mode;
    if (opts->mode_set) {
        mode = opts->mode;
    } else {
        /* Auto: use stored fingerprint if available. */
        mode = (key_store_load_session_fp(ctx->fp) == 0)
             ? CANTIL_TRUST_PINNED_SELF_SIGNED
             : CANTIL_TRUST_NONE;
    }
    ctx->policy.mode = mode;

    if (mode == CANTIL_TRUST_PINNED_SELF_SIGNED) {
        /* Explicit --trust pin: load fingerprint (may not have been auto-loaded). */
        if (opts->mode_set && key_store_load_session_fp(ctx->fp) != 0) {
            fprintf(stderr,
                    "error: --trust pin requires a stored fingerprint.\n"
                    "Run 'cantil pair <port>' first.\n");
            return 1;
        }
        ctx->policy.expected_fingerprint = ctx->fp;
    }

    if (mode == CANTIL_TRUST_CA_ALLOWLIST ||
        mode == CANTIL_TRUST_CA_PLUS_CN_PIN) {

        if (!opts->ca_dir && !opts->ca_cert) {
            fprintf(stderr,
                    "error: --trust ca / ca+cn requires --ca-dir or --ca-cert.\n");
            return 1;
        }

        cantil_trust_store_t *store = cantil_trust_store_new();
        if (!store) {
            fprintf(stderr, "error: out of memory allocating trust store\n");
            return 1;
        }
        int loaded = 0;

        if (opts->ca_dir) {
            int n = cantil_trust_load_dir(store, opts->ca_dir);
            if (n < 0) {
                fprintf(stderr, "error: cannot read CA dir '%s': %s\n",
                        opts->ca_dir, strerror(-n));
                cantil_trust_store_free(store);
                return 1;
            }
            loaded += n;
        }
        if (opts->ca_cert) {
            uint8_t *der; size_t len;
            int rc = slurp_file(opts->ca_cert, &der, &len);
            if (rc) {
                fprintf(stderr, "error: cannot read CA cert '%s': %s\n",
                        opts->ca_cert, strerror(-rc));
                cantil_trust_store_free(store);
                return 1;
            }
            rc = cantil_trust_add_ca(store, der, len);
            free(der);
            if (rc) {
                fprintf(stderr, "error: cannot add CA cert from '%s'\n",
                        opts->ca_cert);
                cantil_trust_store_free(store);
                return 1;
            }
            loaded++;
        }

        if (loaded == 0) {
            fprintf(stderr,
                    "error: no CA certs loaded — check --ca-dir / --ca-cert\n");
            cantil_trust_store_free(store);
            return 1;
        }

        ctx->store = store;
        ctx->policy.trust_store = store;
    }

    if (mode == CANTIL_TRUST_CA_PLUS_CN_PIN) {
        if (opts->cn_override) {
            ctx->policy.expected_cn = opts->cn_override;
        } else if (key_store_load_session_cn(ctx->cn, sizeof(ctx->cn)) == 0) {
            ctx->policy.expected_cn = ctx->cn;
        } else {
            fprintf(stderr,
                    "error: --trust ca+cn requires --cn or a stored CN "
                    "(run 'cantil pair' first).\n");
            policy_ctx_free(ctx);
            return 1;
        }
    }

    return 0;
}

/* Parse trust-related flags from argv[start..argc-2] (port is argv[argc-1]).
 * Unknown flags are ignored here — command parsers handle their own flags.
 * Returns 0 on success, 1 on error. */
static int parse_trust_opts(int argc, char **argv, int start,
                             trust_opts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    for (int i = start; i < argc - 1; i++) {
        if (strcmp(argv[i], "--trust") == 0 && i + 1 < argc - 1) {
            const char *m = argv[++i];
            if      (strcmp(m, "none")  == 0)
                opts->mode = CANTIL_TRUST_NONE;
            else if (strcmp(m, "pin")   == 0)
                opts->mode = CANTIL_TRUST_PINNED_SELF_SIGNED;
            else if (strcmp(m, "ca")    == 0)
                opts->mode = CANTIL_TRUST_CA_ALLOWLIST;
            else if (strcmp(m, "ca+cn") == 0)
                opts->mode = CANTIL_TRUST_CA_PLUS_CN_PIN;
            else {
                fprintf(stderr,
                        "error: unknown --trust mode '%s' "
                        "(none|pin|ca|ca+cn)\n", m);
                return 1;
            }
            opts->mode_set = 1;
        } else if (strcmp(argv[i], "--ca-dir") == 0 && i + 1 < argc - 1) {
            opts->ca_dir = argv[++i];
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc - 1) {
            opts->ca_cert = argv[++i];
        } else if (strcmp(argv[i], "--cn") == 0 && i + 1 < argc - 1) {
            opts->cn_override = argv[++i];
        }
    }
    return 0;
}

/* ── Client identity cert (Method 4, T-19) ──────────────────────────────── */

/*
 * Module-level client cert for Method 4 connections.  Populated once at
 * startup from --client-cert / --client-chain CLI flags (or auto-loaded from
 * the key store when no flag is given and client_cert.der is stored).
 * NULL cert_der means "no client cert" → sends {} on msg3 (Methods 0–3).
 */
static cantil_client_cert_t g_client_cert = {0};
static uint8_t *g_client_cert_buf   = NULL;
static uint8_t *g_client_chain_buf  = NULL;

static void free_client_cert(void)
{
    free(g_client_cert_buf);
    free(g_client_chain_buf);
    g_client_cert_buf  = NULL;
    g_client_chain_buf = NULL;
    memset(&g_client_cert, 0, sizeof(g_client_cert));
}

/*
 * Load the client cert (and optional chain) from `cert_file`/`chain_file`
 * paths.  If both are NULL, auto-load from the key store if present.
 * Returns 0 on success (even if no cert is available), 1 on hard error.
 */
static int load_client_cert(const char *cert_file, const char *chain_file)
{
    free_client_cert();

    if (cert_file) {
        if (slurp_file(cert_file, &g_client_cert_buf, &g_client_cert.cert_len)) {
            fprintf(stderr, "error: cannot read --client-cert '%s': %s\n",
                    cert_file, strerror(errno));
            return 1;
        }
        g_client_cert.cert_der = g_client_cert_buf;

        if (chain_file) {
            if (slurp_file(chain_file, &g_client_chain_buf,
                           &g_client_cert.chain_len)) {
                fprintf(stderr, "error: cannot read --client-chain '%s': %s\n",
                        chain_file, strerror(errno));
                free_client_cert();
                return 1;
            }
            g_client_cert.chain_der = g_client_chain_buf;
        }
    } else {
        /* Auto-load from key store (non-fatal if absent). */
        if (key_store_has_client_cert()) {
            if (key_store_load_client_cert(&g_client_cert_buf,
                                           &g_client_cert.cert_len) == 0) {
                g_client_cert.cert_der = g_client_cert_buf;
                /* Chain is optional; ignore -ENOENT. */
                if (key_store_load_client_chain(&g_client_chain_buf,
                                                &g_client_cert.chain_len) == 0) {
                    g_client_cert.chain_der = g_client_chain_buf;
                } else {
                    free(g_client_chain_buf);
                    g_client_chain_buf = NULL;
                    g_client_cert.chain_der = NULL;
                    g_client_cert.chain_len = 0;
                }
            }
        }
    }
    return 0;
}

/* Convenience: pass to cantil_session_open(); NULL when no cert loaded. */
static const cantil_client_cert_t *client_cert_arg(void)
{
    return g_client_cert.cert_der ? &g_client_cert : NULL;
}

/* Print a 32-byte key as a short fingerprint: SHA-256 → first 8 bytes hex */
static void print_fingerprint(const char *label, const uint8_t key[32])
{
    uint8_t hash[32];
    crypto_hash_sha256(hash, key, 32);
    printf("%s: ", label);
    for (int i = 0; i < 8; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

/* ── open_device_session() ──────────────────────────────────────────────── */

/*
 * Open an authenticated session to the device at `port`.
 *
 * Steps:
 *   1. key_store_init() (idempotent)
 *   2. Load client keypair (global)
 *   3. Open transport
 *   4. Open Tier-1 session (NULL policy) — TOFU first contact
 *   5. Get device pubkey from the live session
 *   6. key_store_select_device() — error if not paired
 *   7. build_policy_ctx(topts) — reads per-device session_fp etc.
 *   8. If policy mode != CANTIL_TRUST_NONE: verify policy post-handshake
 *   9. Return open session; set *t_out and *pctx_out.
 *
 * On success the session is open and the caller owns it.
 * On failure a message has been printed to stderr, *t_out is closed,
 * and NULL is returned.
 */
static cantil_session_t *open_device_session(const char *port,
                                              const trust_opts_t *topts,
                                              cantil_transport_t **t_out,
                                              policy_ctx_t *pctx_out)
{
    *t_out = NULL;

    int ret = key_store_init();
    if (ret) {
        fprintf(stderr, "error: cannot initialise key store: %s\n",
                strerror(-ret));
        return NULL;
    }

    cantil_key_t client_priv, client_pub;
    ret = key_store_load_client_keypair(client_priv.bytes, client_pub.bytes);
    if (ret == -ENOENT) {
        fprintf(stderr,
                "error: no client keypair found. Run 'cantil pair' first.\n");
        return NULL;
    } else if (ret) {
        fprintf(stderr, "error: cannot load client keypair: %s\n",
                strerror(-ret));
        return NULL;
    }

    cantil_transport_t *t = cantil_transport_open_usb(port);
    if (!t) {
        fprintf(stderr, "error: cannot open %s: %s\n", port, strerror(errno));
        return NULL;
    }

    /* Tier 1 first — learn the device's static key. */
    cantil_session_t *s = cantil_session_open(t, &client_priv, NULL,
                                              client_cert_arg(), 0);
    if (!s) {
        fprintf(stderr, "error: Noise_XX handshake failed\n");
        cantil_transport_close(t);
        return NULL;
    }

    /* Get the live device pubkey. */
    cantil_key_t dev_pub;
    if (cantil_session_get_device_pubkey(s, &dev_pub) != CANTIL_OK) {
        fprintf(stderr, "error: cannot retrieve device pubkey from session\n");
        cantil_session_close(s);
        cantil_transport_close(t);
        return NULL;
    }

    /* Select the per-device key-store subdir. */
    ret = key_store_select_device(dev_pub.bytes);
    if (ret == -ENOENT) {
        fprintf(stderr,
                "error: device not paired. "
                "Run 'cantil pair %s' first.\n", port);
        cantil_session_close(s);
        cantil_transport_close(t);
        return NULL;
    } else if (ret) {
        fprintf(stderr, "error: key store error: %s\n", strerror(-ret));
        cantil_session_close(s);
        cantil_transport_close(t);
        return NULL;
    }

    /* Build policy from per-device state + CLI options. */
    memset(pctx_out, 0, sizeof(*pctx_out));
    if (build_policy_ctx(topts, pctx_out) != 0) {
        cantil_session_close(s);
        cantil_transport_close(t);
        return NULL;
    }

    /* Post-handshake trust check (skip for Tier 1). */
    if (pctx_out->policy.mode != CANTIL_TRUST_NONE) {
        cantil_err_t terr = cantil_session_verify_policy(s, &pctx_out->policy);
        if (terr != CANTIL_OK) {
            fprintf(stderr,
                    "error: trust check failed — wrong device, cert mismatch, "
                    "or key changed (re-pair with --force to reset)\n");
            policy_ctx_free(pctx_out);
            cantil_session_close(s);
            cantil_transport_close(t);
            return NULL;
        }
    }

    *t_out = t;
    return s;
}

/* ── pair ──────────────────────────────────────────────────────────────── */

static int cmd_pair(const char *port, int force, uint32_t passkey,
                    const char *cert_file, const char *chain_file)
{
    int ret;

    ret = key_store_init();
    if (ret) {
        fprintf(stderr, "error: cannot initialise key store: %s\n",
                strerror(-ret));
        return 1;
    }

    /* Load or generate the client's static keypair. */
    cantil_key_t client_priv, client_pub;
    ret = key_store_load_client_keypair(client_priv.bytes, client_pub.bytes);
    if (ret == -ENOENT) {
        printf("Generating new client keypair...\n");
        cantil_err_t err = cantil_keygen(&client_priv, &client_pub);
        if (err != CANTIL_OK) {
            fprintf(stderr, "error: keygen failed: %s\n", cantil_strerror(err));
            return 1;
        }
        ret = key_store_save_client_keypair(client_priv.bytes, client_pub.bytes);
        if (ret) {
            fprintf(stderr, "error: cannot save client keypair: %s\n",
                    strerror(-ret));
            return 1;
        }
        printf("Client keypair saved.\n");
    } else if (ret) {
        fprintf(stderr, "error: cannot load client keypair: %s\n",
                strerror(-ret));
        return 1;
    }

    /* Load client cert from file (if given) or key store (auto). */
    if (load_client_cert(cert_file, chain_file) != 0)
        return 1;

    /* Connect to device — TOFU mode: no trust policy (Tier 1). */
    printf("Connecting to %s...\n", port);
    cantil_transport_t *t = cantil_transport_open_usb(port);
    if (!t) {
        fprintf(stderr, "error: cannot open %s: %s\n", port, strerror(errno));
        return 1;
    }

    cantil_session_t *s = cantil_session_open(t, &client_priv, NULL,
                                              client_cert_arg(), 0);
    if (!s) {
        fprintf(stderr, "error: Noise_XX handshake failed\n");
        cantil_transport_close(t);
        return 1;
    }

    /* Retrieve the device's static public key learned during the handshake.
     * This must happen BEFORE the force check — we need the key to compute
     * the per-device subdir path. */
    cantil_key_t device_pub;
    cantil_err_t err = cantil_session_get_device_pubkey(s, &device_pub);
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: cannot get device pubkey: %s\n",
                cantil_strerror(err));
        cantil_session_close(s);
        cantil_transport_close(t);
        return 1;
    }

    /* Force check: if this exact device is already paired and --force not set,
     * refuse to overwrite.  A different device always gets a new subdir. */
    if (!force && key_store_select_device(device_pub.bytes) == 0
                && key_store_has_device_pubkey()) {
        fprintf(stderr,
                "error: this device is already paired. "
                "Use --force to re-pair and overwrite the stored device key.\n");
        cantil_session_close(s);
        cantil_transport_close(t);
        return 1;
    }

    /* Create/select the per-device subdir. */
    ret = key_store_init_device(device_pub.bytes);
    if (ret) {
        fprintf(stderr, "error: cannot create device key store: %s\n",
                strerror(-ret));
        cantil_session_close(s);
        cantil_transport_close(t);
        return 1;
    }

    /* Method 3 passkey exchange: if a passkey was given (or prompted),
     * send it as the first command so the device can validate + tap-confirm. */
    uint32_t pk = passkey;
    if (pk == 0) {
        /* Prompt interactively only if stdin is a terminal. */
        char buf[16];
        fprintf(stdout, "Enter device passkey (6 digits; leave blank to skip): ");
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) && buf[0] != '\n') {
            char *end;
            unsigned long v = strtoul(buf, &end, 10);
            if (*end == '\n' || *end == '\0') {
                pk = (uint32_t)v;
            }
        }
    }
    if (pk != 0) {
        printf("Sending passkey to device (tap the device to confirm)...\n");
        cantil_err_t perr = cantil_pairing_passkey_reply(s, pk);
        if (perr != CANTIL_OK) {
            fprintf(stderr, "error: passkey rejected: %s\n", cantil_strerror(perr));
            cantil_session_close(s);
            cantil_transport_close(t);
            return 1;
        }
        printf("Passkey accepted.\n");
    }

    /* Save session cert fingerprint and CN for Tier 2/4 on subsequent sessions. */
    const uint8_t *leaf_der; size_t leaf_len;
    if (cantil_session_device_cert(s, 0, &leaf_der, &leaf_len) == 0) {
        uint8_t fp[32];
        crypto_hash_sha256(fp, leaf_der, leaf_len);
        if (key_store_save_session_fp(fp) != 0)
            fprintf(stderr,
                    "warning: could not save session cert fingerprint\n");
    } else {
        fprintf(stderr,
                "warning: device sent no session cert — Tier 2 pinning "
                "unavailable until re-paired\n");
    }

    char cn[128] = {0};
    if (cantil_session_get_leaf_cn(s, cn, sizeof(cn)) == CANTIL_OK) {
        if (key_store_save_session_cn(cn) != 0)
            fprintf(stderr,
                    "warning: could not save session cert CN\n");
    }

    /* Persist the client cert to the key store when --client-cert was given,
     * so subsequent connections auto-load it without needing the flag. */
    if (cert_file && g_client_cert.cert_der) {
        if (key_store_save_client_cert(g_client_cert.cert_der,
                                       g_client_cert.cert_len) == 0) {
            printf("Client cert saved to key store.\n");
        } else {
            fprintf(stderr, "warning: could not save client cert\n");
        }
        if (g_client_cert.chain_der && g_client_cert.chain_len > 0) {
            if (key_store_save_client_chain(g_client_cert.chain_der,
                                            g_client_cert.chain_len) != 0)
                fprintf(stderr, "warning: could not save client chain\n");
        }
    }

    /* Verify the session works. With PAIRING_TAP_CONFIRM the device won't
     * process any commands until the user taps; give them 25 seconds. */
    fprintf(stderr,
            "Tap confirm on the device: press button TWICE, pause, TWICE\n"
            "(LED should be blinking cyan — you have 25 seconds)...\n");
    cantil_status_t status;
    err = cantil_get_status_wait(s, &status, 25000);
    cantil_session_close(s);
    cantil_transport_close(t);

    if (err == CANTIL_ERR_DEVICE_LOCKED) {
        /* Locked is OK — the device is reachable, session is established. */
    } else if (err != CANTIL_OK) {
        fprintf(stderr, "error: status check after pairing failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    /* Save the device public key to the per-device subdir. */
    ret = key_store_save_device_pubkey(device_pub.bytes);
    if (ret) {
        fprintf(stderr, "error: cannot save device pubkey: %s\n",
                strerror(-ret));
        return 1;
    }

    printf("Paired successfully.\n");
    print_fingerprint("Client key fingerprint", client_pub.bytes);
    print_fingerprint("Device key fingerprint", device_pub.bytes);
    if (cn[0])
        printf("Device session CN:      %s\n", cn);
    printf("\nThe device key and cert fingerprint are now pinned.\n"
           "Subsequent connections default to Tier 2 (fingerprint check).\n");
    return 0;
}

/* ── status ────────────────────────────────────────────────────────────── */

static int cmd_status(const char *port, const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    /* Get the live device Noise static key from the open session. */
    cantil_key_t device_pub;
    cantil_session_get_device_pubkey(s, &device_pub);

    cantil_status_t status;
    cantil_err_t err = cantil_get_status(s, &status);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err != CANTIL_OK && err != CANTIL_ERR_DEVICE_LOCKED) {
        fprintf(stderr, "error: status command failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    printf("Device status:\n");
    printf("  State:              %s\n",
           status.locked ? "LOCKED" : "UNLOCKED");
    printf("  Firmware:           %u.%u.%u\n",
           status.fw_major, status.fw_minor, status.fw_patch);
    printf("  Key slots:          %u / %u used\n",
           status.key_slots_used, status.key_slots_total);
    printf("  Certs issued:       %u (lifetime)\n", status.certs_issued);
    printf("  Certs stored:       %u\n", status.certs_stored);
    printf("  Flash free:         %u KB\n", status.flash_free_kb);
    printf("  BLE bonds:          %u\n", status.ble_bonds);
    printf("  External flash:     %s\n",
           status.has_external_flash ? "yes" : "no");
    print_fingerprint("  Device key        ", device_pub.bytes);
    return 0;
}

/* ── random ────────────────────────────────────────────────────────────── */

static int cmd_random(uint32_t nbytes, const char *port,
                      const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    uint8_t buf[CANTIL_RANDOM_MAX_REQUEST];
    cantil_err_t err = cantil_random_bytes(s, buf, nbytes);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err != CANTIL_OK) {
        fprintf(stderr, "error: random command failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    for (uint32_t i = 0; i < nbytes; i++) {
        printf("%02x", buf[i]);
        if ((i & 0x1F) == 0x1F && i + 1 < nbytes)
            printf("\n");
    }
    if (nbytes & 0x1F)
        printf("\n");
    return 0;
}

/* ── session-cert / session-csr (T-05) ─────────────────────────────────────
 *
 * Fetch the device's session transport-identity cert (GET_SESSION_CERT, 0x60)
 * or a freshly-built session CSR (GET_SESSION_CSR, 0x61) over the pinned Noise
 * session. The DER is printed as plain hex (no separators) so it pipes straight
 * into openssl for parse-verification, e.g.:
 *
 *   cantil session-cert /dev/ttyACM0 | xxd -r -p | openssl x509 -inform DER -text -noout
 *   cantil session-csr  /dev/ttyACM0 | xxd -r -p | openssl req  -inform DER -text -noout
 */
static int cmd_session(const char *what, const char *port,
                       const trust_opts_t *topts)
{
    int want_csr = (strcmp(what, "csr") == 0);
    int want_ca  = (strcmp(what, "ca-cert") == 0);

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    uint8_t      *der = NULL;
    size_t        der_len = 0;
    cantil_err_t  err = want_ca
        ? cantil_get_ca_cert(s, &der, &der_len)
        : want_csr
        ? cantil_get_session_csr(s, &der, &der_len)
        : cantil_get_session_cert(s, &der, &der_len);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err != CANTIL_OK) {
        fprintf(stderr, "error: session-%s command failed: %s\n",
                what, cantil_strerror(err));
        free(der);
        return 1;
    }

    fprintf(stderr, "session %s: %zu bytes DER\n", what, der_len);
    for (size_t i = 0; i < der_len; i++)
        printf("%02x", der[i]);
    printf("\n");
    free(der);
    return 0;
}

/* ── session-sign (T-06) ───────────────────────────────────────────────────
 *
 * CA-sign the device's session transport-identity cert with an on-device CA
 * slot (SIGN_SESSION_FROM_SLOT, 0x62). Requires the device to be UNLOCKED and
 * a tap-confirm gesture — the CLI blocks while the device waits for the tap.
 *
 *   cantil session-sign <issuer_slot> [--force] <port>
 */
static int cmd_session_sign(uint32_t issuer_slot, int force, const char *port,
                            const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    fprintf(stderr,
            "requesting CA-sign of session cert by slot %u%s — "
            "tap the confirm gesture on the device...\n",
            issuer_slot, force ? " (force)" : "");

    cantil_err_t err = cantil_sign_session_from_slot(s, issuer_slot,
                                                     force ? 1 : 0);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err != CANTIL_OK) {
        fprintf(stderr, "error: session-sign failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    fprintf(stderr, "session cert re-signed by slot %u. "
            "Fetch it with 'cantil session-cert %s'.\n", issuer_slot, port);
    return 0;
}

/* ── session-push (T-07) ───────────────────────────────────────────────────
 *
 * Install an externally-signed session transport-identity cert
 * (PUSH_SESSION_CERT, 0x63). The cert (DER) is what an upstream CA produced
 * from the CSR fetched via 'cantil session-csr'; the optional chain (DER,
 * concatenated) carries the issuer cert(s) above the leaf. Requires the device
 * UNLOCKED + a tap-confirm gesture — the CLI blocks while the device waits.
 *
 *   cantil session-push <cert.der> [--chain <chain.der>] [--force] <port>
 */
static int cmd_session_push(const char *cert_path, const char *chain_path,
                            int force, const char *port,
                            const trust_opts_t *topts)
{
    uint8_t *cert = NULL, *chain = NULL;
    size_t cert_len = 0, chain_len = 0;
    int rc = slurp_file(cert_path, &cert, &cert_len);
    if (rc) {
        fprintf(stderr, "error: cannot read cert '%s': %s\n",
                cert_path, strerror(-rc));
        return 1;
    }
    if (chain_path) {
        rc = slurp_file(chain_path, &chain, &chain_len);
        if (rc) {
            fprintf(stderr, "error: cannot read chain '%s': %s\n",
                    chain_path, strerror(-rc));
            free(cert);
            return 1;
        }
    }

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s) {
        free(cert); free(chain);
        return 1;
    }

    fprintf(stderr,
            "pushing session cert (%zu B cert, %zu B chain)%s — "
            "tap the confirm gesture on the device...\n",
            cert_len, chain_len, force ? " (force)" : "");

    cantil_err_t err = cantil_push_session_cert(s, cert, cert_len,
                                                chain, chain_len,
                                                force ? 1 : 0);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    free(cert); free(chain);

    if (err != CANTIL_OK) {
        fprintf(stderr, "error: session-push failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    fprintf(stderr, "session cert installed. "
            "Verify with 'cantil session-cert %s'.\n", port);
    return 0;
}

/* ── provision-ca (test helper) ────────────────────────────────────────────
 *
 * Make CA slot 0 a *ready* CA by pushing X.509 subject data (PUSH_KEY_X509,
 * 0x26). Slot 0 ships with an auto-generated key but no cert until this is
 * called (bootstrap exemption lets a protected-but-certless slot 0 accept it).
 * Used to set up the on-device CA before exercising session-sign (T-06).
 *
 *   cantil provision-ca <port>
 */
static int cmd_provision_ca(int new_slot, const cantil_x509_data_t *x509,
                            const char *port,
                            const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    uint32_t slot = 0;
    if (new_slot) {
        cantil_err_t gerr = cantil_gen_key(s, CANTIL_KEY_TYPE_EC_P256, &slot);
        if (gerr != CANTIL_OK) {
            fprintf(stderr, "error: gen-key failed: %s\n",
                    cantil_strerror(gerr));
            cantil_session_close(s);
            cantil_transport_close(t);
            policy_ctx_free(&pctx);
            return 1;
        }
        fprintf(stderr, "generated fresh P-256 key in slot %u\n", slot);
    }

    cantil_err_t err = cantil_push_key_x509(s, slot, x509);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err != CANTIL_OK) {
        fprintf(stderr, "error: provision-ca failed: %s\n",
                cantil_strerror(err));
        return 1;
    }
    fprintf(stderr, "CA slot %u provisioned (CN=%s).\n", slot, x509->cn);
    return 0;
}

/* ── sign-key-slot ─────────────────────────────────────────────────────────
 *
 * Sign the cert for subject_slot using the CA key in issuer_slot, entirely
 * on-device (no key leaves).  Requires the device to be UNLOCKED.
 *
 *   cantil sign-key-slot <issuer_slot> <subject_slot> [opts] <port>
 */
static int cmd_sign_key_slot(uint32_t issuer_slot, uint32_t subject_slot,
                              const char *port,
                              const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    fprintf(stderr, "signing slot %u cert with issuer slot %u...\n",
            subject_slot, issuer_slot);
    cantil_err_t err = cantil_sign_key_slot(s, issuer_slot, subject_slot);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: sign-key-slot failed: %s\n",
                cantil_strerror(err));
        return 1;
    }
    fprintf(stderr, "slot %u cert signed by slot %u.\n",
            subject_slot, issuer_slot);
    return 0;
}

/* ── protect / unprotect ───────────────────────────────────────────────────
 *
 *   cantil protect   <slot> [--certs] [opts] <port>  (tap-confirm)
 *   cantil unprotect <slot>            [opts] <port>  (tap-confirm)
 */
static int cmd_protect_unprotect(uint32_t slot_id, int do_unprotect,
                                  uint8_t protect_certs,
                                  const char *port,
                                  const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    fprintf(stderr, "%s slot %u — tap the confirm gesture on the device...\n",
            do_unprotect ? "unprotecting" : "protecting", slot_id);
    cantil_err_t err = do_unprotect
        ? cantil_unprotect_slot(s, slot_id)
        : cantil_protect_slot(s, slot_id, protect_certs);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: %s failed: %s\n",
                do_unprotect ? "unprotect" : "protect", cantil_strerror(err));
        return 1;
    }
    fprintf(stderr, "slot %u %s.\n", slot_id,
            do_unprotect ? "unprotected" : "protected");
    return 0;
}

/* ── key-chain ─────────────────────────────────────────────────────────────
 *
 * Fetch the full cert chain for a key slot (leaf first, hex DER).
 *
 *   cantil key-chain <slot> [opts] <port>
 *
 * Example:
 *   cantil key-chain 1 /dev/ttyACM0 | xxd -r -p | openssl x509 -inform DER -text -noout
 */
static int cmd_key_chain(uint32_t slot_id, const char *port,
                          const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    uint8_t *der = NULL;
    size_t   der_len = 0;
    cantil_err_t err = cantil_get_key_chain(s, slot_id, &der, &der_len);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: key-chain failed: %s\n", cantil_strerror(err));
        free(der);
        return 1;
    }
    fprintf(stderr, "slot %u chain: %zu bytes DER\n", slot_id, der_len);
    for (size_t i = 0; i < der_len; i++)
        printf("%02x", der[i]);
    printf("\n");
    free(der);
    return 0;
}

/* ── sign-csr-slot ─────────────────────────────────────────────────────────
 *
 * Sign an external CSR with a CA key slot on the device.  Prints the signed
 * cert DER as hex so it can be piped to disk or openssl.
 *
 *   cantil sign-csr-slot <issuer_slot> <csr.der> [opts] <port>
 *
 * Example:
 *   cantil sign-csr-slot 1 codesign.csr.der /dev/ttyACM0 | xxd -r -p > codesign.der
 */
static int cmd_sign_csr_slot(uint32_t issuer_slot, const char *csr_path,
                               const char *port,
                               const trust_opts_t *topts)
{
    uint8_t *csr = NULL;
    size_t   csr_len = 0;
    int rc = slurp_file(csr_path, &csr, &csr_len);
    if (rc) {
        fprintf(stderr, "error: cannot read CSR '%s': %s\n",
                csr_path, strerror(-rc));
        return 1;
    }

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s) {
        free(csr);
        return 1;
    }
    uint8_t *cert = NULL;
    size_t   cert_len = 0;
    cantil_err_t err = cantil_sign_csr_slot(s, issuer_slot,
                                             csr, csr_len,
                                             &cert, &cert_len);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    free(csr);
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: sign-csr-slot failed: %s\n",
                cantil_strerror(err));
        free(cert);
        return 1;
    }
    fprintf(stderr, "signed cert: %zu bytes DER\n", cert_len);
    for (size_t i = 0; i < cert_len; i++)
        printf("%02x", cert[i]);
    printf("\n");
    free(cert);
    return 0;
}

/* ── roundtrip (debug) ─────────────────────────────────────────────────── */

static double ms_since(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec  - t0->tv_sec)  * 1000.0
         + (now.tv_nsec - t0->tv_nsec) / 1.0e6;
}

static void hex_dump(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i & 0x0F) == 0x0F && i + 1 < len)
            printf("\n  ");
        else if (i + 1 < len)
            printf(" ");
    }
    printf("\n");
}

static int cmd_roundtrip(uint16_t count, const char *port,
                         const trust_opts_t *topts)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    double handshake_ms = ms_since(&t0);
    if (!s)
        return 1;
    printf("Noise_XX handshake: %.1f ms\n", handshake_ms);

    uint8_t req[4] = {
        CMD_GET_RANDOM_NAMES,
        0x01,                       /* seq */
        (uint8_t)(count >> 8),
        (uint8_t)(count & 0xFF),
    };
    hex_dump("request", req, sizeof(req));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int send_rc = cantil_session_send(s, req, sizeof(req));
    if (send_rc) {
        fprintf(stderr, "error: session_send failed: %d\n", send_rc);
        cantil_session_close(s);
        cantil_transport_close(t);
        policy_ctx_free(&pctx);
        return 1;
    }

    uint8_t resp[4096];
    size_t  resp_len = 0;
    int ret = cantil_session_recv(s, resp, sizeof(resp), &resp_len);
    double roundtrip_ms = ms_since(&t0);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (ret) {
        fprintf(stderr, "error: session_recv failed: %d\n", ret);
        return 1;
    }

    printf("roundtrip: %.1f ms\n", roundtrip_ms);
    hex_dump("response", resp, resp_len);

    if (resp_len < 2) {
        fprintf(stderr, "error: response shorter than header\n");
        return 1;
    }
    if (resp[0] != 0x01) {
        fprintf(stderr, "error: seq mismatch (got 0x%02x)\n", resp[0]);
        return 1;
    }
    if (resp[1] != PROTO_ERR_OK) {
        fprintf(stderr, "error: device returned err=0x%02x\n", resp[1]);
        return 1;
    }

    /* Split payload on 0xFF, print each name. */
    printf("decoded names:\n");
    size_t  start = 2;
    uint8_t name_count = 0;
    for (size_t i = 2; i < resp_len; i++) {
        if (resp[i] == 0xFF) {
            if (i > start) {
                printf("  %2u  %.*s\n",
                       name_count + 1,
                       (int)(i - start), (const char *)&resp[start]);
                name_count++;
            }
            start = i + 1;
        }
    }
    printf("(%u names decoded, requested %u)\n", name_count, count);
    return 0;
}

/* ── clients (T-15) ────────────────────────────────────────────────────────
 *
 *   cantil clients [opts] <port>
 *   cantil unpair  <hex-pubkey> [opts] <port>
 *   cantil name    <hex-pubkey> <name> [opts] <port>
 */

static int print_client_cb(const cantil_client_info_t *info, void *user)
{
    (void)user;
    const char *kind = (info->kind == CANTIL_CLIENT_KIND_PEER_DEVICE)
                       ? "peer-device" : "host";
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", info->pubkey[i]);
    hex[64] = '\0';
    printf("  %s  kind=%-12s  created=%u  name=%s\n",
           hex, kind, info->created_at,
           info->friendly_name[0] ? info->friendly_name : "(none)");
    return 0;
}

/* ── update-firmware ────────────────────────────────────────────────────── */

static int cmd_update_firmware(const char *uf2_path, const char *mount_hint,
                               const char *port,
                               const trust_opts_t *topts)
{
    /* Verify the .uf2 file is readable before touching the device. */
    struct stat st;
    if (stat(uf2_path, &st) != 0) {
        fprintf(stderr, "error: cannot access %s: %s\n", uf2_path,
                strerror(errno));
        return 1;
    }

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    fprintf(stderr, "Triggering UF2 reboot...\n");
    cantil_err_t err = cantil_trigger_uf2_reboot(s);
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err == CANTIL_ERR_NOT_SUPPORTED) {
        fprintf(stderr,
                "error: device firmware does not support UF2 reboot "
                "(MCUBOOT build)\n");
        return 1;
    }
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: update-firmware command failed: %s\n",
                cantil_strerror(err));
        return 1;
    }

    /* Device is rebooting into UF2 bootloader. Poll for the drive. */
    const char *glob_pat = mount_hint ? mount_hint : "/run/media/*/XIAO-SENSE*";
    char mount_path[256] = {0};

    fprintf(stderr, "Waiting for UF2 drive (%s)...\n", glob_pat);
    for (int i = 0; i < 100; i++) {  /* up to 10 s in 100 ms steps */
        glob_t g;
        if (glob(glob_pat, GLOB_NOSORT, NULL, &g) == 0 && g.gl_pathc > 0) {
            struct stat ms;
            if (stat(g.gl_pathv[0], &ms) == 0 && S_ISDIR(ms.st_mode)) {
                snprintf(mount_path, sizeof(mount_path), "%s", g.gl_pathv[0]);
                globfree(&g);
                break;
            }
        }
        globfree(&g);
        nanosleep(&(struct timespec){0, 100000000L}, NULL);  /* 100 ms */
    }

    if (mount_path[0] == '\0') {
        fprintf(stderr,
                "error: UF2 drive did not appear after 10 s\n"
                "  Check that the device booted into UF2 mode, or specify\n"
                "  the mount point with --mount <path>\n");
        return 1;
    }

    /* Copy the .uf2 file to the drive. */
    char dest[512];
    const char *basename_start = strrchr(uf2_path, '/');
    const char *fname = basename_start ? basename_start + 1 : uf2_path;
    snprintf(dest, sizeof(dest), "%s/%s", mount_path, fname);

    fprintf(stderr, "Copying %s -> %s\n", uf2_path, dest);

    FILE *fin = fopen(uf2_path, "rb");
    if (!fin) {
        fprintf(stderr, "error: cannot open %s: %s\n", uf2_path, strerror(errno));
        return 1;
    }
    FILE *fout = fopen(dest, "wb");
    if (!fout) {
        fprintf(stderr, "error: cannot write to %s: %s\n", dest, strerror(errno));
        fclose(fin);
        return 1;
    }

    uint8_t buf[4096];
    size_t n;
    int copy_err = 0;
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "error: write failed: %s\n", strerror(errno));
            copy_err = 1;
            break;
        }
    }
    if (!copy_err && ferror(fin)) {
        fprintf(stderr, "error: read failed: %s\n", strerror(errno));
        copy_err = 1;
    }
    fclose(fout);
    fclose(fin);

    if (copy_err)
        return 1;

    fprintf(stderr, "Done — device will reboot into new firmware.\n");
    return 0;
}

/* ── fw-update (MCUboot streaming, MCUBOOT tier) ───────────────────── */

static void fw_progress_cb(size_t done, size_t total, void *user)
{
    (void)user;
    int pct = (total > 0) ? (int)(done * 100 / total) : 0;
    fprintf(stderr, "\rStreaming: %zu / %zu bytes (%d%%)   ", done, total, pct);
    fflush(stderr);
}

static int cmd_fw_update(const char *bin_path, const char *port,
                         const trust_opts_t *topts)
{
    struct stat st;
    if (stat(bin_path, &st) != 0) {
        fprintf(stderr, "error: cannot access %s: %s\n", bin_path,
                strerror(errno));
        return 1;
    }

    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;

    fprintf(stderr, "Streaming %s to device...\n", bin_path);
    cantil_err_t err = cantil_fw_update(s, bin_path, fw_progress_cb, NULL);
    fprintf(stderr, "\n");

    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);

    if (err == CANTIL_ERR_NOT_SUPPORTED) {
        fprintf(stderr,
                "error: device does not support MCUboot streaming\n"
                "  (UF2 build? Use 'update-firmware' instead)\n");
        return 1;
    }
    if (err != CANTIL_OK) {
        fprintf(stderr, "error: fw-update failed: %s\n", cantil_strerror(err));
        return 1;
    }

    fprintf(stderr, "Done — device is rebooting to install new firmware.\n");
    return 0;
}

static int cmd_clients(const char *port, const trust_opts_t *topts)
{
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    printf("Bonded clients:\n");
    cantil_err_t rc = cantil_list_clients(s, print_client_cb, NULL);
    if (rc != CANTIL_OK)
        fprintf(stderr, "error: %s\n", cantil_strerror(rc));
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    return (rc == CANTIL_OK) ? 0 : 1;
}

static int hex_decode32(const char *hex, uint8_t out[32])
{
    size_t len = strlen(hex);
    if (len != 64) return -1;
    for (int i = 0; i < 32; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        int hv = (hi >= '0' && hi <= '9') ? hi - '0' :
                 (hi >= 'a' && hi <= 'f') ? 10 + (hi - 'a') :
                 (hi >= 'A' && hi <= 'F') ? 10 + (hi - 'A') : -1;
        int lv = (lo >= '0' && lo <= '9') ? lo - '0' :
                 (lo >= 'a' && lo <= 'f') ? 10 + (lo - 'a') :
                 (lo >= 'A' && lo <= 'F') ? 10 + (lo - 'A') : -1;
        if (hv < 0 || lv < 0) return -1;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return 0;
}

static int cmd_unpair(const char *hex_pubkey, const char *port,
                      const trust_opts_t *topts)
{
    uint8_t pubkey[32];
    if (hex_decode32(hex_pubkey, pubkey) != 0) {
        fprintf(stderr, "error: pubkey must be 64 hex chars\n");
        return 1;
    }
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    fprintf(stderr, "Tap the device to confirm...\n");
    cantil_err_t rc = cantil_unpair_client(s, pubkey);
    if (rc != CANTIL_OK)
        fprintf(stderr, "error: unpair failed: %s\n", cantil_strerror(rc));
    else
        printf("Client unpaired.\n");
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    return (rc == CANTIL_OK) ? 0 : 1;
}

static int cmd_set_name(const char *hex_pubkey, const char *name,
                        const char *port,
                        const trust_opts_t *topts)
{
    uint8_t pubkey[32];
    if (hex_decode32(hex_pubkey, pubkey) != 0) {
        fprintf(stderr, "error: pubkey must be 64 hex chars\n");
        return 1;
    }
    if (strlen(name) >= CANTIL_CLIENT_NAME_MAX) {
        fprintf(stderr, "error: name must be < %d bytes\n", CANTIL_CLIENT_NAME_MAX);
        return 1;
    }
    cantil_transport_t *t = NULL;
    policy_ctx_t pctx;
    cantil_session_t *s = open_device_session(port, topts, &t, &pctx);
    if (!s)
        return 1;
    cantil_err_t rc = cantil_set_client_name(s, pubkey, name);
    if (rc != CANTIL_OK)
        fprintf(stderr, "error: set-name failed: %s\n", cantil_strerror(rc));
    else
        printf("Client name updated.\n");
    cantil_session_close(s);
    cantil_transport_close(t);
    policy_ctx_free(&pctx);
    return (rc == CANTIL_OK) ? 0 : 1;
}

/* ── main ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s list                                                   List attached Cantil USB devices\n"
            "  %s pair [--force] [--passkey <d>] [--client-cert f [--client-chain f]] <port>\n"
            "  %s status              [opts] <port>                      Show device status\n"
            "  %s random  <n>         [opts] <port>                      Read N random bytes from TRNG (hex)\n"
            "\n"
            "CA hierarchy setup:\n"
            "  %s provision-ca [--new] --cn <cn> [--o <o>] [--ou <ou>] [--c <c>] [--st <st>] [--l <l>]\n"
            "                  [--validity <days>] [--path-len <n>] [opts] <port>\n"
            "                                                             Provision slot 0 (or --new slot) as a CA\n"
            "  %s sign-key-slot <issuer_slot> <subject_slot> [opts] <port>\n"
            "                                                             Sign subject slot cert with issuer CA slot\n"
            "  %s protect   <slot> [--certs] [opts] <port>               Protect a key slot (tap-confirm)\n"
            "  %s unprotect <slot>            [opts] <port>               Unprotect a key slot (tap-confirm)\n"
            "  %s key-chain <slot>            [opts] <port>               Fetch slot cert chain DER (hex, leaf first)\n"
            "  %s sign-csr-slot <issuer_slot> <csr.der> [opts] <port>     Sign an external CSR with a CA slot\n"
            "\n"
            "Session identity:\n"
            "  %s session-cert              [opts] <port>                 Fetch session cert DER (hex)\n"
            "  %s session-csr               [opts] <port>                 Fetch session CSR DER (hex)\n"
            "  %s session-sign <slot> [--force] [opts] <port>             CA-sign session cert (tap-confirm)\n"
            "  %s session-push <cert.der> [--chain <f>] [--force] [opts] <port>  Install externally-signed session cert (tap-confirm)\n"
            "\n"
            "Firmware update:\n"
            "  %s update-firmware <firmware.uf2> [--mount <path>] [opts] <port>\n"
            "                                                             Reboot into UF2 mode (authenticated) and flash firmware\n"
            "  %s fw-update <firmware.signed.bin> [opts] <port>          Stream signed image to MCUboot secondary slot (MCUBOOT tier)\n"
            "\n"
            "Bond management:\n"
            "  %s clients              [opts] <port>                      List bonded clients\n"
            "  %s unpair  <hex-pubkey> [opts] <port>                      Remove a bond (tap-confirm)\n"
            "  %s name    <hex-pubkey> <name> [opts] <port>               Set friendly name for a bond\n"
            "\n"
            "Trust options [opts]:\n"
            "  --trust none|pin|ca|ca+cn     Trust tier (default: pin if fingerprint stored, else none)\n"
            "  --ca-dir  <path>              Load all *.der CA certs from directory (Tier 3/4)\n"
            "  --ca-cert <file>              Load single CA cert DER file (Tier 3/4)\n"
            "  --cn      <value>             Expected leaf CN for Tier 4\n"
            "\n"
            "Examples:\n"
            "  # Set up SystemHalted root CA in slot 0:\n"
            "  %s unprotect 0 /dev/ttyACM0\n"
            "  %s provision-ca --cn \"SystemHalted ROOT CA 0\" --o SystemHalted --ou \"Trust Chain\" \\\n"
            "       --c US --st Massachusetts --l Boston --validity 7300 --path-len 1 /dev/ttyACM0\n"
            "  # Provision subordinate CA in slot 1:\n"
            "  %s provision-ca --new --cn \"SystemHalted Sub CA 0-1\" --o SystemHalted \\\n"
            "       --ou \"Trust Chain\" --c US --st Massachusetts --l Boston --validity 3650 \\\n"
            "       --path-len 0 /dev/ttyACM0\n"
            "  # Sign sub CA with root CA, then lock both:\n"
            "  %s sign-key-slot 0 1 /dev/ttyACM0\n"
            "  %s protect 0 /dev/ttyACM0 && %s protect 1 /dev/ttyACM0\n"
            "  # Export sub CA chain (leaf first):\n"
            "  %s key-chain 1 /dev/ttyACM0 | xxd -r -p > subca_chain.der\n"
            "  # Sign an external code-signing CSR:\n"
            "  %s sign-csr-slot 1 codesign.csr.der /dev/ttyACM0 | xxd -r -p > codesign.der\n",
            prog, prog, prog, prog,
            prog, prog, prog, prog, prog, prog,
            prog, prog, prog, prog,
            prog, prog, prog, prog,
            prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "error: libsodium init failed\n");
        return 1;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "list") == 0) {
        cantil_usb_device_t *devs = NULL;
        int n = cantil_list_usb_devices(&devs);
        if (n < 0) {
            fprintf(stderr, "error: %s\n",
                    cantil_strerror((cantil_err_t)n));
            return 1;
        }
        if (n == 0) {
            printf("No Cantil devices found.\n");
            free(devs);
            return 0;
        }
        printf("Found %d Cantil device%s:\n", n, n == 1 ? "" : "s");
        for (int i = 0; i < n; i++) {
            printf("  [%d] %04x:%04x  serial=%s\n",
                   i, devs[i].vid, devs[i].pid,
                   devs[i].serial[0] ? devs[i].serial : "(none)");
            printf("      protocol: %s\n",
                   devs[i].protocol_port[0] ? devs[i].protocol_port : "(not enumerated)");
            printf("      console:  %s\n",
                   devs[i].console_port[0] ? devs[i].console_port : "(not enumerated)");
        }
        free(devs);
        return 0;
    }

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    const char *port = argv[argc - 1];  /* last argument is always the port */

    /* ── pair is always Tier 1 TOFU — no trust flags ─────────────────────── */
    if (strcmp(cmd, "pair") == 0) {
        int force = 0;
        uint32_t passkey = 0;
        const char *cert_file = NULL, *chain_file = NULL;
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--force") == 0) {
                force = 1;
            } else if (strcmp(argv[i], "--passkey") == 0) {
                if (i + 1 >= argc - 1) {
                    fprintf(stderr, "error: --passkey requires a 6-digit value\n");
                    return 1;
                }
                char *end;
                unsigned long v = strtoul(argv[++i], &end, 10);
                if (*end != '\0' || v == 0 || v > 999999UL) {
                    fprintf(stderr, "error: --passkey must be 000001–999999\n");
                    return 1;
                }
                passkey = (uint32_t)v;
            } else if (strcmp(argv[i], "--client-cert") == 0) {
                if (i + 1 >= argc - 1) {
                    fprintf(stderr, "error: --client-cert requires a file path\n");
                    return 1;
                }
                cert_file = argv[++i];
            } else if (strcmp(argv[i], "--client-chain") == 0) {
                if (i + 1 >= argc - 1) {
                    fprintf(stderr, "error: --client-chain requires a file path\n");
                    return 1;
                }
                chain_file = argv[++i];
            } else {
                fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                usage(argv[0]);
                return 1;
            }
        }
        key_store_init();  /* needed for cert save and keypair load */
        return cmd_pair(port, force, passkey, cert_file, chain_file);
    }

    /* ── All other commands: parse trust opts + client cert ─────────────────── */
    trust_opts_t topts;
    if (parse_trust_opts(argc, argv, 2, &topts) != 0)
        return 1;

    /* Parse --client-cert / --client-chain into module globals so
     * open_device_session() → client_cert_arg() picks them up. */
    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "--client-cert") == 0 && i + 1 < argc - 1)
            g_cert_file = argv[++i];
        else if (strcmp(argv[i], "--client-chain") == 0 && i + 1 < argc - 1)
            g_chain_file = argv[++i];
    }

    /* Pre-load the client cert (auto or explicit). key_store_init() is
     * called again inside open_device_session(); this early call ensures
     * load_client_cert() can auto-load from the global store before we
     * connect (client cert is global — not device-specific). */
    if (key_store_init() == 0) {
        if (load_client_cert(g_cert_file, g_chain_file) != 0)
            return 1;
    }

    int rc;

    if (strcmp(cmd, "status") == 0) {
        return cmd_status(port, &topts);
    }

    if (strcmp(cmd, "random") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        long n = strtol(argv[2], NULL, 10);
        if (n <= 0 || n > CANTIL_RANDOM_MAX_REQUEST) {
            fprintf(stderr, "error: nbytes must be 1..%d\n",
                    CANTIL_RANDOM_MAX_REQUEST);
            return 1;
        }
        return cmd_random((uint32_t)n, port, &topts);
    }

    if (strcmp(cmd, "session-cert") == 0 || strcmp(cmd, "session-csr") == 0) {
        return cmd_session(cmd + strlen("session-"), port, &topts);
    }

    if (strcmp(cmd, "ca-cert") == 0) {
        return cmd_session("ca-cert", port, &topts);
    }

    if (strcmp(cmd, "provision-ca") == 0) {
        int new_slot = 0;
        cantil_x509_data_t x509 = {
            .validity_days = 3650,
            .is_ca         = true,
            .path_len      = -1,
            .key_usage     = CANTIL_KU_DIGITAL_SIGNATURE |
                             CANTIL_KU_KEY_CERT_SIGN |
                             CANTIL_KU_CRL_SIGN,
            .cn = "Cantil CA",
            .o  = "Cantil",
        };
        for (int i = 2; i < argc - 1; i++) {
            if      (strcmp(argv[i], "--new") == 0) { new_slot = 1; }
            else if (strcmp(argv[i], "--cn")  == 0 && i + 1 < argc - 1) { x509.cn = argv[++i]; }
            else if (strcmp(argv[i], "--o")   == 0 && i + 1 < argc - 1) { x509.o  = argv[++i]; }
            else if (strcmp(argv[i], "--ou")  == 0 && i + 1 < argc - 1) { x509.ou = argv[++i]; }
            else if (strcmp(argv[i], "--c")   == 0 && i + 1 < argc - 1) { x509.c  = argv[++i]; }
            else if (strcmp(argv[i], "--st")  == 0 && i + 1 < argc - 1) { x509.st = argv[++i]; }
            else if (strcmp(argv[i], "--l")   == 0 && i + 1 < argc - 1) { x509.l  = argv[++i]; }
            else if (strcmp(argv[i], "--validity") == 0 && i + 1 < argc - 1) {
                x509.validity_days = (uint16_t)strtoul(argv[++i], NULL, 10);
            }
            else if (strcmp(argv[i], "--path-len") == 0 && i + 1 < argc - 1) {
                x509.path_len = (int8_t)strtol(argv[++i], NULL, 10);
            }
        }
        if (!x509.cn || x509.cn[0] == '\0') {
            fprintf(stderr, "error: --cn is required\n");
            return 1;
        }
        return cmd_provision_ca(new_slot, &x509, port, &topts);
    }

    if (strcmp(cmd, "sign-key-slot") == 0) {
        /* cantil sign-key-slot <issuer_slot> <subject_slot> [opts] <port> */
        if (argc < 5) { usage(argv[0]); return 1; }
        long issuer  = strtol(argv[2], NULL, 10);
        long subject = strtol(argv[3], NULL, 10);
        if (issuer < 0 || issuer > 63 || subject < 0 || subject > 63) {
            fprintf(stderr, "error: slot numbers must be 0..63\n");
            return 1;
        }
        return cmd_sign_key_slot((uint32_t)issuer, (uint32_t)subject, port, &topts);
    }

    if (strcmp(cmd, "protect") == 0 || strcmp(cmd, "unprotect") == 0) {
        /* cantil protect   <slot> [--certs] [opts] <port>
         * cantil unprotect <slot>            [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        long slot = strtol(argv[2], NULL, 10);
        if (slot < 0 || slot > 63) {
            fprintf(stderr, "error: slot must be 0..63\n");
            return 1;
        }
        int do_unprotect = (strcmp(cmd, "unprotect") == 0);
        uint8_t protect_certs = 0;
        for (int i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--certs") == 0) protect_certs = 1;
        }
        return cmd_protect_unprotect((uint32_t)slot, do_unprotect,
                                     protect_certs, port, &topts);
    }

    if (strcmp(cmd, "key-chain") == 0) {
        /* cantil key-chain <slot> [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        long slot = strtol(argv[2], NULL, 10);
        if (slot < 0 || slot > 63) {
            fprintf(stderr, "error: slot must be 0..63\n");
            return 1;
        }
        return cmd_key_chain((uint32_t)slot, port, &topts);
    }

    if (strcmp(cmd, "sign-csr-slot") == 0) {
        /* cantil sign-csr-slot <issuer_slot> <csr.der> [opts] <port> */
        if (argc < 5) { usage(argv[0]); return 1; }
        long issuer = strtol(argv[2], NULL, 10);
        if (issuer < 0 || issuer > 63) {
            fprintf(stderr, "error: issuer_slot must be 0..63\n");
            return 1;
        }
        return cmd_sign_csr_slot((uint32_t)issuer, argv[3], port, &topts);
    }

    if (strcmp(cmd, "session-sign") == 0) {
        /* cantil session-sign <issuer_slot> [--force] [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        long slot = strtol(argv[2], NULL, 10);
        if (slot < 0 || slot > 63) {
            fprintf(stderr, "error: issuer_slot must be 0..63\n");
            return 1;
        }
        int force = 0;
        for (int i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--force") == 0) force = 1;
        }
        return cmd_session_sign((uint32_t)slot, force, port, &topts);
    }

    if (strcmp(cmd, "session-push") == 0) {
        /* cantil session-push <cert.der> [--chain <chain.der>] [--force] [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *cert_path = argv[2];
        const char *chain_path = NULL;
        int force = 0;
        for (int i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--force") == 0) {
                force = 1;
            } else if (strcmp(argv[i], "--chain") == 0 && i + 1 < argc - 1) {
                chain_path = argv[++i];
            } else if (strcmp(argv[i], "--trust")   == 0 ||
                       strcmp(argv[i], "--ca-dir")  == 0 ||
                       strcmp(argv[i], "--ca-cert") == 0 ||
                       strcmp(argv[i], "--cn")      == 0) {
                i++;  /* skip trust flag value — already consumed */
            } else {
                fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                usage(argv[0]);
                return 1;
            }
        }
        return cmd_session_push(cert_path, chain_path, force, port, &topts);
    }

    if (strcmp(cmd, "roundtrip") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        long n = strtol(argv[2], NULL, 10);
        if (n <= 0 || n > 65535) {
            fprintf(stderr, "error: count must be 1..65535\n");
            return 1;
        }
        return cmd_roundtrip((uint16_t)n, port, &topts);
    }

    /* T-15: client bond management. */
    if (strcmp(cmd, "clients") == 0) {
        return cmd_clients(port, &topts);
    }

    if (strcmp(cmd, "unpair") == 0) {
        /* cantil unpair <hex-pubkey> [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *hex_pub = argv[2];
        return cmd_unpair(hex_pub, port, &topts);
    }

    if (strcmp(cmd, "name") == 0) {
        /* cantil name <hex-pubkey> <name> [opts] <port> */
        if (argc < 5) { usage(argv[0]); return 1; }
        const char *hex_pub = argv[2];
        /* name is argv[3]; port is argv[argc-1].  If argc==5 they don't overlap. */
        const char *name = argv[3];
        return cmd_set_name(hex_pub, name, port, &topts);
    }

    if (strcmp(cmd, "update-firmware") == 0) {
        /* cantil update-firmware <firmware.uf2> [--mount <path>] [opts] <port> */
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *uf2_path = argv[2];
        const char *mount_hint = NULL;
        /* Scan for --mount <path> between argv[3] and the last arg (port). */
        for (int i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--mount") == 0 && i + 1 < argc - 1) {
                mount_hint = argv[i + 1];
                break;
            }
        }
        return cmd_update_firmware(uf2_path, mount_hint, port, &topts);
    }

    if (strcmp(cmd, "fw-update") == 0) {
        /* cantil fw-update <firmware.signed.bin> [opts] <port>
         * MCUboot streaming path (MCUBOOT tier). */
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *bin_path = argv[2];
        return cmd_fw_update(bin_path, port, &topts);
    }

    (void)rc;
    fprintf(stderr, "error: unknown command '%s'\n", cmd);
    usage(argv[0]);
    return 1;
}
