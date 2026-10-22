/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * wolfCrypt build configuration for Cantil.
 *
 * Selected by CONFIG_WOLFSSL_SETTINGS_FILE; the module's zephyr/user_settings.h
 * includes this *instead of* its own body, so what is here is the whole
 * configuration — nothing is inherited.
 *
 * The module's zephyr/CMakeLists.txt hands every wolfSSL and wolfCrypt source
 * file to the compiler unconditionally, TLS included. Almost all of them are
 * wrapped in feature guards, so this header is what decides which of them
 * produce object code. Two consequences worth stating:
 *
 *   - WOLFCRYPT_ONLY removes the entire TLS/DTLS layer (ssl.c, tls.c, tls13.c,
 *     dtls*.c, sniffer.c, wolfio.c). Cantil speaks Noise_XX, not TLS; the
 *     transport is a USB CDC pipe with no sockets behind it. This is the single
 *     largest saving here.
 *   - Anything switched on below is code that ships. Adding an algorithm to
 *     this file is a deliberate act, not a convenience.
 *
 * The set enabled here covers firmware/src/crypto/crypto.h (8 functions),
 * firmware/src/session/noise_crypto.h (6 functions), and — as of step 4 of
 * docs/roadmap/wolfssl-migration.md — the ca/certgen.h X.509 writer
 * (WOLFSSL_CERT_GEN / _REQ / _EXT, see the certificate-generation section
 * below). ca.c's certificate *writers* now route through certgen_wolfssl.c;
 * its X.509 *reads* are still mbedTLS until steps 5–6, so this build keeps
 * CONFIG_MBEDTLS=y and links both libraries.
 */

#ifndef CANTIL_WOLFSSL_USER_SETTINGS_H
#define CANTIL_WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- platform */

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG          8

/* The module compiles every source file in the tree; this silences the
 * "file included but not needed" warnings from the ones that guard out. */
#define WOLFSSL_IGNORE_FILE_WARN

/*
 * wolfCrypt's Zephyr port offers exactly two locking models (wc_port.h:316):
 * SINGLE_THREADED, or wolfSSL_Mutex mapped onto pthreads via
 * CONFIG_POSIX_THREADS. There is no k_mutex option.
 *
 * SINGLE_THREADED here is a claim about Cantil, so state what it rests on:
 * every crypto call is made from the command pipeline — session handshake,
 * CA signing, storage blob encrypt/decrypt — and that pipeline is serial by
 * construction, one request at a time. The only application thread the
 * firmware creates is tap_mic (src/gesture/tap_mic.c), which touches no
 * crypto and is compiled out entirely on the XIAO, where input is a GPIO
 * button. WOLFCRYPT_ONLY removes the session cache, and
 * CUSTOM_RAND_GENERATE_BLOCK removes the DRBG, so the two pieces of shared
 * mutable state wolfCrypt would otherwise want a lock for are not present.
 *
 * What would invalidate it: a second thread that calls crypto — a background
 * key-generation worker, a BLE pipeline running alongside USB, the userspace
 * separation sketched in docs/roadmap/userspace-separation.md. Any of those
 * means pulling in CONFIG_POSIX_THREADS rather than leaving this defined.
 */
#define SINGLE_THREADED

/* No filesystem, no sockets, no stdin/stdout. Cantil's only I/O is the USB
 * CDC transport, which wolfCrypt never sees. */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER

/* Error strings are a table of English sentences that nothing on the device
 * can display — the wire returns numeric error codes and the log is RTT. */
#define NO_ERROR_STRINGS

/* -------------------------------------------------------------- TLS: none */

/*
 * wolfCrypt primitives only. Cantil's transport security is Noise_XX
 * (docs/transport-and-pairing.md) and there is no network interface at all,
 * so the TLS state machine, its record layer, and its socket I/O are dead
 * weight rather than an unused option.
 */
#define WOLFCRYPT_ONLY

/* -------------------------------------------------- algorithms: off */

/*
 * Everything Cantil does not use. wolfCrypt defaults most of these *on*, so
 * omitting a line here ships the algorithm rather than skipping it.
 */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
/*
 * SHA-1. Nothing in Cantil signs, hashes, or verifies with it — the CA is
 * ECDSA-P-256/SHA-256 throughout — but wolfCrypt compiles it by default, and
 * measured on the linked image it was 4,146 B of a hash the project has a
 * policy against using.
 */
#define NO_SHA
#define NO_PKCS12
#define NO_PKCS7
#define NO_PSK
#define NO_AES_CBC

/*
 * No real-time clock on the nRF52840, so there is no trustworthy "now" to
 * compare a certificate's validity window against. That is already the CA's
 * policy — chain validation ignores validity dates (see ca_validate_client_
 * cert_chain, and T-07/T-12 in docs/transport-and-pairing.md) — and this
 * makes it a property of the build rather than of one call site. It also
 * keeps wolfCrypt from needing a time() backend Zephyr does not provide here.
 *
 * Kept through step 4: certgen_wolfssl.c writes notBefore/notAfter by handing
 * wc_MakeCert pre-encoded Cert.beforeDate/afterDate (from the host-supplied,
 * fixed-baseline dates), which takes the manual-date path in wolfCrypt's cert
 * encoder and never calls SetValidity — so no RTC/time() backend is needed.
 */
#define NO_ASN_TIME

/* --------------------------------------------------- algorithms: on */

/* ECDSA P-256 — CA signing (crypto_sign, crypto_keygen). */
#define HAVE_ECC
#define ECC_USER_CURVES /* compile only the curves named below */
#define HAVE_ECC256
#define ECC_TIMING_RESISTANT

/*
 * Deterministic ECDSA nonces, RFC 6979. Matches what the mbedTLS backend does
 * via mbedtls_ecdsa_sign_det_ext, and for the same reason: a repeated or
 * biased k leaks the private key, and this device's private key cannot be
 * rotated because it cannot be exported.
 */
#define WOLFSSL_ECDSA_DETERMINISTIC_K

/* X25519 — Noise_XX DH (noise_crypto_dh, noise_crypto_dh_keygen). */
#define HAVE_CURVE25519

/* ChaCha20-Poly1305 — Noise_XX AEAD (noise_crypto_encrypt/decrypt). */
#define HAVE_CHACHA
#define HAVE_POLY1305

/*
 * AES-256-GCM — storage blob encryption (crypto_encrypt_blob). GCM_SMALL
 * picks the table-free GHASH: the payload is a 60-byte key blob written
 * perhaps once a year, so the multiply tables would be flash spent on
 * throughput nothing here consumes.
 */
#define HAVE_AESGCM
#define WOLFSSL_AES_256
#define GCM_SMALL
/*
 * Small S-box tables too. The default AES tables measured 14,816 B in the
 * linked image — more than every other primitive here put together — to speed
 * up a cipher this device runs over 60 bytes at a time. Small tables are also
 * the more cache-timing-resistant choice, though that matters little on a
 * cacheless Cortex-M4.
 */
#define WOLFSSL_AES_SMALL_TABLES

/* SHA-256 — MixHash, HKDF, and the digest ECDSA signs over. */
#define WOLFSSL_SHA256

/*
 * HKDF-SHA256 — storage key derivation and the Noise HKDF. Kept as
 * wc_HKDF_Extract/wc_HKDF_Expand rather than hand-rolled HMAC chaining, so
 * the derivation stays inside the library boundary; see "Why abstraction
 * serves the FIPS goal" in docs/roadmap/wolfssl-migration.md.
 */
#define HAVE_HKDF

/* -------------------------------------------- certificate generation */

/*
 * X.509 certificate + CSR writing for ca/certgen.h (certgen_wolfssl.c),
 * step 4 of docs/roadmap/wolfssl-migration.md. wc_MakeCert / wc_SignCert build
 * certificates; WOLFSSL_CERT_REQ adds wc_MakeCertReq for CSRs; WOLFSSL_CERT_EXT
 * enables the extension fields (basicConstraints, keyUsage) certgen sets on the
 * Cert struct.
 */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT

/*
 * The template ASN.1 encoder. Required by wc_SetCustomExtension (guarded on
 * WOLFSSL_ASN_TEMPLATE && WOLFSSL_CUSTOM_OID && HAVE_OID_ENCODING) and by the
 * basicConstraints/keyUsage/manual-date encode paths certgen relies on.
 */
#define WOLFSSL_ASN_TEMPLATE

/*
 * Arbitrary-OID extension support, for the private 1.3.6.1.4.1.58270.1.1
 * extension that binds the Noise X25519 static key into the session cert/CSR.
 * WOLFSSL_CUSTOM_OID exposes wc_SetCustomExtension; HAVE_OID_ENCODING lets it
 * turn the dotted-decimal OID into DER (EncodePolicyOID).
 */
#define WOLFSSL_CUSTOM_OID
#define HAVE_OID_ENCODING

/*
 * wc_CheckCertSigPubKey — verify a certificate's signature against a supplied
 * public key. Step 6a of docs/roadmap/wolfssl-migration.md uses it to build
 * certificate paths in src/ca/certparse_wolfssl.c.
 *
 * This is the piece that keeps the firmware WOLFCRYPT_ONLY. wolfSSL's own
 * chain walker (wolfSSL_CertManager*) lives in the TLS layer — ssl_certman.c
 * is #include'd into ssl.c and needs a TLS method — so using it would drag
 * internal.c, tls.c and tls13.c into a device with no network interface. This
 * symbol lives in wolfcrypt/src/asn.c, which is already linked.
 *
 * Despite the name it is not a "small" variant of anything we use; the macro
 * is simply what guards the public API.
 */
#define WOLFSSL_SMALL_CERT_VERIFY

/* ---------------------------------------------------------------- math */

/*
 * Single-precision math, no heap. WOLFSSL_SP_MATH_ALL replaces the general
 * big-integer library (tfm.c / integer.c) outright, and WOLFSSL_SP_NO_MALLOC
 * keeps the intermediates on the stack.
 *
 * The heap matters here: firmware/prj.conf sets no CONFIG_HEAP_MEM_POOL_SIZE,
 * so what allocation there is falls to picolibc's arena. A crypto path that
 * can fail on allocation is a crypto path that can fail while holding the
 * decrypted CA key in RAM.
 */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_MALLOC

/*
 * Cortex-M assembly for the SP routines. Guarded on the target rather than
 * enabled outright because the ztest suites build for native_sim/native/64,
 * where sp_cortexm.c is neither compilable nor wanted — and those suites are
 * what proves this backend agrees with mbedTLS bit for bit.
 *
 * It costs nothing to keep. Measured on the xiao_ble image, turning it off
 * *grew* the build by 2,096 B: sp_cortexm.c is 22,930 B, but the generic C
 * paths in sp_int.c it displaces are larger still. So this is the faster and
 * the smaller option, not a trade.
 */
#if defined(__arm__) && defined(__thumb__)
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#endif

/* ----------------------------------------------------------------- RNG */

/*
 * Entropy comes straight from the Zephyr entropy device (the nRF52840's
 * CC310 hardware TRNG), exactly as the mbedTLS backend does. Defining
 * CUSTOM_RAND_GENERATE_BLOCK routes wc_RNG_GenerateBlock at it and drops
 * wolfCrypt's Hash-DRBG, whose state would be RAM spent re-whitening output
 * that is already a hardware TRNG's.
 *
 * cantil_wc_rand_block() is implemented in src/crypto/crypto_wolfssl.c and
 * returns 0 on success, which is what wolfCrypt expects.
 */
int cantil_wc_rand_block(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_BLOCK cantil_wc_rand_block
#define WC_NO_HASHDRBG

#ifdef __cplusplus
}
#endif

#endif /* CANTIL_WOLFSSL_USER_SETTINGS_H */
