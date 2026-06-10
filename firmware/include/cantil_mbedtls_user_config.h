/*
 * MBEDTLS_USER_CONFIG_FILE — augments Zephyr's config-tls-generic.h.
 *
 * The generic config gates a few X.509 / OID dependencies on TLS key
 * exchange symbols (RSA_C, X509_CRT_PARSE_C → X509_USE_C → OID_C), which
 * a pure-PKI build like this one does not enable.  Force the macros on
 * here so the X.509 writer (PUSH_KEY_X509 → self-signed cert at slot 0
 * bootstrap, and future SIGN_CSR) compiles.
 */
#ifndef MBEDTLS_X509_USE_C
#define MBEDTLS_X509_USE_C
#endif

#ifndef MBEDTLS_OID_C
#define MBEDTLS_OID_C
#endif

#ifndef MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_PARSE_C
#endif

/*
 * X.509 parser — config-tls-generic.h only defines this when one of the TLS
 * key exchanges is enabled.  We need it for:
 *   - the ca_bootstrap ztest, which round-trips the generated cert through
 *     mbedtls_x509_crt_parse_der to validate it;
 *   - future SIGN_CSR (parse incoming CSR DER) and chain validation.
 */
#ifndef MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C
#endif

/*
 * X.509 CSR parser — required by SIGN_CSR.  Also gated on TLS in the
 * generic config; force it on here for the pure-PKI build.
 */
#ifndef MBEDTLS_X509_CSR_PARSE_C
#define MBEDTLS_X509_CSR_PARSE_C
#endif

/*
 * X.509 CRL parser — required by the crl_der ztest suite, which round-trips
 * the device's RFC 5280 CertificateList through mbedtls_x509_crl_parse_der
 * and verifies the signature. Also useful for any future client-side CRL
 * consumption.
 */
#ifndef MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#endif
