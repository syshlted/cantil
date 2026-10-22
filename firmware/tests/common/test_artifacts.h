/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_TEST_ARTIFACTS_H
#define CANTIL_TEST_ARTIFACTS_H

/*
 * Hand a generated DER blob to the OpenSSL gate.
 *
 * A suite that mints certificates cannot be its own judge: the writer and the
 * reader come from the same library, so they share any misunderstanding of DER
 * and a round trip proves only self-consistency. These files are picked up
 * after the run by scripts/openssl_gate.sh, which is a third implementation
 * and has no such blind spot.
 *
 * The suffix tells the gate what the suite is claiming — see openssl_gate.sh:
 *
 *   test_artifact_cert("root", der, len)   -> root.cert.der   must parse
 *   test_artifact_csr("slot1", der, len)   -> slot1.csr.der    must parse + self-verify
 *   test_artifact_crl("slot0", der, len)   -> slot0.crl.der    must parse
 *   test_artifact_leaf("issued", ...)      -> issued.leaf.der  }  chain must
 *   test_artifact_ca("issued", ...)        -> issued.ca.der    }  verify
 *
 * native_sim is a host process with a real POSIX filesystem, which is what
 * makes this possible at all.
 *
 * Writes are best-effort and never fail a test: CANTIL_TEST_ARTIFACT_DIR is
 * set by scripts/test.sh, and a developer running zephyr.exe by hand has no
 * reason to be told about it. The gate is what enforces; this only supplies.
 * (An unset directory means the gate sees an empty dir and passes trivially —
 * which is why test.sh always creates it, so "no artifacts" is a real
 * statement about the suite rather than about the environment.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

static inline void test_artifact_write(const char *name, const char *suffix, const uint8_t *der,
				       size_t len)
{
	const char *dir = getenv("CANTIL_TEST_ARTIFACT_DIR");

	if (!dir || !der || len == 0) {
		return;
	}

	char path[512];

	if (snprintf(path, sizeof(path), "%s/%s.%s.der", dir, name, suffix) >= (int)sizeof(path)) {
		return;
	}

	FILE *f = fopen(path, "wb");

	if (!f) {
		return;
	}
	(void)fwrite(der, 1, len, f);
	fclose(f);
}

static inline void test_artifact_cert(const char *n, const uint8_t *d, size_t l)
{
	test_artifact_write(n, "cert", d, l);
}

static inline void test_artifact_csr(const char *n, const uint8_t *d, size_t l)
{
	test_artifact_write(n, "csr", d, l);
}

static inline void test_artifact_crl(const char *n, const uint8_t *d, size_t l)
{
	test_artifact_write(n, "crl", d, l);
}

static inline void test_artifact_leaf(const char *n, const uint8_t *d, size_t l)
{
	test_artifact_write(n, "leaf", d, l);
}

static inline void test_artifact_ca(const char *n, const uint8_t *d, size_t l)
{
	test_artifact_write(n, "ca", d, l);
}

#endif /* CANTIL_TEST_ARTIFACTS_H */
