# Test Vector Attribution

## cacophony_xx_25519_chachapoly_sha256.json

This file contains the published test vector for the Noise_XX_25519_ChaChaPoly_SHA256 handshake pattern, extracted from:

- **Project:** Cacophony, by John Galt (centromere)
- **Upstream:** <https://github.com/centromere/cacophony>
- **Source file:** [`vectors/cacophony.txt`](https://github.com/centromere/cacophony/blob/master/vectors/cacophony.txt)
- **Upstream license:** [Unlicense](https://github.com/centromere/cacophony/blob/master/LICENSE) — public domain dedication. Attribution is not legally required; we provide it as a courtesy.

The JSON in this directory is a re-encoded subset of the Cacophony vector covering just the parameters our `noise_xx_ref.py` validator and our Noise_XX ZTEST suite exercise. The underlying byte sequences (keys, prologue, ephemeral, handshake/transport messages, handshake hash) are reproduced verbatim from the upstream `cacophony.txt`.

How this vector is used: [`gen_cacophony_vector.py`](../gen_cacophony_vector.py) loads this file and drives [`noise_xx_ref.py`](../noise_xx_ref.py) with the upstream's exact inputs, asserting every produced wire byte matches Cacophony's published output. Passing that check is the keystone evidence that our spec interpretation of Noise_XX is correct.
