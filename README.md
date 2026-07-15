# Android Hardware Attestation Verifier

A comprehensive hardware-level attestation verification toolkit for Android devices.
Implements Android KeyStore key attestation, TEE environment detection,
certificate chain verification, and bootloader status checking.

## Features

- **Key Attestation** — `src/key_attestation.py`
  Android KeyStore/Keymint hardware-backed key attestation verification.
  Parses attestation records, validates security posture, and assesses
  hardware trust guarantees.

- **Certificate Chain Verifier** — `src/chain_verifier.py`
  Verifies attestation certificate chains against Google's root CA repository.
  Supports CRL and OCSP revocation checking.

- **TEE Checker** — `src/tee_check.py`
  Detects and classifies Trusted Execution Environment (TEE) implementations
  (Trusty, OP-TEE, TEEgris, QSEE, Knox, TZOS, etc.) through filesystem,
  process, and property analysis.

- **Bootloader Checker** — `src/bootloader_check.py`
  Multi-method bootloader lock state detection (filesystem, properties,
  fastboot, dm-verity, vbmeta) with confidence scoring.

- **Verification Example** — `examples/verification_example.py`
  Complete end-to-end verification workflow demonstrating all checks.

## Quick Start

```bash
# Run complete verification example
python examples/verification_example.py

# Verify key attestation
python -m src.key_attestation --challenge "YOUR_CHALLENGE"

# Check TEE environment
python -m src.tee_check --json

# Check bootloader status
python -m src.bootloader_check --json

# Verify certificate chain
python -m src.chain_verifier --chain-length 3 --json
```

## Security Assessment Matrix

| Check | What it verifies | Pass criteria |
|---|---|---|
| Key Attestation | Hardware-backed key, attestation record | Secure key, valid challenge |
| Chain Verifier | Certificate chain to Google root | Known Google root CA |
| TEE Checker | TEE type and isolation level | Trusty/TEEgris/QSEE/Knox |
| Bootloader | Lock state, verified boot | Locked, verified boot state |

## Architecture

```
Android Device                        Server (this toolkit)
┌──────────────────────┐             ┌─────────────────────────────┐
│ KeyStore (TEE/HSM)  │──attest()──▶│ AttestationKeyAttester     │
│  └─ Hardware Key     │             │  └─ ChainVerifier           │
│                      │             │  └─ TEEEnvironmentChecker   │
│ Bootloader (locked)  │────────────▶│  └─ BootloaderChecker       │
│  └─ Verified Boot   │  read state │                             │
│                      │             └─────────────────────────────┘
└──────────────────────┘
```

## Key Attestation Flow

1. Android app generates key pair in KeyStore (hardware-backed)
2. App calls `KeyStore.getCertificate Chain()` to get attestation
3. Attestation certificate chain sent to server
4. Server verifies chain → checks attestation record → assesses security posture
5. Server grants/denies access based on security assessment

## Supported TEE Types

- **Trusty** — Google TEE (Pixel, Android One)
- **TEEgris** — Qualcomm TEE (recent Qualcomm chips)
- **QSEE** — Qualcomm Secure Environment (older Qualcomm)
- **TZOS / Knox** — Samsung Trusted OS
- **OP-TEE** — Open Portable TEE (NXP, STM, etc.)
- **Huawei Huyang** — Huawei Trusted Core

## Contact & Support

- **Website:** [qtphone.com](https://qtphone.com)
- **GitHub Issues:** Open an issue in this repository
- **Email:** contact@qtphone.com

## License

MIT License
