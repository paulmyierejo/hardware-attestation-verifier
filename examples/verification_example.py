"""
Verification Example for Hardware Attestation Verifier
Demonstrates the complete key attestation verification workflow.
"""

import json
import base64
from src.key_attestation import AttestationKeyAttester, MockKeyAttester, AttestationMode
from src.chain_verifier import ChainVerifier
from src.tee_check import TEEChecker
from src.bootloader_check import BootloaderChecker


def main():
    print("=" * 60)
    print("  Android Hardware Attestation Verification Example")
    print("=" * 60)

    # ─── Step 1: Generate attestation challenge ─────────────────────────────
    import time
    challenge = base64.b64encode(
        f"server-challenge-{int(time.time())}".encode()
    ).decode().rstrip("=")
    print(f"\n1. Generated Challenge: {challenge[:32]}...")

    # ─── Step 2: Mock attestation response from Android device ──────────────
    print("\n2. Simulating Android device attestation response...")
    mock_result = MockKeyAttester.generate_mock_attestation(
        challenge=challenge,
        security_level=AttestationMode.STRONG_BOX,
        bootloader_locked=True,
        verified_boot_state="verified",
        os_version=33,
        os_patch_level=202401,
    )
    print(f"   Is Valid: {mock_result['is_valid']}")
    print(f"   Is Secure: {mock_result['is_secure']}")
    print(f"   Key Info: {mock_result.get('key_info')}")

    # ─── Step 3: Verify attestation on server ────────────────────────────────
    print("\n3. Server-side attestation verification...")
    attester = AttestationKeyAttester()
    result = attester.verify(
        attestation_chain_der=[b"mock_der_certificate_data"],
        expected_challenge=challenge,
        require_strong_box=True,
        require_locked_bootloader=True,
        require_verified_boot=True,
        min_os_patch_level=202401,
    )
    print(f"   Valid: {result.get('is_valid')}")
    print(f"   Secure: {result.get('is_secure')}")
    print(f"   Failed Checks: {result.get('failed_checks', [])}")
    if result.get('key_info'):
        ki = result['key_info']
        print(f"   Bootloader Locked: {ki.get('bootloader_locked')}")
        print(f"   Verified Boot: {ki.get('verified_boot')}")
        print(f"   OS Patch Level: {ki.get('os_patch_level')}")

    # ─── Step 4: Verify certificate chain ─────────────────────────────────
    print("\n4. Verifying attestation certificate chain...")
    chain_verifier = ChainVerifier()
    chain_result = chain_verifier.verify_chain(
        attestation_chain=[b"leaf_cert", b"intermediate_cert", b"root_cert"],
        check_revocation=False,
    )
    print(f"   Status: {chain_result.get('status')}")
    print(f"   Chain Length: {chain_result.get('chain_length')}")
    print(f"   Root Recognized: {chain_result.get('root_recognized')}")

    # ─── Step 5: TEE Environment Check ─────────────────────────────────────
    print("\n5. Checking TEE environment...")
    tee_checker = TEEChecker()
    tee_info = tee_checker.detect()
    tee_assessment = tee_checker.assess_trustworthiness(tee_info)
    print(f"   TEE Type: {tee_info.tee_type.value}")
    print(f"   Security Level: {tee_info.security_level.value}")
    print(f"   Hardware-backed: {tee_info.is_hardware_backed}")
    print(f"   Trust Score: {tee_assessment['trust_score']}/100")

    # ─── Step 6: Bootloader Check ───────────────────────────────────────────
    print("\n6. Checking bootloader status...")
    boot_checker = BootloaderChecker()
    boot_info = boot_checker.check()
    boot_posture = boot_checker.assess_security_posture(boot_info)
    print(f"   Bootloader State: {boot_info.state.value}")
    print(f"   OEM Unlock Enabled: {boot_info.oem_unlock_enabled}")
    print(f"   Security Score: {boot_posture['security_score']}/100")
    print(f"   Posture: {boot_posture['posture']}")

    # ─── Final Assessment ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Final Assessment")
    print("=" * 60)

    all_passed = (
        result.get('is_secure', False) and
        boot_info.state.value == 'locked' and
        tee_info.security_level.value in ('strong', 'moderate')
    )

    if all_passed:
        print("\n  ✅ Device meets security requirements for:")
        print("     • Hardware-backed key attestation")
        print("     • Locked bootloader")
        print("     • Verified boot")
        print("     • Current security patches")
        print("\n  → Access granted")
    else:
        print("\n  ❌ Device does not meet security requirements")
        print("\n  → Access denied")
        if boot_info.state.value == 'unlocked':
            print("     Reason: Bootloader is unlocked")
        elif not tee_info.is_hardware_backed:
            print("     Reason: No hardware-backed security detected")
        print("\n  → Grant limited access or request remediation")

    print()


if __name__ == "__main__":
    main()
