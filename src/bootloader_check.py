"""
Bootloader Lock Status Detector
Detects and verifies Android bootloader lock state through multiple channels.
The bootloader state is a critical component of device integrity.
"""

import json
import os
import re
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class BootloaderState(Enum):
    """Bootloader lock state."""
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    UNKNOWN = "unknown"
    TAMPERED = "tampered"


@dataclass
class BootloaderInfo:
    """Comprehensive bootloader information."""
    state: BootloaderState
    manufacturer: str
    model: str
    verified_boot_key_hash: Optional[str] = None
    vbmeta_digest: Optional[str] = None
    unlock_allowed: bool = False
    unlock_critical_allowed: bool = False
    oem_unlock_enabled: bool = False
    anti_rollback_version: Optional[int] = None
    boot_version: Optional[str] = None
    radio_version: Optional[str] = None
    verification_method: str = "unknown"
    confidence: float = 0.0


class BootloaderFileChecker:
    """
    Check bootloader state through filesystem indicators.
    """

    # Files and directories that indicate bootloader state
    BOOTLOADER_INDICATORS = {
        BootloaderState.LOCKED: [
            "/proc/bootloader",       # Contains "locked" or "unlocked"
            "/sys/class/android_usb/android0/enable",
            "/sys/block/sda/device/type",  # USB mode
        ],
        BootloaderState.UNLOCKED: [
            "/unlocked",              # Flag file when unlocked
            "/system/customized",     # Unlocked device marker
        ],
    }

    @classmethod
    def read_bootloader_status(cls) -> Optional[str]:
        """Read bootloader status from /proc/bootloader."""
        proc_path = "/proc/bootloader"
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "r") as f:
                    return f.read().strip().lower()
            except Exception:
                pass
        return None

    @classmethod
    def check_unlock_flags(cls) -> Tuple[bool, bool]:
        """
        Check for unlock-related flag files.
        Returns: (unlocked_flag_found, oem_unlock_enabled)
        """
        unlock_flags = [
            "/unlocked",
            "/data/unlocked",
            "/cache/unlocked",
            "/efs/unlock_status",
        ]

        unlocked = any(os.path.exists(f) for f in unlock_flags)

        # Check for OEM unlock setting in various locations
        oem_unlock = False
        prop_files = ["/system/build.prop", "/data/property/persist.sys.oem.unlock"]
        for pf in prop_files:
            if os.path.exists(pf):
                try:
                    with open(pf) as f:
                        content = f.read()
                        if "oem.unlock" in content.lower():
                            oem_unlock = True
                except Exception:
                    pass

        return unlocked, oem_unlock

    @classmethod
    def detect_state(cls) -> BootloaderState:
        """Detect bootloader state from filesystem."""
        status = cls.read_bootloader_status()
        if status:
            if "unlocked" in status:
                return BootloaderState.UNLOCKED
            elif "locked" in status:
                return BootloaderState.LOCKED

        unlocked, oem = cls.check_unlock_flags()
        if unlocked:
            return BootloaderState.UNLOCKED

        return BootloaderState.UNKNOWN


class BootloaderPropertyChecker:
    """
    Check bootloader state through Android system properties.
    """

    BOOTLOADER_PROPERTIES = {
        # Build properties indicating bootloader state
        "ro.bootloader": {
            "description": "Bootloader version string",
            "pattern": None,  # Just read the value
        },
        "ro.boot.verifiedbootstate": {
            "description": "Verified boot state",
            "locked_value": "green",
            "unlocked_values": ["yellow", "orange"],
        },
        "ro.boot.veritymode": {
            "description": "DM-verity enforcement mode",
            "enforcing": "ENFORCING",
            "permissive": "PERMISSIVE",
        },
        "ro.oem_unlock_supported": {
            "description": "Whether OEM unlock is supported",
            "supported": "1",
        },
    }

    @classmethod
    def get_property(cls, key: str) -> Optional[str]:
        """Read a system property."""
        prop_file = None

        # Check common property sources
        search_paths = [
            f"/system/build.prop",
            f"/vendor/build.prop",
            f"/data/property/persist.{key}",
        ]

        for path in search_paths:
            if os.path.exists(path):
                prop_file = path
                break

        if prop_file:
            try:
                with open(prop_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith(key + "="):
                            return line.split("=", 1)[1].strip()
            except Exception:
                pass

        return None

    @classmethod
    def detect_verified_boot_state(cls) -> str:
        """Detect verified boot state from properties."""
        state = cls.get_property("ro.boot.verifiedbootstate")
        if state:
            return state.lower()

        verity = cls.get_property("ro.boot.veritymode")
        if verity:
            return verity.lower()

        return "unknown"

    @classmethod
    def is_oem_unlock_allowed(cls) -> bool:
        """Check if OEM unlock is enabled."""
        val = cls.get_property("ro.oem_unlock_supported")
        return val == "1"


class BootloaderCommandChecker:
    """
    Check bootloader state through Android/Linux commands.
    These require appropriate permissions on the device.
    """

    @staticmethod
    def run_command(cmd: List[str]) -> Tuple[str, int]:
        """Run a command and return (stdout, return_code)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip(), result.returncode
        except Exception:
            return "", -1

    @classmethod
    def get_fastboot_status(cls) -> Optional[BootloaderState]:
        """
        Get bootloader state via fastboot (requires USB debugging and unlocked OEM).
        """
        # Try fastboot oem device-info
        output, rc = cls.run_command(["fastboot", "oem", "device-info"])
        if rc == 0 and output:
            output_lower = output.lower()
            if "unlocked: yes" in output_lower or "unlocked: true" in output_lower:
                return BootloaderState.UNLOCKED
            elif "unlocked: no" in output_lower or "unlocked: false" in output_lower:
                return BootloaderState.LOCKED
        return None

    @classmethod
    def get_dm_verity_status(cls) -> str:
        """Check dm-verity status (enforcing = bootloader locked)."""
        output, _ = cls.run_command(["getprop", "ro.boot.veritymode"])
        if output:
            return output.strip()

        # Check /proc/mounts for verity
        mounts_path = "/proc/mounts"
        if os.path.exists(mounts_path):
            try:
                with open(mounts_path) as f:
                    for line in f:
                        if "/system" in line and "verity" in line:
                            return "enforcing"
            except Exception:
                pass

        return "unknown"

    @classmethod
    def get_vbmeta_info(cls) -> Dict[str, Any]:
        """Get vbmeta partition information (requires root)."""
        info = {}

        # Try to read vbmeta digest from kernel cmdline
        cmdline_path = "/proc/cmdline"
        if os.path.exists(cmdline_path):
            try:
                with open(cmdline_path) as f:
                    cmdline = f.read()
                    for part in cmdline.split():
                        if part.startswith("androidboot.vbmeta.hashalg="):
                            info["hash_algorithm"] = part.split("=", 1)[1]
                        elif part.startswith("androidboot.vbmeta.digest="):
                            info["digest"] = part.split("=", 1)[1]
                        elif part.startswith("androidboot.verifiedbootstate="):
                            info["verified_boot_state"] = part.split("=", 1)[1]
            except Exception:
                pass

        return info


class BootloaderChecker:
    """
    Main bootloader checking engine. Combines multiple detection methods
    with confidence scoring.
    """

    def __init__(self):
        self.file_checker = BootloaderFileChecker()
        self.property_checker = BootloaderPropertyChecker()
        self.cmd_checker = BootloaderCommandChecker()

    def check(self) -> BootloaderInfo:
        """
        Perform comprehensive bootloader state detection.
        Combines filesystem, property, and command-based checks.
        """
        results: List[Tuple[BootloaderState, float]] = []
        verification_methods = []
        vbmeta_info = {}
        verified_boot_state = "unknown"
        oem_unlock_allowed = False

        # Method 1: Filesystem check
        fs_state = self.file_checker.detect_state()
        if fs_state != BootloaderState.UNKNOWN:
            results.append((fs_state, 0.6))
            verification_methods.append("filesystem")

        # Method 2: Property check
        verified_boot_state = self.property_checker.detect_verified_boot_state()
        oem_unlock_allowed = self.property_checker.is_oem_unlock_allowed()
        if verified_boot_state == "green":
            results.append((BootloaderState.LOCKED, 0.8))
            verification_methods.append("verified_boot_property")
        elif verified_boot_state in ("yellow", "orange"):
            results.append((BootloaderState.UNLOCKED, 0.9))
            verification_methods.append("verified_boot_property")

        # Method 3: DM-verity check
        verity_status = self.cmd_checker.get_dm_verity_status()
        if verity_status == "enforcing":
            results.append((BootloaderState.LOCKED, 0.7))
            verification_methods.append("dm_verity")
        elif verity_status == "permissive":
            results.append((BootloaderState.UNLOCKED, 0.7))
            verification_methods.append("dm_verity")

        # Method 4: Command check (fastboot, etc.)
        fastboot_state = self.cmd_checker.get_fastboot_status()
        if fastboot_state:
            results.append((fastboot_state, 1.0))
            verification_methods.append("fastboot")

        # Method 5: VBMeta info
        vbmeta_info = self.cmd_checker.get_vbmeta_info()

        # Aggregate results with weighted confidence
        state_counts: Dict[BootloaderState, float] = {}
        for state, confidence in results:
            state_counts[state] = state_counts.get(state, 0) + confidence

        if state_counts:
            primary_state = max(state_counts, key=lambda s: state_counts[s])
            max_confidence = state_counts[primary_state]
            total_confidence = sum(state_counts.values())
            normalized_confidence = max_confidence / total_confidence if total_confidence else 0.0
        else:
            primary_state = BootloaderState.UNKNOWN
            normalized_confidence = 0.0

        # Check for tampered state
        if BootloaderState.UNLOCKED in state_counts and normalized_confidence < 0.5:
            primary_state = BootloaderState.TAMPERED
            normalized_confidence = 0.3

        # Get bootloader version
        boot_version = self.property_checker.get_property("ro.bootloader")

        return BootloaderInfo(
            state=primary_state,
            manufacturer=self.property_checker.get_property("ro.product.manufacturer") or "Unknown",
            model=self.property_checker.get_property("ro.product.model") or "Unknown",
            verified_boot_key_hash=vbmeta_info.get("digest"),
            oem_unlock_enabled=oem_unlock_allowed,
            unlock_allowed=oem_unlock_allowed,
            verification_method=", ".join(verification_methods) or "unknown",
            confidence=normalized_confidence,
            boot_version=boot_version,
        )

    def assess_security_posture(self, info: BootloaderInfo) -> Dict[str, Any]:
        """
        Assess device security posture based on bootloader state.
        """
        issues = []
        score = 100

        if info.state == BootloaderState.UNLOCKED:
            score -= 80
            issues.append("Bootloader is UNLOCKED — system can be modified")
        elif info.state == BootloaderState.TAMPERED:
            score -= 90
            issues.append("Bootloader state is TAMPERED")
        elif info.state == BootloaderState.UNKNOWN:
            score -= 20
            issues.append("Bootloader state could not be determined")

        if info.oem_unlock_enabled:
            score -= 10
            issues.append("OEM unlock is enabled (bootloader can be unlocked)")

        if info.verified_boot_key_hash is None:
            score -= 5
            issues.append("No verified boot key hash detected")

        posture = "SECURE" if score >= 80 else "WARNING" if score >= 50 else "CRITICAL"

        return {
            "security_score": max(0, score),
            "posture": posture,
            "issues": issues,
            "recommendation": self._get_recommendation(info),
        }

    def _get_recommendation(self, info: BootloaderInfo) -> str:
        if info.state == BootloaderState.UNLOCKED:
            return "Re-lock the bootloader and reflash stock firmware if possible. " \
                   "Running with unlocked bootloader significantly increases security risk."
        elif info.state == BootloaderState.LOCKED and info.oem_unlock_enabled:
            return "Bootloader is locked but OEM unlock is enabled. Consider disabling " \
                   "OEM unlock in Developer Options if not planning to unlock."
        elif info.state == BootloaderState.LOCKED:
            return "Bootloader is properly locked with verified boot enabled. " \
                   "This is the recommended security configuration."
        return "Unable to determine bootloader security posture. Manual inspection recommended."


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Bootloader Status Checker")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    checker = BootloaderChecker()
    info = checker.check()
    posture = checker.assess_security_posture(info)

    if args.json:
        print(json.dumps({
            "state": info.state.value,
            "manufacturer": info.manufacturer,
            "model": info.model,
            "bootloader_version": info.boot_version,
            "verified_boot_key_hash": info.verified_boot_key_hash,
            "oem_unlock_enabled": info.oem_unlock_enabled,
            "verification_method": info.verification_method,
            "confidence": info.confidence,
            "security_score": posture["security_score"],
            "posture": posture["posture"],
            "issues": posture["issues"],
            "recommendation": posture["recommendation"],
        }, indent=2))
    else:
        print("Bootloader Security Assessment")
        print("=" * 50)
        print(f"State: {info.state.value.upper()}")
        print(f"Manufacturer: {info.manufacturer}")
        print(f"Model: {info.model}")
        print(f"Bootloader Version: {info.boot_version or 'Unknown'}")
        print(f"OEM Unlock Enabled: {'⚠️  YES' if info.oem_unlock_enabled else '✅  NO'}")
        print(f"Verified Boot Hash: {info.verified_boot_key_hash or 'Not detected'[:40]}...")
        print(f"Verification Method: {info.verification_method}")
        print(f"Confidence: {info.confidence:.0%}")
        print("-" * 50)
        print(f"Security Score: {posture['security_score']}/100 ({posture['posture']})")
        print()
        for issue in posture["issues"]:
            print(f"  ⚠️  {issue}")
        print()
        print(f"Recommendation: {posture['recommendation']}")


if __name__ == "__main__":
    main()
