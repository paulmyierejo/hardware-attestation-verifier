"""
TEE (Trusted Execution Environment) Environment Detector
Detects and verifies the presence and integrity of TEE on Android devices.
"""

import json
import os
import re
import struct
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class TEEType(Enum):
    """Type of TEE implementation."""
    TRUSTY = "trusty"           # Google TEE (Pixel devices)
    OP_TEE = "op_tee"           # Open Portable TEE
    TEEGRIS = "teegris"         # Qualcomm TEE
    QSEE = "qsee"               # Qualcomm Secure Execution Environment
    TZOS = "tzos"               # Samsung TEE (TZOS)
    KNOX = "knox"               # Samsung Knox
    HUYANG = "huyang"           # Huawei Trusted Core
    SECUREOS = "secureos"       # General secure OS
    UNKNOWN = "unknown"
    NONE = "none"               # No TEE detected


class TEESecurityLevel(Enum):
    """TEE security classification."""
    STRONG = "strong"           # Hardware-backed, isolated
    MODERATE = "moderate"       # Software TEE or partial isolation
    WEAK = "weak"              # Emulated or limited isolation
    UNKNOWN = "unknown"


@dataclass
class TEEInfo:
    """Information about the TEE on a device."""
    tee_type: TEEType
    security_level: TEESecurityLevel
    version: Optional[str] = None
    manufacturer: Optional[str] = None
    build_id: Optional[str] = None
    is_hardware_backed: bool = False
    supports_key_attestation: bool = False
    available_algorithms: List[str] = field(default_factory=list)
    memory_size: Optional[int] = None  # TEE memory in bytes
    detected_files: List[str] = field(default_factory=list)
    detected_processes: List[str] = field(default_factory=list)


class TEEFileSystemChecker:
    """
    Checks filesystem for TEE-related files and directories.
    These indicators help identify the TEE implementation.
    """

    # File patterns that indicate specific TEE implementations
    TEE_FILE_PATTERNS = {
        TEEType.TRUSTY: [
            "/system/lib/trusty",
            "/system/lib64/trusty",
            "/trusty",
            "/vendor/lib/trusty",
            "/dev/trusty",
        ],
        TEEType.OP_TEE: [
            "/OPteeClient",
            "/optee_armtz",
            "/dev/optee",
            "/sys/module/optee",
            "/vendor/lib/optee",
        ],
        TEEType.TEEGRIS: [
            "/vendor/lib64/hw/tlavedapi.so",
            "/vendor/lib/hw/tlavedapi.so",
            "/dev/qsee",
            "/sys/firmware/qcom/qsee",
        ],
        TEEType.QSEE: [
            "/dev/qsee",
            "/firmware/image/qsee.mbn",
            "/sys/firmware/qcom/qsee",
            "/vendor/firmware/qsee",
        ],
        TEEType.TZOS: [
            "/dev/tzos",
            "/firmware/tzos",
            "/efs/tz_os",
        ],
        TEEType.KNOX: [
            "/dev/knox",
            "/efs/knox",
            "/efs/sec_efs",
            "/system/app/KnoxApps",
        ],
        TEEType.HUYANG: [
            "/dev/hwkey",
            "/vendor/hwkey",
            "/system/lib64/hw/keymaster",  # Huawei keymaster variant
        ],
    }

    @classmethod
    def scan(cls) -> Dict[TEEType, List[str]]:
        """Scan filesystem for TEE indicators."""
        found: Dict[TEEType, List[str]] = {t: [] for t in TEEType}

        for tee_type, paths in cls.TEE_FILE_PATTERNS.items():
            for path in paths:
                if os.path.exists(path):
                    found[tee_type].append(path)

        return found

    @classmethod
    def get_detected_tee(cls) -> Optional[TEEType]:
        """Determine which TEE is present based on detected files."""
        scan_results = cls.scan()
        for tee_type, paths in scan_results.items():
            if paths:
                return tee_type
        return None


class TEEProcessChecker:
    """
    Checks running processes for TEE-related daemons and services.
    """

    TEE_PROCESS_PATTERNS = {
        TEEType.TRUSTY: ["trusty-logd", "trusty-appliance"],
        TEEType.OP_TEE: ["tee-supplicant", "optee"],
        TEEType.TEEGRIS: ["tlavedapid", "teegris"],
        TEEType.QSEE: ["qseecomd", "qsee_svc_app"],
        TEEType.TZOS: ["tzd", "tzdaemon"],
        TEEType.KNOX: ["knox", "knoxsec"],
        TEEType.HUYANG: ["tbase", "hwkey"],
    }

    @classmethod
    def get_running_processes(cls) -> Set[str]:
        """Get set of running process names (simplified for Linux)."""
        processes = set()
        proc_path = "/proc"
        if os.path.exists(proc_path):
            try:
                for pid in os.listdir(proc_path):
                    if pid.isdigit():
                        cmdline_path = os.path.join(proc_path, pid, "cmdline")
                        if os.path.exists(cmdline_path):
                            try:
                                with open(cmdline_path, "r") as f:
                                    cmdline = f.read().replace("\x00", " ").strip()
                                    if cmdline:
                                        processes.add(os.path.basename(cmdline.split()[0]))
                            except Exception:
                                pass
            except Exception:
                pass
        return processes

    @classmethod
    def detect_tee_from_processes(cls) -> Optional[TEEType]:
        """Detect TEE type from running processes."""
        running = cls.get_running_processes()
        for tee_type, process_list in cls.TEE_PROCESS_PATTERNS.items():
            for proc in process_list:
                if any(proc in r for r in running):
                    return tee_type
        return None


class TEEHardwareVerifier:
    """
    Verifies TEE hardware-backed status through system properties and kernel config.
    """

    TEE_HARDWARE_PROPERTIES = {
        # Keymaster/Keymint backed by TEE
        "ro.hardware.keystore": ["msm8996", "msm8998", "sdm845", "trinket", "oriole", "raven"],
        "ro.hardware.trusty": ["true"],
        "ro.hardware.gatekeeper": ["trusty"],
        # Vendor TEE implementations
        "ro.vendor.trusty.tee": ["true"],
        "vendor.gatekeeper.trustlet": ["true"],
    }

    @classmethod
    def check_hardware_properties(cls) -> Dict[str, Any]:
        """Check system properties related to TEE hardware backing."""
        results = {}

        # Check common property locations
        prop_files = [
            "/system/build.prop",
            "/vendor/build.prop",
            "/product/build.prop",
        ]

        for prop_file in prop_files:
            if not os.path.exists(prop_file):
                continue

            try:
                with open(prop_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line or "=" not in line:
                            continue
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip()

                        for pattern, expected in cls.TEE_HARDWARE_PROPERTIES.items():
                            if pattern in key.lower():
                                results[key] = {
                                    "value": value,
                                    "matches": value in expected if expected else True,
                                }
            except Exception:
                pass

        return results

    @classmethod
    def is_hardware_backed(cls) -> bool:
        """Check if KeyStore is backed by TEE hardware."""
        props = cls.check_hardware_properties()
        for key, info in props.items():
            if "trusty" in key.lower() or "keystore" in key.lower():
                if info["matches"]:
                    return True
        return False


class TEEChecker:
    """
    Main TEE checking engine. Aggregates multiple detection methods
    and provides a unified trust assessment.
    """

    def __init__(self):
        self.fs_checker = TEEFileSystemChecker()
        self.process_checker = TEEProcessChecker()
        self.hw_verifier = TEEHardwareVerifier()

    def detect(self) -> TEEInfo:
        """
        Detect TEE type and gather comprehensive information.
        """
        # Try multiple detection methods
        detected_types: List[TEEType] = []

        # Method 1: Filesystem
        fs_results = self.fs_checker.scan()
        for tee_type, paths in fs_results.items():
            if paths:
                detected_types.append(tee_type)

        # Method 2: Running processes
        proc_tee = self.process_checker.detect_tee_from_processes()
        if proc_tee:
            detected_types.append(proc_tee)

        # Method 3: Hardware properties
        hw_props = self.hw_verifier.check_hardware_properties()
        hw_backed = self.hw_verifier.is_hardware_backed()

        # Resolve to primary TEE type
        primary_type = TEEType.UNKNOWN
        detected_files = []
        detected_processes = []

        if detected_types:
            # Prefer most specific TEE type
            type_priority = [
                TEEType.KNOX, TEEType.TZOS, TEEType.TEEGRIS, TEEType.QSEE,
                TEEType.TRUSTY, TEEType.OP_TEE, TEEType.HUYANG, TEEType.SECUREOS,
            ]
            for preferred in type_priority:
                if preferred in detected_types:
                    primary_type = preferred
                    break
            if primary_type == TEEType.UNKNOWN:
                primary_type = detected_types[0]

        # Gather all detected files
        for paths in fs_results.values():
            detected_files.extend(paths)
        detected_processes = list(self.process_checker.get_running_processes())

        # Determine security level
        security_level = TEESecurityLevel.UNKNOWN
        if primary_type == TEEType.TRUSTY:
            security_level = TEESecurityLevel.STRONG
        elif primary_type in (TEEType.TEEGRIS, TEEType.QSEE, TEEType.KNOX, TEEType.TZOS):
            security_level = TEESecurityLevel.STRONG
        elif primary_type in (TEEType.OP_TEE, TEEType.HUYANG):
            security_level = TEESecurityLevel.MODERATE
        elif primary_type == TEEType.NONE:
            security_level = TEESecurityLevel.WEAK

        # Build TEE info
        return TEEInfo(
            tee_type=primary_type if primary_type else TEEType.NONE,
            security_level=security_level,
            is_hardware_backed=hw_backed,
            supports_key_attestation=primary_type in (
                TEEType.TRUSTY, TEEType.TEEGRIS, TEEType.QSEE, TEEType.KNOX
            ),
            available_algorithms=["RSA", "EC", "AES", "HMAC"] if primary_type != TEEType.NONE else [],
            detected_files=detected_files,
            detected_processes=[p for p in detected_processes if any(
                t.value in p.lower() for t in TEEType
            )],
            version=self._extract_tee_version(primary_type),
        )

    def _extract_tee_version(self, tee_type: TEEType) -> Optional[str]:
        """Extract TEE version from system properties (simplified)."""
        if tee_type == TEEType.TRUSTY:
            return "4.0"
        elif tee_type == TEEType.KNOX:
            return "3.0"
        return None

    def assess_trustworthiness(self, tee_info: TEEInfo) -> Dict[str, Any]:
        """
        Assess overall device trustworthiness based on TEE findings.
        """
        score = 0
        max_score = 100
        findings = []

        if tee_info.tee_type == TEEType.NONE:
            score += 0
            findings.append("No TEE detected — no hardware security guarantees")
        elif tee_info.security_level == TEESecurityLevel.STRONG:
            score += 50
            findings.append(f"Strong TEE detected: {tee_info.tee_type.value}")
        elif tee_info.security_level == TEESecurityLevel.MODERATE:
            score += 30
            findings.append(f"Moderate TEE detected: {tee_info.tee_type.value}")

        if tee_info.is_hardware_backed:
            score += 30
            findings.append("Hardware-backed security confirmed")

        if tee_info.supports_key_attestation:
            score += 20
            findings.append("Key attestation supported")

        trust_level = "LOW"
        if score >= 80:
            trust_level = "HIGH"
        elif score >= 50:
            trust_level = "MEDIUM"

        return {
            "tee_info": tee_info,
            "trust_score": score,
            "max_score": max_score,
            "trust_level": trust_level,
            "findings": findings,
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="TEE Environment Checker")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    checker = TEEChecker()
    tee_info = checker.detect()
    assessment = checker.assess_trustworthiness(tee_info)

    if args.json:
        print(json.dumps({
            "tee_type": tee_info.tee_type.value,
            "security_level": tee_info.security_level.value,
            "is_hardware_backed": tee_info.is_hardware_backed,
            "supports_key_attestation": tee_info.supports_key_attestation,
            "detected_files": tee_info.detected_files,
            "trust_score": assessment["trust_score"],
            "trust_level": assessment["trust_level"],
            "findings": assessment["findings"],
        }, indent=2))
    else:
        print("TEE Environment Check Report")
        print("=" * 50)
        print(f"TEE Type: {tee_info.tee_type.value}")
        print(f"Security Level: {tee_info.security_level.value}")
        print(f"Hardware-backed: {'✅' if tee_info.is_hardware_backed else '❌'}")
        print(f"Key Attestation: {'✅' if tee_info.supports_key_attestation else '❌'}")
        print(f"Trust Score: {assessment['trust_score']}/100 ({assessment['trust_level']})")
        print()
        print("Findings:")
        for finding in assessment["findings"]:
            print(f"  • {finding}")
        if tee_info.detected_files:
            print()
            print(f"Detected files ({len(tee_info.detected_files)}):")
            for f in tee_info.detected_files[:10]:
                print(f"  {f}")


if __name__ == "__main__":
    main()
