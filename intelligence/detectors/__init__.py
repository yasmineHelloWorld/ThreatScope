from intelligence.detectors.brute_force import BruteForceDetector
from intelligence.detectors.port_scanner import PortScanDetector
from intelligence.detectors.credential_stuffing import CredentialStuffingDetector
from intelligence.detectors.injection import InjectionDetector

# return instance of all detectors
# config could be json file
# each detector has its own config passed to the constructor
def get_all_detectors(config: dict = None) -> list:
    config = config or {}
    return [
        BruteForceDetector(config.get("brute_force", {})),
        PortScanDetector(config.get("port_scanner", {})),
        CredentialStuffingDetector(config.get("credential_stuffing", {})),
        InjectionDetector(config.get("injection", {})),
    ]

# decide what will be exported from this file
__all__ = [
    "get_all_detectors",
    "BruteForceDetector",
    "PortScanDetector",
    "CredentialStuffingDetector",
    "InjectionDetector",
]
