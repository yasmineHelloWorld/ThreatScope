from intelligence.detectors.brute_force import BruteForceDetector
from intelligence.detectors.credential_stuffing import CredentialStuffingDetector
from intelligence.detectors.injection import InjectionDetector
from intelligence.detectors.port_scanner import PortScanDetector
from evaluation.generate_attacks import normal_browsing


def test_normal_traffic_false_positive_rate():
    detectors = [
        BruteForceDetector({"threshold": 10, "window_seconds": 60}),
        PortScanDetector({"threshold": 5, "window_seconds": 30}),
        CredentialStuffingDetector({"min_ips_for_reuse": 3, "unique_creds_threshold": 5}),
        InjectionDetector(),
    ]
    false_positives = 0
    events = normal_browsing(200)

    for event in events:
        if any(detector.detect(event, []).is_attack for detector in detectors):
            false_positives += 1

    assert false_positives / len(events) < 0.05
