from intelligence.detectors.brute_force import BruteForceDetector
from intelligence.detectors.credential_stuffing import CredentialStuffingDetector
from intelligence.detectors.injection import InjectionDetector
from intelligence.detectors.port_scanner import PortScanDetector
from evaluation.generate_attacks import brute_force, credential_stuffing, injection, port_scan


def detection_rate(results: list[bool]) -> float:
    return sum(results) / len(results)


def test_brute_force_detection_rate():
    detector = BruteForceDetector({"threshold": 10, "window_seconds": 60})
    results = [detector.detect(event, []).is_attack for event in brute_force(100)]
    assert detection_rate(results[9:]) > 0.90


def test_port_scan_detection_rate():
    detector = PortScanDetector({"threshold": 5, "window_seconds": 30})
    results = [detector.detect(event, []).is_attack for event in port_scan(60)]
    assert detection_rate(results[4:]) > 0.90


def test_credential_stuffing_detection_rate():
    detector = CredentialStuffingDetector(
        {"min_ips_for_reuse": 3, "unique_creds_threshold": 5, "window_seconds": 300}
    )
    results = [detector.detect(event, []).is_attack for event in credential_stuffing(80)]
    assert detection_rate(results[4:]) > 0.85


def test_injection_detection_rate():
    detector = InjectionDetector()
    results = [detector.detect(event, []).is_attack for event in injection(50)]
    assert detection_rate(results) > 0.90
