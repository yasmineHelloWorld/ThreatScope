from intelligence.detectors.brute_force import BruteForceDetector
from intelligence.detectors.credential_stuffing import CredentialStuffingDetector
from intelligence.detectors.injection import InjectionDetector
from intelligence.detectors.port_scanner import PortScanDetector
from intelligence.risk_scorer import RiskScorer
from evaluation.generate_attacks import make_event, normal_browsing


def score_event(detectors, scorer, event):
    return scorer.compute_score([detector.detect(event, []) for detector in detectors])


def test_risk_score_separation_for_normal_and_composite_attackers():
    detectors = [
        BruteForceDetector({"threshold": 10, "window_seconds": 60}),
        PortScanDetector({"threshold": 5, "window_seconds": 30}),
        CredentialStuffingDetector({"min_ips_for_reuse": 3, "unique_creds_threshold": 5}),
        InjectionDetector(),
    ]
    scorer = RiskScorer()

    normal_scores = [score_event(detectors, scorer, event) for event in normal_browsing(50)]

    attacker_scores = []
    for i in range(30):
        event = make_event(
            ip_address="203.0.113.250",
            request_type="POST",
            endpoint=f"/scan-{i % 8}",
            username=f"admin{i % 4}",
            password="' OR 1=1--",
            payload="' OR 1=1--",
            label="composite_attack",
        )
        attacker_scores.append(score_event(detectors, scorer, event))

    normal_avg = sum(normal_scores) / len(normal_scores)
    attacker_avg = sum(attacker_scores[-20:]) / 20

    assert normal_avg < 30
    assert max(attacker_scores) >= 70
    assert attacker_avg - normal_avg > 50


def test_risk_scorer_classification_boundaries():
    scorer = RiskScorer()

    assert scorer.classify(0) == "normal"
    assert scorer.classify(30) == "normal"
    assert scorer.classify(31) == "suspicious"
    assert scorer.classify(70) == "suspicious"
    assert scorer.classify(71) == "attacker"
