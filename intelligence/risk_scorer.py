import logging
from intelligence.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "brute_force": 0.35,
    "port_scanner": 0.25,
    "credential_stuffing": 0.20,
    "injection": 0.20,
}

CLASSIFICATION_THRESHOLDS = {
    "normal": (0, 30),
    "suspicious": (30, 70),
    "attacker": (70, 100),
}

class RiskScorer:

    def __init__(self, config: dict = None):
        config = config or {}
        self.weights = config.get("weights", DEFAULT_WEIGHTS)
        self.thresholds = config.get("thresholds", CLASSIFICATION_THRESHOLDS)

    def compute_score(self, results: list[DetectorResult]) -> int:
        
        total = 0.0
        for result in results:
            weight = self.weights.get(result.detector_name, 0.0)
            total += weight * result.score * 100

        score = int(min(100, round(total)))
        logger.debug("Risk score computed: %d", score)
        return score

    def classify(self, score: int) -> str:
        
        for label, (low, high) in self.thresholds.items():
            if low <= score <= high:
                return label
        return "attacker"

    def get_dominant_attack(self, results: list[DetectorResult]) -> str | None:

        attack_results = [r for r in results if r.is_attack]
        if not attack_results:
            return None
        return max(attack_results, key=lambda r: r.score).attack_type