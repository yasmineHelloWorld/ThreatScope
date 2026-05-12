import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import yaml

from intelligence.detectors import get_all_detectors
from intelligence.detectors.base import DetectorResult
from intelligence.risk_scorer import RiskScorer
from intelligence.classifier import AttackClassifier

logger = logging.getLogger(__name__)

# Default rules path relative to this file
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.yaml")


@dataclass
class AnalysisResult:

    risk_score: int = 0
    classification: str = "normal"
    is_attack: bool = False
    attack_type: Optional[str] = None
    detector_results: list[DetectorResult] = field(default_factory=list)
    recommended_profile: str = "normal"
    details: dict = field(default_factory=dict)


class IntelligenceAnalyzer:
 
    def __init__(self, rules_path: str = RULES_PATH): #get rules
        self.config = self._load_rules(rules_path)
        
        # Initialize components
        detector_config = self.config.get("detectors", {})
        self.detectors = get_all_detectors(detector_config)
        
        scoring_config = self.config.get("scoring", {})
        self.scorer = RiskScorer(scoring_config)
        
        classification_config = self.config.get("classification", {})
        self.classifier = AttackClassifier(classification_config)

        # Per-IP event history: ip -> list of (timestamp, event_data)
        self._history: Dict[str, list] = {}
        self._history_ttl = self.config.get("history_ttl_seconds", 600)
        self._max_history = self.config.get("max_history_per_ip", 200)
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # seconds

        logger.info(
            "IntelligenceAnalyzer initialized with %d detectors",
            len(self.detectors),
        )

    def _load_rules(self, path: str) -> dict:

        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    config = yaml.safe_load(f) or {}
                logger.info("Rules loaded from %s", path)
                return config
            except Exception as e:
                logger.warning("Failed to load rules from %s: %s", path, e)
        else:
            logger.warning("Rules file not found at %s. Using default empty config.", path)
        return {}

    def analyze_event(self, event_data: dict) -> AnalysisResult:
   
        ip = event_data.get("ip_address", "unknown")
        history = self._get_history(ip)

        # 1. Run all detectors
        results: list[DetectorResult] = []
        for detector in self.detectors:
            try:
                result = detector.detect(event_data, history)
                results.append(result)
            except Exception as e:
                logger.error(
                    "Detector '%s' failed for IP %s: %s",
                    detector.name, ip, e,
                )
                results.append(DetectorResult(
                    detector_name=detector.name, score=0.0
                ))

        # 2. Compute risk score and rule-based classification
        risk_score = self.scorer.compute_score(results)
        rule_classification = self.scorer.classify(risk_score)
        dominant_attack = self.scorer.get_dominant_attack(results)
        is_attack = any(r.is_attack for r in results)

        # 3. LLM/Mock classification (Groq)
        try:
            groq_classification = self.classifier.classify(
                event_data, results, history, risk_score
            )
            final_classification = groq_classification["primary_type"]
        except Exception as e:
            logger.error("Classifier failed: %s. Using rule-based classification.", e)
            final_classification = rule_classification
            groq_classification = {}

        # 4. Update history
        self._update_history(ip, event_data)

        # 5. Periodic cleanup
        self._maybe_cleanup()

        analysis = AnalysisResult(
            risk_score=risk_score,
            classification=final_classification,
            is_attack=is_attack,
            attack_type=dominant_attack,
            detector_results=results,
            recommended_profile=rule_classification,  # Rule-based for deception profiles
            details={
                "ip": ip,
                "detector_scores": {
                    r.detector_name: r.score for r in results
                },
                "groq_classification": groq_classification,
                "rule_classification": rule_classification,
                "groq_reasoning": groq_classification.get("reasoning", ""),
                "groq_confidence": groq_classification.get("confidence", 0.0),
                "recommended_actions": groq_classification.get("recommended_actions", []),
                "history_length": len(history),
            },
        )

        logger.info(
            "Event analyzed: IP=%s score=%d class=%s attack=%s",
            ip, risk_score, final_classification,
            dominant_attack or "none",
        )

        return analysis

    def _get_history(self, ip: str) -> list[dict]:
        """Get recent event history for an IP."""
        if ip not in self._history:
            return []
        now = time.time()
        cutoff = now - self._history_ttl
        # Clean up stale entries for this IP on read
        self._history[ip] = [
            (ts, evt) for ts, evt in self._history[ip] if ts >= cutoff
        ]
        return [evt for _, evt in self._history[ip]]

    def _update_history(self, ip: str, event_data: dict):
        
        now = time.time()
        if ip not in self._history:
            self._history[ip] = []
        self._history[ip].append((now, event_data))
        if len(self._history[ip]) > self._max_history:
            self._history[ip] = self._history[ip][-self._max_history:]

    def _maybe_cleanup(self):
        
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self._history_ttl
        stale_ips = [
            ip for ip, entries in self._history.items()
            if not entries or entries[-1][0] < cutoff
        ]
        for ip in stale_ips:
            del self._history[ip]
        if stale_ips:
            logger.debug("Cleaned up %d stale IP histories", len(stale_ips))

    def reset(self):

        for detector in self.detectors:
            detector.reset()
        self._history.clear()
        logger.info("Analyzer state reset")
