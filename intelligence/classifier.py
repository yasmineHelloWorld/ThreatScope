import json
import logging
from typing import List, Dict, Optional
from intelligence.llm_client import GroqClient

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity threat classifier for an adaptive honeypot system called ThreatScope.
Your job is to analyze honeypot interaction data and classify the threat level.

You will receive:
- Event data (IP, service, request type, credentials, payload, endpoint, user agent)
- Detector signals (scores from brute force, port scan, credential stuffing, injection detectors)
- IP history summary (recent activity from this IP)
- Computed risk score (0-100)

You MUST respond with valid JSON matching this exact schema:
{
    "primary_type": "normal" | "suspicious" | "attacker",
    "confidence": <float 0.0-1.0>,
    "reasoning": "<detailed explanation of the threat>",
    "ai_logic": "<the internal assumptions and logic you used to reach this conclusion>",
    "recommended_actions": ["<action1>", "<action2>", ...],
    "attack_category": "<category or null>"
}

Classification guidelines:
- "normal": Benign traffic, no malicious intent detected
- "suspicious": Potentially malicious, warrants monitoring (e.g., light probing, unusual patterns)
- "attacker": Confirmed malicious activity (e.g., active exploitation, brute force, injection)

Recommended actions can include: "monitor", "log_only", "rate_limit", "block_ip", "escalate", "deploy_decoy", "extend_session", "capture_tools"

Attack categories can include: "brute_force", "port_scan", "credential_stuffing", "injection_sql", "injection_nosql", "injection_command", "injection_ssti", "reconnaissance", "unknown", or null if normal.

Respond ONLY with the JSON object. No markdown, no explanation outside the JSON."""


class AttackClassifier:
    
    def __init__(self, config: dict = None):
        self.llm = GroqClient(config)

    def classify(
        self,
        event_data: dict,
        detector_results: list,
        ip_history: list[dict],
        risk_score: int,
    ) -> dict:
       
        prompt = self._build_prompt(event_data, detector_results, ip_history, risk_score)
        
        # Call the LLM client
        response_text = self.llm.get_completion(SYSTEM_PROMPT, prompt)
        
        # If the LLM failed or is in mock mode, use local fallback logic
        if response_text is None:
            return self._mock_classify(event_data, detector_results, risk_score)

        return self._parse_response(response_text)

    def _mock_classify(self, event_data: dict, detector_results: list, risk_score: int) -> dict:
        
        primary_type = "normal"
        if risk_score >= 70:
            primary_type = "attacker"
        elif risk_score >= 30:
            primary_type = "suspicious"

        attack_category = next((r.attack_type for r in detector_results if r.is_attack), None)
        
        actions = ["monitor"]
        if primary_type == "attacker":
            actions.append("block_ip")
        elif primary_type == "suspicious":
            actions.append("rate_limit")

        return {
            "primary_type": primary_type,
            "confidence": 0.8 if risk_score > 80 or risk_score < 10 else 0.5,
            "reasoning": f"Local rule-based fallback triggered (Risk Score: {risk_score}).",
            "ai_logic": "Rule-based scoring thresholds reached. LLM was bypassed or unavailable.",
            "recommended_actions": actions,
            "attack_category": attack_category,
        }

    def _build_prompt(
        self,
        event_data: dict,
        detector_results: list,
        ip_history: list[dict],
        risk_score: int,
    ) -> str:
        
        event_section = (
            "== CURRENT EVENT ==\n"
            f"IP Address:    {event_data.get('ip_address', 'unknown')}\n"
            f"Service:       {event_data.get('service_type', 'unknown')}\n"
            f"Request Type:  {event_data.get('request_type', 'unknown')}\n"
            f"Endpoint:      {event_data.get('endpoint', 'N/A')}\n"
            f"Username:      {event_data.get('username', 'N/A')}\n"
            f"Password:      {event_data.get('password', 'N/A')}\n"
            f"User-Agent:    {event_data.get('user_agent', 'N/A')}\n"
            f"Payload:       {(event_data.get('payload', '') or '')[:500]}\n"
        )

        signals = [
            f"  - {r.detector_name}: score={r.score:.2f}, is_attack={r.is_attack}, type={r.attack_type}"
            for r in detector_results
        ]
        detector_section = "== DETECTOR SIGNALS ==\n" + "\n".join(signals) + "\n"

        history_count = len(ip_history)
        recent = ip_history[-5:] if ip_history else []
        history_lines = [f"Total events from this IP: {history_count}"]
        for evt in recent:
            history_lines.append(f"  - {evt.get('request_type', '?')} {evt.get('endpoint', '?')}")
        history_section = "== IP HISTORY (last 5) ==\n" + "\n".join(history_lines) + "\n"

        return f"{event_section}\n{detector_section}\n{history_section}\n== RISK SCORE ==\n{risk_score}/100"

    def _parse_response(self, response_text: str) -> dict:
        """Validates and cleans the AI output."""
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse AI JSON: %s", e)
            return {"primary_type": "suspicious", "confidence": 0.0, "reasoning": "Parse Error"}

        return {
            "primary_type": data.get("primary_type", "suspicious"),
            "confidence": max(0.0, min(1.0, float(data.get("confidence", 0.5)))),
            "reasoning": data.get("reasoning", "No reasoning provided"),
            "ai_logic": data.get("ai_logic", "No internal logic provided"),
            "recommended_actions": data.get("recommended_actions", ["monitor"]),
            "attack_category": data.get("attack_category"),
        }
