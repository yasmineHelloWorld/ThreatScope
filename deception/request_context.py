from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re


@dataclass
class RequestContext:
    service_type: str
    client_ip: str
    raw_request: str
    risk_score: int
    timestamp: str


class InMemoryRiskScorer:
    def __init__(self):
        self._counts: dict[str, int] = {}

    def score(self, service_type: str, client_ip: str, raw_request: str) -> int:
        req = raw_request or ""
        lowered = req.lower()

        base = 12
        if service_type == "ssh":
            base = 20

        suspicious_patterns = [
            r"union\s+select",
            r"or\s+1=1",
            r"drop\s+table",
            r"<script",
            r"javascript:",
            r"\.\./",
            r"/etc/passwd",
            r"\$\(",
            r"\|\|",
            r";",
            r"admin",
            r"debug",
        ]
        if any(re.search(p, lowered) for p in suspicious_patterns):
            base = max(base, 78)

        try:
            parsed = json.loads(req) if req.strip().startswith("{") else None
            if isinstance(parsed, dict):
                payload_text = json.dumps(parsed).lower()
                if any(re.search(p, payload_text) for p in suspicious_patterns):
                    base = max(base, 85)
        except Exception:
            pass

        count = self._counts.get(client_ip, 0) + 1
        self._counts[client_ip] = count

        escalation = min((count - 1) * 6, 25)
        return min(100, base + escalation)


def build_request_context(
    service_type: str,
    client_ip: str,
    raw_request: str,
    scorer: InMemoryRiskScorer,
) -> RequestContext:
    risk = scorer.score(service_type=service_type, client_ip=client_ip, raw_request=raw_request)
    return RequestContext(
        service_type=service_type,
        client_ip=client_ip,
        raw_request=raw_request,
        risk_score=risk,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
