import time
from collections import defaultdict
from intelligence.detectors.base import BaseDetector, DetectorResult

#main goal for class if ip try to scan many ports in short time 
#port scanning: attacker send requests to ports or services to check avaliable services (kam haga mokhtalefa fe wa2t mokhtalef)
#detect port scanning by tracking unique endpoints accessed by this ip in short time 
#beygrab y-check ala endpoint men kaza protocol (ports mokhtalefa ) ashan yeshof anhy fehom eli shaghala 

class PortScanDetector(BaseDetector):
    
    def __init__(self, config: dict = None):
        config = config or {}
        self.window_seconds = config.get("window_seconds", 30)
        self.threshold = config.get("threshold", 5)
        self._access_log: dict[str, list] = defaultdict(list)
    
    @property
    def name(self):
        return "port_scanner"

    def detect(self, event_data: dict, history: list[dict]) -> DetectorResult:
        ip = event_data.get("ip_address", "")
        endpoint = event_data.get("endpoint", "")
        service = event_data.get("service_type", "")
        now = time.time()
        
        target = f"{service}:{endpoint}" if endpoint else service
        self._access_log[ip].append((target, now))

        cutoff = now - self.window_seconds
        self._access_log[ip] = [
            (target_item, t) for target_item, t in self._access_log[ip] if t > cutoff 
        ]

        unique_targets = set(target_item for target_item, t in self._access_log[ip])
        unique_count = len(unique_targets)

        score = min(1.0, unique_count / self.threshold)
        is_attack = unique_count >= self.threshold

        return DetectorResult(
            detector_name=self.name,
            score=score,
            attack_type="port_scanning" if is_attack else None,
            confidence=score,
            is_attack=is_attack,
            details={
                "unique_targets": unique_count,
                "endpoints_seen": list(unique_targets),
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "ip": ip
            }
        )
    def reset(self):
        self._access_log.clear()
        
