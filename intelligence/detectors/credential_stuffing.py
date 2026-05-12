import time 
from collections import defaultdict
from intelligence.detectors.base import BaseDetector, DetectorResult
#case law attacker m3ah list kbeera men el usernames we passwords we beyhawel yegarab yedakhlhom gowa el website dahfe moda olayela gedan 
#fekreto eno yet2ad en law nafs ip beykhosh be credentials kteer aw naf el credentails bas men kaza ip
 
class CredentialStuffingDetector(BaseDetector):
    def __init__(self, config: dict = None):
        config = config or {}
        self.min_ips_for_reuse = config.get("min_ips_for_reuse", 3)  # same cred diff ips
        self.unique_creds_threshold = config.get("unique_creds_threshold", 5)  # diff creds same ip
        self.window_seconds = config.get("window_seconds", 300)
        self._credential_map: dict[tuple, set] = defaultdict(set)  # same username+password -> set(ips)
        self.ip_creds: dict[str, list] = defaultdict(list)  # ip ->list(username,password)

    @property
    def name(self) -> str:
        return "credential_stuffing"

    def detect(self, event_data: dict, history: list[dict]) -> DetectorResult:
        ip = event_data.get("ip_address", "")
        username = event_data.get("username")
        password = event_data.get("password")

        if not username or not password:
            return DetectorResult(detector_name=self.name, score=0.0)

        now = time.time()
        cred_pair = (username, password)

        self._credential_map[cred_pair].add(ip)
        reuse_count = len(self._credential_map[cred_pair])

        self.ip_creds[ip].append((now, cred_pair))
        cutoff = now - self.window_seconds
        self.ip_creds[ip] = [(t, credentials) for t, credentials in self.ip_creds[ip] if t > cutoff]

        unique_creds = len(set(credentials for t, credentials in self.ip_creds[ip]))

        reuse_score = min(1.0, reuse_count / self.min_ips_for_reuse)
        stuffing_score = min(1.0, unique_creds / self.unique_creds_threshold)

        score = max(reuse_score, stuffing_score)
        is_attack = (reuse_count >= self.min_ips_for_reuse or unique_creds >= self.unique_creds_threshold)

        return DetectorResult(
            detector_name=self.name,
            score=score,
            attack_type="credential_stuffing" if is_attack else None,
            confidence=score,
            is_attack=is_attack,
            details={
                "credential_reuse_ips": reuse_count,
                "unique_cred_from_ip": unique_creds,
                "ip": ip,
                "username": username
            }
        )

    def reset(self):
        self._credential_map.clear()
        self.ip_creds.clear()

        
    