import re
from intelligence.detectors.base import BaseDetector, DetectorResult

# el fekra badal ma tedakhal user input tabi3y ana momken  adakhal inject khabith yegbly sensitive data
# beyshtaghal in user beydakhal data fe regex pattern mawgoda gowa el detector y-check in requested data di mesh men el injections 
# law ah beyraga3 no3 attack we score we keda

# SQL-> attacks bethsal ala sql databases 
# NoSQL -> mogno_db or couch db 
# Command Injection -> command shell bestkhdam user input
# SSTI -> server side template injection bethsal (treat user input as template not as normal data) templates:dynammic html pages 
# inject command {{}} momken yehot hagat tekhalih ye2ra el files nafsaha 


DEFAULT_PATTERNS = {
    "sql": [
        r"(?i)('\s*(OR|AND)\s+(1|'[^']*')\s*=\s*(1|'[^']*'))",
        r"(?i)(UNION\s+(ALL\s+)?SELECT)",
        r"(?i)(SELECT\s+.*\s+FROM\s+)",
        r"(?i)(INSERT\s+INTO\s+)",
        r"(?i)(DROP\s+(TABLE|DATABASE))",
        r"(?i)(--\s*$|;\s*--)",
        r"(?i)(SLEEP\s*\(|BENCHMARK\s*\()",
        r"(?i)('\s*;\s*(DROP|DELETE|UPDATE|INSERT))",
    ],
    "nosql": [
        r"(\$gt|\$lt|\$ne|\$eq|\$regex|\$where|\$exists)",
        r"(\{\s*\$[a-z]+\s*:)",
        r"(?i)(db\.[a-zA-Z]+\.find\()",
    ],
    "command": [
        r"(;\s*(ls|cat|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\b)",
        r"(\|\s*(ls|cat|whoami|id|uname)\b)",
        r"(`[^`]*`)",
        r"(\$\([^)]+\))",
        r"(?i)(\.\./\.\./)",
        r"(?i)(/etc/passwd|/etc/shadow)",
        r"(?i)(cmd\.exe|powershell|cmd\s*/c)",
    ],
    "ssti": [
        r"(\{\{.*\}\})",
        r"(\$\{.*\})",
        r"(?i)(\{%.*%\})",
        r"(?i)(__class__|__mro__|__subclasses__|__builtins__)",
    ],
}

class InjectionDetector(BaseDetector):
    def __init__(self, config: dict = None):
        config = config or {}
        raw_pattern = config.get("patterns", DEFAULT_PATTERNS)  # custom patterns if provided
        self._compiled: dict[str, list] = {}
        for inj_type, patterns in raw_pattern.items():
            self._compiled[inj_type] = [re.compile(p) for p in patterns]  # stored pattern compiled

    @property
    def name(self) -> str:
        return "injection"

    def detect(self, event_data: dict, history: list[dict]) -> DetectorResult:
        # list of places in which attacker can inject from
        fields_to_scan = [
            str(event_data.get("payload", "") or " "),
            str(event_data.get("username", "") or " "),
            str(event_data.get("password", "") or " "),
            str(event_data.get("endpoint", "") or " "),
            str(event_data.get("user_agent", "") or " ")
        ]
        combined_text = "".join(fields_to_scan)  # one big string to search in

        if not combined_text or combined_text.isspace():
            return DetectorResult(detector_name=self.name, score=0.0)

        best_score = 0.0
        detected_type = None
        matched_patterns = []

        # check injection type if exists  how many regex match in this injection type 
        for inj_type, patterns in self._compiled.items():
            type_matches = 0
            for pattern in patterns:  # loop through each pattern of this type 
                if pattern.search(combined_text):
                    type_matches += 1
                    matched_patterns.append({
                        "type": inj_type,
                        "pattern": pattern.pattern
                    })

            if type_matches > 0:
                type_score = min(1.0, type_matches / 2.0)  # divide two to full confidence
                if type_score > best_score:
                    best_score = type_score
                    detected_type = inj_type

        is_attack = best_score >= 0.5
        
        return DetectorResult(
            detector_name=self.name,
            score=best_score,
            attack_type=f"injection_{detected_type}" if is_attack else None,
            confidence=best_score,
            is_attack=is_attack,
            details={
                "matched_patterns": matched_patterns,
                "injection_type": detected_type,
                "fields_scanned":len(fields_to_scan)
            }
        )

    def reset(self):
        pass  # injection detector is stateless
