from dataclasses import dataclass


@dataclass
class ResponseProfile:
    label: str
    risk_min: int
    risk_max: int
    http_response: str
    ssh_response: str
    api_response: str
    logging_verbosity: str


NORMAL = ResponseProfile(
    label="normal",
    risk_min=0,
    risk_max=30,
    http_response="NORMAL_LOGIN_PAGE",
    ssh_response="PERMISSION_DENIED",
    api_response="401_UNAUTHORIZED",
    logging_verbosity="minimal",
)

SUSPICIOUS = ResponseProfile(
    label="suspicious",
    risk_min=30,
    risk_max=70,
    http_response="FAKE_ADMIN_HINT",
    ssh_response="SLOW_RESPONSE_FAKE_USER_LIST",
    api_response="SAMPLE_USER_DATA",
    logging_verbosity="full",
)

ATTACKER = ResponseProfile(
    label="attacker",
    risk_min=70,
    risk_max=100,
    http_response="FAKE_DEBUG_ENDPOINT_TRAP_CREDS",
    ssh_response="FAKE_ROOT_SHELL_PROMPT",
    api_response="FAKE_API_KEYS_TOKENS",
    logging_verbosity="verbose",
)

PROFILES = [NORMAL, SUSPICIOUS, ATTACKER]


def get_profile(risk_score: int) -> ResponseProfile:
    for profile in PROFILES:
        if profile.risk_min <= risk_score <= profile.risk_max:
            return profile
    return ATTACKER
