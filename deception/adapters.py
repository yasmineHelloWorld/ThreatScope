import logging

from deception.response_profiles import get_profile

logger = logging.getLogger(__name__)


def select_response(risk_score: int, service_type: str) -> dict:
    profile = get_profile(risk_score)
    logger.debug("Risk score %d -> profile '%s' for %s", risk_score, profile.label, service_type)

    if service_type == "http":
        return {"response_type": profile.http_response, "profile": profile.label}
    elif service_type == "ssh":
        return {"response_type": profile.ssh_response, "profile": profile.label}
    elif service_type == "api":
        return {"response_type": profile.api_response, "profile": profile.label}
    return {"response_type": "default", "profile": profile.label}
