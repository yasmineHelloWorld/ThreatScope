import logging

from deception.response_profiles import get_profile

logger = logging.getLogger(__name__)


class ResponseAdapter:
    def __init__(self):
        self._service_selectors = {
            "http": lambda profile: profile.http_response,
            "ssh": lambda profile: profile.ssh_response,
            "api": lambda profile: profile.api_response,
        }

    def select_response(self, risk_score: int, service_type: str) -> dict:
        profile = get_profile(risk_score)
        selector = self._service_selectors.get(service_type, lambda _profile: "default")
        response_type = selector(profile)
        logger.info(
            "adapter.select service=%s risk_score=%d profile=%s response_type=%s",
            service_type,
            risk_score,
            profile.label,
            response_type,
        )
        return {"response_type": response_type, "profile": profile.label}


_default_adapter = ResponseAdapter()


def select_response(risk_score: int, service_type: str) -> dict:
    return _default_adapter.select_response(risk_score, service_type)
