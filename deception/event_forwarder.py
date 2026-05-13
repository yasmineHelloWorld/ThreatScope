import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)


INGEST_HOST = os.getenv("THREATSCOPE_INGEST_HOST", "127.0.0.1")
INGEST_PORT = int(os.getenv("THREATSCOPE_INGEST_PORT", "8000"))
INGEST_PATH = os.getenv("THREATSCOPE_INGEST_PATH", "/api/events/ingest")


def _risk_level_from_score(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


async def forward_event(
    *,
    endpoint: str,
    method: str,
    client_ip: str,
    payload: str | None,
    user_agent: str | None,
    risk_score: int,
) -> None:
    body = {
        "endpoint": endpoint,
        "method": method,
        "payload": payload,
        "userAgent": user_agent,
        "riskLevel": _risk_level_from_score(risk_score),
        "ip": client_ip,
    }
    body_bytes = json.dumps(body).encode("utf-8")
    req = (
        f"POST {INGEST_PATH} HTTP/1.1\r\n"
        f"Host: {INGEST_HOST}:{INGEST_PORT}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + body_bytes

    try:
        reader, writer = await asyncio.open_connection(INGEST_HOST, INGEST_PORT)
        writer.write(req)
        await writer.drain()
        await asyncio.wait_for(reader.read(512), timeout=2)
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        logger.debug("Failed to forward deception event: %s", e)
