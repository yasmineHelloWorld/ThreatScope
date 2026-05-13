import asyncio
import json
import logging
from deception.adapters import ResponseAdapter
from deception.event_forwarder import forward_event
from deception.request_context import build_request_context, InMemoryRiskScorer

logger = logging.getLogger(__name__)

ROUTES = {
    b"POST /api/v1/login HTTP/1.1": (401, {"error": "Invalid credentials"}),
    b"GET /api/v1/users HTTP/1.1": (200, {"users": []}),
    b"GET /api/v1/admin HTTP/1.1": (403, {"error": "Forbidden"}),
}


class FakeAPIServer:
    def __init__(self, host: str, port: int, adapter: ResponseAdapter, scorer: InMemoryRiskScorer):
        self.host = host
        self.port = port
        self.adapter = adapter
        self.scorer = scorer
        self._server = None

    async def start(self):
        logger.info("Fake API server starting on %s:%d", self.host, self.port)
        self._server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Fake API server stopped.")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logger.info("API connection from %s", addr)

        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=10)
            request_text = data.decode("utf-8", errors="replace")
            first_line = request_text.split("\r\n")[0].encode() if request_text else b""
            logger.debug("API request from %s: %s", addr, first_line)

            client_ip = addr[0] if addr else "unknown"
            context = build_request_context(
                service_type="api",
                client_ip=client_ip,
                raw_request=request_text,
                scorer=self.scorer,
            )
            selection = self.adapter.select_response(context.risk_score, "api")
            logger.info(
                "deception.flow service=%s ip=%s risk_score=%d profile=%s response_type=%s",
                "api",
                client_ip,
                context.risk_score,
                selection["profile"],
                selection["response_type"],
            )

            status_code, body = self._render_api(selection["response_type"], first_line)
            first_line_text = first_line.decode("utf-8", errors="replace")
            parts = first_line_text.split(" ")
            method = parts[0] if len(parts) > 0 else "GET"
            endpoint = parts[1] if len(parts) > 1 else "/"
            asyncio.create_task(
                forward_event(
                    endpoint=endpoint,
                    method=method,
                    client_ip=client_ip,
                    payload=request_text[:1000],
                    user_agent="deception-api-client",
                    risk_score=context.risk_score,
                )
            )
            body_bytes = json.dumps(body).encode()

            response = (
                f"HTTP/1.1 {status_code} {'OK' if status_code == 200 else 'Error'}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode() + body_bytes

            writer.write(response)
            await writer.drain()
        except asyncio.TimeoutError:
            logger.warning("API connection from %s timed out", addr)
        except Exception as e:
            logger.error("Error handling API connection from %s: %s", addr, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _render_api(self, response_type: str, first_line: bytes) -> tuple[int, dict]:
        if response_type == "FAKE_API_KEYS_TOKENS":
            return (
                200,
                {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.decoy.signature",
                    "api_key": "sk_live_decoy_4bfc2ac8",
                    "endpoints": ["/api/v1/admin/keys", "/api/v1/debug/export", "/api/v1/internal/users"],
                },
            )
        if response_type == "SAMPLE_USER_DATA":
            return (200, {"users": [{"id": 1, "name": "svc.deploy"}, {"id": 2, "name": "monitor.bot"}]})
        return ROUTES.get(first_line, (404, {"error": "Not found"}))
