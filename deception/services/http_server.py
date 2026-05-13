import asyncio
import logging
from deception.adapters import ResponseAdapter
from deception.event_forwarder import forward_event
from deception.request_context import build_request_context, InMemoryRiskScorer

logger = logging.getLogger(__name__)


class FakeHTTPServer:
    def __init__(self, host: str, port: int, adapter: ResponseAdapter, scorer: InMemoryRiskScorer):
        self.host = host
        self.port = port
        self.adapter = adapter
        self.scorer = scorer
        self._server = None

    async def start(self):
        logger.info("Fake HTTP server starting on %s:%d", self.host, self.port)
        self._server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Fake HTTP server stopped.")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logger.info("HTTP connection from %s", addr)

        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            request_text = data.decode("utf-8", errors="replace")
            client_ip = addr[0] if addr else "unknown"
            context = build_request_context(
                service_type="http",
                client_ip=client_ip,
                raw_request=request_text,
                scorer=self.scorer,
            )
            selection = self.adapter.select_response(context.risk_score, "http")
            logger.info(
                "deception.flow service=%s ip=%s risk_score=%d profile=%s response_type=%s",
                "http",
                client_ip,
                context.risk_score,
                selection["profile"],
                selection["response_type"],
            )

            response = self._render_http(selection["response_type"])
            first_line = request_text.split("\r\n", 1)[0] if request_text else "GET / HTTP/1.1"
            method = first_line.split(" ")[0] if " " in first_line else "GET"
            endpoint = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "/"
            asyncio.create_task(
                forward_event(
                    endpoint=endpoint,
                    method=method,
                    client_ip=client_ip,
                    payload=request_text[:1000],
                    user_agent="deception-http-client",
                    risk_score=context.risk_score,
                )
            )
            writer.write(response.encode())
            await writer.drain()
        except asyncio.TimeoutError:
            logger.warning("HTTP connection from %s timed out", addr)
        except Exception as e:
            logger.error("Error handling HTTP connection from %s: %s", addr, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _render_http(self, response_type: str) -> str:
        if response_type == "FAKE_DEBUG_ENDPOINT_TRAP_CREDS":
            body = (
                "<!DOCTYPE html><html><head><title>Admin Debug</title></head><body>"
                "<h2>Admin Diagnostics Panel</h2>"
                "<p>Privileged telemetry enabled. Session mirrored.</p>"
                "<form method='POST' action='/admin/debug'>"
                "  <input type='text' name='token' value='dbg_live_7f2ac'/>"
                "  <input type='password' name='root_password' value='P@ssw0rd!2026'/>"
                "  <button type='submit'>Validate</button>"
                "</form></body></html>"
            )
        elif response_type == "FAKE_ADMIN_HINT":
            body = (
                "<!DOCTYPE html><html><head><title>Sign In</title></head><body>"
                "<h2>Sign In</h2><p>Tip: admin debug tools are available after authentication.</p>"
                "<form method='POST' action='/login'>"
                "  <input type='text' name='username' placeholder='Username'><br>"
                "  <input type='password' name='password' placeholder='Password'><br>"
                "  <button type='submit'>Login</button>"
                "</form></body></html>"
            )
        else:
            body = (
                "<!DOCTYPE html><html><head><title>Sign In</title></head><body>"
                "<h2>Sign In</h2>"
                "<form method='POST' action='/login'>"
                "  <input type='text' name='username' placeholder='Username'><br>"
                "  <input type='password' name='password' placeholder='Password'><br>"
                "  <button type='submit'>Login</button>"
                "</form></body></html>"
            )

        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
