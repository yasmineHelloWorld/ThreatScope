import asyncio
import json
import logging

logger = logging.getLogger(__name__)

ROUTES = {
    b"POST /api/v1/login HTTP/1.1": (401, {"error": "Invalid credentials"}),
    b"GET /api/v1/users HTTP/1.1": (200, {"users": []}),
    b"GET /api/v1/admin HTTP/1.1": (403, {"error": "Forbidden"}),
}


class FakeAPIServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
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

            status_code, body = ROUTES.get(first_line, (404, {"error": "Not found"}))
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
