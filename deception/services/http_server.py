import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class FakeHTTPServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
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
            logger.debug("HTTP request:\n%s", request_text)

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE html><html><head><title>Sign In</title></head><body>"
                "<h2>Sign In</h2>"
                "<form method='POST' action='/login'>"
                "  <input type='text' name='username' placeholder='Username'><br>"
                "  <input type='password' name='password' placeholder='Password'><br>"
                "  <button type='submit'>Login</button>"
                "</form></body></html>"
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
