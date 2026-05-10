import asyncio
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"


class FakeSSHServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server = None

    async def start(self):
        logger.info("Fake SSH server starting on %s:%d", self.host, self.port)
        self._server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Fake SSH server stopped.")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logger.info("SSH connection from %s", addr)

        try:
            writer.write(SSH_BANNER)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            client_banner = data.decode("utf-8", errors="replace").strip()
            logger.debug("SSH client banner from %s: %s", addr, client_banner)

            fake_auth_failure = (
                b"\x00\x00\x00\x0c\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00"
                + b"Permission denied (publickey,password).\r\n"
            )
            writer.write(fake_auth_failure)
            await writer.drain()

            await asyncio.sleep(0.5)
        except asyncio.TimeoutError:
            logger.warning("SSH connection from %s timed out", addr)
        except Exception as e:
            logger.error("Error handling SSH connection from %s: %s", addr, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
