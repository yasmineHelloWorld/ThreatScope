import asyncio
import logging
from deception.adapters import ResponseAdapter
from deception.event_forwarder import forward_event
from deception.request_context import build_request_context, InMemoryRiskScorer

logger = logging.getLogger(__name__)

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"


class FakeSSHServer:
    def __init__(self, host: str, port: int, adapter: ResponseAdapter, scorer: InMemoryRiskScorer):
        self.host = host
        self.port = port
        self.adapter = adapter
        self.scorer = scorer
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

            client_ip = addr[0] if addr else "unknown"
            context = build_request_context(
                service_type="ssh",
                client_ip=client_ip,
                raw_request=client_banner,
                scorer=self.scorer,
            )
            selection = self.adapter.select_response(context.risk_score, "ssh")
            logger.info(
                "deception.flow service=%s ip=%s risk_score=%d profile=%s response_type=%s",
                "ssh",
                client_ip,
                context.risk_score,
                selection["profile"],
                selection["response_type"],
            )

            writer.write(self._render_ssh(selection["response_type"]))
            asyncio.create_task(
                forward_event(
                    endpoint="/ssh/session",
                    method="CONNECT",
                    client_ip=client_ip,
                    payload=client_banner[:1000],
                    user_agent="deception-ssh-client",
                    risk_score=context.risk_score,
                )
            )
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

    def _render_ssh(self, response_type: str) -> bytes:
        if response_type == "FAKE_ROOT_SHELL_PROMPT":
            return b"Last login: Tue May 12 21:10:07 UTC 2026 on pts/0\r\nroot@nexora-core:~# "
        if response_type == "SLOW_RESPONSE_FAKE_USER_LIST":
            return b"Permission denied. Try keyboard-interactive.\r\nuser: deploy, backup, monitor\r\n"
        return (
            b"\x00\x00\x00\x0c\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00"
            b"Permission denied (publickey,password).\r\n"
        )
