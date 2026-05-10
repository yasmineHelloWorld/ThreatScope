import asyncio
import logging
from deception.services.http_server import FakeHTTPServer
from deception.services.ssh_server import FakeSSHServer
from deception.services.api_endpoints import FakeAPIServer

logger = logging.getLogger(__name__)


class DeceptionEngine:
    def __init__(self):
        self.services = []

    async def start_all(self):
        self.services = [
            FakeHTTPServer(host="0.0.0.0", port=8080),
            FakeSSHServer(host="0.0.0.0", port=2222),
            FakeAPIServer(host="0.0.0.0", port=8081),
        ]
        tasks = [srv.start() for srv in self.services]
        logger.info("Starting all deception services...")
        await asyncio.gather(*tasks)

    async def stop_all(self):
        for srv in self.services:
            await srv.stop()
        logger.info("All deception services stopped.")
