import asyncio
import logging
from deception.adapters import ResponseAdapter
from deception.request_context import InMemoryRiskScorer
from deception.services.http_server import FakeHTTPServer
from deception.services.ssh_server import FakeSSHServer
from deception.services.api_endpoints import FakeAPIServer

logger = logging.getLogger(__name__)


class DeceptionEngine:
    def __init__(self):
        self.services = []
        self.adapter = ResponseAdapter()
        self.risk_scorer = InMemoryRiskScorer()

    async def start_all(self):
        self.services = [
            FakeHTTPServer(host="0.0.0.0", port=8080, adapter=self.adapter, scorer=self.risk_scorer),
            FakeSSHServer(host="0.0.0.0", port=2222, adapter=self.adapter, scorer=self.risk_scorer),
            FakeAPIServer(host="0.0.0.0", port=8081, adapter=self.adapter, scorer=self.risk_scorer),
        ]
        tasks = [srv.start() for srv in self.services]
        logger.info("Starting all deception services...")
        await asyncio.gather(*tasks)

    async def stop_all(self):
        for srv in self.services:
            await srv.stop()
        logger.info("All deception services stopped.")
