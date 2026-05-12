import json
from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        disconnected: list[WebSocket] = []
        payload = json.dumps(message, default=str)
        for websocket in self.active_connections:
            try:
                await websocket.send_text(payload)
            except RuntimeError:
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(websocket)


websocket_manager = WebSocketManager()
