"""Async WebSocket signaling server for P2P file transfer pairing."""

import json
import secrets
import string
from typing import Any, Dict, Optional, Set

import websockets
from websockets.exceptions import ConnectionClosed


class SignalingServer:
    """Manages in-memory transfer session rooms and relays signals between peers."""

    def __init__(self) -> None:
        self._rooms: Dict[str, Dict[str, Any]] = {}
        self._active_connections: Set[Any] = set()

    def _generate_code(self) -> str:
        """Generate a unique 6-character alphanumeric pairing code."""
        chars = string.ascii_uppercase + string.digits
        while True:
            code = ''.join(secrets.choice(chars) for _ in range(6))
            if code not in self._rooms:
                return code

    async def _handle_create(self, ws: Any, room: Dict[str, Any]) -> str:
        """Handle 'create' action: generate code, register sender, return pairing code."""
        code = self._generate_code()
        self._rooms[code] = {"sender": ws}
        await ws.send(json.dumps({"status": "created", "code": code}))
        return code

    async def _handle_join(self, ws: Any, code: str) -> bool:
        """Handle 'join' action: match receiver to room, notify both peers."""
        room = self._rooms.get(code)
        if room is None or "receiver" in room:
            await ws.send(json.dumps({"status": "invalid"}))
            return False

        room["receiver"] = ws
        # Notify both peers they are paired
        sender_ws = room["sender"]
        await sender_ws.send(json.dumps({"status": "paired"}))
        await ws.send(json.dumps({"status": "paired"}))
        return True

    async def _handle_signal(self, ws: Any, payload: Dict[str, Any]) -> None:
        """Relay payload to the opposite peer in the room."""
        for room_code, room in list(self._rooms.items()):
            if ws is room.get("sender") or ws is room.get("receiver"):
                target = room["receiver"] if ws is room["sender"] else room["sender"]
                await target.send(json.dumps({"type": "signal", "payload": payload}))
                return

    async def _handle_client(self, ws: Any) -> None:
        """Handle a single client connection."""
        self._active_connections.add(ws)
        try:
            while True:
                raw_message = await ws.recv()
                try:
                    data = json.loads(raw_message)
                except (json.JSONDecodeError, Exception):
                    await ws.send(json.dumps({"status": "error", "message": "Invalid JSON"}))
                    continue

                action = data.get("action")

                if action == "create":
                    await self._handle_create(ws, {})
                elif action == "join":
                    room_code = data.get("code")
                    if not room_code or not isinstance(room_code, str):
                        await ws.send(json.dumps({"status": "error", "message": "Missing code"}))
                        continue
                    await self._handle_join(ws, room_code)
                elif action == "signal":
                    payload = data.get("payload", {})
                    await self._handle_signal(ws, payload)
                else:
                    await ws.send(json.dumps({"status": "error", "message": f"Unknown action: {action}"}))
        except ConnectionClosed:
            pass
        finally:
            self._active_connections.discard(ws)
            # Clean up rooms where this peer was connected
            codes_to_remove = []
            for room_code, room in self._rooms.items():
                if ws is room.get("sender") or ws is room.get("receiver"):
                    if room.get("sender") is ws:
                        del room["sender"]
                    else:
                        del room["receiver"]
                    if not room:
                        codes_to_remove.append(room_code)
            for room_code in codes_to_remove:
                del self._rooms[room_code]

    async def start(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        """Start the WebSocket signaling server."""
        self._server = await websockets.serve(
            self._handle_client, host, port, process_request=self._process_request
        )
        print(f"Signaling server listening on ws://{host}:{port}")
        await self._server.wait_closed()

    @staticmethod
    async def _process_request(connection: Any, request: Any):
        """Allow all WebSocket connections (e.g., /path).

        In websockets v17+, process_request receives (connection, request).
        Return None to proceed with handshake, or a tuple to reject.
        """
        if request.path == "/signaling":
            return None  # Proceed with WebSocket handshake
        # Reject non-signaling paths
        return (
            403,
            [("Content-Type", "text/plain")],
            b"Forbidden\n",
        )


_instance: Optional[SignalingServer] = None


def get_instance() -> SignalingServer:
    """Get or create the singleton signaling server instance."""
    global _instance
    if _instance is None:
        _instance = SignalingServer()
    return _instance


async def run_signaling_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Convenience function to run the signaling server."""
    server = get_instance()
    await server.start(host, port)


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_signaling_server())
