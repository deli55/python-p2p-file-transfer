"""Signaling client for P2P file transfer pairing and signal relay."""

import base64
import json
from typing import Any, Dict, Optional

import websockets


def _encode_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Encode bytes values in payload to base64 for JSON serialization."""
    encoded = {}
    for k, v in payload.items():
        if isinstance(v, bytes):
            encoded[k] = base64.b64encode(v).decode("ascii")
            encoded[k + "_encoding"] = "base64"
        else:
            encoded[k] = v
    return encoded


def _decode_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Decode base64 values back to bytes in payload."""
    decoded = {}
    for k, v in payload.items():
        if k.endswith("_encoding"):
            continue
        # Check if the value looks like base64 and was encoded
        alt_key = k + "_encoding"
        if isinstance(v, str) and alt_key in payload:
            try:
                decoded[k] = base64.b64decode(v)
            except Exception:
                decoded[k] = v
        else:
            decoded[k] = v
    return decoded


class SignalingClient:
    """Async class wrapping websockets.connect for signaling server communication."""

    def __init__(self, uri: str = "ws://127.0.0.1:8765/signaling") -> None:
        self._uri = uri
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._connected = False

    async def _ensure_connection(self) -> websockets.WebSocketClientProtocol:
        """Ensure we have an active WebSocket connection."""
        if self._ws is None or self._connected is False:
            self._ws = await websockets.connect(self._uri)
            self._connected = True
        return self._ws

    async def create_room(self) -> str:
        """Connect to signaling server, send action: create, and return the 6-digit pairing code.

        Returns:
            The 6-character alphanumeric pairing code.

        Raises:
            RuntimeError: If the pairing code is not received.
        """
        ws = await self._ensure_connection()
        await ws.send(json.dumps({"action": "create"}))
        response = json.loads(await ws.recv())
        if response.get("status") != "created":
            raise RuntimeError(f"Failed to create room: {response}")
        code = response.get("code")
        if not code:
            raise RuntimeError("No pairing code received")
        return code

    async def wait_for_paired(self) -> None:
        """Wait for 'paired' status message from the signaling server.

        Raises:
            RuntimeError: If paired status is not received.
        """
        if self._ws is None or self._connected is False:
            raise RuntimeError("No active connection.")
        raw = await self._ws.recv()
        response = json.loads(raw)
        if response.get("status") != "paired":
            raise RuntimeError(f"Expected paired status, got: {response}")

    async def join_room(self, code: str) -> None:
        """Connect to signaling server, send action: join, and wait for status: paired.

        Args:
            code: The 6-character pairing code.

        Raises:
            RuntimeError: If pairing fails.
        """
        ws = await self._ensure_connection()
        await ws.send(json.dumps({"action": "join", "code": code}))
        response = json.loads(await ws.recv())
        if response.get("status") != "paired":
            raise RuntimeError(f"Failed to join room: {response}")

    async def send_signal(self, payload: Dict[str, Any]) -> None:
        """Send a signal payload across the relay.

        Bytes values in the payload are automatically base64-encoded for JSON serialization.

        Args:
            payload: The payload to send (e.g., ECDH public key, file metadata).
        """
        if self._ws is None or self._connected is False:
            raise RuntimeError("No active connection. Call create_room or join_room first.")
        encoded = _encode_payload(payload)
        await self._ws.send(json.dumps({"action": "signal", "payload": encoded}))

    async def receive_signal(self) -> Dict[str, Any]:
        """Receive a signal payload from the relay.

        Base64-encoded values are automatically decoded back to bytes.

        Skips non-signal messages (e.g. status updates like 'paired').

        Returns:
            The received payload dictionary.

        Raises:
            RuntimeError: If no active connection.
        """
        if self._ws is None or self._connected is False:
            raise RuntimeError("No active connection. Call create_room or join_room first.")
        while True:
            raw = await self._ws.recv()
            data = json.loads(raw)
            # Skip status messages (e.g. {"status": "paired"})
            if "status" in data and "payload" not in data:
                continue
            decoded = _decode_payload(data.get("payload", data))
            return decoded

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
            self._connected = False
