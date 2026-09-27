"""Tests for the signaling server and client."""

import asyncio
import json
import random

import pytest
import websockets

from signaling_server import SignalingServer
from p2p_transfer.signaling import SignalingClient


def _get_random_port():
    """Pick a random port between 9000-9999 to avoid conflicts."""
    return random.randint(9000, 9999)


class TestSignalingServer:
    """Test suite for the signaling server functionality."""

    @pytest.mark.asyncio
    async def test_sender_creates_room(self):
        """Test that a sender can create a room and receive a 6-digit alphanumeric code."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            sender = SignalingClient(uri=uri)
            code = await sender.create_room()

            # Verify the code is exactly 6 characters
            assert len(code) == 6

            # Verify the code is alphanumeric and uppercase
            assert code.isalnum()
            assert code == code.upper()

            # Verify each character is uppercase letter or digit
            import string
            valid_chars = set(string.ascii_uppercase + string.digits)
            assert all(c in valid_chars for c in code), \
                f"Code contains invalid characters: {code}"

            # Sender.create_room() waits for "paired", so we need a receiver
            # to join the room for the test to complete
            receiver = SignalingClient(uri=uri)
            await receiver.join_room(code)

            await sender.close()
            await receiver.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_receiver_joins_with_code(self):
        """Test that receiver can join a room with the correct code and both receive paired status."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            # Sender creates room
            sender = SignalingClient(uri=uri)
            code = await sender.create_room()

            # Receiver joins room
            receiver = SignalingClient(uri=uri)
            await receiver.join_room(code)

            # Both should have received "paired" status
            # We can verify by checking the room state
            # Let's send a signal to verify the connection is still alive
            await sender.send_signal({"test": "alive"})
            response = await receiver.receive_signal()
            assert response.get("test") == "alive"

            await sender.close()
            await receiver.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_both_receive_paired_status(self):
        """Test that both sender and receiver receive status: paired after joining."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            sender = SignalingClient(uri=uri)
            code = await sender.create_room()

            # We need to connect a receiver
            receiver_ws = await websockets.connect(uri)
            await receiver_ws.send(json.dumps({"action": "join", "code": code}))

            # Both should receive "paired"
            sender_response = json.loads(await sender._ws.recv())
            receiver_response = json.loads(await receiver_ws.recv())

            assert sender_response.get("status") == "paired"
            assert receiver_response.get("status") == "paired"

            await sender.close()
            await receiver_ws.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_signal_payload_exchange(self):
        """Test that both peers can exchange signal payloads (e.g., ECDH public key)."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            sender = SignalingClient(uri=uri)
            code = await sender.create_room()

            receiver = SignalingClient(uri=uri)
            await receiver.join_room(code)

            # Wait for sender to receive "paired" status
            await sender.wait_for_paired()

            # Simulate ECDH public key exchange
            ecdh_public_key_pem = (
                "-----BEGIN PUBLIC KEY-----\n"
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
                "7Z+q8V3Lk7JZ9V1xJXFhrPWJYXZ3D0V5hF\n"
                "5qN0F9xL0y5rKZvJ3yJ7xN0F9xJXFhrPWJY\n"
                "-----END PUBLIC KEY-----"
            )

            # Sender sends ECDH public key to receiver
            await sender.send_signal({
                "type": "ecdh_public_key",
                "public_key_pem": ecdh_public_key_pem
            })

            # Receiver should receive the payload
            received = await receiver.receive_signal()
            assert received["type"] == "ecdh_public_key"
            assert received["public_key_pem"] == ecdh_public_key_pem

            # Receiver sends back its ECDH public key
            receiver_ecdh = (
                "-----BEGIN PUBLIC KEY-----\n"
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx\n"
                "2yN7V8kL9mP3qR5tU7wE1sA9fG4hJ6kL8mN\n"
                "0pQ2rS4tU6vW8xY0zA1bC3dE5fG7hJ9kL\n"
                "-----END PUBLIC KEY-----"
            )

            await receiver.send_signal({
                "type": "ecdh_public_key",
                "public_key_pem": receiver_ecdh
            })

            # Sender should receive the payload
            sender_received = await sender.receive_signal()
            assert sender_received["type"] == "ecdh_public_key"
            assert sender_received["public_key_pem"] == receiver_ecdh

            await sender.close()
            await receiver.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_code_join(self):
        """Test that joining with an invalid code returns invalid status."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            ws = await websockets.connect(uri)
            await ws.send(json.dumps({"action": "join", "code": "INVALID"}))

            response = json.loads(await ws.recv())
            assert response.get("status") == "invalid"

            await ws.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_unique_codes(self):
        """Test that each room creation generates a unique code."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            codes = set()

            for _ in range(10):
                client = SignalingClient(uri=uri)
                code = await client.create_room()
                assert code not in codes, f"Duplicate code generated: {code}"
                codes.add(code)
                await client.close()

            assert len(codes) == 10
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_multiple_signals(self):
        """Test that multiple signals can be exchanged between paired clients."""
        port = _get_random_port()
        host = "127.0.0.1"
        uri = f"ws://{host}:{port}/signaling"

        server_instance = SignalingServer()
        server = await websockets.serve(
            server_instance._handle_client, host, port,
            process_request=SignalingServer._process_request
        )

        try:
            sender = SignalingClient(uri=uri)
            code = await sender.create_room()

            receiver = SignalingClient(uri=uri)
            await receiver.join_room(code)

            # Exchange multiple signals
            for i in range(5):
                await sender.send_signal({"index": i, "data": f"message_{i}"})
                received = await receiver.receive_signal()
                assert received["index"] == i
                assert received["data"] == f"message_{i}"

            await sender.close()
            await receiver.close()
        finally:
            server.close()
            await server.wait_closed()
