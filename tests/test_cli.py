"""Tests for p2p_transfer.cli module."""

import asyncio
import hashlib
import json
import struct
from pathlib import Path
from typing import AsyncGenerator

import pytest
import typer
import websockets
from typer.testing import CliRunner

from p2p_transfer.cli import app, console
from p2p_transfer.crypto import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key,
    encrypt_chunk,
    decrypt_chunk,
)
from p2p_transfer.signaling import SignalingClient
from p2p_transfer.network import send_frame, read_frame
from p2p_transfer.transfer import read_file_chunks, write_file_chunks, TransferResult


runner = CliRunner()


# ---------------------------------------------------------------------------
# Help output tests
# ---------------------------------------------------------------------------

class TestHelpOutput:
    """Test --help flags for all CLI commands."""

    def test_app_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Secure End-to-End Encrypted P2P File Transfer CLI" in result.stdout

    def test_send_help(self):
        result = runner.invoke(app, ["send", "--help"])
        assert result.exit_code == 0
        assert "Path to the file to send" in result.stdout

    def test_receive_help(self):
        result = runner.invoke(app, ["receive", "--help"])
        assert result.exit_code == 0
        assert "6-digit pairing code from the sender" in result.stdout

    def test_server_help(self):
        result = runner.invoke(app, ["server", "--help"])
        assert result.exit_code == 0
        assert "Host to bind the signaling server" in result.stdout


# ---------------------------------------------------------------------------
# Send command validation tests
# ---------------------------------------------------------------------------

class TestSendValidation:
    """Test send command file validation."""

    def test_send_nonexistent_file(self, tmp_path):
        result = runner.invoke(app, ["send", str(tmp_path / "nonexistent.txt")])
        assert result.exit_code != 0

    def test_send_directory_instead_of_file(self, tmp_path):
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        result = runner.invoke(app, ["send", str(subdir)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Integration tests: end-to-end send/receive via in-mem signaling server
# ---------------------------------------------------------------------------

@pytest.fixture
def test_file(tmp_path) -> Path:
    """Create a small test file with known content."""
    test_file_path = tmp_path / "test_data.bin"
    content = b"Hello, P2P encrypted transfer! " * 100
    test_file_path.write_bytes(content)
    return test_file_path


class TestEndToEndTransfer:
    """End-to-end integration tests running send and receive against an in-memory signaling server."""

    def test_full_send_receive(self, test_file: Path, tmp_path: Path):
        """Test a complete file send and receive cycle."""
        from signaling_server import SignalingServer

        async def run_test():
            # Start signaling server
            server = SignalingServer()
            ws_server = await websockets.serve(
                server._handle_client,
                "127.0.0.1",
                0,
                process_request=SignalingServer._process_request,
            )
            server_port = ws_server.sockets[0].getsockname()[1]
            server_url = f"ws://127.0.0.1:{server_port}/signaling"

            output_dir = tmp_path / "received"
            output_dir.mkdir()

            # --- Phase 1: Create room and pair ---
            sender_sc = SignalingClient(server_url)
            code = await sender_sc.create_room()

            # Receiver joins with the pairing code
            receiver_sc = SignalingClient(server_url)
            await receiver_sc.join_room(code)

            # --- Phase 2: Key exchange via signaling ---
            sender_private_key = generate_keypair()
            sender_public_key_pem = serialize_public_key(sender_private_key)

            receiver_private_key = generate_keypair()
            receiver_public_key_pem = serialize_public_key(receiver_private_key)

            # Receiver sends its public key first (so sender is ready to receive)
            await receiver_sc.send_signal({"public_key_pem": receiver_public_key_pem})

            # Sender receives receiver's public key
            sender_recv = await sender_sc.receive_signal()
            sender_remote_public_key = deserialize_public_key(sender_recv["public_key_pem"])
            sender_symmetric_key = derive_shared_key(sender_private_key, sender_remote_public_key)

            # Sender sends its public key (+ TCP info, set later)
            await sender_sc.send_signal({"public_key_pem": sender_public_key_pem})

            # Receiver receives sender's public key
            receiver_recv = await receiver_sc.receive_signal()
            receiver_remote_public_key = deserialize_public_key(receiver_recv["public_key_pem"])
            receiver_symmetric_key = derive_shared_key(receiver_private_key, receiver_remote_public_key)

            # --- Phase 3: TCP connection ---
            # Sender starts TCP listener
            sender_tcp_ready: asyncio.Future = asyncio.get_event_loop().create_future()

            async def sender_tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                if not sender_tcp_ready.done():
                    sender_tcp_ready.set_result((reader, writer))

            sender_tcp_server = await asyncio.start_server(sender_tcp_handler, "0.0.0.0", 0)
            sender_tcp_port = sender_tcp_server.sockets[0].getsockname()[1]

            # Update sender's signal with TCP info and resend (or send as extra)
            # For simplicity, send TCP info as a second signal
            await sender_sc.send_signal({"host": "127.0.0.1", "port": sender_tcp_port})

            # Receiver gets TCP info
            tcp_info = await receiver_sc.receive_signal()
            tcp_host = tcp_info["host"]
            tcp_port = tcp_info["port"]

            # Receiver connects to sender over TCP
            receiver_reader, receiver_writer = await asyncio.wait_for(
                asyncio.open_connection(tcp_host, tcp_port), timeout=30
            )

            # Sender accepts TCP connection
            sender_reader, sender_writer = await asyncio.wait_for(
                sender_tcp_ready, timeout=30
            )

            # --- Phase 4: File transfer ---
            # Sender reads file and sends metadata + encrypted chunks
            chunk_gen, transfer_result = await read_file_chunks(test_file)
            all_chunks: list[bytes] = []
            async for chunk in chunk_gen:
                all_chunks.append(chunk)

            file_size = test_file.stat().st_size
            sha256_hex = transfer_result.sha256_hex
            file_name = test_file.name

            # Send metadata
            metadata = json.dumps({
                "file_name": file_name,
                "file_size": file_size,
                "sha256": sha256_hex,
            }).encode("utf-8")
            send_frame(sender_writer, metadata)
            await sender_writer.drain()

            # Send encrypted chunks
            for raw_chunk in all_chunks:
                encrypted = encrypt_chunk(sender_symmetric_key, raw_chunk)
                send_frame(sender_writer, encrypted)
                await sender_writer.drain()

            # Send EOF
            send_frame(sender_writer, b"")
            await sender_writer.drain()

            # Close sender side
            sender_writer.close()
            try:
                await sender_writer.wait_closed()
            except Exception:
                pass

            # --- Phase 5: Receiver reads file ---
            # Read metadata
            meta_frame = await read_frame(receiver_reader)
            meta = json.loads(meta_frame.decode("utf-8"))
            expected_sha256 = meta["sha256"]

            output_path = output_dir / meta["file_name"]

            async def decrypted_stream() -> AsyncGenerator[bytes, None]:
                while True:
                    frame = await read_frame(receiver_reader)
                    if frame == b"":
                        break
                    yield decrypt_chunk(receiver_symmetric_key, frame)

            await write_file_chunks(output_path, decrypted_stream(), expected_sha256)

            # --- Phase 6: Verify ---
            received_files = list(output_dir.iterdir())
            assert len(received_files) == 1
            received_file = received_files[0]
            assert received_file.read_bytes() == test_file.read_bytes()

            # Cleanup
            sender_tcp_server.close()
            await sender_tcp_server.wait_closed()
            await sender_sc.close()
            await receiver_sc.close()
            ws_server.close()
            await ws_server.wait_closed()

        asyncio.run(run_test())

    def test_send_receive_small_file(self, tmp_path: Path):
        """Test with a very small file (single chunk)."""
        from signaling_server import SignalingServer

        async def run_test():
            server = SignalingServer()
            ws_server = await websockets.serve(
                server._handle_client,
                "127.0.0.1",
                0,
                process_request=SignalingServer._process_request,
            )
            server_port = ws_server.sockets[0].getsockname()[1]
            server_url = f"ws://127.0.0.1:{server_port}/signaling"

            test_file = tmp_path / "tiny.bin"
            test_file.write_bytes(b"tiny file content")

            output_dir = tmp_path / "received_tiny"
            output_dir.mkdir()

            # Create room and pair
            sender_sc = SignalingClient(server_url)
            code = await sender_sc.create_room()
            receiver_sc = SignalingClient(server_url)
            await receiver_sc.join_room(code)

            # Key exchange
            sender_priv = generate_keypair()
            sender_pub = serialize_public_key(sender_priv)
            receiver_priv = generate_keypair()
            receiver_pub = serialize_public_key(receiver_priv)

            await receiver_sc.send_signal({"public_key_pem": receiver_pub})
            sender_recv = await sender_sc.receive_signal()
            sender_key = derive_shared_key(sender_priv, deserialize_public_key(sender_recv["public_key_pem"]))

            await sender_sc.send_signal({"public_key_pem": sender_pub})
            receiver_recv = await receiver_sc.receive_signal()
            receiver_key = derive_shared_key(receiver_priv, deserialize_public_key(receiver_recv["public_key_pem"]))

            # TCP
            tcp_ready = asyncio.get_event_loop().create_future()
            async def tcp_handler(reader, writer):
                if not tcp_ready.done():
                    tcp_ready.set_result((reader, writer))
            tcp_server = await asyncio.start_server(tcp_handler, "0.0.0.0", 0)
            port = tcp_server.sockets[0].getsockname()[1]

            await sender_sc.send_signal({"host": "127.0.0.1", "port": port})
            tcp_info = await receiver_sc.receive_signal()

            r_reader, r_writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", tcp_info["port"]), timeout=30)
            s_reader, s_writer = await asyncio.wait_for(tcp_ready, timeout=30)

            # Send file
            chunk_gen, tr = await read_file_chunks(test_file)
            chunks = []
            async for c in chunk_gen:
                chunks.append(c)

            meta = json.dumps({"file_name": "tiny.bin", "file_size": len(b"tiny file content"), "sha256": tr.sha256_hex}).encode()
            send_frame(s_writer, meta)
            await s_writer.drain()
            for c in chunks:
                send_frame(s_writer, encrypt_chunk(sender_key, c))
                await s_writer.drain()
            send_frame(s_writer, b"")
            await s_writer.drain()
            s_writer.close()
            await s_writer.wait_closed()

            # Receive file
            mf = await read_frame(r_reader)
            m = json.loads(mf.decode())
            op = output_dir / m["file_name"]

            async def ds():
                while True:
                    f = await read_frame(r_reader)
                    if f == b"":
                        break
                    yield decrypt_chunk(receiver_key, f)
            await write_file_chunks(op, ds(), m["sha256"])

            assert op.read_bytes() == test_file.read_bytes()

            tcp_server.close()
            await tcp_server.wait_closed()
            await sender_sc.close()
            await receiver_sc.close()
            ws_server.close()
            await ws_server.wait_closed()

        asyncio.run(run_test())


class TestCliHelpResponses:
    """Test that each command returns proper help output."""

    def test_send_help_contains_file_path(self):
        result = runner.invoke(app, ["send", "--help"])
        assert result.exit_code == 0
        assert "FILE_PATH" in result.stdout or "file_path" in result.stdout.lower()

    def test_receive_help_contains_code(self):
        result = runner.invoke(app, ["receive", "--help"])
        assert result.exit_code == 0
        assert "CODE" in result.stdout or "code" in result.stdout.lower()

    def test_server_help_contains_host_port(self):
        result = runner.invoke(app, ["server", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.stdout or "host" in result.stdout.lower()
        assert "--port" in result.stdout or "port" in result.stdout.lower()


class TestServerCommand:
    """Test the server CLI command help."""

    def test_server_command_exists(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "server" in result.stdout.lower() or "Server" in result.stdout
