"""End-to-end tests for async TCP P2P file transfer with encrypted streaming."""

import asyncio
import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from p2p_transfer.network import receive_file_p2p, send_file_p2p


@pytest.mark.asyncio
async def test_p2p_file_transfer_over_tcp():
    """Spin up a minimal TCP server, transfer a 1 MB file with
    encryption, and assert content integrity plus SHA-256 verification.
    """
    # --- Create a 1 MB temporary source file with random bytes ---
    file_size = 1 * 1024 * 1024  # 1 MB
    source_data = os.urandom(file_size)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as src_tmp:
        src_tmp.write(source_data)
        src_path = Path(src_tmp.name)

    try:
        # Derive a random 32-byte symmetric key.
        symmetric_key = os.urandom(32)

        # Track output_dir and received_path for assertions.
        output_dir = Path(tempfile.mkdtemp())
        file_name = src_path.name
        received_path: Path | None = None

        async def handle_client(reader, writer):
            nonlocal received_path
            received_path = await receive_file_p2p(reader, writer, output_dir, symmetric_key)

        # --- Spin up a server on 127.0.0.1:0 (any available port) ---
        server = await asyncio.start_server(
            handle_client, "127.0.0.1", 0
        )
        host, port = server.sockets[0].getsockname()

        try:
            # --- Connect a client ---
            reader, writer = await asyncio.open_connection(host, port)

            # Run the sender on the client side.
            await send_file_p2p(reader, writer, src_path, symmetric_key)

            # Give the server handler time to complete the transfer.
            await asyncio.sleep(0.5)

        finally:
            server.close()
            await server.wait_closed()

        # --- Assertions ---
        assert received_path is not None, "Server never received the file"
        assert received_path.exists(), "Received file does not exist"

        # Read the received file and compare with the original.
        received_data = received_path.read_bytes()
        assert received_data == source_data, "Received file content does not match source"

        # Verify SHA-256 hash matches.
        received_hash = hashlib.sha256(received_data).hexdigest()
        source_hash = hashlib.sha256(source_data).hexdigest()
        assert received_hash == source_hash, "SHA-256 hash mismatch"
    finally:
        # Clean up source file.
        if src_path.exists():
            src_path.unlink()
