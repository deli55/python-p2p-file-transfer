"""Edge-case tests for P2P file transfer: path traversal, zero-byte files,
Unicode filenames, and mid-stream disconnection cleanup.
"""

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from p2p_transfer.network import receive_file_p2p, send_file_p2p, send_frame
from p2p_transfer.crypto import encrypt_chunk


# ---------------------------------------------------------------------------
# Test 1: Path Traversal Prevention
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_path_traversal_prevention():
    """A metadata payload containing a path traversal attack like
    ``../../evil_script.py`` or ``C:\\Windows\\System32\\evil.dll`` must be
    sanitised by ``receive_file_p2p()`` so that the output file lives
    strictly inside ``output_dir``.
    """
    output_dir = Path(tempfile.mkdtemp())
    symmetric_key = os.urandom(32)
    payload = b"evil content"

    # Choose a path-traversal filename
    traversal_name = "../../evil_script.py"

    received_path = None

    async def handler(reader, writer):
        nonlocal received_path
        received_path = await receive_file_p2p(
            reader, writer, output_dir, symmetric_key
        )

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()

    try:
        reader, writer = await asyncio.open_connection(host, port)

        send_frame(writer, json.dumps({
            "file_name": traversal_name,
            "file_size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }).encode("utf-8"))
        await writer.drain()

        encrypted = encrypt_chunk(symmetric_key, payload)
        send_frame(writer, encrypted)
        await writer.drain()

        send_frame(writer, b"")
        await writer.drain()

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        await asyncio.sleep(0.3)
    finally:
        server.close()
        await server.wait_closed()

    assert received_path is not None, "Server never received the file"
    assert received_path.exists(), "Received file does not exist"

    # The file must be named exactly ``evil_script.py`` (no directory components)
    assert received_path.name == "evil_script.py"

    # The file must be inside output_dir
    assert received_path.resolve().is_relative_to(output_dir.resolve())

    # Content must match
    assert received_path.read_bytes() == payload


# ---------------------------------------------------------------------------
# Test 2: Zero-Byte File Transfer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zero_byte_file_transfer():
    """An empty (0-byte) file must be transferred cleanly: framing,
    zero-byte SHA-256 hash calculation, and EOF handling must all succeed
    without errors.
    """
    source_data = b""
    empty_hash = hashlib.sha256(b"").hexdigest()

    output_dir = Path(tempfile.mkdtemp())
    symmetric_key = os.urandom(32)
    file_name = "empty.bin"

    received_path = None

    async def handler(reader, writer):
        nonlocal received_path
        received_path = await receive_file_p2p(
            reader, writer, output_dir, symmetric_key
        )

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()

    try:
        reader, writer = await asyncio.open_connection(host, port)

        send_frame(writer, json.dumps({
            "file_name": file_name,
            "file_size": 0,
            "sha256": empty_hash,
        }).encode("utf-8"))
        await writer.drain()

        # Immediately send EOF (no data chunks)
        send_frame(writer, b"")
        await writer.drain()

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        await asyncio.sleep(0.3)
    finally:
        server.close()
        await server.wait_closed()

    assert received_path is not None
    assert received_path.exists()
    assert received_path.stat().st_size == 0
    assert received_path.read_bytes() == b""


# ---------------------------------------------------------------------------
# Test 3: Unicode Filename Transfer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unicode_filename_transfer():
    """A file with UTF-8 / Emoji characters in the filename must be
    transferred and preserved exactly.
    """
    unicode_name = "测试_data_🎉.txt"
    content = "Hello, Unicode 世界! 🌍🎊".encode("utf-8")

    output_dir = Path(tempfile.mkdtemp())
    symmetric_key = os.urandom(32)

    received_path = None

    async def handler(reader, writer):
        nonlocal received_path
        received_path = await receive_file_p2p(
            reader, writer, output_dir, symmetric_key
        )

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()

    try:
        reader, writer = await asyncio.open_connection(host, port)

        send_frame(writer, json.dumps({
            "file_name": unicode_name,
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }).encode("utf-8"))
        await writer.drain()

        encrypted = encrypt_chunk(symmetric_key, content)
        send_frame(writer, encrypted)
        await writer.drain()

        send_frame(writer, b"")
        await writer.drain()

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        await asyncio.sleep(0.3)
    finally:
        server.close()
        await server.wait_closed()

    assert received_path is not None
    assert received_path.exists()
    # Filename must match exactly
    assert received_path.name == unicode_name
    # Content must match
    assert received_path.read_bytes() == content


# ---------------------------------------------------------------------------
# Test 4: Mid-Stream Disconnection Cleanup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mid_stream_disconnection_cleanup():
    """Transmit a multi-chunk file but close the writer mid-transfer
    (after only 1-2 chunks).  ``receive_file_p2p()`` must:
      1. Catch the premature connection drop.
      2. Delete the partial file from disk.
      3. Raise an exception (e.g. ``IncompleteReadError`` or ``ValueError``).
    """
    # Create a multi-chunk source file (3 chunks = 3 × 64 KiB default)
    chunk_size = 64 * 1024
    num_chunks = 3
    full_data = os.urandom(chunk_size * num_chunks)
    expected_sha256 = hashlib.sha256(full_data).hexdigest()

    output_dir = Path(tempfile.mkdtemp())
    symmetric_key = os.urandom(32)
    file_name = "multi_chunk.bin"

    received_path = None
    received_exception = None
    server_writer_ref = [None]

    async def handler(reader, writer):
        nonlocal received_path, received_exception, server_writer_ref
        server_writer_ref[0] = writer
        try:
            received_path = await receive_file_p2p(
                reader, writer, output_dir, symmetric_key
            )
        except Exception as exc:
            received_exception = exc

    # Start the handler as a background task so we can control timing
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()

    try:
        reader, writer = await asyncio.open_connection(host, port)

        # Send metadata
        send_frame(writer, json.dumps({
            "file_name": file_name,
            "file_size": len(full_data),
            "sha256": expected_sha256,
        }).encode("utf-8"))
        await writer.drain()

        # Send only 1 chunk
        encrypted = encrypt_chunk(symmetric_key, full_data[:chunk_size])
        send_frame(writer, encrypted)
        await writer.drain()

        # Close client writer mid-transfer (simulate disconnection)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # Close the server-side writer transport to force the connection
        # closed state to propagate back to the reader.
        await asyncio.sleep(0.05)
        if server_writer_ref[0] is not None:
            server_writer_ref[0].close()
            try:
                await server_writer_ref[0].wait_closed()
            except Exception:
                pass

        # Wait for the handler to complete
        await asyncio.sleep(0.5)
    finally:
        server.close()
        await server.wait_closed()

    # The receiver should have raised an exception
    # (either IncompleteReadError, ValueError, or asyncio.TimeoutError)
    assert received_exception is not None, (
        f"Expected an exception on incomplete read, but got received_path={received_path}"
    )

    # The partial file should have been cleaned up (deleted)
    partial_path = output_dir / file_name
    assert not partial_path.exists(), (
        f"Partial file {partial_path} should have been deleted on incomplete transfer"
    )
