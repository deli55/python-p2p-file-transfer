"""Async TCP transport with encrypted file streaming using Length-Prefixed Framing."""

import asyncio
import json
import struct
from pathlib import Path
from typing import AsyncGenerator

from p2p_transfer.crypto import decrypt_chunk, encrypt_chunk
from p2p_transfer.transfer import read_file_chunks, write_file_chunks


# ---------------------------------------------------------------------------
# Length-Prefixed Framing Protocol Helpers
# ---------------------------------------------------------------------------
# Each frame consists of:
#   - 4-byte big-endian unsigned integer: length of the payload
#   - payload bytes of the specified length
# ---------------------------------------------------------------------------


def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Write a length-prefixed frame to *writer* and drain the stream.

    Writes a 4-byte uint32 big-endian length prefix followed by *data*,
    then calls ``await writer.drain()`` to flush the buffer.

    Args:
        writer: An open asyncio StreamWriter.
        data: The payload bytes to send.
    """
    length_prefix = len(data).to_bytes(4, "big")
    writer.write(length_prefix + data)


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read a length-prefixed frame from *reader*.

    Reads a 4-byte big-endian length prefix, then reads exactly that many
    payload bytes.

    Args:
        reader: An open asyncio StreamReader.

    Returns:
        The payload bytes of the frame.

    Raises:
        asyncio.IncompleteReadError: If the connection closes before the full
            frame is received.
    """
    length_bytes = await reader.readexactly(4)
    payload_len = struct.unpack("!I", length_bytes)[0]
    payload = await reader.readexactly(payload_len)
    return payload


# ---------------------------------------------------------------------------
# P2P File Transfer Functions
# ---------------------------------------------------------------------------


async def send_file_p2p(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    file_path: Path,
    symmetric_key: bytes,
) -> None:
    """Send a file over an already-connected TCP stream with encryption.

    1. Reads the file metadata and computes its SHA-256 hash via
       :func:`p2p_transfer.transfer.read_file_chunks`.
    2. Sends the metadata as a single framed JSON blob containing
       ``file_name``, ``file_size``, and ``sha256``.
    3. Streams each file chunk: encrypts it with :func:`encrypt_chunk` and
       sends it as a framed payload.
    4. Sends an empty frame ``b""`` as the end-of-file (EOF) marker.

    Args:
        reader: StreamReader attached to the TCP connection (used for the
            underlying async I/O loop, not consumed directly).
        writer: StreamWriter attached to the TCP connection.
        file_path: Path to the file to send.
        symmetric_key: 32-byte symmetric key for ChaCha20-Poly1305 encryption.
    """
    # Step 1: read metadata and compute SHA-256.
    chunk_gen, transfer_result = await read_file_chunks(file_path)

    # Collect all chunks so we can iterate twice (once for hash, once for send).
    all_chunks: list[bytes] = []
    async for chunk in chunk_gen:
        all_chunks.append(chunk)

    file_size = file_path.stat().st_size
    sha256_hex = transfer_result.sha256_hex
    file_name = file_path.name

    # Step 2: send metadata frame as JSON bytes.
    metadata = json.dumps({
        "file_name": file_name,
        "file_size": file_size,
        "sha256": sha256_hex,
    }).encode("utf-8")
    send_frame(writer, metadata)
    await writer.drain()

    # Step 3: stream encrypted file chunks.
    for raw_chunk in all_chunks:
        encrypted = encrypt_chunk(symmetric_key, raw_chunk)
        send_frame(writer, encrypted)
        await writer.drain()

    # Step 4: send EOF marker (empty frame).
    send_frame(writer, b"")
    await writer.drain()

    # Close the writer to signal completion.
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def receive_file_p2p(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    output_dir: Path,
    symmetric_key: bytes,
) -> Path:
    """Receive an encrypted file from a TCP stream and save it to disk.

    1. Reads and parses the initial JSON metadata frame to obtain
       ``file_name``, ``file_size``, and ``sha256``.
    2. Defines an inner async generator ``decrypted_chunk_stream()`` that
       reads incoming frames, decrypts each using :func:`decrypt_chunk`,
       and yields the plaintext until the EOF frame ``b""`` is received.
    3. Streams decrypted chunks to disk via
       :func:`p2p_transfer.transfer.write_file_chunks`, verifying the
       SHA-256 hash.

    Args:
        reader: StreamReader attached to the TCP connection.
        writer: StreamWriter attached to the TCP connection (echo-only).
        output_dir: Directory where the received file will be saved.
        symmetric_key: 32-byte symmetric key for ChaCha20-Poly1305 decryption.

    Returns:
        The absolute :class:`Path` of the saved file.
    """
    # Step 1: read and parse metadata frame.
    metadata_frame = await read_frame(reader)
    metadata = json.loads(metadata_frame.decode("utf-8"))
    raw_file_name = metadata["file_name"]

    # Path traversal protection: use .name to strip any directory components
    # (e.g., "../evil.py", "C:\Windows\evil.dll", "/etc/passwd").
    file_name = Path(raw_file_name).name
    expected_sha256 = metadata["sha256"]

    # Ensure output directory exists.
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / file_name

    # Step 2: inner async generator for decrypted chunks.
    async def decrypted_chunk_stream() -> AsyncGenerator[bytes, None]:
        """Yield decrypted chunks from incoming frames until EOF."""
        while True:
            frame = await read_frame(reader)
            if frame == b"":
                # EOF marker received.
                break
            decrypted = decrypt_chunk(symmetric_key, frame)
            yield decrypted

    # Step 3: write decrypted stream to disk with hash verification.
    # Catch any exception (e.g. IncompleteReadError on premature disconnect)
    # and clean up the partial file.
    try:
        await write_file_chunks(output_path, decrypted_chunk_stream(), expected_sha256)
    except Exception:
        # If the transfer failed for any reason, delete the partial file.
        output_path.unlink(missing_ok=True)
        raise

    return output_path
