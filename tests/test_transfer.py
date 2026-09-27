"""Tests for async file streaming and SHA-256 hash verification."""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest
import asyncio

from p2p_transfer.transfer import read_file_chunks, write_file_chunks


@pytest.mark.asyncio
async def test_file_chunk_streaming():
    """Create a ~500 KB temporary file with random bytes, stream it via
    read_file_chunks / write_file_chunks and assert content integrity and
    SHA-256 match.
    """
    # --- Create a ~500 KB source file with random bytes ---
    file_size = 500 * 1024  # 500 KB
    random_data = os.urandom(file_size)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as src:
        src.write(random_data)
        src_path = Path(src.name)

    try:
        # Compute the expected SHA-256 of the source file.
        expected_hash = hashlib.sha256(random_data).hexdigest()

        # --- Stream chunks and write to destination ---
        chunk_gen, source_result = await read_file_chunks(src_path)
        dest_path = Path(tempfile.mkdtemp()) / "output.bin"
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        dest_result = await write_file_chunks(dest_path, chunk_gen, expected_hash)

        # 1. Destination file content must match source file content exactly.
        with open(dest_path, "rb") as f:
            written_data = f.read()
        assert written_data == random_data, "Destination content does not match source"

        # 2. SHA-256 checksums must match.
        assert (
            dest_result.sha256_hex == expected_hash
        ), "Destination SHA-256 does not match expected hash"
        assert (
            source_result.sha256_hex == expected_hash
        ), "Source SHA-256 does not match expected hash"

        # Verify sizes match.
        assert dest_result.total_size == file_size
        assert source_result.total_size == file_size

    finally:
        # Clean up the source file.
        if src_path.exists():
            src_path.unlink()


@pytest.mark.asyncio
async def test_corrupted_stream_raises_error():
    """Stream chunks, intentionally tamper with one chunk in memory, pass to
    write_file_chunks, and assert that ValueError is raised.
    """
    # --- Create a ~100 KB source file ---
    file_size = 100 * 1024  # 100 KB
    random_data = os.urandom(file_size)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as src:
        src.write(random_data)
        src_path = Path(src.name)

    try:
        expected_hash = hashlib.sha256(random_data).hexdigest()

        # Read chunks from the source.
        chunk_gen, _ = await read_file_chunks(src_path)

        # Collect all chunks first so we can tamper with one.
        all_chunks = []
        async for chunk in chunk_gen:
            all_chunks.append(chunk)

        # Tamper with the second chunk (or first if only one chunk).
        tamper_index = min(1, len(all_chunks) - 1)
        original_chunk = all_chunks[tamper_index]
        # Flip a byte in the middle of the chunk.
        corrupted = bytearray(original_chunk)
        mid = len(corrupted) // 2
        corrupted[mid] ^= 0xFF  # flip all bits
        all_chunks[tamper_index] = bytes(corrupted)

        # Create an async generator from the corrupted list.
        async def corrupted_stream():
            for chunk in all_chunks:
                yield chunk

        # Write to destination — should raise ValueError due to hash mismatch.
        dest_path = Path(tempfile.mkdtemp()) / "corrupted.bin"
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="SHA-256 checksum mismatch"):
            await write_file_chunks(dest_path, corrupted_stream(), expected_hash)

        # Verify the partial file was removed.
        assert not dest_path.exists(), "Partial file should have been removed"

    finally:
        if src_path.exists():
            src_path.unlink()
