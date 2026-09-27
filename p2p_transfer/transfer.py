"""Async file streaming and SHA-256 hash verification engine for P2P transfers."""

import asyncio
import hashlib
from pathlib import Path
from typing import AsyncGenerator, Tuple


class TransferResult:
    """Holds the final SHA-256 hex digest and total file size after streaming."""

    def __init__(self):
        self._digest = hashlib.sha256()
        self._total_size = 0

    @property
    def sha256_hex(self) -> str:
        """Return the computed SHA-256 hex digest."""
        return self._digest.hexdigest()

    @property
    def total_size(self) -> int:
        """Return the total number of bytes processed."""
        return self._total_size

    def update(self, data: bytes) -> None:
        """Feed bytes into the running digest."""
        self._digest.update(data)
        self._total_size += len(data)


async def read_file_chunks(
    file_path: Path, chunk_size: int = 64 * 1024
) -> Tuple[AsyncGenerator[bytes, None], TransferResult]:
    """Async generator that reads a file in chunks using non-blocking I/O.

    Opens *file_path* for binary reading, yields raw chunks of up to
    ``chunk_size`` bytes (default 64 KiB) via ``asyncio.to_thread`` so that
    disk I/O does not block the event loop, and updates a running
    ``hashlib.sha256()`` digest tracked in a :class:`TransferResult` object.

    Returns:
        A tuple of ``(async_generator, TransferResult)``.  The caller should
        consume all chunks from the generator first; once exhausted the
        ``TransferResult`` will contain the final SHA-256 hex digest and
        total file size.
    """
    result = TransferResult()

    def _read_sync(file_obj, offset, size):
        file_obj.seek(offset)
        return file_obj.read(size)

    async def _chunk_generator():
        with open(file_path, "rb") as f:
            while True:
                chunk = await asyncio.to_thread(_read_sync, f, f.tell(), chunk_size)
                if not chunk:
                    break
                result.update(chunk)
                yield chunk

    return _chunk_generator(), result


async def write_file_chunks(
    file_path: Path,
    chunk_stream: AsyncGenerator[bytes, None],
    expected_sha256: str,
) -> TransferResult:
    """Write an async stream of decrypted chunks to disk and verify the hash.

    Receives a *chunk_stream* (an async generator / stream of encrypted
    chunks), opens *file_path* for binary writing, writes each chunk to disk
    using ``asyncio.to_thread``, and updates a running ``hashlib.sha256()``
    digest.

    After the stream completes the calculated hex digest is compared against
    ``expected_sha256``.  If they do not match the partial file is removed and
    a :exc:`ValueError` is raised with the message *SHA-256 checksum mismatch*.

    Returns:
        :class:`TransferResult` with the computed hash and total size.
    """
    result = TransferResult()

    def _write_sync(file_obj, data):
        file_obj.write(data)

    with open(file_path, "wb") as f:
        async for chunk in chunk_stream:
            result.update(chunk)
            await asyncio.to_thread(_write_sync, f, chunk)

    if result.sha256_hex != expected_sha256:
        file_path.unlink(missing_ok=True)
        raise ValueError("SHA-256 checksum mismatch")

    return result
