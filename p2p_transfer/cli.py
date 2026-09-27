"""Typer CLI with Rich progress UI and full end-to-end P2P file transfer orchestration."""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, TransferSpeedColumn, TimeElapsedColumn

from p2p_transfer.crypto import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key,
)
from p2p_transfer.network import send_file_p2p, receive_file_p2p
from p2p_transfer.signaling import SignalingClient

app = typer.Typer(help="Secure End-to-End Encrypted P2P File Transfer CLI")
console = Console()


# ---------------------------------------------------------------------------
# ``send`` command
# ---------------------------------------------------------------------------

@app.command()
def send(
    file_path: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, help="Path to the file to send"),
    server_url: str = typer.Option("ws://localhost:8765", help="Signaling server WebSocket URL."),
):
    """Send a file over a secure P2P encrypted connection.

    Creates a room, displays a pairing code for the receiver, waits for the
    receiver to join, exchanges encryption keys, then streams the file over a
    direct TCP connection.
    """
    asyncio.run(_do_send(file_path, server_url))


async def _do_send(file_path: Path, server_url: str) -> None:
    file_path = Path(file_path).resolve()
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(1)

    local_private_key = generate_keypair()
    local_public_key_pem = serialize_public_key(local_private_key)

    # Start TCP listener
    received_connection: asyncio.Future = asyncio.get_event_loop().create_future()

    async def tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not received_connection.done():
            received_connection.set_result((reader, writer))

    tcp_server = await asyncio.start_server(tcp_handler, "0.0.0.0", 0)
    tcp_port = tcp_server.sockets[0].getsockname()[1]

    sc = SignalingClient(server_url)
    try:
        # Create room and get pairing code
        code = await sc.create_room()
        console.print(
            Panel(
                f"[bold green]{code}[/bold green]",
                title="Share Pairing Code",
                subtitle="Give this code to the receiver",
                style="bold blue",
            )
        )

        # Wait for receiver to join
        await sc.wait_for_paired()
        console.print("[bold green]Receiver connected via signaling.[/bold green]")

        # Send our public key + TCP host/port to receiver
        sender_signal = {
            "public_key_pem": local_public_key_pem,
            "host": "127.0.0.1",
            "port": tcp_port,
        }
        await sc.send_signal(sender_signal)

        # Receive receiver's public key
        remote_payload = await sc.receive_signal()
        remote_public_key = deserialize_public_key(remote_payload["public_key_pem"])
        symmetric_key = derive_shared_key(local_private_key, remote_public_key)
        console.print("[bold green]ECDH key exchange complete.[/bold green]")

        # Wait for receiver to connect over TCP
        console.print("[bold yellow]Waiting for TCP connection from receiver...[/bold yellow]")
        reader, writer = await asyncio.wait_for(received_connection, timeout=60)

        # Stream the file with progress
        file_size = file_path.stat().st_size
        console.print(f"[bold green]Sending {file_path.name} ({file_size} bytes)...[/bold green]")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Sending file...", total=file_size)
            await _send_with_progress(progress, task, reader, writer, file_path, symmetric_key)

        console.print("[bold green]File sent successfully![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error during send:[/bold red] {e}")
        raise typer.Exit(1)
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
        await sc.close()


async def _send_with_progress(
    progress: Progress,
    task: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    file_path: Path,
    symmetric_key: bytes,
) -> None:
    """Send file while updating a Rich progress bar."""
    from p2p_transfer.transfer import read_file_chunks
    from p2p_transfer.crypto import encrypt_chunk
    from p2p_transfer.network import send_frame

    chunk_gen, tr = await read_file_chunks(file_path)
    all_chunks: list[bytes] = []
    async for chunk in chunk_gen:
        all_chunks.append(chunk)

    file_size = file_path.stat().st_size
    sha256_hex = tr.sha256_hex
    file_name = file_path.name

    metadata = json.dumps({
        "file_name": file_name,
        "file_size": file_size,
        "sha256": sha256_hex,
    }).encode("utf-8")
    send_frame(writer, metadata)
    await writer.drain()

    for raw_chunk in all_chunks:
        encrypted = encrypt_chunk(symmetric_key, raw_chunk)
        send_frame(writer, encrypted)
        await writer.drain()
        progress.update(task, advance=len(raw_chunk))

    send_frame(writer, b"")
    await writer.drain()

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ``receive`` command
# ---------------------------------------------------------------------------

@app.command()
def receive(
    code: str = typer.Argument(..., help="6-digit pairing code from the sender"),
    output_dir: Path = typer.Option(Path("."), exists=True, file_okay=False, dir_okay=True, help="Directory to save the received file."),
    server_url: str = typer.Option("ws://localhost:8765", help="Signaling server WebSocket URL."),
):
    """Receive a file from a secure P2P encrypted connection."""
    asyncio.run(_do_receive(code, output_dir, server_url))


async def _do_receive(code: str, output_dir: Path, server_url: str) -> None:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    local_private_key = generate_keypair()
    local_public_key_pem = serialize_public_key(local_private_key)

    sc = SignalingClient(server_url)
    try:
        # Join room
        await sc.join_room(code)
        console.print("[bold green]Joined room via signaling.[/bold green]")

        # Send our public key to sender
        await sc.send_signal({"public_key_pem": local_public_key_pem})

        # Receive sender's public key + TCP host/port
        sender_payload = await sc.receive_signal()
        sender_public_key = deserialize_public_key(sender_payload["public_key_pem"])
        tcp_host = sender_payload["host"]
        tcp_port = sender_payload["port"]

        # Derive shared key
        symmetric_key = derive_shared_key(local_private_key, sender_public_key)
        console.print("[bold green]ECDH key exchange complete.[/bold green]")

        # Connect to sender over TCP
        console.print(f"[bold yellow]Connecting to sender at {tcp_host}:{tcp_port}...[/bold yellow]")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(tcp_host, tcp_port), timeout=60
        )

        # Receive file with progress
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            saved_path = await _receive_with_progress(progress, reader, writer, output_dir, symmetric_key)

        console.print(
            Panel(
                f"[bold green]File saved:[/bold green] {saved_path}\n[bold green]SHA-256 verified[/bold green]",
                title="Transfer Complete",
                style="bold green",
            )
        )
    except Exception as e:
        console.print(f"[bold red]Error during receive:[/bold red] {e}")
        raise typer.Exit(1)
    finally:
        await sc.close()


async def _receive_with_progress(
    progress: Progress,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    output_dir: Path,
    symmetric_key: bytes,
) -> Path:
    """Receive file while updating a Rich progress bar."""
    from p2p_transfer.network import read_frame
    from p2p_transfer.transfer import write_file_chunks
    from p2p_transfer.crypto import decrypt_chunk

    # Read metadata frame
    metadata_frame = await read_frame(reader)
    metadata = json.loads(metadata_frame.decode("utf-8"))
    file_name = metadata["file_name"]
    expected_sha256 = metadata["sha256"]
    file_size = metadata["file_size"]

    output_path = output_dir / file_name

    # Create progress task
    task = progress.add_task("Receiving file...", total=file_size)

    async def decrypted_chunk_stream():
        while True:
            frame = await read_frame(reader)
            if frame == b"":
                break
            decrypted = decrypt_chunk(symmetric_key, frame)
            progress.update(task, advance=len(decrypted))
            yield decrypted

    await write_file_chunks(output_path, decrypted_chunk_stream(), expected_sha256)
    return output_path


# ---------------------------------------------------------------------------
# ``server`` command
# ---------------------------------------------------------------------------

@app.command()
def server(
    host: str = typer.Option("0.0.0.0", help="Host to bind the signaling server."),
    port: int = typer.Option(8765, help="Port to bind the signaling server."),
):
    """Run the signaling server directly from the CLI."""
    asyncio.run(_run_server(host, port))


async def _run_server(host: str, port: int) -> None:
    """Start the signaling server using websockets.serve."""
    import websockets
    from signaling_server import SignalingServer

    srv = SignalingServer()
    server = await websockets.serve(
        srv._handle_client,
        host,
        port,
        process_request=SignalingServer._process_request,
    )
    console.print(
        Panel(
            f"[bold green]Signaling server running on ws://{host}:{port}/signaling[/bold green]",
            title="Signaling Server",
            style="bold blue",
        )
    )
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
