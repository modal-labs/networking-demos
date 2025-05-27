"""
Benchmark `aioquic` after UDP hole punching.

Between two containers: `modal run aioquic_modal.py`
Between local client and container: `modal run aioquic_modal.py --local`

Larger workload: `modal run aioquic_modal.py --request-kib=600 --response-kib=5`

Even between two datacenters in the northern California region, the minimum latency is around 50ms. This is most likely
due to a limitation in `aioquic`.
"""

import asyncio
import os
import socket as socketlib
import time

import modal

app = modal.App("quic-nat-traversal")

# Install required packages
image = modal.Image.debian_slim().pip_install("aioquic", "pynat", "cryptography", "six")

# Global constants
SERVER_LOCAL_PORT = 5555
CLIENT_LOCAL_PORT = 5556
N_ITERATIONS = 25
PUNCH_TIMEOUT = 15  # seconds

# Socket buffer size (1MiB)
SOCKET_BUFFER_SIZE = 1 * 1024 * 1024

SERVER_REGION = "us-west-1"
CLIENT_REGION = "us-sanjose-1"


def create_cert(key):
    """Create a self-signed certificate for the given key."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic-benchmark")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic-benchmark")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


async def get_ext_addr(sock):
    """Get external IP and port using STUN."""
    from pynat import get_stun_response

    response = get_stun_response(sock, ("stun.ekiga.net", 3478))
    return response["ext_ip"], response["ext_port"]


def create_socket(local_port: int):
    # Initialize socket with large buffers
    sock = socketlib.socket(socketlib.AF_INET, socketlib.SOCK_DGRAM)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_RCVBUF, SOCKET_BUFFER_SIZE)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_SNDBUF, SOCKET_BUFFER_SIZE)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", local_port))
    sock.setblocking(False)
    return sock


@app.function(image=image, region=SERVER_REGION)
async def run_server(rendezvous: modal.Dict, punch_strings: list[bytes], response_kib: int):
    """
    Server function that:
    1. Gets its external IP/port via STUN
    2. Registers with the rendezvous server
    3. Gets client endpoint from rendezvous
    4. Punches NAT and starts QUIC server
    """
    import ssl

    from aioquic.asyncio import serve
    from aioquic.quic.configuration import QuicConfiguration
    from cryptography.hazmat.primitives.asymmetric import ec

    sock = create_socket(SERVER_LOCAL_PORT)

    # Continuously register public IP/port with rendezvous, wait for client to do the same.
    client_endpoint = None
    while not client_endpoint:
        pub_ip, pub_port = await get_ext_addr(sock)
        print(f"[SERVER] Public endpoint: {pub_ip}:{pub_port}")
        await rendezvous.put.aio(key="server", value=(pub_ip, pub_port))
        client_endpoint = await rendezvous.get.aio(key="client")
        if client_endpoint:
            print(f"[SERVER] Got client endpoint: {client_endpoint}")
            break
        print("[SERVER] Waiting for client to register...")
        await asyncio.sleep(0.1)

    # Server starts punching immediately. This creates a NAT mapping so the client can reach us.
    client_ip, client_port = client_endpoint
    print(f"[SERVER] Starting to punch NAT to {client_ip}:{client_port}")

    # Send punch packets to client, while also waiting for a punch packet from the client.
    punch_success = False
    for i in range(50):
        print(f"[SERVER] sending packet to {client_ip}:{client_port}")
        sock.sendto(punch_strings[0], (client_ip, client_port))

        # Listen for incoming bytes.
        LISTEN_MS = 200
        try:
            data, addr = await asyncio.wait_for(
                asyncio.get_event_loop().sock_recvfrom(sock, 32), timeout=LISTEN_MS / 1000
            )
            print(f"[SERVER] Received data from {addr}")

            if addr[0] != client_ip or addr[1] != client_port:
                print(f"[SERVER] Client is using different port! STUN: {client_port}, Actual: {addr[1]}")
                client_ip, client_port = addr

            if data == punch_strings[0]:
                print(f"[SERVER] Acknowledging punch from client at {addr}.")
                sock.sendto(punch_strings[1], addr)
                punch_success = True
                break
            else:
                print(f"[SERVER] Received unexpected data from client: {data} {punch_strings=}")
                continue
        except (asyncio.TimeoutError, BlockingIOError):
            print("[SERVER] No incoming bytes received after 200ms.")
            continue

    if not punch_success:
        print("[SERVER] Failed to punch NAT with client")
        return

    # Close UDP socket before QUIC can use the port
    sock.close()
    print("[SERVER] UDP socket closed, preparing QUIC server")

    # Configure optimized QUIC server
    cfg = QuicConfiguration(
        is_client=False,
        alpn_protocols=["hq-29"],
        verify_mode=ssl.CERT_NONE,
        congestion_control_algorithm="cubic",
        max_data=10_000_000,  # Large flow control window
        max_stream_data=5_000_000,  # Large stream window
        max_datagram_size=1400,  # Optimize for MTU
    )
    cfg.private_key = ec.generate_private_key(ec.SECP256R1())
    cfg.certificate = create_cert(cfg.private_key)

    async def handle_benchmark(reader, writer):
        print("[SERVER] Client connected via QUIC!")
        iteration = 0

        # Create 5KB response data once
        pong_data = b"P" * response_kib * 1024

        while True:
            # First read 4 bytes for message length
            length_bytes = await reader.read(4)
            if not length_bytes or len(length_bytes) < 4:
                break

            # Decode message length
            msg_length = int.from_bytes(length_bytes, byteorder="big")
            print(f"[SERVER] Expected message length: {msg_length} bytes")

            # Read the complete message with optimized buffer size
            data = b""
            remaining = msg_length
            while remaining > 0:
                chunk = await reader.read(min(remaining, 1024 * 64))  # 64KB chunks
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)

            if len(data) != msg_length:
                print(f"[SERVER] Warning: Incomplete message: {len(data)}/{msg_length} bytes")
                continue

            print(f"[SERVER] Received complete message: {len(data)} bytes")
            iteration += 1

            # Send length-prefixed response
            response_len = len(pong_data).to_bytes(4, byteorder="big")
            writer.write(response_len + pong_data)
            await writer.drain()
            print(f"[SERVER] Sent response {iteration}: {response_kib * 1024} bytes")

        writer.close()
        print("[SERVER] QUIC connection closed")

    def stream_handler(reader, writer):
        asyncio.create_task(handle_benchmark(reader, writer))

    # Start QUIC server
    print("[SERVER] Starting QUIC server...")
    await serve(
        host="0.0.0.0",
        port=SERVER_LOCAL_PORT,
        configuration=cfg,
        stream_handler=stream_handler,
    )
    print("[SERVER] QUIC server started")

    # Keep server running
    while True:
        await asyncio.sleep(600)


@app.function(image=image, region=CLIENT_REGION)
async def run_client(request_kib: int, response_kib: int):
    """
    Client function that:
    1. Gets its external IP/port via STUN
    2. Registers its public IP/port in rendezvous (distributed dictionary).
    3. Gets server endpoint from rendezvous (distributed dictionary).
    4. Punches NAT and establishes QUIC connection.
    5. Runs benchmark with 1KiB requests, 1KiB responses.
    """
    import ssl

    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.logger import QuicLogger

    sock = create_socket(CLIENT_LOCAL_PORT)

    # Create random string for punch and ack packets.
    punch_strings = [os.urandom(16) for _ in range(3)]

    with modal.Dict.ephemeral() as rendezvous:
        # Create a server.
        run_server.spawn(rendezvous, punch_strings, response_kib)

        # Continuously register public IP/port with rendezvous, wait for server to do the same.
        server_endpoint = None
        while not server_endpoint:
            pub_ip, pub_port = await get_ext_addr(sock)
            print(f"[CLIENT] Public endpoint: {pub_ip}:{pub_port}")
            await rendezvous.put.aio(key="client", value=(pub_ip, pub_port))
            server_endpoint = await rendezvous.get.aio(key="server")
            if server_endpoint:
                print(f"[CLIENT] Got server endpoint: {server_endpoint}")
                break
            print("[CLIENT] Waiting for server to register...")
            await asyncio.sleep(0.1)

    server_ip, server_port = server_endpoint

    print(f"[CLIENT] Starting to punch to server at {server_ip}:{server_port}")

    # Send punch packets to server, while also waiting for a punch packet from the server.
    punch_success = False
    for i in range(50):
        print(f"[CLIENT] sending packet to {server_ip}:{server_port}")
        sock.sendto(punch_strings[0], (server_ip, server_port))

        # Listen for incoming bytes.
        LISTEN_MS = 200
        try:
            data, addr = await asyncio.wait_for(
                asyncio.get_event_loop().sock_recvfrom(sock, 32), timeout=LISTEN_MS / 1000
            )
            print(f"[CLIENT] Received data from {addr}")

            if addr[0] != server_ip or addr[1] != server_port:
                print(f"[CLIENT] Server is using different port! STUN: {server_port}, Actual: {addr[1]}")
                server_ip, server_port = addr

            if data == punch_strings[0]:
                print(f"[CLIENT] Received punch from server at {addr}")
                continue
            elif data == punch_strings[1]:
                print(f"[CLIENT] Received punch ack from server at {addr}")
                punch_success = True
                break
            else:
                print(f"[CLIENT] Received unexpected data from server: {data} {punch_strings=}")

        except (asyncio.TimeoutError, BlockingIOError):
            print(f"[CLIENT] No response received after {LISTEN_MS}ms.")
            continue

    if not punch_success:
        print("[CLIENT] Failed to punch NAT with server")
        return

    # Close UDP socket before QUIC can use the port
    sock.close()
    print("[CLIENT] UDP socket closed, preparing QUIC client")

    # Configure optimized QUIC client
    qlogger = QuicLogger()
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hq-29"],
        verify_mode=ssl.CERT_NONE,
        congestion_control_algorithm="cubic",
        max_data=10_000_000,  # Large flow control window
        max_stream_data=5_000_000,  # Large stream window
        max_datagram_size=1400,  # Optimize for MTU
        quic_logger=qlogger,
    )

    # Create fixed-size ping data
    ping_data = b"P" * request_kib * 1024

    # Store latency measurements
    latencies = []

    # Try to connect with multiple attempts
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            async with connect(
                server_ip,
                server_port,
                configuration=cfg,
                local_port=CLIENT_LOCAL_PORT,
                wait_connected=True,
            ) as quic:
                reader, writer = await quic.create_stream()
                print(f"[CLIENT] QUIC connection established on attempt {attempt + 1}")

                # Run benchmark iterations
                print(f"[CLIENT] Starting benchmark with {N_ITERATIONS} iterations")
                print(f"[CLIENT] Request size: {request_kib / 1024:.1f}KB, Response size: {response_kib / 1024:.1f}KB")

                for i in range(N_ITERATIONS):
                    # Send length-prefixed request
                    start_time = time.monotonic()
                    length_prefix = len(ping_data).to_bytes(4, byteorder="big")
                    writer.write(length_prefix + ping_data)
                    await writer.drain()

                    # Read response length
                    length_bytes = await reader.read(4)
                    if len(length_bytes) < 4:
                        print("[CLIENT] Failed to read response length")
                        break

                    resp_length = int.from_bytes(length_bytes, byteorder="big")

                    # Read complete response with optimized buffer size
                    response = b""
                    remaining = resp_length
                    while remaining > 0:
                        chunk = await reader.read(min(remaining, 1024 * 64))  # 64KB chunks
                        if not chunk:
                            break
                        response += chunk
                        remaining -= len(chunk)

                    if len(response) != resp_length:
                        print(f"[CLIENT] Warning: Incomplete response: {len(response)}/{resp_length} bytes")
                        continue

                    end_time = time.monotonic()
                    latency = end_time - start_time
                    latencies.append(latency * 1000)  # Convert to ms

                    print(f"[CLIENT] Iteration {i + 1}/{N_ITERATIONS}: {latency * 1000:.2f}ms")

                    # Small pause between iterations
                    await asyncio.sleep(0.1)

                writer.close()
                break  # Exit the retry loop if successful

        except Exception as e:
            print(f"[CLIENT] Connection attempt {attempt + 1} failed: {e}")
            if attempt < max_attempts - 1:
                print("[CLIENT] Retrying in 2 seconds...")
                await asyncio.sleep(2)
            else:
                print("[CLIENT] All connection attempts failed")
                raise

    # Calculate and print statistics
    if latencies:
        client_region = os.environ.get("MODAL_REGION", "local")

        latencies.sort()
        num_latencies = len(latencies)

        avg_latency = sum(latencies) / num_latencies
        p50_latency = latencies[num_latencies // 2]
        p90_latency = latencies[int(num_latencies * 0.9)]
        p99_latency = latencies[int(num_latencies * 0.99)]
        min_latency = latencies[0]
        max_latency = latencies[-1]

        print(f"\n===== QUIC BENCHMARK RESULTS FROM {client_region} to {SERVER_REGION} =====")
        print(f"Completed {num_latencies} iterations")
        print(f"Request size: {request_kib / 1024:.1f}KB, Response size: {response_kib / 1024:.1f}KB")
        print(f"Average latency: {avg_latency:.2f}ms")
        print(f"Median latency (p50): {p50_latency:.2f}ms")
        print(f"90th percentile (p90): {p90_latency:.2f}ms")
        print(f"99th percentile (p99): {p99_latency:.2f}ms")
        print(f"Min latency: {min_latency:.2f}ms")
        print(f"Max latency: {max_latency:.2f}ms")
        print("==================================\n")


@app.local_entrypoint()
async def main(local: bool = False, request_kib: int = 1, response_kib: int = 1):
    if local:
        await run_client.local(request_kib, response_kib)
    else:
        await run_client.remote.aio(request_kib, response_kib)
