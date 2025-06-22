"""
UDP Hole Punching Demo (Clean Version)

Implements the algorithm described in the provided text:
- Clients A and B register with a server S, reporting their private and public endpoints.
- Server S records both endpoints for each client.
- When A wants to connect to B, S shares each client's endpoints with the other.
- Both clients attempt to send UDP packets to each other's public and private endpoints to punch holes in their respective NATs.
- Clients authenticate messages to avoid confusion from stray packets.
"""

import socket
import threading
import time
from typing import Tuple, Dict
from pynat import get_ip_info
import argparse
import modal
import asyncio
import os
import random
import platform
import json
import ssl
from aioquic.asyncio import serve, connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives.asymmetric import ec
import time as time_mod

# --- Data Structures ---
class Endpoint:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
    def __repr__(self):
        return f"{self.ip}:{self.port}"

class ClientInfo:
    def __init__(self, client_id: str, private_ep: Endpoint, public_ep: Endpoint):
        self.client_id = client_id
        self.private_ep = private_ep
        self.public_ep = public_ep

# --- Client (A or B) ---
class HolePunchingClient:
    def __init__(self, client_id: str, server_addr: Tuple[str, int], local_port: int, stun_host: str = "stun.l.google.com", stun_port: int = 19302):
        self.client_id = client_id
        self.server_addr = server_addr
        self.local_port = local_port
        self.stun_host = stun_host
        self.stun_port = stun_port
        self.private_ep = None  # type: Endpoint
        self.public_ep = None   # type: Endpoint
        self.peer_info = None   # type: ClientInfo
        # Only set up UDP socket for actual communication, not for STUN queries
        self.sock = None

    @staticmethod
    def discover_endpoints_static(local_port, stun_servers, client_id):
        """Use all STUN servers to discover private and public endpoints (static method, binds/releases socket). Returns a list of dicts with endpoint info, nat type, stun server, and hairpin test result."""
        endpoint_infos = []
        for stun_host, stun_port in stun_servers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", local_port))
            try:
                topology, ext_ip, ext_port, src_ip = get_ip_info(
                    sock=sock, stun_host=stun_host, stun_port=stun_port, include_internal=True
                )
                private_ep = Endpoint(src_ip, local_port)
                public_ep = Endpoint(ext_ip, ext_port)
                stun_server = f"{stun_host}:{stun_port}"
                # Hairpin test for this public endpoint
                hairpin_supported = HolePunchingClient.test_hairpin_nat_static(local_port, public_ep.ip, public_ep.port, client_id)
                endpoint_infos.append({
                    "private_ip": private_ep.ip,
                    "private_port": private_ep.port,
                    "public_ip": public_ep.ip,
                    "public_port": public_ep.port,
                    "nat_type": topology,
                    "stun_server": stun_server,
                    "hairpin_supported": hairpin_supported,
                })
                print(f"[Client {client_id}] STUN {stun_server} -> Private: {private_ep}, Public: {public_ep}, NAT type: {topology}, Hairpin: {hairpin_supported}")
            except Exception as e:
                print(f"[Client {client_id}] STUN {stun_host}:{stun_port} failed: {e}")
            finally:
                sock.close()
        return endpoint_infos

    @staticmethod
    def test_hairpin_nat_static(local_port, public_ip, public_port, client_id):
        """Static method to test hairpin NAT for a given public endpoint."""
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            test_sock.bind(("0.0.0.0", local_port + 10))  # Use a different port to avoid conflict
            test_sock.settimeout(1.0)
            msg = b'HAIRPIN_TEST'
            test_sock.sendto(msg, (public_ip, public_port))
            try:
                data, addr = test_sock.recvfrom(1024)
                if data == msg:
                    print(f"[Client {client_id}] Hairpin NAT supported (received own packet from {addr})")
                    return True
                else:
                    print(f"[Client {client_id}] Hairpin NAT test: received unexpected data")
            except socket.timeout:
                print(f"[Client {client_id}] Hairpin NAT NOT supported (no packet received)")
            except Exception as e:
                print(f"[Client {client_id}] Hairpin NAT test recv error: {e}")
        except Exception as e:
            print(f"[Client {client_id}] Hairpin NAT test bind/send error: {e}")
        finally:
            test_sock.close()
        return False

    def discover_endpoints(self):
        """Instance method for compatibility, uses static method."""
        self.endpoint_infos = self.discover_endpoints_static(
            self.local_port, STUN_SERVERS, self.client_id
        )
        return [info["nat_type"] for info in self.endpoint_infos]

    def register_with_modal_dict(self, rendezvous, peer_id: str):
        """Register with modal.Dict and wait for peer info."""
        my_info = {
            "client_id": self.client_id,
            "endpoint_infos": self.endpoint_infos,  # List of dicts
        }
        print(f"[Client {self.client_id}] Registering with rendezvous...")
        rendezvous[self.client_id] = my_info
        print(f"[Client {self.client_id}] Waiting for peer {peer_id} to register...")
        while peer_id not in rendezvous:
            time.sleep(0.2)
        peer_info = rendezvous[peer_id]
        print(f"[Client {self.client_id}] Got peer info: {peer_info}")
        return peer_info

    async def punch_holes_and_communicate(self, peer_info, auth_token: bytes, rendezvous=None):
        """Attempt to send UDP packets to all peer's public and private endpoints."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.local_port))
        self.sock.settimeout(0.2)
        print(f"[Client {self.client_id}] Socket bound to: {self.sock.getsockname()}")
        print(f"[Client {self.client_id}] Hostname: {platform.node()} PID: {os.getpid()}")
        # Collect all unique peer endpoints
        peer_endpoints = set()
        for ep in peer_info["endpoint_infos"]:
            peer_endpoints.add((ep["private_ip"], ep["private_port"]))  # private
            peer_endpoints.add((ep["public_ip"], ep["public_port"]))  # public
        print(f"[Client {self.client_id}] Will punch to peer endpoints: {peer_endpoints}")
        punch_packet = auth_token + b"PUNCH"
        ack_packet = auth_token + b"ACK"
        working_endpoint = None
        punch_phase_start = time.time()
        print(f"[Client {self.client_id}] Punch phase START at {punch_phase_start}")
        for attempt in range(10):
            try:
                print(f"[Client {self.client_id}] Sending punch packets (attempt {attempt + 1}) at {time.time()} to: {peer_endpoints}")
                for endpoint in peer_endpoints:
                    try:
                        self.sock.sendto(punch_packet, endpoint)
                    except Exception as e:
                        print(f"[Client {self.client_id}] sendto error to {endpoint}: {e}")
                try:
                    data, addr = self.sock.recvfrom(1024)
                    print(f"[Client {self.client_id}] Received {len(data)} bytes from {addr}")
                    if not data.startswith(auth_token):
                        print(f"[Client {self.client_id}] Received unauthenticated packet, ignoring")
                        continue
                    msg = data[len(auth_token):]
                    if msg == b"PUNCH":
                        print(f"[Client {self.client_id}] Got PUNCH from {addr}, sending ACK")
                        try:
                            self.sock.sendto(ack_packet, addr)
                        except Exception as e:
                            print(f"[Client {self.client_id}] sendto ACK error to {addr}: {e}")
                        working_endpoint = addr
                        break
                    elif msg == b"ACK":
                        print(f"[Client {self.client_id}] Got ACK from {addr}")
                        working_endpoint = addr
                        break
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f"[Client {self.client_id}] recvfrom error: {e}")
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"[Client {self.client_id}] Error in attempt {attempt + 1}: {e}")
                continue
        punch_phase_end = time.time()
        print(f"[Client {self.client_id}] Punch phase END at {punch_phase_end} (duration: {punch_phase_end - punch_phase_start:.2f}s)")
        if working_endpoint:
            print(f"[Client {self.client_id}] Successfully established connection with peer at {working_endpoint}")
            # Save our success endpoint to the rendezvous dict if provided
            if rendezvous is not None:
                await rendezvous.put.aio(f"success_endpoint_{self.client_id}", working_endpoint)
            self.sock.close()
            self.sock = None
        else:
            print(f"[Client {self.client_id}] Failed to establish connection with peer")
            self.sock.close()
            self.sock = None
        return working_endpoint

    def test_hairpin_nat(self, public_ip, public_port):
        """Test if hairpin translation is supported by sending a UDP packet to our own public endpoint."""
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            test_sock.bind(("0.0.0.0", self.local_port + 10))  # Use a different port to avoid conflict
            test_sock.settimeout(1.0)
            msg = b'HAIRPIN_TEST'
            test_sock.sendto(msg, (public_ip, public_port))
            try:
                data, addr = test_sock.recvfrom(1024)
                if data == msg:
                    print(f"[Client {self.client_id}] Hairpin NAT supported (received own packet from {addr})")
                    return True
                else:
                    print(f"[Client {self.client_id}] Hairpin NAT test: received unexpected data")
            except socket.timeout:
                print(f"[Client {self.client_id}] Hairpin NAT NOT supported (no packet received)")
            except Exception as e:
                print(f"[Client {self.client_id}] Hairpin NAT test recv error: {e}")
        except Exception as e:
            print(f"[Client {self.client_id}] Hairpin NAT test bind/send error: {e}")
        finally:
            test_sock.close()
        return False

# --- Main Demo Flow ---
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
    ("stun.ekiga.net", 3478),
]

app = modal.App("udp-hole-punching-clean")
image = modal.Image.debian_slim().pip_install("aioquic", "cryptography", "six").pip_install("pynat")

async def quic_server(local_port, response_kib, n_iterations=100):
    cfg = QuicConfiguration(
        is_client=False,
        alpn_protocols=["hq-29"],
        verify_mode=ssl.CERT_NONE,
        congestion_control_algorithm="cubic",
        max_data=10_000_000,
        max_stream_data=5_000_000,
        max_datagram_size=1400,
    )
    cfg.private_key = ec.generate_private_key(ec.SECP256R1())
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    import datetime
    cfg.certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic-benchmark")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic-benchmark")]))
        .public_key(cfg.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(cfg.private_key, hashes.SHA256())
    )
    results = {"received": 0, "latencies": []}
    pong_data = b"P" * response_kib * 1024 * 100
    async def handle_benchmark(reader, writer):
        for _ in range(n_iterations):
            length_bytes = await reader.read(4)
            if not length_bytes or len(length_bytes) < 4:
                break
            msg_length = int.from_bytes(length_bytes, byteorder="big")
            data = await reader.read(msg_length)
            start = time_mod.monotonic()
            response_len = len(pong_data).to_bytes(4, byteorder="big")
            writer.write(response_len + pong_data)
            await writer.drain()
            end = time_mod.monotonic()
            results["received"] += 1
            results["latencies"].append((end - start) * 1000)
        writer.close()
    def stream_handler(reader, writer):
        asyncio.create_task(handle_benchmark(reader, writer))
    server = await serve(
        host="0.0.0.0",
        port=local_port,
        configuration=cfg,
        stream_handler=stream_handler,
    )
    # Wait for one connection to finish
    await asyncio.sleep(2 + n_iterations * 0.2)
    server.close()
    return results

async def quic_client(server_ip, server_port, local_port, request_kib, n_iterations=10):
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hq-29"],
        verify_mode=ssl.CERT_NONE,
        congestion_control_algorithm="cubic",
        max_data=10_000_000,
        max_stream_data=5_000_000,
        max_datagram_size=1400,
    )
    ping_data = b"P" * request_kib * 1024
    results = {"received": 0, "latencies": [], "bytes_received": []}
    async with connect(
        server_ip,
        server_port,
        configuration=cfg,
        local_port=local_port,
        wait_connected=True,
    ) as quic:
        reader, writer = await quic.create_stream()
        for _ in range(n_iterations):
            start = time_mod.monotonic()
            writer.write(len(ping_data).to_bytes(4, "big") + ping_data)
            await writer.drain()
            length_bytes = await reader.read(4)
            if not length_bytes or len(length_bytes) < 4:
                break
            resp_length = int.from_bytes(length_bytes, "big")
            response = await reader.read(resp_length)
            end = time_mod.monotonic()
            results["latencies"].append((end - start) * 1000)
            results["received"] += 1
            results["bytes_received"].append(resp_length)
            await asyncio.sleep(0.05)
        writer.close()
    return results

def get_region():
    return os.environ.get('MODAL_REGION', 'local')

async def run_hole_punch_peer(rendezvous, client_id, peer_id, local_port):
    import socket
    import os
    import platform
    import time
    endpoint_infos = HolePunchingClient.discover_endpoints_static(
        local_port, STUN_SERVERS, client_id
    )
    print(f"[Client {client_id}] All discovered endpoint infos: {endpoint_infos}")
    print(f"[Client {client_id}] Hostname: {platform.node()}")
    print(f"[Client {client_id}] Local port: {local_port}")
    print(f"[Client {client_id}] Registration start time: {time.time()}")
    client = HolePunchingClient(
        client_id=client_id,
        server_addr=("127.0.0.1", 5000),
        local_port=local_port,
        stun_host=STUN_SERVERS[0][0],
        stun_port=STUN_SERVERS[0][1],
    )
    client.endpoint_infos = endpoint_infos
    my_info = {
        "client_id": client.client_id,
        "endpoint_infos": client.endpoint_infos,  # List of dicts
        "region": get_region(),
    }
    print(f"[Client {client.client_id}] Registering with rendezvous...")
    rendezvous[client.client_id] = my_info
    print(f"[Client {client.client_id}] Waiting for peer {peer_id} to register...")
    while peer_id not in rendezvous:
        await asyncio.sleep(0.2)  # Modern async polling
    peer_info = rendezvous[peer_id]
    print(f"[Client {client.client_id}] Got peer info: {peer_info}")
    # Create a shared auth token through the rendezvous server
    if client_id < peer_id:  # Only one client should generate the token
        auth_token = os.urandom(16)
        print(f"[Client {client_id}] Generated auth_token: {auth_token.hex()} at {time.time()}")
        rendezvous["auth_token"] = auth_token
    while "auth_token" not in rendezvous:
        await asyncio.sleep(0.1)  # Modern async polling
    auth_token = rendezvous["auth_token"]
    print(f"[Client {client_id}] Using auth_token: {auth_token.hex()} at {time.time()}")
    # Staggered start for punching
    punch_start_time = time.time()
    if client_id < peer_id:
        print(f"[Client {client_id}] Staggering start: waiting 1.5s before punching at {punch_start_time}")
        await asyncio.sleep(1.5)
    else:
        print(f"[Client {client_id}] Staggering start: waiting 0.5s before punching at {punch_start_time}")
        await asyncio.sleep(0.5)
    print(f"[Client {client_id}] Starting punch_holes_and_communicate at {time.time()}")
    working_endpoint = await client.punch_holes_and_communicate(peer_info, auth_token, rendezvous)
    return {
        "registration": {
            "self": my_info,
            "peer": peer_info,
        },
        "working_endpoint": working_endpoint,
        "endpoint_infos": endpoint_infos,
    }

async def run_quic_test(client_id, peer_info, working_endpoint, local_port, request_kib, response_kib, n_iterations):
    quic_results = None
    if working_endpoint:
        if client_id == "A":
            print(f"[Client {client_id}] Running QUIC server on port {local_port}")
            quic_results = await quic_server(local_port, response_kib, n_iterations)
        elif client_id == "B":
            await asyncio.sleep(1.0)  # Modern async sleep
            a_public = None
            for ep in peer_info["endpoint_infos"]:
                if ep["public_ip"] != "0.0.0.0":
                    a_public = (ep["public_ip"], ep["public_port"])
                    break
            if a_public:
                print(f"[Client {client_id}] Running QUIC client to {a_public} from port {local_port}")
                quic_results = await quic_client(a_public[0], a_public[1], local_port, request_kib, n_iterations)
            else:
                print(f"[Client {client_id}] Could not find A's public endpoint for QUIC test")
    return quic_results

region = os.environ.get('FORCE_MODAL_REGION', None)
@app.function(image=image, max_inputs=1, region=region)
async def run_quic_peer(rendezvous: modal.Dict, client_id: str, peer_id: str, local_port: int, run_quic: bool = True, request_kib: int = 1, response_kib: int = 1, n_iterations: int = 100):
    # Run hole punching
    hole_punch_result = await run_hole_punch_peer(rendezvous, client_id, peer_id, local_port)
    working_endpoint = hole_punch_result["working_endpoint"]
    peer_info = hole_punch_result["registration"]["peer"]
    # Run QUIC test if requested and successful
    quic_results = None
    if run_quic and working_endpoint:
        quic_results = await run_quic_test(client_id, peer_info, working_endpoint, local_port, request_kib, response_kib, n_iterations)
    result = {
        **hole_punch_result,
        "quic_results": quic_results,
    }
    return result

@app.local_entrypoint()
async def local_main(client_id: str = "A", peer_id: str = "B", local_port: int = 5555, local: bool = False, output_path: str = None):
    """Local entrypoint for Modal: run registration and peer info exchange locally.
    If output_path is provided, saves the result to that file (JSON).
    Pass --output <path> to modal run to use this feature.
    """
    # Randomize the local port for each run
    port_offset = random.randint(0, 1000)
    local_port = local_port + port_offset
    print(f"[Entrypoint] Using randomized local_port={local_port}")
    async with modal.Dict.ephemeral() as rendezvous:
        # Spawn the peer registration
        await run_quic_peer.spawn.aio(rendezvous, client_id, peer_id, local_port + 1)
        # Run our registration
        if not local:
            peer_info = await run_quic_peer.remote.aio(rendezvous, peer_id, client_id, local_port)
        else:
            peer_info = await run_quic_peer.local(rendezvous, peer_id, client_id, local_port)
        print(f"[Local Entrypoint] Peer info: {peer_info}")
        if output_path:
            with open(output_path, "w") as f:
                json.dump(peer_info, f)
        return peer_info


