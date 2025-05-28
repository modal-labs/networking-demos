"""
Benchmark custom `quic-portal` library.

After UDP hole punching, `quic-portal` uses a Python wrappers around `quinn` to create an abstract data transport layer.

Between two containers: `modal run quic_portal_modal.py`
Between local client and container: `modal run quic_portal_modal.py --local`

Larger workload: `modal run quic_portal_modal.py --request-kib=600 --response-kib=5`
"""

import asyncio
import os
import time

import modal

app = modal.App("quic-portal-modal-demo")

image = modal.Image.debian_slim().pip_install("quic-portal")

SERVER_REGION = "us-west-1"
CLIENT_REGION = "us-sanjose-1"

N_ITERATIONS = 25


@app.function(image=image, region=SERVER_REGION)
async def run_server(rendezvous: modal.Dict, response_kib: int):
    from quic_portal import Portal

    portal = await Portal.create_server(rendezvous)

    # Create response data once
    response_data = b"x" * (response_kib * 1024)
    for _ in range(N_ITERATIONS):
        await portal.recv()
        await portal.send(response_data)

    await asyncio.sleep(1)


@app.function(image=image, region=CLIENT_REGION)
async def run_client(request_kib: int, response_kib: int):
    from quic_portal import Portal

    async with modal.Dict.ephemeral.aio() as rendezvous:
        run_server.spawn(rendezvous, response_kib)
        portal = await Portal.create_client(rendezvous)

        # Create request data once
        request_data = b"x" * (request_kib * 1024)
        expected_response = b"x" * (response_kib * 1024)

        print(f"[CLIENT] Starting benchmark with {N_ITERATIONS} iterations")
        print(f"[CLIENT] Request size: {request_kib}KB, Response size: {response_kib}KB")

        latencies = []

        for i in range(N_ITERATIONS):
            start_time = time.monotonic()

            await portal.send(request_data)
            response = await portal.recv()

            end_time = time.monotonic()
            latency = (end_time - start_time) * 1000  # Convert to ms
            latencies.append(latency)

            print(f"[CLIENT] Iteration {i + 1}/{N_ITERATIONS}: {latency:.2f}ms")

            # Verify response
            if response != expected_response:
                print(f"[CLIENT] Warning: Response size mismatch: {len(response)} vs {len(expected_response)}")

            # Small pause between iterations
            await asyncio.sleep(0.1)

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

            print(f"\n===== QUIC-PORTAL BENCHMARK RESULTS FROM {client_region} to {SERVER_REGION} =====")
            print(f"Completed {num_latencies} iterations")
            print(f"Request size: {request_kib}KB, Response size: {response_kib}KB")
            print(f"Average latency: {avg_latency:.2f}ms")
            print(f"Median latency (p50): {p50_latency:.2f}ms")
            print(f"90th percentile (p90): {p90_latency:.2f}ms")
            print(f"99th percentile (p99): {p99_latency:.2f}ms")
            print(f"Min latency: {min_latency:.2f}ms")
            print(f"Max latency: {max_latency:.2f}ms")
            print("==================================\n")


@app.local_entrypoint()
def main(local: bool = False, request_kib: int = 1, response_kib: int = 1):
    if local:
        run_client.local(request_kib=request_kib, response_kib=response_kib)
    else:
        run_client.remote(request_kib=request_kib, response_kib=response_kib)
