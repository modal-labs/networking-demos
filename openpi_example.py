"""
Uses `quic-portal` to demonstrate inference.

Requires Modal setup:
- Create Modal account at modal.com
- Install modal: `pip install modal`
- `modal setup` or `python -m modal setup`

For testing:
- Install quic-portal library: `pip install quic-portal==0.1.6`
"""

import time

import modal

app = modal.App("openpi-example")

openpi_image = (
    modal.Image.from_registry("nvidia/cuda:12.2.2-cudnn8-runtime-ubuntu22.04", add_python="3.11")
    .apt_install("git")
    .run_commands("git clone --recurse-submodules https://github.com/Physical-Intelligence/openpi.git /root/openpi")
    .pip_install("uv")
    .run_commands(
        "cd /root/openpi && unset UV_INDEX_URL && GIT_LFS_SKIP_SMUDGE=1 UV_PROJECT_ENVIRONMENT='/usr/local/' uv sync"
    )
    .run_commands("cd /root && unset UV_INDEX_URL && GIT_LFS_SKIP_SMUDGE=1 uv pip install --system -e openpi")
    .run_commands("cd /root && unset UV_INDEX_URL && GIT_LFS_SKIP_SMUDGE=1 uv pip install --system modal")
    .run_commands("cd /root && unset UV_INDEX_URL && GIT_LFS_SKIP_SMUDGE=1 uv pip install --system quic-portal==0.1.6")
)

volume = modal.Volume.from_name("openpi-cache", create_if_missing=True)


@app.function(
    image=openpi_image,
    region="us-sanjose-1",
    timeout=3600,
    gpu="a100",
    volumes={"/root/.cache/openpi": volume},
)
def server(rendezvous: modal.Dict):
    from openpi.policies import policy_config as _policy_config
    from openpi.training import config as _config
    from openpi_client import msgpack_numpy
    from quic_portal import Portal

    class ModalPolicyServer:
        def __init__(self, policy, portal: Portal) -> None:
            self._policy = policy
            self._portal = portal
            self._packer = msgpack_numpy.Packer()

            # Server expects hello from client.
            assert self._portal.recv() == b"hello"
            self._portal.send(self._packer.pack(policy.metadata))
            print("[server] Server metadata sent.")

        def serve_forever(self):
            while True:
                obs = msgpack_numpy.unpackb(self._portal.recv())

                t0 = time.time()
                action = self._policy.infer(obs)
                elapsed = time.time() - t0
                print(f"[server] (no network) inference time: {elapsed * 1000:.2f}ms.")

                self._portal.send(self._packer.pack(action))

    t0 = time.time()
    print("[server] Creating policy ...")
    policy_name = "pi0_aloha_sim"
    policy_checkpoint = "s3://openpi-assets/checkpoints/pi0_aloha_sim"
    policy = _policy_config.create_trained_policy(
        _config.get_config(policy_name), policy_checkpoint, default_prompt=None
    )
    print(f"[server] Policy created in {time.time() - t0:.2f}s.")

    t0 = time.time()
    print("[server] Initalizing server ...")
    portal = Portal.create_server(rendezvous)
    server = ModalPolicyServer(policy, portal)
    print(f"[server] Server initialized in {time.time() - t0:.2f}s.")

    print("[server] Starting to serve policy ...")
    server.serve_forever()


@app.function(image=openpi_image, region="us-west-1")
def client():
    from typing import Dict

    import numpy as np
    from openpi_client import base_policy as _base_policy, msgpack_numpy
    from quic_portal import Portal

    def _random_observation_aloha() -> dict:
        return {
            "state": np.ones((14,)),
            "images": {
                "cam_high": np.random.randint(256, size=(3, 224, 224), dtype=np.uint8),
                "cam_low": np.random.randint(256, size=(3, 224, 224), dtype=np.uint8),
                "cam_left_wrist": np.random.randint(256, size=(3, 224, 224), dtype=np.uint8),
                "cam_right_wrist": np.random.randint(256, size=(3, 224, 224), dtype=np.uint8),
            },
            "prompt": "do something",
        }

    class ModalClientPolicy(_base_policy.BasePolicy):
        def __init__(self, portal: Portal) -> None:
            self._portal = portal
            self._packer = msgpack_numpy.Packer()

            # Client sends hello to server and gets metadata.
            print("[client] Sending hello to server ...")
            self._portal.send(b"hello")
            self._server_metadata = msgpack_numpy.unpackb(self._portal.recv())
            print("[client] Server metadata received.")

        def get_server_metadata(self) -> Dict:
            return self._server_metadata

        def infer(self, obs: np.ndarray) -> np.ndarray:
            self._portal.send(self._packer.pack(obs))
            return msgpack_numpy.unpackb(self._portal.recv())

    # Send 1 observation to make sure the model is loaded.
    with modal.Dict.ephemeral() as rendezvous:
        server_handle = server.spawn(rendezvous)
        portal = Portal.create_client(rendezvous)

    policy = ModalClientPolicy(portal)
    policy.infer(_random_observation_aloha())

    n_steps = 100
    start = time.time()
    for _ in range(n_steps):
        t0 = time.time()
        policy.infer(_random_observation_aloha())
        elapsed = time.time() - t0
        print(f"[client] (+network) inference time: {elapsed * 1000:.2f}ms.")
    end = time.time()

    print(f"Total time taken: {end - start:.2f} s")
    print(f"Average inference time: {1000 * (end - start) / n_steps:.2f} ms")

    # Shut down the server.
    server_handle.cancel()


@app.local_entrypoint()
def main(local: bool = False):
    if local:
        # Run from local machine.
        client.local()
    else:
        # Run proof of concept from Modal container.
        client.remote()
