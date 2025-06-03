import modal

app = modal.App("quic-portal-debugging")

image = modal.Image.debian_slim().pip_install("quic-portal==0.1.7")


@app.function(image=image, region="us-sanjose-1")
def run_server(rendezvous: modal.Dict):
    from quic_portal import Portal

    portal = Portal.create_server(rendezvous)

    # Server sends the first message.
    print("[server] Sending hello ...")
    portal.send(b"hello")


@app.function(image=image, region="us-west-1")
def run_client():
    from quic_portal import Portal

    with modal.Dict.ephemeral() as rendezvous:
        run_server.spawn(rendezvous)
        portal = Portal.create_client(rendezvous)

    msg = portal.recv()
    print(f"[client] Received message: {len(msg)} bytes")


@app.local_entrypoint()
def main():
    run_client.local()
