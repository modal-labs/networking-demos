"""
Benchmark custom `quic-portal` library.

After UDP hole punching, `quic-portal` uses a Python wrappers around `quinn` to create an abstract data transport layer.

Between two containers: `modal run quic_portal_modal.py`
Between local client and container: `modal run quic_portal_modal.py --local`

Larger workload: `modal run quic_portal_modal.py --request-kib=600 --response-kib=5`
"""
