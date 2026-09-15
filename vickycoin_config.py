import os
import requests

VICKYCOIN_NODE_URL = os.environ.get(
    "VICKYCOIN_NODE_URL",
    ""
).rstrip("/")

def vic_enabled():
    return bool(VICKYCOIN_NODE_URL)

def vic_get_balance(address):
    if not VICKYCOIN_NODE_URL:
        raise RuntimeError("VICKYCOIN_NODE_URL is not configured")

    r = requests.get(
        f"{VICKYCOIN_NODE_URL}/balance",
        params={"address": address},
        timeout=15
    )
    r.raise_for_status()
    return r.json()

def vic_get_transaction(tx_id):
    if not VICKYCOIN_NODE_URL:
        raise RuntimeError("VICKYCOIN_NODE_URL is not configured")

    r = requests.get(
        f"{VICKYCOIN_NODE_URL}/transaction",
        params={"id": tx_id},
        timeout=15
    )
    r.raise_for_status()
    return r.json()

def vic_get_status():
    if not VICKYCOIN_NODE_URL:
        raise RuntimeError("VICKYCOIN_NODE_URL is not configured")

    r = requests.get(
        f"{VICKYCOIN_NODE_URL}/status",
        timeout=15
    )
    r.raise_for_status()
    return r.json()
