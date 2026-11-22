"""Generate PIA WireGuard credentials.

Follows the flow in PIA's manual-connections scripts
(https://github.com/pia-foss/manual-connections):

1. Get a token from PIA's API using the account username and password.
2. Pick a WireGuard server in the region from PIA's server list.
3. Generate a fresh WireGuard key pair.
4. Register the public key with that server (addKey) to get the rest of the config.
"""

import base64
import http.client
import json
import random
import socket
import ssl
import urllib.parse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
SERVER_LIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
PIA_CA_FILE = "/app/ca.rsa.4096.crt"
ADD_KEY_PORT = 1337


def get_token(username, password):
    """Log in to PIA and return an auth token."""
    response = requests.post(
        TOKEN_URL,
        # Sent as multipart form data, the same as `curl --form` in PIA's script
        files={"username": (None, username), "password": (None, password)},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["token"]


def pick_server(region_id):
    """Pick a random WireGuard server in the region. Returns {"ip": ..., "cn": ...}."""
    response = requests.get(SERVER_LIST_URL, timeout=30)
    response.raise_for_status()
    data = json.loads(response.text.splitlines()[0])  # line 1 is JSON, the rest is a signature

    for region in data["regions"]:
        if region["id"] == region_id:
            servers = region["servers"].get("wg", [])
            if not servers:
                raise RuntimeError(f"Region {region_id} has no WireGuard servers")
            return random.choice(servers)
    raise RuntimeError(f"Region {region_id} not found in PIA's server list")


def generate_keypair():
    """Return a new WireGuard (X25519) key pair as base64 strings: (private, public)."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def register_key(server, token, public_key):
    """Call addKey on the server and return its JSON response.

    Connects to the server's IP but verifies the certificate against its
    name (cn), like `curl --connect-to` in PIA's script.

    PIA's certificates are old-style, so two modern checks are relaxed. The
    chain is still verified against PIA's CA and the name must still match:
    - the servers only put their name in the Common Name field (no SAN)
    - PIA's CA has no Key Usage extension, which Python 3.13+ rejects by default
    """
    context = ssl.create_default_context(cafile=PIA_CA_FILE)
    context.hostname_checks_common_name = True
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    connection = http.client.HTTPSConnection(server["cn"], ADD_KEY_PORT, context=context, timeout=30)
    raw_socket = socket.create_connection((server["ip"], ADD_KEY_PORT), timeout=30)
    connection.sock = context.wrap_socket(raw_socket, server_hostname=server["cn"])

    try:
        query = urllib.parse.urlencode({"pt": token, "pubkey": public_key})
        connection.request("GET", f"/addKey?{query}")
        result = json.loads(connection.getresponse().read())
    finally:
        connection.close()

    if result.get("status") != "OK":
        raise RuntimeError(f"addKey on {server['cn']} failed: {result.get('status')}")
    return result


def generate_config(username, password, region_id):
    """Return the gluetun stack variables for a fresh PIA WireGuard connection."""
    token = get_token(username, password)
    server = pick_server(region_id)
    private_key, public_key = generate_keypair()
    result = register_key(server, token, public_key)

    address = result["peer_ip"]
    return {
        "WIREGUARD_PRIVATE_KEY": private_key,
        "WIREGUARD_PUBLIC_KEY": result["server_key"],
        "WIREGUARD_ADDRESSES": address if "/" in address else f"{address}/32",  # gluetun wants CIDR
        "WIREGUARD_ENDPOINT_IP": server["ip"],
        "WIREGUARD_ENDPOINT_PORT": str(result["server_port"]),
        "PIA_SERVER_CN": server["cn"],
    }
