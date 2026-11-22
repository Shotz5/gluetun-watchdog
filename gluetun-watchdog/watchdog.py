import json
import logging
import os
import time

import docker
import requests

# --- Settings -----------------------------------------------------------
GLUETUN = os.getenv("GLUETUN_CONTAINER", "gluetun")
DEPENDENTS = os.getenv("DEPENDENT_CONTAINERS", "qbittorrent autobrr").split()
PIA_USER = os.environ["PIA_USER"]
PIA_PASS = os.environ["PIA_PASS"]
PIA_REGION = os.getenv("PIA_REGION", "ca_vancouver")
PORTAINER_URL = os.environ["PORTAINER_URL"].rstrip("/")
STACK_ID = os.environ["PORTAINER_STACK_ID"]
ENDPOINT_ID = os.environ["PORTAINER_ENDPOINT_ID"]

CHECK_INTERVAL = 30   # seconds between health checks
BAD_CHECKS_BEFORE_ACTING = 4
COOLDOWN = 15 * 60    # minimum seconds between regenerations
FORCE_FILE = "/tmp/force"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger()
docker_client = docker.from_env()
portainer = requests.Session()
portainer.headers["X-API-Key"] = os.environ["PORTAINER_API_KEY"]


# --- Gluetun health -----------------------------------------------------
def gluetun_is_bad():
    try:
        container = docker_client.containers.get(GLUETUN)
    except docker.errors.NotFound:
        return True
    health = container.attrs["State"].get("Health", {}).get("Status")
    return container.status != "running" or health == "unhealthy"


def wait_until_healthy(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        container = docker_client.containers.get(GLUETUN)
        if container.attrs["State"].get("Health", {}).get("Status") == "healthy":
            return True
        time.sleep(5)
    return False


# --- New WireGuard credentials -------------------------------------------
def generate_wireguard_config():
    """Run pia-wg-config once and parse the config it prints."""
    output = docker_client.containers.run(
        "pia-wg-config:local", ["-r", PIA_REGION, PIA_USER, PIA_PASS], remove=True
    ).decode()

    values = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()

    endpoint_ip, endpoint_port = values["Endpoint"].rsplit(":", 1)
    return {
        "WIREGUARD_PRIVATE_KEY": values["PrivateKey"],
        "WIREGUARD_PUBLIC_KEY": values["PublicKey"],
        "WIREGUARD_ADDRESSES": values["Address"],
        "WIREGUARD_ENDPOINT_IP": endpoint_ip,
        "WIREGUARD_ENDPOINT_PORT": endpoint_port,
    }


def pia_server_name(ip):
    """Look up the server's name (cn) in PIA's public server list."""
    response = requests.get("https://serverlist.piaservers.net/vpninfo/servers/v6", timeout=30)
    response.raise_for_status()
    data = json.loads(response.text.splitlines()[0])  # line 1 is JSON, the rest is a signature
    for region in data["regions"]:
        for server in region["servers"].get("wg", []):
            if server["ip"] == ip:
                return server["cn"]
    raise RuntimeError(f"No PIA server found with IP {ip}")


# --- Portainer ----------------------------------------------------------
def portainer_api(method, path, **kwargs):
    response = portainer.request(method, f"{PORTAINER_URL}/api{path}", timeout=120, **kwargs)
    response.raise_for_status()
    return response.json()


def update_stack_variables(new_values):
    """Overwrite some of the stack's variables (keeping the rest) and redeploy."""
    stack = portainer_api("GET", f"/stacks/{STACK_ID}")
    compose_file = portainer_api("GET", f"/stacks/{STACK_ID}/file")["StackFileContent"]

    variables = {item["name"]: item["value"] for item in stack.get("Env") or []}
    variables.update(new_values)

    portainer_api(
        "PUT",
        f"/stacks/{STACK_ID}",
        params={"endpointId": ENDPOINT_ID},
        json={
            "stackFileContent": compose_file,
            "env": [{"name": k, "value": v} for k, v in variables.items()],
            "prune": False,
            "pullImage": False,
        },
    )


# --- Recovery -----------------------------------------------------------
def recover():
    log.info("Generating new WireGuard credentials")
    new_values = generate_wireguard_config()
    new_values["PIA_SERVER_CN"] = pia_server_name(new_values["WIREGUARD_ENDPOINT_IP"])
    log.info("New server: %s (%s)", new_values["PIA_SERVER_CN"], new_values["WIREGUARD_ENDPOINT_IP"])

    log.info("Updating Portainer stack %s and redeploying", STACK_ID)
    update_stack_variables(new_values)

    if wait_until_healthy():
        log.info("gluetun is healthy")
    else:
        log.warning("gluetun did not become healthy within 3 minutes")

    for name in DEPENDENTS:
        log.info("Restarting %s", name)
        docker_client.containers.get(name).restart()


def main():
    log.info("Watching %s", GLUETUN)
    bad_checks = 0
    last_recovery = 0

    while True:
        bad_checks = bad_checks + 1 if gluetun_is_bad() else 0
        forced = os.path.exists(FORCE_FILE)
        cooled_down = time.time() - last_recovery >= COOLDOWN

        if forced or (bad_checks >= BAD_CHECKS_BEFORE_ACTING and cooled_down):
            if forced:
                os.remove(FORCE_FILE)
                log.info("Manual trigger")
            else:
                log.info("gluetun has been unhealthy for %d checks", bad_checks)
            try:
                recover()
            except Exception:
                log.exception("Recovery failed")
            last_recovery = time.time()
            bad_checks = 0

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
