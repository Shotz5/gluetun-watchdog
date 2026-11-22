import json
import logging
import os
import time

import docker
import requests

# --- Settings -----------------------------------------------------------
GLUETUN_SERVICE = os.getenv("GLUETUN_SERVICE", "gluetun")
DEPENDENT_SERVICES = os.getenv("DEPENDENT_SERVICES", "qbittorrent autobrr").split()
PIA_USER = os.environ["PIA_USER"]
PIA_PASS = os.environ["PIA_PASS"]
PIA_REGION = os.getenv("PIA_REGION", "ca_vancouver")
# Passes -v to pia-wg-config for troubleshooting. Its verbose output may
# include auth details, so turn this back off once things work.
PIA_WG_VERBOSE = os.getenv("PIA_WG_VERBOSE", "false").lower() in ("1", "true", "yes")
PORTAINER_URL = os.environ["PORTAINER_URL"].rstrip("/")
STACK_ID = os.environ["PORTAINER_STACK_ID"]
ENDPOINT_ID = os.environ["PORTAINER_ENDPOINT_ID"]

CHECK_INTERVAL = 30   # seconds between health checks
BAD_CHECKS_BEFORE_ACTING = 4
COOLDOWN = 15 * 60    # minimum seconds between regenerations
COMPOSE_PROJECT = None  # looked up from Portainer at startup

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger()
docker_client = docker.from_env()
portainer = requests.Session()
portainer.headers["X-API-Key"] = os.environ["PORTAINER_API_KEY"]


# --- Finding containers ------------------------------------------------
def find_container(service):
    """Find a container by its Compose project + service labels.

    Container names change when Portainer recreates them, so look them up
    by label every time instead of by name. Returns None if not found.
    """
    matches = docker_client.containers.list(all=True, filters={"label": [
        f"com.docker.compose.project={COMPOSE_PROJECT}",
        f"com.docker.compose.service={service}",
    ]})
    running = [c for c in matches if c.status == "running"]
    return (running or matches or [None])[0]


def health_of(container):
    return container.attrs["State"].get("Health", {}).get("Status")


# --- Gluetun health -----------------------------------------------------
def gluetun_is_unhealthy():
    """True only when gluetun is running and Docker reports it unhealthy.

    A missing or stopped container is left alone: new credentials won't help
    a container that isn't running.
    """
    container = find_container(GLUETUN_SERVICE)
    if container is None or container.status != "running":
        return False
    return health_of(container) == "unhealthy"


def wait_until_healthy(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        container = find_container(GLUETUN_SERVICE)
        if container is not None and health_of(container) == "healthy":
            return True
        time.sleep(5)
    return False


# --- New WireGuard credentials -------------------------------------------
def run_pia_wg_config():
    """Run pia-wg-config once and return what it prints to stdout.

    stdout and stderr are read separately so a failure shows the tool's
    actual error message (and never the command line, which has the password).
    """
    args = ["-r", PIA_REGION]
    if PIA_WG_VERBOSE:
        args.append("-v")
    args += [PIA_USER, PIA_PASS]

    container = docker_client.containers.run("pia-wg-config:local", args, detach=True)
    try:
        exit_code = container.wait(timeout=120)["StatusCode"]
        stdout = container.logs(stdout=True, stderr=False).decode().strip()
        stderr = container.logs(stdout=False, stderr=True).decode().strip()
    finally:
        container.remove(force=True)

    if exit_code != 0:
        raise RuntimeError(
            f"pia-wg-config exited with status {exit_code}\n"
            f"  stdout: {stdout or '(empty)'}\n"
            f"  stderr: {stderr or '(empty)'}"
        )
    return stdout


def generate_wireguard_config():
    """Run pia-wg-config and parse the config it prints."""
    output = run_pia_wg_config()

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

    for service in DEPENDENT_SERVICES:
        container = find_container(service)
        if container is None:
            log.warning("No container found for service %s", service)
            continue
        log.info("Restarting %s", container.name)
        container.restart()


def main():
    global COMPOSE_PROJECT
    # Portainer uses the stack's name as the Compose project name
    COMPOSE_PROJECT = os.getenv("COMPOSE_PROJECT") or portainer_api("GET", f"/stacks/{STACK_ID}")["Name"]
    gluetun = find_container(GLUETUN_SERVICE)
    if gluetun is None:
        log.warning("No container found for service %s in project %s", GLUETUN_SERVICE, COMPOSE_PROJECT)
    else:
        log.info("Watching %s (project %s, service %s)", gluetun.name, COMPOSE_PROJECT, GLUETUN_SERVICE)
    bad_checks = 0
    last_recovery = 0

    while True:
        bad_checks = bad_checks + 1 if gluetun_is_unhealthy() else 0
        cooled_down = time.time() - last_recovery >= COOLDOWN

        if bad_checks >= BAD_CHECKS_BEFORE_ACTING and cooled_down:
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
