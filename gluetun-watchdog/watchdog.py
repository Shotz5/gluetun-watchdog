import logging
import os
import time

import docker
import requests

import wireguard

# --- Settings -----------------------------------------------------------
GLUETUN_SERVICE = os.getenv("GLUETUN_SERVICE", "gluetun")
DEPENDENT_SERVICES = os.getenv("DEPENDENT_SERVICES", "qbittorrent autobrr").split()
PIA_USER = os.environ["PIA_USER"]
PIA_PASS = os.environ["PIA_PASS"]
PIA_REGION = os.getenv("PIA_REGION", "ca_vancouver")
PORTAINER_URL = os.environ["PORTAINER_URL"].rstrip("/")
STACK_ID = os.environ["PORTAINER_STACK_ID"]
ENDPOINT_ID = os.environ["PORTAINER_ENDPOINT_ID"]

CHECK_INTERVAL = 30   # seconds between health checks
BAD_CHECKS_BEFORE_ACTING = 4
COOLDOWN = 15 * 60    # minimum seconds between regenerations
COMPOSE_PROJECT = None  # looked up from Portainer at startup
# Where gluetun saves PIA's forwarded port; it's only valid for the old server
SAVED_PORT_FILE = "/gluetun/piaportforward.json"

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


def delete_saved_port():
    """Delete gluetun's saved forwarded port so it asks the new server for one."""
    container = find_container(GLUETUN_SERVICE)
    if container is None or container.status != "running":
        log.warning("gluetun isn't running, so the saved port file wasn't deleted")
        return
    result = container.exec_run(["rm", "-f", SAVED_PORT_FILE])
    if result.exit_code == 0:
        log.info("Deleted saved forwarded port (%s)", SAVED_PORT_FILE)
    else:
        log.warning("Couldn't delete %s: %s", SAVED_PORT_FILE, result.output.decode().strip())


# --- Recovery -----------------------------------------------------------
def recover():
    log.info("Generating new WireGuard credentials")
    new_values = wireguard.generate_config(PIA_USER, PIA_PASS, PIA_REGION)
    log.info("New server: %s (%s)", new_values["PIA_SERVER_CN"], new_values["WIREGUARD_ENDPOINT_IP"])

    delete_saved_port()

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
