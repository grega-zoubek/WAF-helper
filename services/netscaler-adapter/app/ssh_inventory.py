"""Read-only SSH transport for the NetScaler AppFW CLI inventory."""

from __future__ import annotations

import os
import re
import socket
import time
from pathlib import Path
from typing import Any

import paramiko

from app.cli_inventory import build_waf_inventory, parse_servicegroups, parse_virtual_servers


CLI_COMMANDS = (
    "show lb vserver",
    "show cs vserver",
    "show vpn vserver",
    "show service",
    "show servicegroup",
    "show ns feature",
    "show appfw profile",
    "show appfw policy",
    "show appfw signatures",
    "show appfw settings",
    "show appfw policylabel",
)


def _read_secret() -> str:
    path = os.getenv("NETSCALER_SSH_PASSWORD_FILE", os.getenv("NETSCALER_PASSWORD_FILE", ""))
    return Path(path).read_text(encoding="utf-8").strip() if path and Path(path).is_file() else ""


def _read_until_prompt(channel: paramiko.Channel, timeout: float) -> str:
    data = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            data.extend(channel.recv(65535))
            if re.search(rb"\r?\n>\s*$", data):
                return data.decode("utf-8", errors="replace")
        elif channel.exit_status_ready():
            break
        else:
            time.sleep(0.05)
    raise TimeoutError("Timed out waiting for the NetScaler CLI prompt")


def collect_waf_inventory() -> dict[str, Any]:
    if os.getenv("NETSCALER_SSH_ENABLED", "false").strip().lower() != "true":
        return {"provider": "netscaler-cli-over-ssh", "status": "not-configured", "automatic_apply_allowed": False, "reason": "SSH CLI inventory is disabled by configuration."}
    host = os.getenv("NETSCALER_SSH_HOST", os.getenv("NETSCALER_HOST", ""))
    username = os.getenv("NETSCALER_SSH_USERNAME", os.getenv("NETSCALER_USERNAME", ""))
    password = _read_secret()
    if not host or not username or not password:
        return {"provider": "netscaler-cli-over-ssh", "status": "credential-not-configured", "automatic_apply_allowed": False, "reason": "SSH CLI host, username, or password file is not configured."}
    port = int(os.getenv("NETSCALER_SSH_PORT", "22"))
    timeout = float(os.getenv("NETSCALER_SSH_TIMEOUT_SECONDS", "30"))
    client = paramiko.SSHClient()
    known_hosts = os.getenv("NETSCALER_SSH_KNOWN_HOSTS_FILE", "")
    if known_hosts and Path(known_hosts).is_file():
        client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif os.getenv("NETSCALER_SSH_STRICT_HOST_KEY", "true").strip().lower() == "true":
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        channel = client.invoke_shell(width=240, height=2000)
        _read_until_prompt(channel, timeout)
        outputs: dict[str, str] = {}
        for command in CLI_COMMANDS:
            channel.send(command + "\n")
            output = _read_until_prompt(channel, timeout)
            outputs[command] = output
        # Detail queries are read-only and are derived only from sanitized
        # object names returned by the ADC summary command. They provide the
        # vserver-to-service binding chain needed for generic target matching.
        for vserver_type, summary_command, detail_prefix in (
            ("lb", "show lb vserver", "show lb vserver"),
            ("cs", "show cs vserver", "show cs vserver"),
            ("gw", "show vpn vserver", "show vpn vserver"),
        ):
            for vserver in parse_virtual_servers(outputs.get(summary_command, ""), vserver_type):
                name = str(vserver.get("name", ""))
                if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                    command = f"{detail_prefix} {name}"
                    channel.send(command + "\n")
                    outputs[command] = _read_until_prompt(channel, timeout)
        for servicegroup in parse_servicegroups(outputs.get("show servicegroup", "")):
            name = str(servicegroup.get("name", ""))
            if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                command = f"show servicegroup {name}"
                channel.send(command + "\n")
                outputs[command] = _read_until_prompt(channel, timeout)
        channel.send("exit\n")
        inventory = build_waf_inventory(outputs)
        inventory["source"] = {"transport": "ssh", "host": host, "username": username, "commands": list(CLI_COMMANDS)}
        return inventory
    except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
        return {"provider": "netscaler-cli-over-ssh", "status": "authentication-failed", "automatic_apply_allowed": False, "reason": "The ADC rejected the configured SSH CLI credentials or host key."}
    except (paramiko.SSHException, socket.timeout, TimeoutError, OSError) as exc:
        return {"provider": "netscaler-cli-over-ssh", "status": "unavailable", "automatic_apply_allowed": False, "reason": f"SSH CLI inventory failed with {type(exc).__name__}."}
    finally:
        client.close()
