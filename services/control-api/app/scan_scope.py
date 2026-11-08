"""Scan-target guard: keep the scanner and its browser away from platform-internal hosts.

Private LAN ranges stay allowed (lab applications live there). Loopback, link-local,
unspecified, multicast addresses and the Compose service names are always refused.
An optional SCAN_TARGET_ALLOWLIST (comma-separated hostnames, IPs or CIDRs) restricts
scans to those targets only.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

INTERNAL_HOSTS = frozenset({
    "localhost", "postgres", "frontend", "control-api", "discovery-worker", "analysis-service",
    "runtime-inspector", "netscaler-adapter", "signature-sync", "host.docker.internal",
})


def _blocked_ip(address: ipaddress._BaseAddress) -> bool:
    return address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast


def _allowlist() -> list[str]:
    return [item.strip().casefold() for item in os.getenv("SCAN_TARGET_ALLOWLIST", "").split(",") if item.strip()]


def _in_allowlist(host: str, addresses: list[ipaddress._BaseAddress], entries: list[str]) -> bool:
    for entry in entries:
        if entry == host:
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if any(address in network for address in addresses):
            return True
    return False


def scan_target_error(url: str, *, resolve: bool = True) -> str | None:
    """Return a reason string if the URL must not be scanned, else None."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        return "target must be an http or https URL with a hostname"
    if parsed.username or parsed.password:
        return "credentials in the target URL are not allowed"
    if host in INTERNAL_HOSTS:
        return "target is an internal platform service"
    addresses: list[ipaddress._BaseAddress] = []
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        if resolve:
            try:
                addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)]
            except (socket.gaierror, ValueError):
                addresses = []
    if any(_blocked_ip(address) for address in addresses):
        return "target resolves to a loopback, link-local or otherwise reserved address"
    entries = _allowlist()
    if entries and not _in_allowlist(host, addresses, entries):
        return "target is not in SCAN_TARGET_ALLOWLIST"
    return None
