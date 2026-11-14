"""Create a safe Microsoft Windows App connection profile for SOLIDWORKS.

SOLIDWORKS runs on a licensed Windows x86-64 workstation. Windows App on a
Mac displays the existing Windows desktop; no VM runs on the Mac. Generate
only a private-LAN/VPN RDP connection, never a public Internet RDP endpoint.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re

PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"
))

def validate_host(value: str) -> str:
    if not value or value != value.strip() or len(value) > 253:
        raise ValueError("Expected an internal LAN or VPN host name/address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Only local hostnames and known VPN MagicDNS domain names are allowed.
        labels = value.rstrip(".").split(".")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in labels):
            raise ValueError("Invalid hostname")
        if len(labels) == 1 or value.lower().endswith((".local", ".ts.net")):
            return value.rstrip(".")
        raise ValueError("Use a LAN or VPN endpoint, not an Internet-exposed RDP server")
    if not isinstance(address, ipaddress.IPv4Address) or not any(address in net for net in PRIVATE_NETWORKS):
        raise ValueError("Use a private IPv4 LAN address or a VPN/Tailscale address")
    return str(address)

def rdp_profile(host: str) -> str:
    safe = validate_host(host)
    # Authentication is required; passwords, Windows credentials, file shares,
    # printer redirection, security relaxation, and public gateways are absent.
    settings = [
        "screen mode id:i:2", "use multimon:i:0", "smart sizing:i:1",
        "session bpp:i:32", "desktopwidth:i:1920", "desktopheight:i:1080",
        "full address:s:" + safe, "prompt for credentials:i:1",
        "authentication level:i:2", "enablecredsspsupport:i:1",
        "gatewayusagemethod:i:0", "redirectclipboard:i:1",
        "drivestoredirect:s:", "redirectprinters:i:0",
        "redirectsmartcards:i:0", "redirectcomports:i:0",
        "audiocapturemode:i:0", "audiomode:i:2",
    ]
    return "\r\n".join(settings) + "\r\n"

def write_profile(host: str, output: Path) -> None:
    if output.suffix.lower() != ".rdp" or output.is_symlink():
        raise ValueError("Output must be a new regular .rdp file")
    profile = rdp_profile(host)
    # Exclusive file creation prevents inadvertent overwrites and symlink races.
    handle = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
        stream.write(profile)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate safe macOS Windows App RDP profile for a licensed SOLIDWORKS workstation")
    parser.add_argument("--host", required=True, help="Private LAN IP, VPN address, or Tailscale MagicDNS name")
    parser.add_argument("--output", type=Path, default=Path("SOLIDWORKS-Remote.rdp"))
    args = parser.parse_args(argv)
    try:
        write_profile(args.host, args.output)
    except (OSError, ValueError):
        parser.error("Cannot create profile. Check host, path and whether the output already exists.")
    print("Created Windows App profile. Open it on your Mac and enter your authorized Windows credentials.")
    print("SOLIDWORKS must already be installed and licensed on the remote Windows x86-64 workstation.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
