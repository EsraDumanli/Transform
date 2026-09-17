"""Read-only local-network reconnaissance tools.

Scope is deliberately limited to the user's own LAN: discovering devices
that already announce themselves on the local subnet, and running
version-detection scans against them. No credential guessing, no
exploitation, no scanning outside the local subnet.
"""

import ipaddress
import re
import subprocess

import requests


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        return f"ERROR running {' '.join(cmd)}: {exc}"


def get_default_gateway() -> dict:
    """Return this machine's default gateway IP — almost always the router.

    Call this before router_inspector tools that need the router's address.
    """
    raw = _run(["route", "-n", "get", "default"])
    match = re.search(r"gateway:\s*(\S+)", raw)
    return {"gateway": match.group(1) if match else None, "raw": raw}


def get_local_subnet() -> dict:
    """Return this machine's active IPv4 address, netmask, and CIDR subnet.

    Use the returned CIDR as the `subnet` argument to discover_lan_hosts.
    """
    raw = _run(["ifconfig"])
    best = None
    current_iface = None
    for line in raw.splitlines():
        if line and not line.startswith((" ", "\t")):
            current_iface = line.split(":")[0]
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", line)
        if m and current_iface and not current_iface.startswith(("lo", "utun", "awdl", "llw")):
            ip = m.group(1)
            netmask_int = int(m.group(2), 16)
            netmask = ".".join(str((netmask_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))
            iface_net = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            best = {"interface": current_iface, "ip": ip, "netmask": netmask, "cidr": str(iface_net)}
    return best or {"error": "no active non-loopback IPv4 interface found"}


def _read_arp_table() -> dict:
    """Return {ip: mac} for every resolved (non-incomplete) ARP entry."""
    raw = _run(["arp", "-a"])
    table = {}
    for line in raw.splitlines():
        m = re.match(r"\S+ \(([\d.]+)\) at ([0-9A-Fa-f:]+) ", line)
        if m:
            table[m.group(1)] = m.group(2)
    return table


def discover_lan_hosts(subnet: str) -> dict:
    """Discover live hosts on the given subnet (CIDR, e.g. '10.0.0.0/24').

    Only scans the local subnet you provide — get it from get_local_subnet().
    Runs an nmap ping-sweep to trigger ARP resolution, then reads the OS ARP
    cache for resolved MACs — unprivileged nmap alone often can't see ICMP-
    filtering devices (routers, phones), but they still answer ARP requests
    at the link layer, which the ping-sweep provokes and the ARP cache
    captures. Returns IP + MAC for each responding host.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        return {"error": f"invalid subnet: {exc}"}
    if network.num_addresses > 1024 or not network.is_private:
        return {"error": "refusing to scan a non-private or overly large range"}

    nmap_raw = _run(["nmap", "-sn", str(network)], timeout=90)
    arp_table = _read_arp_table()

    hosts = []
    for ip_str, mac in sorted(arp_table.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        ip = ipaddress.ip_address(ip_str)
        if ip in network and mac.lower() != "ff:ff:ff:ff:ff:ff":
            hosts.append({"ip": ip_str, "mac": mac})
    return {"subnet": str(network), "hosts": hosts, "nmap_raw": nmap_raw}


def scan_host_services(host: str) -> dict:
    """Run an nmap version-detection scan of the top 200 ports on one LAN host.

    `host` must be a plain private IPv4 address (from discover_lan_hosts).
    Identifies service name + version banner per open port for CVE lookup.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return {"error": "host must be a literal IPv4/IPv6 address"}
    if not ip.is_private:
        return {"error": "refusing to scan a non-private address"}

    raw = _run(["nmap", "-sV", "-T4", "--top-ports", "200", str(ip)], timeout=180)
    services = []
    for line in raw.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            services.append(
                {
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "service": m.group(3),
                    "version_banner": m.group(4).strip(),
                }
            )
    return {"host": str(ip), "open_services": services, "raw": raw}


def fetch_http_banner(host: str, port: int = 80) -> dict:
    """GET the root page of a host:port to read its Server header and <title>.

    Read-only HTTP GET, no authentication attempted. Useful for
    fingerprinting a router's web admin UI (make/model/firmware often
    appear in the title or headers) without ever attempting to log in.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return {"error": "host must be a literal IPv4/IPv6 address"}
    if not ip.is_private:
        return {"error": "refusing to contact a non-private address"}

    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        resp = requests.get(url, timeout=5, verify=False)
        title_m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        return {
            "url": url,
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server"),
            "title": title_m.group(1).strip() if title_m else None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": str(exc)}
