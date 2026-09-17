"""Read-only inventory tools for the local device (this Mac).

Every function here only reads local system state. Nothing modifies
configuration, installs software, or sends data off the device.
"""

import plistlib
import re
import subprocess


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        return f"ERROR running {' '.join(cmd)}: {exc}"


def get_os_info() -> dict:
    """Return the macOS product name, version, and build, plus kernel info.

    Use this first to establish what OS patch level the device is on.
    """
    sw_vers = _run(["sw_vers"])
    kernel = _run(["uname", "-a"])
    info = {}
    for line in sw_vers.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()
    return {"sw_vers": info, "kernel": kernel}


def get_pending_os_updates() -> dict:
    """List pending macOS software updates that have not yet been installed.

    A non-empty list here is a direct, actionable finding: unpatched OS
    vulnerabilities the vendor has already fixed.
    """
    raw = _run(["softwareupdate", "-l"], timeout=60)
    return {"raw_output": raw}


def list_installed_packages() -> dict:
    """List Homebrew formulae/casks and their installed versions.

    Used to cross-reference installed software versions against known CVEs.
    """
    brew_formulae = _run(["brew", "list", "--versions"], timeout=30)
    brew_casks = _run(["brew", "list", "--cask", "--versions"], timeout=30)
    return {
        "brew_formulae": brew_formulae.splitlines(),
        "brew_casks": brew_casks.splitlines(),
    }


def list_listening_ports() -> dict:
    """List local processes listening on network ports (potential attack surface).

    Equivalent to `lsof -iTCP -sTCP:LISTEN` — shows what's reachable on this
    device from the network, and by which process.
    """
    raw = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
    udp_raw = _run(["lsof", "-nP", "-iUDP"], timeout=20)
    return {"tcp_listening": raw, "udp": udp_raw}


def get_firewall_status() -> dict:
    """Return the macOS Application Firewall state (on/off) and stealth mode.

    A disabled firewall on a device that also has open listening ports is a
    meaningful finding for the patch/remediation plan.
    """
    fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    state = _run([fw_bin, "--getglobalstate"])
    stealth = _run([fw_bin, "--getstealthmode"])
    return {"global_state": state, "stealth_mode": stealth}


def get_filevault_status() -> dict:
    """Return whether FileVault full-disk encryption is enabled.

    Disk encryption state matters for the overall security posture, not
    just network-facing vulnerabilities.
    """
    return {"filevault": _run(["fdesetup", "status"])}


def get_sip_status() -> dict:
    """Return whether System Integrity Protection (SIP) is enabled."""
    return {"sip": _run(["csrutil", "status"])}
