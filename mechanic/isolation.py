"""Detect whether we run inside a container or a virtual machine (WSL does not count as isolated)."""
import os
import subprocess


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def is_wsl():
    return "microsoft" in _read("/proc/version").lower() or "WSL_DISTRO_NAME" in os.environ


def isolation_reason():
    """Return a short description of the container/VM we are in, or None on a host."""
    if is_wsl():
        return None
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return "container"
    try:
        out = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = ""
    if out and out != "none":
        return out
    cg = _read("/proc/1/cgroup")
    if any(m in cg for m in ("docker", "containerd", "kubepods", "lxc", "libpod", "podman")):
        return "container"
    return None
