#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Record the environment a bench-compare run executed in.

Issue #2102 (epic #2101). Numbers from two machines are only comparable when
you know what each machine was, so every run writes fingerprint.json with:
CPU model / sockets / cores / threads / max MHz / frequency governor /
hypervisor, RAM, OS + kernel, rustc / go / docker / python versions, the
algod-rust and go-algorand commits (and whether go-algorand sits exactly on
the pinned tag, via `git describe --tags`), whether this is a CI runner, and
a list of fairness warnings (governor not `performance`, CI runner, dirty
trees, pin mismatch, virtualised CPU).

Linux is the reference platform (lscpu, /proc, /sys). macOS and Windows get
best-effort values so the selftest tier also runs there. Missing values are
null, never guessed.

Usage: python3 scripts/bench/fingerprint.py [-o fingerprint.json]
           [--repo-root DIR] [--go-algorand DIR] [--expected-tag TAG]
"""
import argparse
import datetime
import glob
import json
import os
import platform
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PIN_FILE = os.path.join(HERE, "go-algorand.pin")
SCHEMA = "bench-fingerprint/v1"


def read_pin(path=PIN_FILE):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    raise ValueError(f"{path}: no tag line")


# --------------------------------------------------------------------------
# parsers (pure functions; unit-tested against captured text)


def _kv_lines(text, sep=":"):
    out = {}
    for line in text.splitlines():
        if sep not in line:
            continue
        k, v = line.split(sep, 1)
        k, v = k.strip(), v.strip()
        if k and k not in out:
            out[k] = v
    return out


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _float(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_lscpu(text):
    kv = _kv_lines(text)
    sockets = _int(kv.get("Socket(s)"))
    per_socket = _int(kv.get("Core(s) per socket"))
    return {
        "model": kv.get("Model name") or None,
        "architecture": kv.get("Architecture") or None,
        "logical_cpus": _int(kv.get("CPU(s)")),
        "sockets": sockets,
        "physical_cores": sockets * per_socket if sockets and per_socket else None,
        "threads_per_core": _int(kv.get("Thread(s) per core")),
        "max_mhz": _float(kv.get("CPU max MHz")) or _float(kv.get("CPU MHz")),
        "hypervisor": kv.get("Hypervisor vendor") or None,
    }


def parse_cpuinfo(text):
    blocks = []
    for chunk in text.replace("\r\n", "\n").split("\n\n"):
        kv = _kv_lines(chunk)
        if "processor" in kv:
            blocks.append(kv)
    if not blocks:
        return {"model": None, "logical_cpus": None, "sockets": None,
                "physical_cores": None, "max_mhz": None}
    first = blocks[0]
    model = first.get("model name") or first.get("Processor") or None
    if model is None and "CPU part" in first:
        model = f"CPU part {first['CPU part']} (implementer {first.get('CPU implementer', '?')})"
    cores = sockets = None
    if all("physical id" in b and "core id" in b for b in blocks):
        cores = len({(b["physical id"], b["core id"]) for b in blocks})
        sockets = len({b["physical id"] for b in blocks})
    mhz = [m for m in (_float(b.get("cpu MHz")) for b in blocks) if m is not None]
    return {
        "model": model,
        "logical_cpus": len(blocks),
        "sockets": sockets,
        "physical_cores": cores,
        "max_mhz": max(mhz) if mhz else None,
    }


def parse_meminfo(text):
    v = _kv_lines(text).get("MemTotal")
    if not v:
        return None
    parts = v.split()
    n = _int(parts[0])
    if n is None:
        return None
    return n * 1024 if len(parts) > 1 and parts[1].lower() == "kb" else n


def parse_os_release(text):
    v = _kv_lines(text, "=").get("PRETTY_NAME")
    return v.strip().strip('"').strip("'") if v else None


def summarize_governors(govs):
    govs = [g.strip() for g in govs if g and g.strip()]
    if not govs:
        return None
    uniq = sorted(set(govs))
    if len(uniq) == 1:
        return uniq[0]
    return "mixed: " + ", ".join(f"{g}={govs.count(g)}" for g in uniq)


def _truthy(v):
    return v is not None and v.strip().lower() not in ("", "0", "false", "no")


def detect_ci(env):
    provider = None
    if env.get("GITHUB_ACTIONS") == "true":
        provider = "github-actions"
    elif _truthy(env.get("GITLAB_CI")):
        provider = "gitlab"
    elif _truthy(env.get("BUILDKITE")):
        provider = "buildkite"
    elif env.get("JENKINS_URL"):
        provider = "jenkins"
    elif _truthy(env.get("CI")):
        provider = "unknown"
    return {
        "is_ci": provider is not None,
        "provider": provider,
        "runner": env.get("RUNNER_NAME"),
        "runner_environment": env.get("RUNNER_ENVIRONMENT"),
    }


def pin_ok(describe, expected):
    return describe is not None and describe == expected


def fairness_warnings(f):
    w = []
    cpu = f.get("cpu") or {}
    gov = cpu.get("governor")
    if gov and gov != "performance":
        w.append(f"CPU frequency governor is '{gov}', not 'performance' "
                 "(see docs/BENCHMARK_COMPARISON.md, Fairness rules)")
    if cpu.get("hypervisor"):
        w.append(f"virtualised CPU ({cpu['hypervisor']}): noisy neighbours can skew results")
    ci = f.get("ci") or {}
    if ci.get("is_ci"):
        w.append(f"running on a CI runner ({ci.get('provider')}): shared hardware, "
                 "treat absolute numbers as indicative only")
    commits = f.get("commits") or {}
    rust = commits.get("algod_rust") or {}
    go = commits.get("go_algorand") or {}
    if rust.get("dirty"):
        w.append("algod-rust working tree has uncommitted changes")
    if go.get("dirty"):
        w.append("go-algorand working tree has uncommitted changes")
    if go.get("present") is False:
        w.append(f"no go-algorand checkout found: pin {go.get('expected_tag')} not verified "
                 "(fine for tiers that need no Go build, e.g. selftest)")
    elif go.get("pin_ok") is False:
        w.append(f"go-algorand checkout is at {go.get('describe')!r}, "
                 f"not the pinned {go.get('expected_tag')}")
    return w


# --------------------------------------------------------------------------
# collection (host-dependent)


def _run(cmd, cwd=None, timeout=20, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.strip() or None


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _cpu():
    cpu = {"model": None, "architecture": platform.machine() or None, "logical_cpus": None,
           "sockets": None, "physical_cores": None, "threads_per_core": None,
           "max_mhz": None, "hypervisor": None, "governor": None, "source": None}
    system = platform.system()
    if system == "Linux":
        lscpu = _run(["lscpu"], env=dict(os.environ, LC_ALL="C"))
        if lscpu:
            cpu.update({k: v for k, v in parse_lscpu(lscpu).items() if v is not None})
            cpu["source"] = "lscpu"
        info = _read("/proc/cpuinfo")
        if info:
            for k, v in parse_cpuinfo(info).items():
                if cpu.get(k) is None and v is not None:
                    cpu[k] = v
            cpu["source"] = cpu["source"] or "/proc/cpuinfo"
        govs = [_read(p) for p in
                glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")]
        cpu["governor"] = summarize_governors([g for g in govs if g])
    elif system == "Darwin":
        cpu["model"] = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        cpu["physical_cores"] = _int(_run(["sysctl", "-n", "hw.physicalcpu"]))
        cpu["source"] = "sysctl"
    if cpu["model"] is None:
        cpu["model"] = platform.processor() or None
    if cpu["logical_cpus"] is None:
        cpu["logical_cpus"] = os.cpu_count()
    cpu["source"] = cpu["source"] or "platform"
    return cpu


def _memory_bytes():
    system = platform.system()
    if system == "Linux":
        t = _read("/proc/meminfo")
        return parse_meminfo(t) if t else None
    if system == "Darwin":
        return _int(_run(["sysctl", "-n", "hw.memsize"]))
    if system == "Windows":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return int(m.ullTotalPhys)
        except (AttributeError, OSError):
            return None
    return None


def _os():
    distro = None
    if platform.system() == "Linux":
        t = _read("/etc/os-release")
        distro = parse_os_release(t) if t else None
    return {
        "system": platform.system() or None,
        "distro": distro or platform.platform(),
        "kernel": platform.release() or None,
        "machine": platform.machine() or None,
    }


def _toolchains():
    docker = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if docker is None:
        docker = _run(["docker", "--version"])
    return {
        "rustc": _run(["rustc", "-V"]),
        "cargo": _run(["cargo", "-V"]),
        "go": _run(["go", "version"]),
        "docker": docker,
        "python": platform.python_version(),
    }


def _git(repo):
    # No local path in the output: fingerprints get published (#2109) and a
    # path would only leak the operator's home directory.
    present = os.path.isdir(repo) and _run(["git", "-C", repo, "rev-parse", "--git-dir"]) is not None
    if not present:
        return {"present": False, "commit": None, "describe": None, "dirty": None}
    status = _run(["git", "-C", repo, "status", "--porcelain", "--untracked-files=no"])
    return {
        "present": True,
        "commit": _run(["git", "-C", repo, "rev-parse", "HEAD"]),
        "describe": _run(["git", "-C", repo, "describe", "--tags", "--always"]),
        "dirty": bool(status),
    }


def collect(repo_root, go_algorand_dir, expected_tag, env=None):
    env = os.environ if env is None else env
    go = _git(go_algorand_dir)
    go["expected_tag"] = expected_tag
    go["pin_ok"] = pin_ok(go["describe"], expected_tag)
    f = {
        "schema": SCHEMA,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cpu": _cpu(),
        "memory": {"total_bytes": _memory_bytes()},
        "os": _os(),
        "toolchains": _toolchains(),
        "commits": {"algod_rust": _git(repo_root), "go_algorand": go},
        "ci": detect_ci(env),
    }
    f["warnings"] = fairness_warnings(f)
    return f


def main(argv=None):
    repo_default = os.path.dirname(os.path.dirname(HERE))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--output", help="write JSON here (default: stdout)")
    ap.add_argument("--repo-root", default=repo_default)
    ap.add_argument("--go-algorand", default=os.environ.get(
        "GO_ALGORAND_DIR", os.path.join(os.path.dirname(repo_default), "go-algorand")))
    ap.add_argument("--expected-tag", default=os.environ.get("GO_ALGORAND_REV") or read_pin())
    args = ap.parse_args(argv)
    f = collect(args.repo_root, args.go_algorand, args.expected_tag)
    text = json.dumps(f, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
