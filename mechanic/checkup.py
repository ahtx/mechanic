"""`mechanic checkup`: a read-only health check with recommendations ("recommendation mode").

Read-only by design:
  - The collectors run only the fixed commands in ALLOWED (argument lists, no shell), through one function, run_fixed().
    run_fixed() refuses any program that is not in ALLOWED.
  - The model gets each section as text and answers with text. Its suggested commands are printed for a human.
    Nothing in this module passes model output to a shell, to subprocess, or to run_fixed().
Secrets (keys, tokens, passwords on command lines, private keys) are masked before data goes to the model and
before the report is written. IP addresses, users and host names are kept, because the report needs them.
"""
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time

from . import __version__, config
from .redact import Redactor

# program -> the only reason it may run. Every collector command starts with one of these.
ALLOWED = {
    "journalctl": "read the system journal",
    "df": "file system usage",
    "du": "directory sizes",
    "ps": "process list",
    "systemctl": "list failed units (systemctl --failed)",
    "free": "memory use",
    "swapon": "swap devices (--show)",
    "ss": "sockets",
    "uptime": "load average",
    "nproc": "CPU count",
    "man": "read the documentation of a suggested command (man -P cat)",
}
# read-only argument patterns for programs that can also change things
SAFE_ARGS = {"systemctl": [["--failed"], ["is-system-running"]], "swapon": [["--show"]], "man": [["-P", "cat"]]}
# options that would change something, refused even for allow-listed programs
DENY_ARGS = re.compile(r"^(--vacuum|--rotate|--flush|--sync|--relinquish-var|--smart-relinquish-var|--setup-keys|"
                       r"--update-catalog|-K$|--kill$|--delete)")
LOG_FILES = ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure", "/var/log/kern.log",
             "/var/log/nginx/error.log", "/var/log/apache2/error.log", "/var/log/httpd/error_log"]
SECTION_LIMIT = 6000           # characters of collected text per section, sent to the model
LINE_LIMIT = 60                # distinct log lines kept per source
WARN = re.compile(r"(?i)\b(error|fail(ed|ure)?|denied|invalid|refused|warn(ing)?|crit(ical)?|alert|emerg|panic|"
                  r"oom|out of memory|killed process|segfault|timed? ?out|unreachable|corrupt|no space)\b")
SELF = re.compile(r"\basciinema\b|-m mechanic\b|/mechanic (checkup|schedule)|\bmechanic (checkup|schedule)\b")
COMMON_PORTS = {22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 631, 993, 995, 3306, 5432, 6379, 8080, 8443, 11211, 27017}

SYSTEM = ("You are a careful Linux system administrator. You get one section of a read-only health report from a "
          "server. Report only problems that the data shows. Number the problems 1, 2, 3. For each problem write:\n"
          "1. Finding: what you see, with the numbers from the data\n"
          "   Why it matters: one sentence\n"
          "   Command: one exact command a human could run to look closer or to fix it\n"
          "   Risk: low, medium or high (the risk of running that command)\n"
          "List at most 3 problems, most important first, and each problem only once. If nothing needs attention, "
          "reply exactly: No issues found.")


class NotAllowed(RuntimeError):
    pass


def run_fixed(argv, timeout=20):
    """Run one allow-listed, read-only command. Returns (exit code, output). Never uses a shell."""
    prog = argv[0]
    if prog not in ALLOWED:
        raise NotAllowed("checkup does not run %r" % prog)
    if prog in SAFE_ARGS and not any(argv[1:1 + len(a)] == a for a in SAFE_ARGS[prog]):
        raise NotAllowed("checkup runs %s only as: %s" % (prog, SAFE_ARGS[prog]))
    bad = [a for a in argv[1:] if DENY_ARGS.match(a)]
    if bad:
        raise NotAllowed("checkup does not pass %s to %s" % (bad, prog))
    if not shutil.which(prog):
        return 127, "(%s is not installed)" % prog
    env = dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="", PAGER="cat", SYSTEMD_COLORS="0")
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b"").decode("utf-8", "replace") + "\n(stopped after %d s)" % timeout
    except OSError as e:
        return 126, str(e)


def read_tail(path, max_bytes=2_000_000):
    """The last part of a log file (read-only open)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
        return data.split("\n", 1)[1] if size > max_bytes and "\n" in data else data
    except OSError:
        return None


# ------------------------------------------------------------------ text helpers
STAMP = re.compile(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?|"
                   r"\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\s+")


def normalize(line):
    """Strip the timestamp and process ids, so that repeated messages collapse into one."""
    s = STAMP.sub("", line.strip())
    s = re.sub(r"\[\d+\]", "", s)                    # sshd[1234] -> sshd
    s = re.sub(r"\b(\d+#\d+)\b", "", s)              # nginx 123#123
    s = re.sub(r"\bport \d+\b", "port N", s)
    s = re.sub(r"\*\d+ ", "", s)                     # nginx connection ids
    return re.sub(r"\s+", " ", s).strip()


def dedupe(lines, limit=LINE_LIMIT, only_warn=False):
    """Repeated lines -> one line with a count, most frequent first."""
    c = collections.Counter()
    first = {}
    for l in lines:
        if not l.strip() or (only_warn and not WARN.search(l)):
            continue
        k = normalize(l)
        if k:
            c[k] += 1
            first.setdefault(k, len(first))
    items = sorted(c.items(), key=lambda kv: (-kv[1], first[kv[0]]))
    out = ["%5dx  %s" % (n, k[:300]) for k, n in items[:limit]]
    if len(items) > limit:
        out.append("(%d more distinct lines)" % (len(items) - limit))
    return out


def cap(text, limit=SECTION_LIMIT):
    return text if len(text) <= limit else text[:limit] + "\n(cut: %d more characters)" % (len(text) - limit)


def human(kb):
    for unit in ("K", "M", "G", "T"):
        if kb < 1024:
            return "%.0f%s" % (kb, unit) if unit == "K" else "%.1f%s" % (kb, unit)
        kb /= 1024.0
    return "%.1fP" % kb


# ------------------------------------------------------------------ collectors
class Collector:
    def __init__(self, runner=run_fixed, reader=read_tail, du_timeout=30):
        self.run = runner
        self.read = reader
        self.du_timeout = du_timeout

    def block(self, title, argv, timeout=20):
        rc, out = self.run(argv, timeout)
        return "### %s\n$ %s\n%s" % (title, " ".join(argv), out.rstrip() or "(no output)")

    def logs(self):
        parts = []
        rc, out = self.run(["journalctl", "--since", "24 hours ago", "-p", "warning..emerg", "--no-pager", "-o",
                            "short-iso", "-n", "20000"], 30)
        lines = out.splitlines()
        if rc == 0 and lines and not lines[0].startswith("-- No entries"):
            parts.append("### journal, priority warning or worse, last 24 h (%d lines)\n%s"
                         % (len(lines), "\n".join(dedupe(lines))))
        else:
            parts.append("### journal\n%s" % (out.strip()[:300] or "(no entries)"))
        rc, out = self.run(["journalctl", "--since", "24 hours ago", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10",
                            "--no-pager", "-o", "short-iso", "-n", "20000"], 30)
        lines = [l for l in out.splitlines() if not l.startswith("-- ")]
        d = dedupe(lines, only_warn=True)
        if rc == 0 and d:
            parts.append("### journal, login and authentication messages, last 24 h\n%s" % "\n".join(d))
        for path in LOG_FILES:
            data = self.read(path)
            if data is None:
                continue
            lines = data.splitlines()[-20000:]
            d = dedupe(lines, only_warn=True)
            parts.append("### %s (warning-like lines among the last %d)\n%s" % (path, len(lines), "\n".join(d) or "(none)"))
        return cap("\n\n".join(parts))

    def disk(self):
        parts = []
        for flag in ("-h", "-i"):
            argv = ["df", flag, "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"]
            rc, out = self.run(argv, 20)
            # drop runtime mounts (/run, /dev, /sys) and single files bind-mounted by container runtimes
            # (/etc/hosts, /etc/resolv.conf); keep tmpfs volumes such as /tmp or /var/log
            keep = [l for l in out.splitlines()
                    if not re.search(r"\s(/run|/dev|/sys|/proc)(/\S*)?$|\s/etc/\S+$", l)]
            parts.append("### df %s\n$ %s\n%s" % (flag, " ".join(argv), "\n".join(keep) or "(no output)"))
        for top in ("/var", "/var/log", "/home", "/tmp"):
            rc, out = self.run(["du", "-x", "-k", "-d", "2", top], self.du_timeout)
            rows = []
            for l in out.splitlines():
                m = re.match(r"^(\d+)\s+(/.*)$", l)
                if m:
                    rows.append((int(m.group(1)), m.group(2)))
            rows.sort(reverse=True)
            note = " (stopped after %d s; partial)" % self.du_timeout if rc == 124 else ""
            parts.append("### largest directories under %s%s\n%s" % (
                top, note, "\n".join("%8s  %s" % (human(k), p) for k, p in rows[:12]) or "(none)"))
        return cap("\n\n".join(parts))

    def processes(self):
        parts = [self.block("uptime", ["uptime"]), self.block("CPUs", ["nproc"])]
        fmt = "pid,user,%cpu,%mem,rss,etime,args"
        for key, title in (("-%cpu", "top CPU"), ("-%mem", "top memory")):
            rc, out = self.run(["ps", "-eo", fmt, "--sort=" + key], 20)
            own = {str(os.getpid()), str(os.getppid())}
            # leave out checkup itself and a terminal recorder around it
            lines = [l for l in out.splitlines() if not (l.split() and l.split()[0] in own) and not SELF.search(l)]
            parts.append("### %s\n%s" % (title, "\n".join(l[:200] for l in lines[:11])))
        rc, out = self.run(["ps", "-eo", "pid,ppid,stat,etime,args"], 20)
        z = [l for l in out.splitlines()[1:] if len(l.split()) > 2 and l.split()[2].startswith("Z")]
        parts.append("### zombie processes\n%s" % ("\n".join(z[:20]) or "(none)"))
        rc, out = self.run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"], 20)
        parts.append("### failed systemd units\n%s" % (out.strip() or "(none)"))
        return cap("\n\n".join(parts))

    def memory(self):
        parts = [self.block("free -m", ["free", "-m"]), self.block("swap", ["swapon", "--show"])]
        rc, out = self.run(["journalctl", "-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso",
                            "--grep", "Out of memory|oom-kill|Killed process"], 30)
        lines = [l for l in out.splitlines() if not l.startswith("-- ")]
        if rc != 0 and not lines:
            data = self.read("/var/log/kern.log") or ""
            lines = [l for l in data.splitlines()[-20000:] if re.search(r"(?i)out of memory|oom-kill|killed process", l)]
        parts.append("### OOM kills, last 24 h\n%s" % ("\n".join(dedupe(lines, 20)) or "(none)"))
        return cap("\n\n".join(parts))

    def network(self):
        rc, listen = self.run(["ss", "-H", "-tulpn"], 20)
        parts = ["### listening sockets\n$ ss -tulpn\n%s" % (listen.strip() or "(none)")]
        odd = []
        for l in listen.splitlines():
            f = l.split()
            if len(f) < 5:
                continue
            local = f[4]
            m = re.match(r"^(.*):(\d+)$", local)
            if not m:
                continue
            addr, port = m.group(1), int(m.group(2))
            if addr.startswith("127.") or addr in ("[::1]", "::1") or "%lo" in addr:
                continue
            if port not in COMMON_PORTS and port >= 1024:
                odd.append("%s %s %s" % (f[0], local, " ".join(f[6:])[:120]))
        parts.append("### listeners on uncommon ports, reachable from outside (check these)\n%s" % ("\n".join(odd) or "(none)"))
        rc, est = self.run(["ss", "-H", "-tn", "state", "established"], 20)
        peers = collections.Counter()
        for l in est.splitlines():
            f = l.split()
            if len(f) >= 4:
                peers[re.sub(r":\d+$", "", f[3])] += 1
        parts.append("### established TCP connections by remote address (%d total)\n%s" % (
            sum(peers.values()), "\n".join("%5d  %s" % (n, a) for a, n in peers.most_common(15)) or "(none)"))
        return cap("\n\n".join(parts))

    SECTIONS = (("Logs, last 24 hours", "logs"), ("Disk", "disk"), ("Processes and services", "processes"),
                ("Memory", "memory"), ("Network", "network"))


# ------------------------------------------------------------------ review of the model's suggestions
LEVELS = ["low", "medium", "high"]
SHELL_WORDS = {"echo", "cat", "grep", "egrep", "sort", "uniq", "head", "tail", "wc", "awk", "sed", "cut", "tr", "xargs",
               "sudo", "less", "test", "[", "true", "false", "printf", "env", "time", "watch", "timeout"}
VALUE_ARG = re.compile(r"(?i)^<?(port|num|number|count|seconds?|secs|size|lines|bytes|pid|uid|gid|n|interval|timeout)>?$")


def risk_floor(cmd):
    """The lowest risk mechanic accepts for a suggested command, by fixed rules. Returns (level, reason)."""
    from .shellparse import redirect_targets, simple_commands
    level, why = "low", ""

    def up(lv, reason):
        nonlocal level, why
        if LEVELS.index(lv) > LEVELS.index(level):
            level, why = lv, reason

    for prog, args, text in simple_commands(cmd):
        a = " ".join(args)
        if prog in ("iptables", "ip6tables", "nft", "ufw", "firewall-cmd"):
            if re.search(r"(?i)\b(DROP|REJECT|deny|flush|-F|-P|--policy|delete|-D|reset|reject)\b", a) or "-j DROP" in a:
                up("high", "%s can cut network access" % prog)
            elif not re.search(r"(^|\s)(-L|-S|--list|list|status|-n)(\s|$)", a) or re.search(r"(^|\s)-[AIR](\s|$)", a):
                up("medium", "%s changes firewall rules" % prog)
        elif prog in ("rm", "shred", "unlink", "rmdir", "dd", "truncate", "wipefs") or prog.startswith("mkfs"):
            up("high", "%s deletes or overwrites data" % prog)
        elif prog == "find" and ("-delete" in args or "-exec" in args):
            up("high", "find -delete/-exec can delete data")
        elif prog in ("ip", "ifdown", "nmcli") and re.search(r"\b(down|del|delete|flush)\b", a):
            up("high", "%s can cut network access" % prog)
        elif prog in ("reboot", "shutdown", "poweroff", "halt"):
            up("high", "%s stops the machine" % prog)
        elif prog in ("systemctl", "service") and re.search(r"\b(stop|disable|mask|restart|kill|reload|try-restart|"
                                                              r"isolate|enable|start)\b", a):
            up("high" if re.search(r"\b(ssh|sshd|networking|NetworkManager|systemd-networkd)\b", a)
               and re.search(r"\b(stop|disable|mask|kill)\b", a) else "medium",
               "systemctl changes a service")
        elif prog in ("kill", "pkill", "killall"):
            up("medium", "%s stops processes" % prog)
        elif prog in ("apt", "apt-get", "dnf", "yum", "zypper", "snap", "pip", "pip3") and re.search(
                r"\b(remove|purge|autoremove|clean|autoclean|install|upgrade|dist-upgrade|erase)\b", a):
            up("high" if re.search(r"\b(purge|autoremove)\b", a) else "medium", "%s changes installed packages" % prog)
        elif prog == "sed" and re.search(r"(^|\s)(-i|--in-place)", a):
            up("medium", "sed -i edits a file")
        elif prog in ("tee", "mv", "cp", "chmod", "chown", "chgrp", "ln", "crontab", "useradd", "userdel", "usermod",
                      "passwd", "sysctl", "swapon", "swapoff", "mount", "umount", "logrotate", "journalctl"):
            if prog == "journalctl" and not re.search(r"--vacuum|--rotate|--flush", a):
                continue
            if prog == "crontab" and not re.search(r"(^|\s)-(e|r)\b", a):
                continue
            if prog == "sysctl" and "-w" not in args:
                continue
            if prog in ("swapon", "mount") and (not args or a.strip() in ("--show", "-s")):
                continue
            up("medium", "%s changes the system" % prog)
    for path, mode in redirect_targets(cmd):
        up("medium" if mode == "append" else "high", "the command writes to %s" % path)
    return level, why


class SuggestionChecker:
    """Checks a suggested command against the local documentation, only through run_fixed (`man`)."""

    def __init__(self, runner=None):
        self.run = runner or run_fixed
        self.cache = {}
        self.unchecked = []

    def docs(self, prog):
        if prog not in self.cache:
            rc, out = self.run(["man", "-P", "cat", prog], 20)
            self.cache[prog] = out if rc == 0 and "No manual entry" not in out else ""
        return self.cache[prog]

    def problems(self, cmd):
        from .flags import MIN_OPTS, flag_ok, mentioned, options
        from .shellparse import simple_commands
        found = []
        self.unchecked = []
        for prog, args, _ in simple_commands(cmd):
            if prog in SHELL_WORDS or not prog:
                continue
            if self.run is run_fixed and not shutil.which(prog) and not os.path.exists("/usr/sbin/" + prog):
                found.append("`%s` is not installed here" % prog)
                continue
            text = self.docs(prog)
            opts = options(text)
            if len(opts) < MIN_OPTS:
                if any(a.startswith("-") and len(a) > 1 for a in args):
                    self.unchecked.append(prog)       # options we cannot check: shown, but marked
                continue
            for k, a in enumerate(args):
                if a == "--":
                    break
                if not a.startswith("-") or len(a) < 2 or " " in a or re.match(r"^-\d", a):
                    continue
                if not (flag_ok(a, opts) or mentioned(a, text)):
                    found.append("`%s` has no option `%s`" % (prog, a.split("=", 1)[0]))
                    continue
                # an option documented with a numeric argument (for example "-p port") must get a number
                m = re.search(r"(?m)^\s*(?:-\w, )?" + re.escape(a) + r"[ =]([<\w>-]+)", text)
                if m and VALUE_ARG.match(m.group(1)) and k + 1 < len(args) and "=" not in a:
                    val = args[k + 1]
                    if not re.match(r"^[\d.,:%a-z]*\d[\d.,:%a-z]*$", val, re.I):
                        found.append("`%s %s` expects %s, not `%s`" % (prog, a, m.group(1).strip("<>"), val))
        return found


CMD_LINE = re.compile(r"^(\s*)Command:\s*(.*)$")
RISK_LINE = re.compile(r"^(\s*)Risk:\s*(low|medium|high)?(.*)$", re.I)


def clean_command(s):
    m = re.search(r"`([^`]+)`", s)
    s = m.group(1) if m else s
    s = re.sub(r"\s+\((?:to|read-only|this|that|if|only|confirm)[^)]*\)\s*$", "", s).strip()
    if len(s) > 1 and s[0] == s[-1] and s[0] in "\"'":          # the whole command in quotes
        s = s[1:-1].strip()
    return s


FIND_START = re.compile(r"^\s*\d+[.)]\s*(?:\*\*)?Finding:?(?:\*\*)?\s*(.*)$", re.I)
FIELD = re.compile(r"^\s*(?:\*\*)?(Why it matters|Command|Risk):?(?:\*\*)?\s*(.*)$", re.I)


def parse_findings(text):
    """Split the model's answer into findings: [{'finding', 'why', 'command', 'risk'}]. Lines before the first
    finding are ignored; a line that is not a field continues the previous field."""
    items, cur, field = [], None, None
    for line in text.splitlines():
        m = FIND_START.match(line)
        if m:
            cur = {"finding": m.group(1).strip(), "why": "", "command": "", "risk": ""}
            items.append(cur)
            field = "finding"
            continue
        if cur is None or not line.strip():
            continue
        m = FIELD.match(line)
        if m:
            field = {"why it matters": "why", "command": "command", "risk": "risk"}[m.group(1).lower()]
            cur[field] = m.group(2).strip()
        elif field:
            cur[field] = (cur[field] + " " + line.strip()).strip()
    return items


def finding_keys(f):
    """What a finding is about: units, PIDs, ports, IP addresses and paths it names. Two findings that share one of
    these are about the same thing."""
    s = f["finding"]
    keys = set()
    keys |= {"unit:" + u for u in re.findall(r"\b[\w@.-]+\.(?:service|timer|socket|mount|target)\b", s)}
    keys |= {"pid:" + p for p in re.findall(r"(?i)\bpid[ =:]*(\d+)", s)}
    keys |= {"port:" + p for p in re.findall(r"(?i)(?:\bport\s+|:)(\d{2,5})\b", s) if int(p) < 65536}
    keys |= {"ip:" + a for a in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)}
    keys |= {"path:" + p.rstrip(".,;:)") for p in re.findall(r"(?<![\w.])/[\w./-]+", s) if p.count("/") >= 2}
    keys = {k for k in keys if not k.startswith("ip:0.0.0.0")}
    return keys


def merge_duplicates(items):
    """Merge findings that share a unit, PID, port, IP address or path. The merged finding keeps the higher risk and
    the first verified command."""
    out = []
    for f in items:
        keys = finding_keys(f)
        twin = next((g for g in out if keys & g["_keys"]), None) if keys else None
        if twin is None:
            f["_keys"] = set(keys)
            f.setdefault("merged", 0)
            out.append(f)
            continue
        twin["_keys"] |= keys
        twin["merged"] = twin.get("merged", 0) + 1
        if LEVELS.index(f["level"]) > LEVELS.index(twin["level"]):
            twin["level"], twin["risk"] = f["level"], f["risk"]
        if twin["command"].startswith("[unverified") and f["command"] and not f["command"].startswith("[unverified"):
            twin["command"] = f["command"]
    return out


def render(items):
    lines = []
    for i, f in enumerate(items, 1):
        lines.append("%d. Finding: %s%s" % (i, f["finding"], "  [%d duplicate merged]" % f["merged"]
                                             if f.get("merged") == 1 else "  [%d duplicates merged]" % f["merged"]
                                             if f.get("merged") else ""))
        if f["why"]:
            lines.append("   Why it matters: " + f["why"])
        if f["command"]:
            lines.append("   Command: " + f["command"])
        lines.append("   Risk: " + f["risk"])
        lines.append("")
    return "\n".join(lines).rstrip()


def review(text, checker=None):
    """Apply mechanic's rules to the model's findings, deterministically:
    - each suggested command is checked against its man page (hidden if invalid, marked if it cannot be checked);
    - a risk is never lower than the rule floor for its command; a missing risk becomes the floor, or medium;
    - findings about the same unit, PID, port, address or path are merged.
    Returns (text, changes, findings). If the answer has no findings, the text is returned unchanged."""
    checker = checker or SuggestionChecker()
    items, changes = parse_findings(text), []
    if not items:
        return text, changes, []
    for f in items:
        cmd = clean_command(f["command"]) if f["command"] else ""
        floor = risk_floor(cmd) if cmd else ("low", "")
        if cmd:
            probs = checker.problems(cmd)
            if probs:
                f["command"] = "[unverified, not shown: %s]" % "; ".join(probs)
                changes.append("hid an unverified command: %s" % "; ".join(probs))
            elif getattr(checker, "unchecked", None):
                f["command"] += "  [options not checked: no local man page for %s]" % ", ".join(
                    sorted(set(checker.unchecked)))
                changes.append("marked a command whose options could not be checked")
        m = re.match(r"(?i)\s*(low|medium|high)\b", f["risk"])
        given = m.group(1).lower() if m else ""
        if not given:
            level = floor[0] if floor[0] != "low" else "medium"
            f["risk"] = "%s (mechanic's rules: %s)" % (level, floor[1] if floor[0] != "low" else "no risk was given")
            changes.append("set a missing risk to %s" % level)
        elif LEVELS.index(given) < LEVELS.index(floor[0]):
            level = floor[0]
            f["risk"] = "%s (mechanic's rules: %s; the model said %s)" % (level, floor[1], given)
            changes.append("raised risk to %s: %s" % (level, floor[1]))
        else:
            level = given
        f["level"] = level
    before = len(items)
    items = merge_duplicates(items)
    if len(items) < before:
        changes.append("merged %d duplicate findings" % (before - len(items)))
    return render(items), changes, items


def build_summary(section_findings):
    """The overall summary, built in code from every finding of every section (after merging across sections), most
    risky first. Nothing is dropped."""
    allf = []
    for title, items in section_findings:
        for f in items:
            g = dict(f, section=title)
            allf.append(g)
    merged = merge_duplicates([dict(f, merged=0) for f in allf])
    order = {t: i for i, (t, _) in enumerate(section_findings)}
    merged.sort(key=lambda f: (-LEVELS.index(f["level"]), order.get(f["section"], 99)))
    lines = []
    for i, f in enumerate(merged, 1):
        text = re.split(r"(?<=[.!?])\s", f["finding"], 1)[0]
        text = text if len(text) <= 160 else text[:157] + "..."
        lines.append("%d. [%s] %s: %s" % (i, f["level"], f["section"], text))
    return "\n".join(lines) or "No issues found."


# ------------------------------------------------------------------ the check
def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.environ.get("MECHANIC_STATE") or os.path.join(base, "mechanic")


class Checkup:
    def __init__(self, client, term, collector=None, redactor=None, quiet=False, checker=None):
        self.client = client
        self.term = term
        self.col = collector or Collector()
        self.red = redactor or Redactor(use_local=False)
        self.quiet = quiet
        self.checker = checker or SuggestionChecker()
        self.changes = []

    def ask(self, system, text, max_tokens=700):
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": text}]
        old = self.client.max_tokens
        self.client.max_tokens = max_tokens
        try:
            return (self.client.chat(msgs)["content"] or "").strip()
        finally:
            self.client.max_tokens = old

    def run(self, host_label=None):
        t = self.term
        started = time.strftime("%Y-%m-%d %H:%M")
        host = host_label or (os.uname().nodename if hasattr(os, "uname") else "this machine")
        md = ["# mechanic checkup: %s, %s" % (host, started), "",
              "Read-only health check by mechanic %s. Suggested commands were not run." % __version__, ""]
        findings = []
        for title, name in Collector.SECTIONS:
            raw = self.red.secrets(getattr(self.col, name)())
            if not self.quiet:
                t.say()
                t.say("== %s " % title + "=" * max(3, 70 - len(title)), "cmd")
                t.say(raw, "dim")
            items = []
            try:
                rec = self.red.secrets(self.ask(SYSTEM, "Section: %s\n\n%s" % (title, raw)))
                rec, changes, items = review(rec, self.checker)
                self.changes += changes
            except Exception as e:           # endpoint errors: keep the data, say what failed
                rec = "(the model did not answer: %s)" % e
            findings.append((title, items))
            if not self.quiet:
                t.say()
                t.say("Mechanic recommends:", "warn")
                t.say(rec, "model")
            md += ["## %s" % title, "", "```text", raw, "```", "", "**Mechanic recommends:**", "", rec, ""]
        summary = build_summary(findings)        # built from every finding, most risky first; nothing dropped
        t.say()
        t.say("== Summary " + "=" * 60, "cmd")
        t.say(summary, "model")
        md[4:4] = ["## Summary", "", summary, ""]
        if self.changes:
            md[4:4] = ["mechanic's rules changed %d suggestions: %s." % (len(self.changes), "; ".join(self.changes)), ""]
        path = self.save("\n".join(md))
        t.say()
        t.say("Report: " + path, "dim")
        return path, summary, findings

    def save(self, text):
        d = os.path.join(state_dir(), "reports")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, time.strftime("%Y-%m-%d-%H%M") + ".md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path


def post_webhook(url, path, summary):
    """Optional: POST {report, summary} as JSON to a webhook (for example a chat incoming-webhook)."""
    import urllib.request
    body = json.dumps({"text": "mechanic checkup: " + summary, "report": path}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status
