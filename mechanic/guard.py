"""Safety guard: find what a proposed command can delete, overwrite, stop or kill, and list it.

analyze(cmd, named_text) returns a list of Risk records. Each record names the action, the targets, what the
targets expand to on this machine (files that a glob matches, the process behind a PID, ...), and whether the user
named the target. A target counts as named when its path, a parent directory of it, its file name, or (for
processes and services) its name appears in the user's own messages.

The guard reads the system (glob, os.stat, /proc, pgrep, a `find` preview) but never changes it.
"""
import fnmatch
import glob
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field

from .shellparse import redirect_targets, simple_commands

LIST_MAX = 10


@dataclass
class Risk:
    action: str                 # "delete", "overwrite", "kill", "stop service", ...
    program: str
    targets: list               # what the command names
    affected: list = field(default_factory=list)   # what that expands to here (files, processes)
    unnamed: list = field(default_factory=list)    # targets the user did not name
    note: str = ""

    def describe(self):
        head = "%s (%s): %s" % (self.action, self.program, ", ".join(self.targets) or "(no explicit target)")
        lines = [head]
        if self.affected:
            lines.append("  affects: " + "; ".join(self.affected[:LIST_MAX]) +
                         (" ... and %d more" % (len(self.affected) - LIST_MAX) if len(self.affected) > LIST_MAX else ""))
        if self.note:
            lines.append("  note: " + self.note)
        if self.unnamed:
            lines.append("  NOT NAMED IN YOUR REQUEST: " + ", ".join(self.unnamed))
        return "\n".join(lines)


def _expand_paths(paths, cwd=None):
    out = []
    for p in paths:
        q = os.path.expanduser(p)
        if cwd and not os.path.isabs(q):
            q = os.path.join(cwd, q)
        hits = sorted(glob.glob(q)) if any(c in q for c in "*?[") else ([q] if os.path.lexists(q) else [])
        if not hits:
            out.append("%s (does not exist now)" % p)
        for h in hits:
            if os.path.isdir(h) and not os.path.islink(h):
                n = 0
                for _, ds, fs in os.walk(h):
                    n += len(fs) + len(ds)
                    if n > 100000:
                        break
                out.append("%s/ (directory, %s entries inside)" % (h, n if n <= 100000 else "more than 100000"))
            else:
                try:
                    out.append("%s (%d bytes)" % (h, os.lstat(h).st_size))
                except OSError:
                    out.append(h)
    return out


def _proc(pid):
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            c = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        return "PID %s: %s" % (pid, c[:160] or "(kernel thread)")
    except OSError:
        return "PID %s (no such process now)" % pid


def _pgrep(pattern, full=False):
    try:
        p = subprocess.run(["pgrep", "-a"] + (["-f"] if full else []) + ["--", pattern], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=5)
        lines = p.stdout.decode("utf-8", "replace").splitlines()
        return ["PID " + l[:170] for l in lines] or ["(no matching process now)"]
    except (OSError, subprocess.SubprocessError):
        return []


def _unit_state(unit):
    try:
        p = subprocess.run(["systemctl", "is-active", unit], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=5)
        return "%s (now %s)" % (unit, p.stdout.decode().strip() or "unknown")
    except (OSError, subprocess.SubprocessError):
        return unit


def _find_preview(args, cwd=None):
    """Run the same find without its -delete / -exec rm action, to list what it would delete."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "-delete":
            i += 1
            continue
        if a in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < len(args) and args[j] not in (";", "+"):
                j += 1
            if a.startswith("-ok") or (i + 1 < len(args) and os.path.basename(args[i + 1]) not in ("rm", "unlink", "shred")):
                return None              # another action: do not run a preview
            i = j + 1
            continue
        if a in ("-fprint", "-fprint0", "-fprintf", "-fls"):
            return None
        out.append(a)
        i += 1
    try:
        out = [a for a in out if a not in ("-print", "-print0", "-ls")]
        p = subprocess.run(["find"] + out + ["-print"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
                           cwd=cwd)
        return list(dict.fromkeys(p.stdout.decode("utf-8", "replace").splitlines()))
    except (OSError, subprocess.SubprocessError):
        return None


def _nonopts(args, value_opts=()):
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in value_opts:
            skip = True
            continue
        if a.startswith("-") and a != "-":
            continue
        out.append(a)
    return out


def _named(target, named_text):
    """Did the user name this target (or a directory that contains it)?"""
    t = target.rstrip("/")
    if not t:
        return False
    if t in named_text:
        return True
    base = os.path.basename(t)
    if base and len(base) > 2 and re.search(r"(?<![\w.-])" + re.escape(base) + r"(?![\w-])", named_text):
        return True
    for p in re.findall(r"(?:~|/)[\w./~-]*", named_text):
        p = p.rstrip("/.,;:")
        if len(p) > 1 and (t == p or t.startswith(p + "/")):
            return True
    for g in re.findall(r"[\w./~-]*[*?][\w./*?-]*", named_text):     # globs the user wrote, such as *.log
        if fnmatch.fnmatch(base, os.path.basename(g)) or fnmatch.fnmatch(t, g):
            return True
    stem = re.split(r"[*?\[]", t)[0].rstrip("/")
    return bool(stem) and stem != t and _named(stem, named_text)


def analyze(cmd, named_text="", cwd=None):
    risks = []

    def add(action, prog, targets, affected=None, note="", check_named=True):
        targets = [t for t in targets if t]
        unnamed = [t for t in targets if check_named and not _named(t, named_text)]
        risks.append(Risk(action, prog, targets, affected or [], unnamed, note))

    for prog, args, text in simple_commands(cmd):
        rec = "-r" in args or "-R" in args or "--recursive" in args or any(
            re.match(r"^-[a-zA-Z]*[rR][a-zA-Z]*$", a) for a in args)
        if prog in ("rm", "unlink", "shred", "rmdir"):
            paths = _nonopts(args)
            add("delete" + (" recursively" if rec and prog == "rm" else ""), prog, paths, _expand_paths(paths, cwd))
        elif prog == "mv" or prog == "cp" or prog == "rsync" and "--delete" in " ".join(args):
            ps = _nonopts(args, ("-t", "--target-directory", "-S", "--suffix", "-e"))
            if prog == "rsync":
                add("delete extra files in destination", prog, ps[-1:], note="rsync --delete removes files that are "
                    "not in the source")
            elif len(ps) >= 2:
                dest = ps[-1]
                srcs = ps[:-1]
                if prog == "mv":
                    add("move away", prog, srcs, _expand_paths(srcs, cwd))
                over = []
                if os.path.isdir(os.path.expanduser(dest)):
                    for s in srcs:
                        d = os.path.join(os.path.expanduser(dest), os.path.basename(s.rstrip("/")))
                        if os.path.lexists(d):
                            over.append(d)
                elif os.path.lexists(os.path.expanduser(dest)):
                    over.append(dest)
                if over:
                    add("overwrite", prog, over, _expand_paths(over, cwd))
        elif prog == "truncate":
            ps = _nonopts(args, ("-s", "--size", "-r", "--reference"))
            add("truncate", prog, ps, _expand_paths(ps, cwd))
        elif prog == "tee" and not ({"-a", "--append"} & set(args)):
            ps = [p for p in _nonopts(args) if p != "/dev/null"]
            ex = [p for p in ps if os.path.lexists(os.path.expanduser(p))]
            if ex:
                add("overwrite", prog, ex, _expand_paths(ex, cwd))
        elif prog == "sed" and any(a == "-i" or a.startswith("-i") or a.startswith("--in-place") for a in args):
            ps = _nonopts(args, ("-e", "--expression", "-f", "--file"))
            if not any(a in ("-e", "--expression", "-f", "--file") for a in args):
                ps = ps[1:]                         # the first non-option word is the script
            add("edit in place", prog, ps, _expand_paths(ps, cwd))
        elif prog == "dd":
            outs = [a[3:] for a in args if a.startswith("of=")]
            add("overwrite", prog, outs, _expand_paths(outs, cwd))
        elif prog in ("mkfs", "wipefs", "fdisk", "sfdisk", "parted", "sgdisk", "blkdiscard") or prog.startswith("mkfs."):
            ps = _nonopts(args)
            add("change disk or partition", prog, ps[-1:] or ps)
        elif prog in ("chmod", "chown", "chgrp", "setfacl", "chattr") and rec:
            ps = _nonopts(args)[1:] if prog != "setfacl" else _nonopts(args, ("-m", "-x", "-M", "-X"))
            add("change permissions recursively", prog, ps, _expand_paths(ps, cwd))
        elif prog in ("ln",) and any(re.match(r"^-[a-zA-Z]*f", a) or a == "--force" for a in args):
            ps = _nonopts(args)
            if ps and os.path.lexists(os.path.expanduser(ps[-1])):
                add("replace", prog, ps[-1:], _expand_paths(ps[-1:], cwd))
        elif prog == "kill":
            pids = [a for a in args if re.match(r"^%?\d+$", a)]
            add("kill", prog, pids, [_proc(p.lstrip("%")) for p in pids], check_named=False)
            risks[-1].unnamed = [p for p in pids if p not in named_text]
        elif prog in ("pkill", "killall"):
            pats = _nonopts(args, ("-s", "--signal", "-u", "-U", "-g", "-G", "-t", "-P", "-n", "-o"))
            full = "-f" in args or "--full" in args
            aff = []
            for p in pats:
                aff += _pgrep(p, full)
            add("kill processes matching", prog, pats, aff)
        elif prog == "systemctl":
            ws = _nonopts(args)
            if ws and ws[0] in ("stop", "disable", "mask", "kill", "restart", "try-restart", "reload-or-restart",
                                "isolate", "reset-failed", "poweroff", "reboot", "halt", "suspend", "hibernate"):
                units = ws[1:]
                if ws[0] in ("poweroff", "reboot", "halt", "suspend", "hibernate"):
                    add(ws[0] + " the machine", prog, ["this machine"], check_named=False)
                    risks[-1].unnamed = [] if ws[0] in named_text else ["this machine"]
                else:
                    add(ws[0] + " service", prog, units, [_unit_state(u) for u in units])
        elif prog == "service" and len(args) >= 2 and args[1] in ("stop", "restart"):
            add(args[1] + " service", prog, args[:1])
        elif prog in ("reboot", "shutdown", "poweroff", "halt"):
            add(prog, prog, ["this machine"], check_named=False)
            risks[-1].unnamed = [] if prog in named_text else ["this machine"]
        elif prog == "crontab" and "-r" in args:
            user = args[args.index("-u") + 1] if "-u" in args and args.index("-u") + 1 < len(args) else "current user"
            add("delete crontab", prog, ["crontab of " + user])
            risks[-1].unnamed = [] if "cron" in named_text.lower() else risks[-1].targets
        elif prog in ("userdel", "groupdel", "deluser", "delgroup"):
            add("delete account", prog, _nonopts(args)[-1:])
        elif prog in ("iptables", "ip6tables") and any(a in ("-F", "--flush", "-X", "-D", "--delete", "-Z") for a in args):
            add("change firewall rules", prog, [" ".join(args)])
        elif prog == "nft" and any(a in ("flush", "delete", "destroy") for a in args):
            add("change firewall rules", prog, [" ".join(args)])
        elif prog in ("apt", "apt-get", "dnf", "yum") and any(a in ("remove", "purge", "autoremove", "erase") for a in args):
            ws = _nonopts(args)
            add("remove packages", prog, ws[1:] or ["(automatic)"])
        elif prog in ("docker", "podman") and any(a in ("rm", "rmi", "kill", "stop", "prune") for a in args):
            ws = _nonopts(args)
            add("remove or stop containers", prog, ws[1:] or ws)
        elif prog == "find" and ("-delete" in args or any(a in ("-exec", "-execdir") for a in args) and
                                 any(os.path.basename(a) in ("rm", "unlink", "shred") for a in args)):
            hits = _find_preview(args, cwd)
            roots = [a for a in args[:next((k for k, a in enumerate(args) if a.startswith("-")), len(args))]]
            add("delete", prog, roots or ["."], hits if hits is not None else [],
                note="" if hits is not None else "preview not run")
            if hits is not None:
                risks[-1].note = "%d paths match now (preview of the same find)" % len(hits)
    for path, mode in redirect_targets(cmd):
        if mode == "overwrite" and os.path.lexists(os.path.expanduser(path)):
            add("overwrite (>)", "shell", [path], _expand_paths([path], cwd))
    return risks


def summary(risks):
    return "\n".join(r.describe() for r in risks)


def quote(s):
    return shlex.quote(s)
