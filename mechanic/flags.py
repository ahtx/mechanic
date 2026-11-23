"""Flag checker: every option in a proposed command must exist in the program's local documentation.

The option parser follows the v27 training filter (options() and flag_ok()): an option counts as documented when a
man page or --help line starts with it. To keep false alarms low, an option that fails that test is still accepted
when it appears as a whole word anywhere in the documentation. A command is stopped only when the program has
documentation, the documentation lists at least MIN_OPTS options, and the option appears nowhere in it.
"""
import difflib
import os
import re
import shutil
import subprocess

from .shellparse import simple_commands

OPT = re.compile(r"(?:^|[\s,\[|])(--?[A-Za-z0-9?][A-Za-z0-9_-]*)")
MIN_OPTS = 3
# Never run `--help` on these: some of them act on the system when they do not understand an option.
NO_HELP_PROBE = {"reboot", "shutdown", "halt", "poweroff", "init", "telinit", "kexec", "systemctl-reboot",
                 "rm", "dd", "mkfs", "wipefs", "shred", "fdisk", "sfdisk", "parted", "sh", "bash", "zsh",
                 "dash", "python", "python3", "perl", "ruby", "node"}
# Shell builtins and programs whose dash words are not options (modes, numbers, signals, expressions).
SKIP_PROGRAMS = {"cd", "echo", "export", "read", "test", "[", "[[", "printf", "set", "source", ".", "trap",
                 "ulimit", "umask", "wait", "kill", "type", "alias", "declare", "local", "eval", "exit", "return",
                 "shift", "unset", "true", "false", "let", "pushd", "popd", "dirs", "hash", "history", "jobs",
                 "fg", "bg", "disown", "getopts", "readonly", "typeset", "bash", "sh", "zsh", "dash", "awk",
                 "gawk", "mawk", "python", "python3", "perl", "ruby", "node", "expr"}
# Programs whose first word is a subcommand with its own options (git commit -m, ip addr show, ...).
SUBCOMMAND_TOOLS = {"git", "systemctl", "ip", "docker", "podman", "apt", "apt-get", "apt-cache", "kubectl", "nmcli",
                    "ufw", "snap", "pip", "pip3", "npm", "cargo", "go", "openssl", "zfs", "zpool", "btrfs", "nft",
                    "tc", "bridge", "timedatectl", "hostnamectl", "loginctl", "resolvectl", "networkctl",
                    "localectl", "busctl", "journalctl", "gh", "helm", "virsh", "lxc", "machinectl", "dnf", "yum",
                    "zypper", "flatpak", "conda", "poetry", "terraform", "certbot", "lvm", "mdadm", "dpkg-query"}
MODE_LIKE = {"chmod": re.compile(r"^-[rwxXst]+$")}


def options(text):
    """Option names at the start of a help/man line (the lines that define options)."""
    opts = set()
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("-"):
            continue
        head = re.split(r"\s{2,}|\t", s, maxsplit=1)[0]
        for m in OPT.finditer(" " + head):
            o = m.group(1).rstrip("-")
            if len(o) > 1 and o != "--":
                opts.add(o)
    return opts


def flag_ok(tok, opts):
    if tok.startswith("--"):
        return tok.split("=", 1)[0] in opts
    if tok in opts or tok.split("=", 1)[0] in opts:
        return True
    chars = tok[1:]
    if all("-" + c in opts for c in chars):          # bundled short flags: -xzf
        return True
    return "-" + chars[0] in opts and not chars[1:].isalpha()   # attached value: -n5, -p8080


def mentioned(tok, text):
    """Lenient test: the option appears as a whole word anywhere in the documentation."""
    name = tok.split("=", 1)[0]
    if name.startswith("--") or len(name) == 2:
        return re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text) is not None
    # single dash, several letters: either a long single-dash option (find -name) or bundled short flags
    if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text):
        return True
    return all(re.search(r"(?<![\w-])-" + re.escape(c) + r"(?![\w-])", text) for c in name[1:])


class FlagChecker:
    def __init__(self, probe_help=True, timeout=5):
        self.probe_help = probe_help
        self.timeout = timeout
        self.cache = {}

    def _run(self, argv):
        env = dict(os.environ, LC_ALL="C", MANPAGER="cat", PAGER="cat", MANWIDTH="200", COLUMNS="200")
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=self.timeout, env=env)
            return p.stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            return ""

    def docs(self, prog, sub=None):
        """man page plus --help text for a program (or `program subcommand`). Cached."""
        key = (prog, sub)
        if key in self.cache:
            return self.cache[key]
        text = ""
        if shutil.which(prog):
            if shutil.which("man"):
                page = "%s-%s" % (prog, sub) if sub else prog
                man = self._run(["man", "-P", "cat", page])
                if "No manual entry" not in man:
                    text += man
            if self.probe_help and prog not in NO_HELP_PROBE:
                text += "\n" + self._run([prog] + ([sub] if sub else []) + ["--help"])
        self.cache[key] = text
        return text

    def check(self, cmd):
        """Problems in a command line: [{'program', 'flag', 'options', 'close'}]. Empty list = nothing to stop."""
        problems = []
        for prog, args, _ in simple_commands(cmd):
            if not prog or prog in SKIP_PROGRAMS:
                continue
            text = self.docs(prog)
            sub = next((a for a in args if not a.startswith("-")), None)
            if prog in SUBCOMMAND_TOOLS and sub and re.match(r"^[a-z][a-z0-9-]*$", sub):
                st = self.docs(prog, sub)
                if st:
                    text = text + "\n" + st
            opts = options(text)
            if len(opts) < MIN_OPTS:
                continue                          # no usable documentation: we cannot judge, so we do not stop
            skip_to = None
            for a in args:
                if skip_to:                       # find -exec ... ; is another program's command line
                    if a in skip_to:
                        skip_to = None
                    continue
                if prog == "find" and a in ("-exec", "-execdir", "-ok", "-okdir"):
                    skip_to = (";", "+")
                    continue
                if a == "--":
                    break
                if not a.startswith("-") or len(a) < 2 or " " in a or re.match(r"^-\d+([.,:]\d+)*[a-zA-Z%]?$", a):
                    continue
                if prog in MODE_LIKE and MODE_LIKE[prog].match(a):
                    continue
                if flag_ok(a, opts) or mentioned(a, text):
                    continue
                name = a.split("=", 1)[0]
                problems.append({"program": prog, "flag": name, "options": sorted(opts), "summary": help_summary(text),
                                 "close": difflib.get_close_matches(name, sorted(opts), n=5, cutoff=0.5)})
        return problems


def help_summary(text, n=40):
    """The NAME line plus the first n option-definition lines of a man page or --help text."""
    lines = text.splitlines()
    out = []
    for k, l in enumerate(lines):
        if l.strip() == "NAME" and k + 1 < len(lines):
            out.append(lines[k + 1].strip())
            break
    seen = 0
    for l in lines:
        if l.strip().startswith("-") and seen < n:
            out.append(l.rstrip())
            seen += 1
    return "\n".join(out)


def feedback(problems):
    """The text that goes back to the model in place of command output. Same wording as the v27 harness
    experiment: "`<flag>` is not an option of `<tool>`. Its options:" + NAME line + first 40 option lines."""
    parts = []
    for p in problems:
        parts.append("`%s` is not an option of `%s`. Its options:\n%s" % (p["flag"], p["program"], p["summary"]))
    return "\n\n".join(parts) + "\n\nThe command was not run."
