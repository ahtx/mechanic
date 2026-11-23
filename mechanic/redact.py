"""Redaction for `mechanic contribute`.

The scanner replaces secrets and identifying details with placeholders such as <SECRET>, <IP_1> and <USER_2>.
The same value gets the same placeholder throughout one session, so the session still reads correctly.

What it finds:
  - private key blocks, SSH public keys, password hashes
  - API keys and tokens in well-known formats (cloud, code hosting, chat, payment, model hubs, JWTs)
  - credentials in URLs, password/token/key assignments, Authorization headers, `--password` options
  - long random-looking strings (high entropy) and long hex strings
  - e-mail addresses, MAC addresses, IPv4 and IPv6 addresses
  - this machine's host names, /etc/hosts names, and private or company domain names
  - this machine's user names (from /etc/passwd and the current user) and home directory paths
  - any extra regular expressions from the user's configuration

It is a pattern scanner. It reduces risk; it does not remove it. The user reviews every payload before it leaves.
"""
import getpass
import math
import os
import re
import socket

SECRET_FORMATS = [
    ("PRIVATE_KEY", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"),
    ("SSH_PUBLIC_KEY", r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+AAAA[0-9A-Za-z+/]+=*(?:\s+\S+@\S+)?"),
    ("PASSWORD_HASH", r"\$(?:1|2[abyx]?|5|6|y|gy|7)\$[^\s:$]{0,60}\$[./A-Za-z0-9$]{8,}"),
    ("SECRET", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
    ("SECRET", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("SECRET", r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    ("SECRET", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("SECRET", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("SECRET", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("SECRET", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    ("SECRET", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("SECRET", r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("SECRET", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("SECRET", r"\bya29\.[0-9A-Za-z_-]{20,}"),
    ("SECRET", r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ("SECRET", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    ("SECRET", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("SECRET", r"\bpypi-[A-Za-z0-9_-]{50,}"),
    ("SECRET", r"\b(?:SK|AC)[0-9a-f]{32}\b"),
    ("SECRET", r"\bdop_v1_[a-f0-9]{64}\b"),
    ("SECRET", r"\btskey-[A-Za-z0-9-]{20,}"),
    ("SECRET", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]
KEYWORD = (r"(?:password|passwd|pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
           r"client[_-]?secret|auth[_-]?token|private[_-]?key|credentials?|bearer)")
ASSIGN = re.compile(r"(?i)(\b[\w.-]*" + KEYWORD + r"[\w.-]*[\"']?\s*(?:=|:|=>)\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;]+)")
HEADER = re.compile(r"(?i)(\b(?:authorization|proxy-authorization|x-api-key|x-auth-token|cookie|set-cookie)\s*:\s*)([^\n\"']+)")
OPTION = re.compile(r"(?i)(--(?:password|passwd|token|api-key|apikey|secret|client-secret|auth-token)(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)")
MYSQL_P = re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n|;]*?\s-p)([^\s\"']\S*)")
URL_CRED = re.compile(r"\b([a-z][a-z0-9+.-]*://)([^\s:/@]+):([^\s@/]+)@")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IPV4 = re.compile(r"(?<![\w.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\w.]*\d)(?:/\d{1,2})?")
IPV6 = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|::(?:[0-9A-Fa-f]{1,4}:?){1,7})(?![\w:])")
HOME = re.compile(r"(/(?:home|Users)/)([^/\s\"':]+)")
HEX = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
RANDOM = re.compile(r"(?<![\w/+=.-])[A-Za-z0-9+/_=-]{32,}(?![\w/+=.-])")
DOMAIN = re.compile(r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-])")

KEEP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "255.255.255.0", "255.255.0.0", "255.0.0.0", "8.8.8.8",
            "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}
KEEP_IP6 = {"::1", "::", "fe80::"}
TLDS = {"com", "net", "org", "io", "dev", "ai", "co", "app", "cloud", "info", "biz", "us", "uk", "de", "fr", "nl",
        "ca", "au", "in", "jp", "cn", "ru", "br", "es", "it", "se", "no", "ch", "edu", "gov", "mil", "me", "tv",
        "xyz", "tech", "site", "online", "pk", "ae", "sa", "sg", "hk", "kr", "eu", "pl", "be", "at", "dk", "fi",
        "ie", "nz", "za", "mx", "ar", "tr", "il", "local", "lan", "internal", "intranet", "corp", "home", "localdomain",
        "home.arpa", "ts", "priv", "private", "test", "example", "invalid", "computer", "ninja", "systems", "network"}
PUBLIC_DOMAINS = {"ubuntu.com", "debian.org", "kernel.org", "python.org", "pypi.org", "docker.com", "docker.io",
                  "nginx.org", "apache.org", "letsencrypt.org", "github.com", "githubusercontent.com", "gitlab.com",
                  "google.com", "cloudflare.com", "example.com", "example.org", "example.net", "launchpad.net",
                  "snapcraft.io", "npmjs.org", "npmjs.com", "rust-lang.org", "golang.org", "go.dev", "fedoraproject.org",
                  "centos.org", "redhat.com", "archlinux.org", "alpinelinux.org", "mozilla.org", "gnu.org",
                  "freedesktop.org", "systemd.io", "huggingface.co", "openssl.org", "postgresql.org", "mysql.com",
                  "mariadb.org", "nodejs.org", "kubernetes.io", "k8s.io", "quay.io", "gcr.io", "microsoft.com",
                  "canonical.com", "opensuse.org", "ntp.org", "pool.ntp.org", "nvidia.com", "amd.com", "intel.com"}
SYSTEM_USERS = {"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
                "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
                "messagebus", "syslog", "sshd", "_apt", "ubuntu", "admin", "user", "test", "nogroup", "staff",
                "adm", "sudo", "wheel", "users", "docker", "postgres", "mysql", "nginx", "redis", "git"}


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def local_identities():
    """User names and host names of this machine, to redact wherever they appear."""
    users, hosts = set(), set()
    try:
        users.add(getpass.getuser())
    except Exception:
        pass
    try:
        with open("/etc/passwd", encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.split(":")
                if len(p) > 3 and p[2].isdigit() and 1000 <= int(p[2]) < 60000:
                    users.add(p[0])
    except OSError:
        pass
    for h in (socket.gethostname(), socket.getfqdn()):
        if h and h not in ("localhost", "localhost.localdomain"):
            hosts.add(h)
            hosts.add(h.split(".")[0])
    try:
        with open("/etc/hosts", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#")[0].split()
                for h in line[1:]:
                    if not h.startswith(("localhost", "ip6-")) and h not in ("broadcasthost",):
                        hosts.add(h)
    except OSError:
        pass
    return {u for u in users if len(u) >= 3 and u not in SYSTEM_USERS}, {h for h in hosts if len(h) >= 3}


class Redactor:
    def __init__(self, users=(), hosts=(), extra_patterns=(), use_local=True):
        lu, lh = local_identities() if use_local else (set(), set())
        self.users = sorted(set(users) | lu, key=len, reverse=True)
        self.hosts = sorted(set(hosts) | lh, key=len, reverse=True)
        self.extra = [re.compile(p) for p in extra_patterns]
        self.maps = {}
        self.counts = {}

    def _ph(self, kind, value):
        m = self.maps.setdefault(kind, {})
        if value not in m:
            m[value] = "<%s_%d>" % (kind, len(m) + 1)
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return m[value]

    def _secret(self, kind="SECRET"):
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return "<%s>" % kind

    def secrets(self, s):
        """Mask only secrets (keys, tokens, passwords, credentials). IPs, hosts and users stay, so a health report keeps
        the facts an administrator needs (for example, the address behind failed logins)."""
        if not s:
            return s
        for kind, pat in SECRET_FORMATS:
            if kind != "SSH_PUBLIC_KEY":
                s = re.sub(pat, lambda m, k=kind: self._secret(k), s)
        s = URL_CRED.sub(lambda m: m.group(1) + m.group(2) + ":" + self._secret() + "@", s)
        s = HEADER.sub(lambda m: m.group(1) + self._secret(), s)
        s = MYSQL_P.sub(lambda m: m.group(1) + self._secret(), s)
        s = OPTION.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("<") else self._secret()), s)
        s = ASSIGN.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("<") or m.group(2) in ('""', "''")
                                               else self._secret()), s)
        for rx in self.extra:
            s = rx.sub(lambda m: self._ph("CUSTOM", m.group(0)), s)
        return s

    def text(self, s):
        if not s:
            return s
        for kind, pat in SECRET_FORMATS:
            s = re.sub(pat, lambda m, k=kind: self._secret(k), s)
        s = URL_CRED.sub(lambda m: m.group(1) + self._ph("USER", m.group(2)) + ":" + self._secret() + "@", s)
        s = HEADER.sub(lambda m: m.group(1) + self._secret(), s)
        s = MYSQL_P.sub(lambda m: m.group(1) + self._secret(), s)
        s = OPTION.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("<") else self._secret()), s)
        s = ASSIGN.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("<") or m.group(2) in ('""', "''")
                                               else self._secret()), s)
        for i, rx in enumerate(self.extra):
            s = rx.sub(lambda m: self._ph("CUSTOM", m.group(0)), s)
        s = EMAIL.sub(lambda m: self._ph("EMAIL", m.group(0).lower()), s)
        s = MAC.sub(lambda m: m.group(0) if m.group(0) in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                    else self._ph("MAC", m.group(0).lower()), s)
        s = IPV4.sub(self._ip4, s)
        s = IPV6.sub(self._ip6, s)
        s = HOME.sub(lambda m: m.group(1) + self._ph("USER", m.group(2)), s)
        for h in self.hosts:
            s = re.sub(r"(?<![\w.-])" + re.escape(h) + r"(?![\w-])", lambda m: self._ph("HOST", h.lower()), s)
        s = DOMAIN.sub(self._domain, s)
        for u in self.users:
            s = re.sub(r"(?<![\w.<-])" + re.escape(u) + r"(?![\w-])", lambda m, u=u: self._ph("USER", u), s)
        s = HEX.sub(lambda m: self._ph("HEX", m.group(0).lower()), s)
        s = RANDOM.sub(self._random, s)
        return s

    def _ip4(self, m):
        ip = m.group(1)
        if ip in KEEP_IPS or ip.startswith("127.") or ip.startswith("255."):
            return m.group(0)
        return self._ph("IP", ip) + m.group(0)[len(ip):]

    def _ip6(self, m):
        x = m.group(1)
        real = ("::" in x and len(re.findall(r"[0-9a-fA-F]{1,4}", x)) >= 2) or x.count(":") == 7
        if not real or x.lower() in KEEP_IP6:
            return m.group(0)
        return self._ph("IPV6", x.lower())

    def _domain(self, m):
        name, tld = m.group(1), m.group(2).lower()
        low = name.lower()
        if tld not in TLDS and not low.endswith(".home.arpa"):
            return name                       # file names such as nginx.conf, access.log
        if any(low == d or low.endswith("." + d) for d in PUBLIC_DOMAINS):
            return name
        return self._ph("HOST", low)

    def _random(self, m):
        s = m.group(0)
        if s.startswith("<") or "/" in s and s.count("/") > 2:
            return s
        classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
        if classes >= 3 and entropy(s) >= 4.0:
            return self._secret()
        return s

    def value(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        return v

    def session(self, records):
        """Redact a list of log records. The placeholder numbering is shared across the whole session."""
        return [self.value(r) for r in records]
