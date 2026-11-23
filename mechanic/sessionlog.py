"""Opt-in session logs: one JSONL file per session, stored locally with owner-only permissions."""
import json
import os
import time
import uuid

from . import __version__, config


def clip(text, limit):
    if text is None or len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n[... %d characters cut ...]\n" % (len(text) - limit) + text[-half:]


class SessionLog:
    """Writes events when enabled; does nothing when disabled."""

    def __init__(self, enabled, output_limit=4000):
        self.enabled = enabled
        self.limit = output_limit
        self.id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        self.path = None
        if enabled:
            d = config.sessions_dir()
            os.makedirs(d, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
            self.path = os.path.join(d, self.id + ".jsonl")

    def write(self, kind, **data):
        if not self.enabled:
            return
        rec = {"type": kind, "session": self.id, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        for k, v in data.items():
            rec[k] = clip(v, self.limit) if isinstance(v, str) and k in ("output", "answer") else v
        new = not os.path.exists(self.path)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if new:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def start(self, request, model):
        extra = {"auto_override": True} if getattr(self, "auto_override", False) else {}
        self.write("session_start", request=request, model=model, mechanic=__version__, **extra)


def read_session(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def list_sessions():
    d = config.sessions_dir()
    if not os.path.isdir(d):
        return []
    return sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".jsonl"))
