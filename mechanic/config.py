"""Settings and local data folders. Nothing here leaves the machine."""
import json
import os

DEFAULTS = {
    "endpoint": "http://localhost:8000/v1",
    "model": None,
    "log": False,                 # session logging is off until the user turns it on
    "flag_check": True,
    "probe_help": True,           # run `program --help` (besides man) to read options
    "max_steps": 20,
    "timeout": 120,               # seconds per command
    "output_limit": 4000,         # characters of command output sent to the model and stored in a log
    "redact_patterns": [],        # extra regular expressions for `mechanic contribute`
    "intake_url": "https://mechanic-intake.mechanic-intake.workers.dev/v1/contribute",
}


def home():
    if os.environ.get("MECHANIC_HOME"):
        return os.environ["MECHANIC_HOME"]
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "mechanic")


def config_path():
    if os.environ.get("MECHANIC_HOME"):
        return os.path.join(os.environ["MECHANIC_HOME"], "config.json")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "mechanic", "config.json")


def sessions_dir():
    return os.path.join(home(), "sessions")


def outbox_dir():
    return os.path.join(home(), "outbox")


def load():
    cfg = dict(DEFAULTS)
    try:
        with open(config_path(), encoding="utf-8") as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    return cfg


def save(cfg):
    p = config_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    out = {k: v for k, v in cfg.items() if k in DEFAULTS and v != DEFAULTS[k]}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
