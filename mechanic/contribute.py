"""`mechanic contribute`: review, redact and share session logs, only with the user's consent.

Steps:
  1. Each logged session that has not been reviewed yet is redacted, and the exact payload is shown.
  2. The user accepts or drops each session (or adds a redaction pattern and looks again).
  3. The user dedicates the logs to the public domain (CC0 1.0), and may give a name for attribution.
  4. mechanic writes one bundle file in the outbox. Then it either uploads it to the intake service
     (after one more confirmation), or prints the file path to attach to a GitHub issue.
Nothing is sent without step 4's confirmation.
"""
import json
import os
import re
import time

from . import __version__, config
from .redact import Redactor
from .sessionlog import list_sessions, read_session

MAX_UPLOAD = 5 * 1024 * 1024
LICENCE = "CC0-1.0"
LICENCE_NAME = "CC0 1.0 Universal (public domain dedication)"
LICENCE_URL = "https://creativecommons.org/publicdomain/zero/1.0/"
CONSENT = ("I dedicate the accepted session logs to the public domain under CC0 1.0 (%s). I confirm that I have the "
           "right to share them, and that I reviewed the redacted payload." % LICENCE_URL)


def ledger_path():
    return os.path.join(config.home(), "contributed.json")


def load_ledger():
    try:
        with open(ledger_path(), encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_ledger(led):
    os.makedirs(config.home(), exist_ok=True)
    with open(ledger_path(), "w", encoding="utf-8") as f:
        json.dump(led, f, indent=1)


def render(records):
    return "\n".join(json.dumps(r, ensure_ascii=False, indent=None) for r in records)


def review(term, cfg, paths, use_local=True):
    """Return (accepted [(path, redacted_records)], dropped [path], patterns added)."""
    patterns = list(cfg.get("redact_patterns") or [])
    accepted, dropped = [], []
    for k, path in enumerate(paths, 1):
        records = read_session(path)
        while True:
            red = Redactor(extra_patterns=patterns, use_local=use_local)
            out = red.session(records)
            term.say()
            term.say("Session %d of %d: %s" % (k, len(paths), os.path.basename(path)), "cmd")
            term.say("Redactions: " + (", ".join("%s %d" % kv for kv in sorted(red.counts.items())) or "none"), "dim")
            term.say("----- exact payload -----", "dim")
            term.say(render(out))
            term.say("----- end of payload -----", "dim")
            a = term.ask("[a]ccept / [d]rop / add a [r]edaction pattern / [s]kip for now / [q]uit: ").strip().lower()
            if a.startswith("r"):
                p = term.ask("Regular expression to redact: ").strip()
                try:
                    re.compile(p)
                    patterns.append(p)
                except re.error as e:
                    term.say("Not a valid regular expression: %s" % e, "bad")
                continue
            break
        if a.startswith("a"):
            accepted.append((path, out))
        elif a.startswith("d"):
            dropped.append(path)
        elif a.startswith("q"):
            break
    return accepted, dropped, patterns


def consent(term):
    term.say()
    term.say("Data licence: " + LICENCE_NAME, "cmd")
    term.say(CONSENT)
    a = term.ask('Type "I agree" to accept, or press Enter to stop: ').strip().lower()
    if a != "i agree":
        return None
    name = term.ask("Name to credit in the model card (optional). Amir acknowledges everyone who contributes a valid dataset: ").strip()
    return {"type": "consent", "consent": True, "licence": LICENCE, "text": CONSENT, "attribution": name or "anonymous",
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "mechanic": __version__, "mechanic_version": __version__}


def write_bundle(consent_rec, accepted):
    os.makedirs(config.outbox_dir(), exist_ok=True)
    name = "mechanic-contribution-%s-%s.jsonl" % (time.strftime("%Y%m%d-%H%M%S"), os.urandom(3).hex())
    path = os.path.join(config.outbox_dir(), name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(consent_rec, ensure_ascii=False) + "\n")
        for _, recs in accepted:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


def upload(bundle, url, opener=None):
    """POST the bundle (gzipped) to the intake Worker. Returns the contribution id."""
    import gzip
    import urllib.error
    import urllib.request
    with open(bundle, "rb") as f:
        body = gzip.compress(f.read())
    if len(body) > MAX_UPLOAD:
        raise RuntimeError("the bundle is %.1f MB compressed; the limit is 5 MB. Contribute fewer sessions at a time, "
                           "or use --file" % (len(body) / 1e6))
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/gzip", "User-Agent": "mechanic/" + __version__})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=60) as r:
            out = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError("upload refused (HTTP %d). Try again later, or use --file" % e.code)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RuntimeError("upload failed: %s. Use --file instead" % e)
    if not out.get("ok"):
        raise RuntimeError("upload failed; use --file instead")
    return out.get("id")


def run(term, cfg, mode="send", include_reviewed=False, use_local=True, opener=None):
    led = load_ledger()
    paths = [p for p in list_sessions() if include_reviewed or os.path.basename(p) not in led]
    if not paths:
        term.say("No new session logs to review. (Logging is off unless you use --log or `mechanic config log on`.)")
        return None
    accepted, dropped, _ = review(term, cfg, paths, use_local)
    for p in dropped:
        led[os.path.basename(p)] = "dropped"
    if not accepted:
        save_ledger(led)
        term.say("Nothing accepted; nothing was written or sent.")
        return None
    c = consent(term)
    if not c:
        save_ledger(led)
        term.say("No consent; nothing was written or sent.")
        return None
    bundle = write_bundle(c, accepted)
    term.say("Bundle written: " + bundle, "ok")
    sent = False
    if mode == "send":
        url = cfg.get("intake_url")
        a = term.ask("Upload this file to the mechanic community dataset (%s)? [y/N]: " % url).strip().lower()
        if a in ("y", "yes"):
            cid = upload(bundle, url, opener)
            term.say("Uploaded. Contribution id: %s" % cid, "ok")
            sent = True
        else:
            term.say("Not sent. The file stays in the outbox.")
    else:
        term.say("To share it, attach this file to a GitHub issue. Nothing was sent.")
    for p, _ in accepted:
        led[os.path.basename(p)] = ("sent:" if sent else "bundled:") + os.path.basename(bundle)
    save_ledger(led)
    return bundle
