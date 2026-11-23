"""`mechanic schedule`: run `mechanic checkup --report` every day, as the current user.

It installs a user systemd timer when `systemctl --user` works, and otherwise one line in the user's crontab.
It never installs anything system-wide and never needs sudo.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys

UNIT = "mechanic-checkup"
MARK = "# mechanic-checkup"


def _run(argv, inp=None):
    try:
        p = subprocess.run(argv, input=inp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                           universal_newlines=True)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def command_line():
    exe = shutil.which("mechanic")
    base = [exe] if exe else [sys.executable, "-m", "mechanic"]
    return base + ["checkup", "--report"]


def parse_time(hhmm):
    m = re.match(r"^([01]?\d|2[0-3]):([0-5]\d)$", hhmm or "")
    if not m:
        raise ValueError("use HH:MM, for example 07:00")
    return int(m.group(1)), int(m.group(2))


def unit_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "systemd", "user")


def unit_files(hh, mm, cmd):
    service = ("[Unit]\nDescription=mechanic read-only health check\n\n[Service]\nType=oneshot\nExecStart=%s\n"
               % " ".join(shlex.quote(c) for c in cmd))
    timer = ("[Unit]\nDescription=Daily mechanic checkup\n\n[Timer]\nOnCalendar=*-*-* %02d:%02d:00\nPersistent=true\n\n"
             "[Install]\nWantedBy=timers.target\n" % (hh, mm))
    return service, timer


def cron_line(hh, mm, cmd):
    return "%d %d * * * %s >/dev/null 2>&1 %s" % (mm, hh, " ".join(shlex.quote(c) for c in cmd), MARK)


def user_systemd_ok(run=_run):
    return shutil.which("systemctl") is not None and run(["systemctl", "--user", "show-environment"])[0] == 0


def install(hhmm, run=_run, say=print, use_systemd=None):
    hh, mm = parse_time(hhmm)
    cmd = command_line()
    if use_systemd is None:
        use_systemd = user_systemd_ok(run)
    if use_systemd:
        d = unit_dir()
        os.makedirs(d, exist_ok=True)
        service, timer = unit_files(hh, mm, cmd)
        for name, text in ((UNIT + ".service", service), (UNIT + ".timer", timer)):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        run(["systemctl", "--user", "daemon-reload"])
        rc, out = run(["systemctl", "--user", "enable", "--now", UNIT + ".timer"])
        if rc != 0:
            say("systemctl --user enable failed: %s" % out.strip())
            return False
        say("Installed user timer %s.timer (daily at %02d:%02d): %s" % (UNIT, hh, mm, os.path.join(d, UNIT + ".timer")))
        say("Runs: " + " ".join(cmd))
        say("Tip: `loginctl enable-linger $USER` lets it run while you are logged out.")
        return True
    if not shutil.which("crontab") and run is _run:
        say("Neither a user systemd manager nor crontab is available; nothing was installed.")
        return False
    rc, cur = run(["crontab", "-l"])
    lines = [l for l in (cur.splitlines() if rc == 0 else []) if MARK not in l]
    lines.append(cron_line(hh, mm, cmd))
    rc, out = run(["crontab", "-"], "\n".join(lines) + "\n")
    if rc != 0:
        say("crontab failed: %s" % out.strip())
        return False
    say("Installed crontab entry: " + lines[-1])
    return True


def remove(run=_run, say=print):
    done = False
    d = unit_dir()
    if os.path.exists(os.path.join(d, UNIT + ".timer")):
        run(["systemctl", "--user", "disable", "--now", UNIT + ".timer"])
        for n in (UNIT + ".timer", UNIT + ".service"):
            try:
                os.remove(os.path.join(d, n))
            except OSError:
                pass
        run(["systemctl", "--user", "daemon-reload"])
        say("Removed user timer %s.timer" % UNIT)
        done = True
    rc, cur = run(["crontab", "-l"])
    if rc == 0 and MARK in cur:
        keep = [l for l in cur.splitlines() if MARK not in l]
        run(["crontab", "-"], "\n".join(keep) + "\n" if keep else "")
        say("Removed crontab entry")
        done = True
    if not done:
        say("No mechanic schedule was installed.")
    return done
