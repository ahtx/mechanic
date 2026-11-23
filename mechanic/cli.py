"""Command line: mechanic [run] TASK | mechanic contribute | mechanic logs | mechanic config."""
import argparse
import json
import os
import sys

from . import __version__, config
from .client import Client, EndpointError
from .session import Session, Terminal, interactive
from .sessionlog import SessionLog, list_sessions, read_session

USAGE = """mechanic "TASK"              ask the agent to do a task (each command needs your approval)
mechanic run [options] "TASK"
mechanic contribute [--file]   review, redact and upload (or write a file) your logged sessions
mechanic logs [--show ID | --delete ID | --delete-all]
mechanic config [KEY VALUE]   show or change settings (for example: mechanic config log on)
mechanic checkup [--report]   read-only health check with recommendations (never runs fixes)
mechanic schedule --daily HH:MM | --remove   run the checkup every day (user timer or crontab)"""


def _bool(v):
    return str(v).lower() in ("1", "on", "yes", "true", "y")


def cmd_run(a, cfg, term):
    if a.endpoint:
        cfg["endpoint"] = a.endpoint
    if a.model:
        cfg["model"] = a.model
    for k in ("max_steps", "timeout"):
        if getattr(a, k):
            cfg[k] = getattr(a, k)
    if a.no_flag_check:
        cfg["flag_check"] = False
    override = False
    if a.auto:
        from .isolation import isolation_reason
        if not isolation_reason():
            if not a.allow_auto_on_host:
                term.say("--auto refuses to run on the host: no container or virtual machine detected.\n"
                         "Run mechanic inside a container or VM, or pass --allow-auto-on-host to accept the risk.",
                         "bad")
                return 1
            term.say("WARNING: --allow-auto-on-host. Every command the model proposes will run on this machine "
                     "without asking, including destructive ones. The guard and flag checker only log what they "
                     "find.", "warn")
            if term.ask('Type "yes" to continue: ').strip().lower() != "yes":
                return 1
            override = True
    logging_on = (cfg.get("log") or a.log) and not a.no_log
    client = Client(cfg["endpoint"], cfg.get("model"), api_key=os.environ.get("MECHANIC_API_KEY"))
    log = SessionLog(bool(logging_on), cfg.get("output_limit", 4000))
    log.auto_override = override
    s = Session(client, cfg, term, auto=a.auto, log=log, cwd=a.cwd)
    task = " ".join(a.task).strip() or term.ask("Task: ").strip()
    if not task:
        return 1
    try:
        interactive(s, task)
    except EndpointError as e:
        term.say("Endpoint error: %s" % e, "bad")
        log.write("error", error=str(e))
        return 2
    except KeyboardInterrupt:
        term.say("\nStopped.", "warn")
        log.write("final", answer=None, stopped_by_user=True)
        return 130
    return 0


def cmd_contribute(a, cfg, term):
    from . import contribute
    try:
        contribute.run(term, cfg, mode="file" if a.file else "send", include_reviewed=a.all)
    except RuntimeError as e:
        term.say(str(e), "bad")
        return 1
    return 0


def cmd_logs(a, cfg, term):
    paths = list_sessions()
    by_id = {os.path.basename(p)[:-6]: p for p in paths}
    if a.delete_all:
        if term.ask("Delete all %d session logs? [y/N]: " % len(paths)).strip().lower() in ("y", "yes"):
            for p in paths:
                os.remove(p)
            term.say("Deleted %d logs." % len(paths))
        return 0
    if a.delete:
        os.remove(by_id[a.delete])
        term.say("Deleted " + a.delete)
        return 0
    if a.show:
        for r in read_session(by_id[a.show]):
            term.say(json.dumps(r, ensure_ascii=False))
        return 0
    term.say("Logging by default: %s. Folder: %s" % ("on" if cfg.get("log") else "off", config.sessions_dir()))
    for sid, p in by_id.items():
        recs = read_session(p)
        req = next((r.get("request", "") for r in recs if r["type"] == "session_start"), "")
        term.say("%s  %s" % (sid, req[:90]))
    return 0


def cmd_config(a, cfg, term):
    if a.key:
        if a.key not in config.DEFAULTS:
            term.say("Unknown setting: %s" % a.key, "bad")
            return 1
        d = config.DEFAULTS[a.key]
        v = a.value
        if isinstance(d, bool):
            v = _bool(v)
        elif isinstance(d, int):
            v = int(v)
        elif isinstance(d, list):
            v = (cfg.get(a.key) or []) + [v]
        cfg[a.key] = v
        config.save(cfg)
    for k in config.DEFAULTS:
        term.say("%-16s %s" % (k, json.dumps(cfg.get(k))))
    term.say("(file: %s)" % config.config_path(), "dim")
    return 0


def cmd_checkup(a, cfg, term):
    from .checkup import Checkup, post_webhook
    endpoint = a.endpoint or cfg["endpoint"]
    client = Client(endpoint, a.model or cfg.get("model"), api_key=os.environ.get("MECHANIC_API_KEY"))
    if a.report and not sys.stdout.isatty():
        term.color = False
    try:
        path, summary, _ = Checkup(client, term, quiet=a.report).run()
    except KeyboardInterrupt:
        term.say("Stopped.", "warn")
        return 130
    if a.webhook:
        try:
            post_webhook(a.webhook, path, summary)
        except Exception as e:
            term.say("Webhook failed: %s" % e, "bad")
            return 2
    return 0


def cmd_schedule(a, cfg, term):
    from . import schedule
    if a.remove:
        schedule.remove(say=term.say)
        return 0
    if not a.daily:
        term.say("Use --daily HH:MM or --remove.", "bad")
        return 1
    try:
        return 0 if schedule.install(a.daily, say=term.say) else 1
    except ValueError as e:
        term.say(str(e), "bad")
        return 1


def main(argv=None, term=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("run", "contribute", "logs", "config", "checkup", "schedule", "-h", "--help",
                                "--version"):
        argv.insert(0, "run")
    p = argparse.ArgumentParser(prog="mechanic", usage=USAGE)
    p.add_argument("--version", action="version", version="mechanic " + __version__)
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="do a task")
    r.add_argument("task", nargs="*")
    r.add_argument("--endpoint", help="OpenAI-compatible base URL (default %s)" % config.DEFAULTS["endpoint"])
    r.add_argument("--model", help="model name to send to the endpoint")
    r.add_argument("--auto", action="store_true", help="run commands without asking (containers and VMs only)")
    r.add_argument("--allow-auto-on-host", action="store_true",
                   help="let --auto run outside a container or VM (asks you to type yes)")
    r.add_argument("--log", action="store_true", help="log this session locally")
    r.add_argument("--no-log", action="store_true", help="do not log this session")
    r.add_argument("--no-flag-check", action="store_true", help="do not check options against --help/man")
    r.add_argument("--max-steps", type=int)
    r.add_argument("--timeout", type=int, help="seconds per command")
    r.add_argument("--cwd", help="working directory for commands")
    c = sub.add_parser("contribute", help="review, redact and share logged sessions")
    g = c.add_mutually_exclusive_group()
    g.add_argument("--file", action="store_true", help="write a file to attach to a GitHub issue instead of uploading")
    c.add_argument("--all", action="store_true", help="also show sessions reviewed before")
    lg = sub.add_parser("logs", help="list, show or delete session logs")
    lg.add_argument("--show")
    lg.add_argument("--delete")
    lg.add_argument("--delete-all", action="store_true")
    cf = sub.add_parser("config", help="show or change settings")
    cf.add_argument("key", nargs="?")
    cf.add_argument("value", nargs="?")
    ck = sub.add_parser("checkup", help="read-only health check with recommendations",
                        description="Collects logs (last 24 h), disk, processes, memory and network status with a fixed "
                                    "list of read-only commands, and asks the model for recommendations. The suggested "
                                    "commands are printed for you; checkup never runs them. Secrets are masked before "
                                    "anything goes to the model or into the report.")
    ck.add_argument("--report", action="store_true", help="quiet mode for timers: print only the summary and report path")
    ck.add_argument("--endpoint", help="OpenAI-compatible base URL (default: config endpoint)")
    ck.add_argument("--model")
    ck.add_argument("--webhook", help="POST the summary and report path as JSON to this URL")
    sc = sub.add_parser("schedule", help="run the checkup every day as your user")
    sg = sc.add_mutually_exclusive_group()
    sg.add_argument("--daily", metavar="HH:MM")
    sg.add_argument("--remove", action="store_true")
    a = p.parse_args(argv)
    if not a.cmd:
        p.print_usage()
        return 1
    cfg = config.load()
    term = term or Terminal()
    return {"run": cmd_run, "contribute": cmd_contribute, "logs": cmd_logs, "config": cmd_config,
            "checkup": cmd_checkup, "schedule": cmd_schedule}[a.cmd](a, cfg, term)


if __name__ == "__main__":
    sys.exit(main())
