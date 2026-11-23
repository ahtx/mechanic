"""The agent loop: the model proposes one bash command at a time; the user approves, edits or rejects it."""
import os
import subprocess
import sys

from . import guard
from .client import command_of
from .flags import FlagChecker, feedback
from .prompts import AGENT_SYS, TOOLS
from .sessionlog import SessionLog, clip


class Terminal:
    """Console input and output. Tests replace it with a scripted version."""

    def __init__(self, color=None):
        self.color = sys.stdout.isatty() if color is None else color

    def _c(self, code, s):
        return "\033[%sm%s\033[0m" % (code, s) if self.color else s

    def say(self, s="", style=None):
        codes = {"cmd": "1;97", "warn": "1;33", "bad": "1;31", "dim": "2", "ok": "32", "model": "36"}
        print(self._c(codes[style], s) if style else s, flush=True)

    def ask(self, prompt, prefill=""):
        try:
            import readline   # noqa: F401  (line editing, and prefill for edits)
            if prefill:
                readline.set_startup_hook(lambda: readline.insert_text(prefill))
            try:
                return input(prompt)
            finally:
                readline.set_startup_hook()
        except ImportError:
            if prefill:
                self.say("current: " + prefill, "dim")
            return input(prompt)


def run_bash(cmd, timeout, cwd=None):
    try:
        p = subprocess.run(["bash", "-c", cmd], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace")
        return 124, out + "\n[mechanic: command stopped after %d seconds]" % timeout


def observation(rc, out, limit):
    """Tool-result text in the format used in training and evaluation."""
    obs = clip(out, limit) if out.strip() else "(no output)"
    return "exit code %d\n%s" % (rc, obs) if rc else obs


class Session:
    def __init__(self, client, cfg, term=None, auto=False, log=None, cwd=None, checker=None, runner=run_bash):
        self.client = client
        self.cfg = cfg
        self.term = term or Terminal()
        self.auto = auto
        self.log = log or SessionLog(False)
        self.cwd = cwd
        self.checker = checker if checker is not None else (
            FlagChecker(probe_help=cfg.get("probe_help", True)) if cfg.get("flag_check", True) else None)
        self.runner = runner
        self.messages = [{"role": "system", "content": AGENT_SYS}]
        self.user_text = ""

    # ---------------------------------------------------------------- one user turn
    def turn(self, request):
        t = self.term
        self.messages.append({"role": "user", "content": request})
        self.user_text += "\n" + request
        for step in range(1, self.cfg.get("max_steps", 20) + 1):
            reply = self.client.chat(self.messages, TOOLS)
            calls = [c for c in reply["tool_calls"] if c.get("function", {}).get("name") == "bash"]
            if not calls:
                answer = reply["content"]
                self.messages.append({"role": "assistant", "content": answer})
                t.say()
                t.say(answer, "model")
                self.log.write("final", answer=answer)
                return answer
            call = dict(calls[0])
            call.setdefault("id", "call_%d" % step)
            cmd = command_of(call)
            self.messages.append({"role": "assistant", "content": reply["content"], "tool_calls": [call]})
            if reply["content"]:
                t.say(reply["content"], "model")
            result, rec = self.handle(step, cmd)
            self.messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
            self.log.write("proposal", step=step, model_text=reply["content"], **rec)
            if rec.get("decision") == "quit":
                self.log.write("final", answer=None, stopped_by_user=True)
                return None
        t.say("Stopped after %d steps without a final answer." % self.cfg.get("max_steps", 20), "warn")
        self.log.write("final", answer=None, step_limit=True)
        return None

    # ---------------------------------------------------------------- one proposed command
    def handle(self, step, cmd):
        t = self.term
        limit = self.cfg.get("output_limit", 4000)
        rec = {"command": cmd}
        t.say()
        t.say("[%d] $ %s" % (step, cmd), "cmd")
        if not cmd.strip():
            rec.update(decision="invalid", output="")
            return "No command was given. Call the bash tool with a command.", rec

        problems = self.checker.check(cmd) if self.checker else []
        rec["flag_problems"] = [{"program": p["program"], "flag": p["flag"]} for p in problems]
        if problems:
            for p in problems:
                t.say("  flag check: `%s` does not document `%s`%s" % (
                    p["program"], p["flag"], (" (closest: %s)" % ", ".join(p["close"])) if p["close"] else ""), "warn")
            override = False
            if not self.auto:
                a = t.ask("  Send the real options back to the model [Enter], or run anyway [r]? ").strip().lower()
                override = a == "r"
            if not override:
                rec.update(decision="blocked_flags", output="")
                t.say("  not run; the model gets the documented options", "dim")
                return feedback(problems), rec
            rec["flag_override"] = True

        risks = guard.analyze(cmd, self.user_text, self.cwd)
        rec["risks"] = [r.describe() for r in risks]
        rec["unnamed_targets"] = sorted({u for r in risks for u in r.unnamed})
        for r in risks:
            t.say("  " + r.describe().replace("\n", "\n  "), "bad" if r.unnamed else "warn")

        run, note = cmd, ""
        if self.auto:
            rec["decision"] = "auto"
        else:
            while True:
                a = t.ask("  Run it? [y]es / [e]dit / [n]o / [q]uit: ").strip().lower()
                if a in ("y", "yes"):
                    rec["decision"] = "approved"
                    break
                if a in ("e", "edit"):
                    new = t.ask("  edit> ", prefill=cmd).strip()
                    if not new:
                        continue
                    if new == cmd:
                        rec["decision"] = "approved"
                        break
                    run = new
                    rec.update(decision="edited", edited_command=new)
                    note = "The user edited the command before it ran. Command run: %s\n" % new
                    risks2 = guard.analyze(new, self.user_text, self.cwd)
                    for r in risks2:
                        t.say("  " + r.describe().replace("\n", "\n  "), "bad" if r.unnamed else "warn")
                    if risks2 and t.ask("  Run the edited command? [y/n]: ").strip().lower() not in ("y", "yes"):
                        continue
                    break
                if a in ("n", "no"):
                    reason = t.ask("  Reason for the model (optional): ").strip()
                    rec.update(decision="rejected", reason=reason, output="")
                    msg = "The user rejected this command, and it was not run."
                    return msg + (" Reason: " + reason if reason else ""), rec
                if a in ("q", "quit"):
                    rec.update(decision="quit", output="")
                    return "The user ended the session.", rec

        rc, out = self.runner(run, self.cfg.get("timeout", 120), self.cwd)
        shown = clip(out, 2000) if out.strip() else "(no output)"
        t.say(("  exit code %d\n" % rc if rc else "") + "  " + shown.replace("\n", "\n  "), "dim")
        rec.update(exit_code=rc, output=clip(out, limit))
        return note + observation(rc, out, limit), rec


def interactive(session, first_request, ask_rating=True):
    t = session.term
    session.log.start(first_request, session.client.model)
    request = first_request
    while request:
        session.turn(request)
        if session.auto:
            break
        request = t.ask("\nFollow-up (Enter to finish): ").strip()
        if request:
            session.log.write("user_followup", request=request)
    if session.log.enabled:
        solved = None
        if ask_rating and not session.auto:
            a = t.ask("Was the task solved? [y]es / [n]o / [s]kip: ").strip().lower()
            solved = True if a.startswith("y") else False if a.startswith("n") else None
        session.log.write("rating", solved=solved)
        t.say("Session log: " + session.log.path, "dim")
