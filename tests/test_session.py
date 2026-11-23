"""Confirm flow and end-to-end dry runs against a local fake endpoint. Commands run for real, in a temp folder."""
import json
import os
import shutil
import sys
import tempfile
import unittest

from mechanic import cli, config, contribute
from mechanic.client import Client
from mechanic.session import Session, interactive
from mechanic.sessionlog import SessionLog, list_sessions, read_session
from tests.fake_endpoint import FakeEndpoint, ScriptedTerminal, final, tool

HAVE_BASH = shutil.which("bash") is not None and sys.platform != "win32"
HELP = "  -a, --all   all\n  -l   long\n  -h, --human-readable   sizes\n  -S   sort by size\n"


def _write(path, text):
    with open(path, "w") as f:
        f.write(text)


class FakeChecker:
    """Flag checker with fixed documentation for `ls`, so the tests do not depend on the host's man pages."""

    def __init__(self):
        from mechanic.flags import FlagChecker
        self.c = FlagChecker(probe_help=False)
        self.c.docs = lambda prog, sub=None: HELP if prog == "ls" else ""

    def check(self, cmd):
        return self.c.check(cmd)


@unittest.skipUnless(HAVE_BASH, "needs bash on Linux")
class SessionTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        os.environ["MECHANIC_HOME"] = self.home
        for n in ("old1.log", "old2.log", "app.conf"):
            _write(os.path.join(self.work, n), n)
        self.cfg = dict(config.DEFAULTS)

    def tearDown(self):
        shutil.rmtree(self.home)
        shutil.rmtree(self.work)
        os.environ.pop("MECHANIC_HOME", None)

    def session(self, script, answers, auto=False, log=False):
        self.ep = FakeEndpoint(script)
        self.addCleanup(self.ep.close)
        term = ScriptedTerminal(answers)
        s = Session(Client(self.ep.url), self.cfg, term, auto=auto, log=SessionLog(log), cwd=self.work,
                    checker=FakeChecker())
        return s, term

    def tool_results(self):
        return [m["content"] for m in self.ep.requests[-1]["messages"] if m["role"] == "tool"]

    def test_approve_edit_reject(self):
        s, term = self.session(
            [tool("ls -la", "First I list the folder."),
             tool("rm old1.log old2.log app.conf"),
             tool("rm old1.log old2.log"),
             tool("cat app.conf"),
             final("Removed old1.log and old2.log.")],
            ["y",                      # approve ls
             "n", "app.conf is the live config",   # reject the rm that includes app.conf
             "e", "rm -v old1.log old2.log", "y",  # edit, then confirm the edited (risky) command
             "y"])
        answer = s.turn("Delete the old *.log files in this folder.")
        self.assertEqual(answer, "Removed old1.log and old2.log.")
        self.assertFalse(os.path.exists(os.path.join(self.work, "old1.log")))
        self.assertTrue(os.path.exists(os.path.join(self.work, "app.conf")))
        res = self.tool_results()
        self.assertIn("old1.log", res[0])
        self.assertIn("rejected", res[1])
        self.assertIn("app.conf is the live config", res[1])
        self.assertIn("Command run: rm -v old1.log old2.log", res[2])
        self.assertIn("removed", res[2])
        self.assertEqual(res[3], "app.conf")
        # the guard showed what the first rm would affect and flagged the file the user did not name
        self.assertIn("NOT NAMED IN YOUR REQUEST: app.conf", term.text())
        # the system prompt and tool schema are the trained ones, and thinking is off
        req = self.ep.requests[0]
        self.assertTrue(req["messages"][0]["content"].startswith("You are a Linux administration agent"))
        self.assertEqual(req["tools"][0]["function"]["name"], "bash")
        self.assertEqual(req["chat_template_kwargs"], {"enable_thinking": False})

    def test_flag_check_returns_options_and_does_not_run(self):
        s, term = self.session([tool("ls --sort-by-size > listing.txt"), tool("ls -lS"), final("done")], ["", "y"])
        s.turn("Which file is largest?")
        res = self.tool_results()
        self.assertIn("`--sort-by-size` is not an option of `ls`", res[0])
        self.assertIn("-S", res[0])
        self.assertFalse(os.path.exists(os.path.join(self.work, "listing.txt")))
        self.assertIn("app.conf", res[1])

    def test_failed_command_and_xml_tool_calls(self):
        s, _ = self.session([tool("cat missing.txt", xml=True), final("The file does not exist.")], ["y"])
        s.turn("Show missing.txt")
        res = self.tool_results()
        self.assertTrue(res[0].startswith("exit code 1\n"))
        self.assertIn("No such file", res[0])

    def test_quit(self):
        s, _ = self.session([tool("ls")], ["q"])
        self.assertIsNone(s.turn("list"))

    def test_auto_mode_with_log(self):
        s, term = self.session([tool("rm old1.log"), tool("ls"), final("Deleted old1.log.")], [], auto=True, log=True)
        interactive(s, "Delete old1.log")
        logs = list_sessions()
        self.assertEqual(len(logs), 1)
        recs = read_session(logs[0])
        self.assertEqual([r["type"] for r in recs], ["session_start", "proposal", "proposal", "final", "rating"])
        self.assertEqual(recs[1]["decision"], "auto")
        self.assertEqual(recs[1]["unnamed_targets"], [])
        self.assertIsNone(recs[-1]["solved"])
        if os.name == "posix":
            self.assertEqual(os.stat(logs[0]).st_mode & 0o777, 0o600)

    def test_logging_off_by_default(self):
        s, _ = self.session([tool("ls"), final("ok")], ["y", ""])
        interactive(s, "list", ask_rating=True)
        self.assertEqual(list_sessions(), [])


@unittest.skipUnless(HAVE_BASH, "needs bash on Linux")
class EndToEndTest(unittest.TestCase):
    """Dry run through the real CLI: run a logged session, then contribute it to a file and to a fake HF API."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        os.environ["MECHANIC_HOME"] = self.home
        _write(os.path.join(self.work, "big.log"), "x" * 5000)

    def tearDown(self):
        shutil.rmtree(self.home)
        shutil.rmtree(self.work)
        os.environ.pop("MECHANIC_HOME", None)

    def run_logged_session(self):
        secret = "ghp_" + "9fKq2LmZ8xV1bN4cR7tY0uW3eA6sD5gH2jK8"
        ep = FakeEndpoint([tool("du -a . | sort -rn | head -3"), tool("echo deploy token %s from 10.20.30.40" % secret),
                           final("big.log is the largest file.")])
        self.addCleanup(ep.close)
        term = ScriptedTerminal(["y", "y", "", "y"])     # approve, approve, no follow-up, solved
        rc = cli.main(["run", "--endpoint", ep.url, "--log", "--no-flag-check", "--cwd", self.work,
                       "What is the largest file here?"], term=term)
        self.assertEqual(rc, 0)
        return secret

    def test_run_then_contribute_to_file(self):
        secret = self.run_logged_session()
        recs = read_session(list_sessions()[0])
        self.assertEqual(recs[-1], dict(recs[-1], type="rating", solved=True))
        self.assertIn(secret, json.dumps(recs))        # the local log is the raw record
        term = ScriptedTerminal(["a", "I agree", "test contributor"])
        self.assertEqual(cli.main(["contribute", "--file"], term=term), 0)
        out = os.listdir(config.outbox_dir())
        self.assertEqual(len(out), 1)
        with open(os.path.join(config.outbox_dir(), out[0]), encoding="utf-8") as f:
            bundle = f.read()
        self.assertNotIn(secret, bundle)
        self.assertNotIn("10.20.30.40", bundle)
        self.assertIn("<IP_1>", bundle)
        first = json.loads(bundle.splitlines()[0])
        self.assertEqual((first["type"], first["licence"], first["attribution"]), ("consent", "CC0-1.0", "test contributor"))
        self.assertNotIn(secret, term.text())
        self.assertIn("exact payload", term.text())
        # a second run finds nothing new
        term2 = ScriptedTerminal([])
        cli.main(["contribute"], term=term2)
        self.assertIn("No new session logs", term2.text())

    def test_contribute_drop_and_no_consent_write_nothing(self):
        self.run_logged_session()
        cli.main(["contribute"], term=ScriptedTerminal(["a", ""]))          # accepted, but no consent
        self.assertFalse(os.path.isdir(config.outbox_dir()) and os.listdir(config.outbox_dir()))
        cli.main(["contribute"], term=ScriptedTerminal(["d"]))              # dropped
        self.assertFalse(os.path.isdir(config.outbox_dir()) and os.listdir(config.outbox_dir()))
        self.assertEqual(list(contribute.load_ledger().values()), ["dropped"])

    def test_contribute_upload(self):
        self.run_logged_session()
        seen = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return b'{"ok":true,"id":"abc"}'

        def opener(req, timeout=0):
            seen.append(req)
            return Resp()

        term = ScriptedTerminal(["a", "I agree", "", "y"])
        contribute.run(term, config.load(), mode="send", opener=opener)
        import gzip
        req = seen[0]
        self.assertEqual(req.get_header("Content-type"), "application/gzip")
        first = json.loads(gzip.decompress(req.data).decode().splitlines()[0])
        self.assertTrue(first["consent"] is True and first["licence"] and first["mechanic_version"])
        self.assertIn("Contribution id: abc", term.text())

@unittest.skipUnless(HAVE_BASH, "needs bash on Linux")
class AutoGuardTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        os.environ["MECHANIC_HOME"] = self.home
        self.addCleanup(shutil.rmtree, self.home)
        self.addCleanup(shutil.rmtree, self.work)
        self.addCleanup(os.environ.pop, "MECHANIC_HOME", None)

    def run_auto(self, reason, extra, answers):
        from unittest import mock
        ep = FakeEndpoint([tool("ls"), final("Done.")])
        self.addCleanup(ep.close)
        term = ScriptedTerminal(answers)
        with mock.patch("mechanic.isolation.isolation_reason", return_value=reason):
            rc = cli.main(["run", "--auto", "--endpoint", ep.url, "--log", "--no-flag-check", "--cwd", self.work,
                           "list files"] + extra, term=term)
        return rc, term

    def test_auto_refused_on_host(self):
        rc, term = self.run_auto(None, [], [])
        self.assertEqual(rc, 1)
        self.assertIn("refuses", term.text())
        self.assertEqual(list_sessions(), [])

    def test_auto_allowed_in_container(self):
        rc, term = self.run_auto("container", [], [])
        self.assertEqual(rc, 0)
        self.assertNotIn("auto_override", json.dumps(read_session(list_sessions()[0])))

    def test_auto_override_on_host(self):
        rc, term = self.run_auto(None, ["--allow-auto-on-host"], ["yes"])
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", term.text())
        self.assertTrue(read_session(list_sessions()[0])[0]["auto_override"])
        rc, _ = self.run_auto(None, ["--allow-auto-on-host"], ["no"])
        self.assertEqual(rc, 1)

    def test_detection_wsl_not_isolated(self):
        from unittest import mock
        from mechanic import isolation
        with mock.patch.object(isolation, "_read", return_value="Linux microsoft-standard-WSL2"), \
                mock.patch("os.path.exists", return_value=True):
            self.assertIsNone(isolation.isolation_reason())


if __name__ == "__main__":
    unittest.main()
