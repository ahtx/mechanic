import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from mechanic import guard
from mechanic.flags import FlagChecker, feedback, flag_ok, options
from mechanic.shellparse import redirect_targets, segments, simple_commands

HELP = """Usage: frob [OPTION]... FILE
  -a, --all             show all
  -n, --lines=NUM       print NUM lines
  -v                    verbose
      --color[=WHEN]    colorize
  -p PORT               port
"""


def _write(path, text):
    with open(path, "w") as f:
        f.write(text)


class FakeChecker(FlagChecker):
    def __init__(self, docs):
        super().__init__(probe_help=False)
        self._docs = docs

    def docs(self, prog, sub=None):
        return self._docs.get((prog, sub) if sub else prog, "")


class ShellParseTest(unittest.TestCase):
    def test_segments_respect_quotes(self):
        segs = [t for t, _ in segments("grep -E 'a|b' f.txt | sort && echo \"x;y\" 2>&1; ls &> /dev/null")]
        self.assertEqual(segs, ["grep -E 'a|b' f.txt", "sort", 'echo "x;y" 2>&1', "ls &> /dev/null"])

    def test_programs_after_wrappers(self):
        progs = [p for p, _, _ in simple_commands("sudo -u www-data env A=1 timeout 5 curl -s x | xargs -I{} rm {}")]
        self.assertEqual(progs, ["curl", "rm"])
        self.assertEqual([p for p, _, _ in simple_commands("su postgres -c 'psql -l'")], ["su"])

    def test_quoted_operators_stay_in_one_command(self):
        progs = [p for p, _, _ in simple_commands("flock /tmp/l sh -c 'a || b' && echo ok")]
        self.assertEqual(len(progs), 2)

    def test_redirects(self):
        self.assertEqual(redirect_targets("echo hi > /etc/motd; date >> /var/log/x; ls 2>/dev/null; a 2>&1"),
                         [("/etc/motd", "overwrite"), ("/var/log/x", "append")])


class FlagTest(unittest.TestCase):
    def test_options_and_flag_ok(self):
        opts = options(HELP)
        self.assertTrue({"-a", "--all", "-n", "--lines", "-v", "--color", "-p"} <= opts)
        for ok in ("-a", "--all", "-av", "-n5", "--lines=3", "--color=auto", "-p8080"):
            self.assertTrue(flag_ok(ok, opts), ok)
        for bad in ("--everything", "-x", "-ax"):
            self.assertFalse(flag_ok(bad, opts), bad)

    def test_checker_blocks_only_undocumented(self):
        c = FakeChecker({"frob": HELP})
        self.assertEqual(c.check("frob -av --lines=3 file | frob --color=never -n -5 x"), [])
        probs = c.check("frob --al file && frob --recursive x")
        self.assertEqual([p["flag"] for p in probs], ["--al", "--recursive"])
        self.assertIn("--all", probs[0]["close"])
        text = feedback(probs)
        self.assertIn("`--recursive` is not an option of `frob`. Its options:", text)
        self.assertIn("--lines=NUM", text)
        self.assertIn("The command was not run.", text)

    def test_find_exec_is_not_checked_as_find_options(self):
        c = FakeChecker({"find": "  -name pattern\n  -type c\n  -exec command ;\n  -mtime n\n"})
        self.assertEqual(c.check("find /var -name '*.tmp' -exec rm -f {} ;"), [])
        self.assertEqual([p["flag"] for p in c.check("find /var -nmae x")], ["-nmae"])

    def test_no_docs_means_no_block(self):
        c = FakeChecker({})
        self.assertEqual(c.check("weirdtool --anything"), [])

    def test_lenient_text_match(self):
        docs = HELP + "\nThe --legacy-mode switch is described in the EXAMPLES section.\n"
        self.assertEqual(FakeChecker({"frob": docs}).check("frob --legacy-mode f"), [])

    def test_subcommand_docs(self):
        c = FakeChecker({"git": "usage: git [-C path]\n  -C <path>  run\n  -p  paginate\n  --version  v",
                         ("git", "commit"): "  -m, --message <msg>  message\n  -a, --all  all\n  --amend  amend"})
        self.assertEqual(c.check("git commit -am 'x' --amend"), [])
        self.assertEqual([p["flag"] for p in c.check("git commit --squash-all")], ["--squash-all"])

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("man"), "needs Linux man pages")
    def test_real_tools(self):
        c = FlagChecker()
        self.assertEqual(c.check("ls -la /tmp | sort -k5,5nr | head -n 5"), [])
        self.assertEqual(c.check("find /var/log -type f -mtime -7 -size +1M -name '*.log' -print"), [])
        self.assertEqual(c.check("tar -czvf /tmp/x.tgz -C /etc hosts"), [])
        self.assertEqual([p["flag"] for p in c.check("ls --show-hidden-files /tmp")], ["--show-hidden-files"])


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "logs"))
        for n in ("a.log", "b.log", "keep.txt"):
            _write(os.path.join(self.d, "logs", n), "x" * 10)
        _write(os.path.join(self.d, "app.conf"), "port 80\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_rm_glob_lists_files_and_marks_unnamed(self):
        logs = os.path.join(self.d, "logs")
        r = guard.analyze("rm -f %s/*.log %s/app.conf" % (logs, self.d), "clean the old logs in %s" % logs)
        self.assertEqual(r[0].action, "delete")
        aff = " ".join(r[0].affected)
        self.assertIn("a.log", aff)
        self.assertIn("b.log", aff)
        self.assertNotIn("keep.txt", aff)
        self.assertEqual(r[0].unnamed, [os.path.join(self.d, "app.conf")])
        self.assertIn("NOT NAMED IN YOUR REQUEST", r[0].describe())

    def test_named_paths_are_not_flagged(self):
        r = guard.analyze("rm -rf %s/logs" % self.d, "delete %s/logs please" % self.d)
        self.assertEqual(r[0].action, "delete recursively")
        self.assertEqual(r[0].unnamed, [])
        self.assertIn("directory, 3 entries", r[0].affected[0])

    @unittest.skipUnless(shutil.which("find") and sys.platform != "win32", "needs find")
    def test_find_delete_preview(self):
        r = guard.analyze("find %s -name '*.log' -print -delete" % self.d, "")
        self.assertEqual((r[0].action, r[0].program), ("delete", "find"))
        self.assertEqual(len(r[0].affected), 2)
        self.assertTrue(os.path.exists(os.path.join(self.d, "logs", "a.log")))   # the preview deleted nothing

    def test_overwrites(self):
        conf = os.path.join(self.d, "app.conf")
        acts = {x.action for x in guard.analyze("sed -i 's/80/81/' %s; echo hi > %s; truncate -s 0 %s" % (conf, conf, conf))}
        self.assertEqual(acts, {"edit in place", "overwrite (>)", "truncate"})
        r = guard.analyze("cp /etc/hostname %s" % conf, "")
        self.assertEqual(r[0].action, "overwrite")

    @unittest.skipUnless(os.path.isdir("/proc"), "needs /proc")
    def test_kill_shows_process(self):
        p = subprocess.Popen(["sleep", "30"])
        try:
            r = guard.analyze("kill -9 %d" % p.pid, "the job is stuck")
            self.assertIn("sleep 30", r[0].affected[0])
            self.assertEqual(r[0].unnamed, [str(p.pid)])
        finally:
            p.kill()
            p.wait()

    def test_services_and_safe_commands(self):
        r = guard.analyze("systemctl stop nginx && systemctl restart ssh", "nginx is broken, restart it")
        self.assertEqual([x.action for x in r], ["stop service", "restart service"])
        self.assertEqual(r[0].unnamed, [])
        self.assertEqual(r[1].unnamed, ["ssh"])
        self.assertEqual(guard.analyze("df -h; du -sh /var/* | sort -h; journalctl -u nginx -n 50", ""), [])


if __name__ == "__main__":
    unittest.main()
