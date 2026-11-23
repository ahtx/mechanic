"""checkup: collectors on fixture outputs, secret masking, report writing, and proof that nothing the model says runs."""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from mechanic import checkup, schedule
from mechanic.checkup import (ALLOWED, Checkup, Collector, NotAllowed, SuggestionChecker, build_summary, dedupe, review,
                              risk_floor,
                              run_fixed)
from mechanic.redact import Redactor
from tests.fake_endpoint import ScriptedTerminal

GH = "ghp_" + "9fKq2LmZ8xV1bN4cR7tY0uW3eA6sD5gH2jK8"
JOURNAL = "\n".join(
    ["2026-11-22T10:%02d:01+0000 box sshd[%d]: Failed password for invalid user admin from 203.0.113.45 port %d ssh2"
     % (i % 60, 900 + i, 40000 + i) for i in range(40)] +
    ["2026-11-22T11:00:00+0000 box systemd[1]: report-sync.service: Failed with result 'exit-code'.",
     "2026-11-22T11:00:05+0000 box deploy[77]: calling api with token=%s" % GH])
DF = ("Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        20G   12G  7.1G  63% /\n"
      "tmpfs           256M  241M   15M  95% /var/log\n")
DU_VAR = "1900000\t/var/log/app\n2100000\t/var/log\n2400000\t/var\n120\t/var/tmp\n"
PS_CPU = ("    PID USER     %CPU %MEM   RSS     ELAPSED COMMAND\n  321 root     99.0 18.0 1500000 01:00:00 python3 /opt/cache-warmer.py "
          "--password=hunter2hunter2\n    1 root      0.0  0.1  12000  2-00:00:00 /sbin/init\n")
PS_ALL = "    PID    PPID STAT     ELAPSED COMMAND\n  400     321 Z    00:10 [worker] <defunct>\n  401   1 S  00:10 sleep 100\n"
FAILED = "report-sync.service loaded failed failed Nightly report sync\n"
SS_LISTEN = ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))\n"
             "tcp LISTEN 0 5 0.0.0.0:31337 0.0.0.0:* users:((\"python3\",pid=55,fd=3))\n"
             "tcp LISTEN 0 5 127.0.0.1:8090 0.0.0.0:* users:((\"llama-server\",pid=66,fd=3))\n")
SS_EST = ("0 0 10.0.0.5:22 203.0.113.45:51000\n0 0 10.0.0.5:22 203.0.113.45:51001\n0 0 10.0.0.5:443 198.51.100.7:6000\n")
OOM = "2026-11-22T09:00:00+0000 box kernel: Out of memory: Killed process 321 (python3) total-vm:3000000kB\n"


def fake_runner(calls):
    def run(argv, timeout=20):
        calls.append(list(argv))
        p = argv[0]
        if p == "journalctl" and "-k" in argv:
            return 0, OOM
        if p == "journalctl":
            return 0, JOURNAL
        if p == "df":
            return 0, DF
        if p == "du":
            return (0, DU_VAR) if argv[-1] == "/var" else (0, "")
        if p == "ps" and any(a.startswith("--sort") for a in argv):
            return 0, PS_CPU
        if p == "ps":
            return 0, PS_ALL
        if p == "systemctl":
            return 0, FAILED
        if p == "ss" and "-tulpn" in argv:
            return 0, SS_LISTEN
        if p == "ss":
            return 0, SS_EST
        if p == "free":
            return 0, "              total        used        free\nMem:           3900        3700         200\n"
        return 0, ""
    return run


class FakeClient:
    """Answers with text that contains dangerous commands, to prove that nothing from the model runs."""
    def __init__(self):
        self.max_tokens = 100
        self.seen = []

    def chat(self, messages, tools=None):
        self.seen.append(messages)
        assert tools is None
        return {"content": "1. Finding: disk full\n   Why it matters: logs stop\n   Command: rm -rf /var/log/app\n"
                           "   Risk: high", "tool_calls": []}


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.col = Collector(runner=fake_runner(self.calls), reader=lambda p: None)

    def test_logs_deduplicate_with_counts(self):
        out = self.col.logs()
        self.assertIn("40x  box sshd: Failed password for invalid user admin from 203.0.113.45 port N ssh2", out)
        self.assertIn("report-sync.service: Failed", out)

    def test_disk_sorted_and_human(self):
        out = self.col.disk()
        self.assertIn("95% /var/log", out)
        i, j = out.index("/var/log/app"), out.index("/var/tmp")
        self.assertLess(out.index("2.3G  /var\n"), i)
        self.assertLess(i, j)

    def test_processes_zombies_failed_units(self):
        out = self.col.processes()
        self.assertIn("cache-warmer", out)
        self.assertIn("<defunct>", out)
        self.assertNotIn("sleep 100", out.split("### zombie processes")[1].split("###")[0])
        self.assertIn("report-sync.service loaded failed", out)

    def test_memory_oom(self):
        self.assertIn("Out of memory: Killed process (python3)", self.col.memory().replace("321 ", ""))

    def test_network_uncommon_listener_and_peers(self):
        out = self.col.network()
        odd = out.split("uncommon ports")[1].split("###")[0]
        self.assertIn("0.0.0.0:31337", odd)
        self.assertNotIn(":22 ", odd)
        self.assertNotIn("127.0.0.1:8090", odd)
        self.assertIn("    2  203.0.113.45", out)

    def test_dedupe_limit(self):
        lines = ["line %d error" % i for i in range(100)]
        d = dedupe(lines, limit=5)
        self.assertEqual(len(d), 6)
        self.assertIn("95 more distinct lines", d[-1])


class ReadOnlyTest(unittest.TestCase):
    def test_runner_refuses_programs_and_options_outside_the_list(self):
        for argv in (["rm", "-rf", "/"], ["bash", "-c", "id"], ["systemctl", "stop", "nginx"], ["swapon", "-a"],
                     ["journalctl", "--vacuum-size=1M"], ["ss", "-K", "dst", "1.2.3.4"]):
            with self.assertRaises(NotAllowed, msg=argv):
                run_fixed(argv)

    def test_every_collector_command_is_allow_listed(self):
        calls = []
        Collector(runner=fake_runner(calls), reader=lambda p: None)
        col = Collector(runner=fake_runner(calls), reader=lambda p: None)
        for _, name in Collector.SECTIONS:
            getattr(col, name)()
        self.assertTrue(calls)
        for argv in calls:
            self.assertIn(argv[0], ALLOWED)

    def test_model_commands_are_never_executed(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        calls = []
        client = FakeClient()
        term = ScriptedTerminal([])
        with mock.patch.dict(os.environ, {"MECHANIC_STATE": home}), \
                mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess.run called")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("Popen called")), \
                mock.patch.object(os, "system", side_effect=AssertionError("os.system called")):
            path, summary, findings = Checkup(client, term, Collector(runner=fake_runner(calls), reader=lambda p: None),
                                              checker=SuggestionChecker(runner=fake_runner(calls))).run("testbox")
        self.assertFalse(any(c[0] == "rm" for c in calls))
        for argv in calls:
            self.assertIn(argv[0], ALLOWED)
        self.assertIn(["man", "-P", "cat", "rm"], calls)                 # the suggestion was only looked up
        self.assertEqual(len(findings), 5)
        self.assertIn("Command: rm -rf /var/log/app", term.text())      # shown as text only
        self.assertIn("Risk: high", term.text())
        self.assertEqual(len(client.seen), 5)                            # 5 sections; the summary is built in code
        with open(path, encoding="utf-8") as f:
            report = f.read()
        self.assertIn("Suggested commands were not run", report)
        self.assertTrue(os.path.basename(path).endswith(".md"))


class SecretMaskingTest(unittest.TestCase):
    def test_secrets_masked_before_model_and_report(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        client = FakeClient()
        with mock.patch.dict(os.environ, {"MECHANIC_STATE": home}):
            path, _, _ = Checkup(client, ScriptedTerminal([]), Collector(runner=fake_runner([]), reader=lambda p: None),
                                 checker=SuggestionChecker(runner=fake_runner([]))).run("testbox")
        sent = str(client.seen)
        with open(path, encoding="utf-8") as f:
            report = f.read()
        for secret in (GH, "hunter2hunter2"):
            self.assertNotIn(secret, sent)
            self.assertNotIn(secret, report)
        self.assertIn("203.0.113.45", sent)          # facts the admin needs stay

    def test_secrets_mode_keeps_ips_and_users(self):
        r = Redactor(use_local=False)
        s = r.secrets("Accepted publickey for alice from 198.51.100.4 port 22; DB_PASSWORD=abc123xyz; "
                      "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")
        self.assertIn("alice from 198.51.100.4", s)
        self.assertNotIn("abc123xyz", s)
        self.assertNotIn("MIIabc", s)


SSHD_MAN = ("SSHD(8)\nNAME\n     sshd - OpenSSH daemon\nOPTIONS\n     -D      do not detach\n     -f config_file\n"
            "     -p port\n             Port for the server.\n     -q      quiet mode\n     -t      test mode\n")


class SuggestionReviewTest(unittest.TestCase):
    def checker(self):
        def run(argv, timeout=20):
            assert argv[:3] == ["man", "-P", "cat"], argv
            return (0, SSHD_MAN) if argv[3] == "sshd" else (16, "No manual entry for %s" % argv[3])
        return SuggestionChecker(runner=run)

    def test_risk_floor_rules(self):
        cases = {"iptables -A INPUT -s 203.0.113.45 -j DROP": "high", "iptables -L -n": "low", "kill -9 79": "medium",
                 "systemctl restart report-sync": "medium", "systemctl stop ssh": "high", "apt-get clean": "medium",
                 "rm -rf /var/log/app": "high", "find /var/log -name '*.gz' -delete": "high",
                 "sed -i 's/a/b/' /etc/app.conf": "medium", "systemctl status report-sync": "low",
                 "du -sh /var/log/* | sort -rh | head": "low", "journalctl -u sshd -n 50": "low",
                 "journalctl --vacuum-size=100M": "medium", "ip link set eth0 down": "high"}
        for cmd, level in cases.items():
            self.assertEqual(risk_floor(cmd)[0], level, cmd)

    def test_model_can_raise_but_not_lower_risk(self):
        text = ("1. Finding: brute force\n   Command: `iptables -A INPUT -s 203.0.113.45 -j DROP` (to block it)\n"
                "   Risk: low\n2. Finding: status\n   Command: systemctl status report-sync\n   Risk: medium")
        out, changes, _ = review(text, self.checker())
        self.assertIn("Risk: high (mechanic's rules: iptables can cut network access; the model said low)", out)
        self.assertIn("   Risk: medium", out.split("2. Finding")[1])         # a higher model rating stays
        self.assertEqual(len([c for c in changes if c.startswith("raised risk")]), 1)

    def test_invented_or_misused_options_are_hidden(self):
        text = ("1. Finding: x\n   Command: sshd -p /var/log/auth.log -t 172.17.0.4 admin\n   Risk: low\n"
                "2. Finding: y\n   Command: sshd -t\n   Risk: low\n3. Finding: z\n   Command: sshd --list-attackers\n   Risk: low")
        out, changes, _ = review(text, self.checker())
        self.assertIn("[unverified, not shown: `sshd -p` expects port, not `/var/log/auth.log`]", out)
        self.assertNotIn("sshd -p /var/log/auth.log", out)
        self.assertIn("Command: sshd -t", out)
        self.assertIn("`sshd` has no option `--list-attackers`", out)
        self.assertEqual(len(changes), 2)

    def test_quoted_command_is_checked_as_a_command(self):
        out, changes, _ = review('1. Finding: x\n   Command: "sshd -t"\n   Risk: low', self.checker())
        self.assertIn('Command: "sshd -t"', out)
        self.assertEqual(changes, [])

    def test_options_without_a_man_page_are_marked(self):
        out, _, _ = review("1. Finding: x\n   Command: journalctl -u cron.service -n 5\n   Risk: low\n"
                        "2. Finding: y\n   Command: free\n   Risk: low", self.checker())
        self.assertIn("Command: journalctl -u cron.service -n 5  [options not checked: no local man page for journalctl]",
                      out)
        self.assertIn("Command: free\n", out)

    def test_missing_risk_gets_rule_floor_or_medium(self):
        out, changes, items = review("1. Finding: hog PID 79\n   Command: kill 79\n"
                                     "2. Finding: odd file /srv/x/y\n   Command: ls -l /srv/x/y\n"
                                     "3. Finding: no command at all", self.checker())
        self.assertEqual([f["level"] for f in items], ["medium", "medium", "medium"])
        self.assertIn("Risk: medium (mechanic's rules: kill stops processes)", out)
        self.assertIn("Risk: medium (mechanic's rules: no risk was given)", out)
        self.assertNotRegex(out, r"Risk:\s*$")

    def test_duplicates_merged_by_port_pid_unit_ip_path(self):
        text = ("1. Finding: python3 (pid 89) listens on 0.0.0.0:31337\n   Command: ss -tlnp\n   Risk: low\n"
                "2. Finding: port 31337 is reachable from outside\n   Command: ss -tulpn\n   Risk: medium\n"
                "3. Finding: report-sync.service failed\n   Command: systemctl status report-sync.service\n   Risk: low\n"
                "4. Finding: the unit report-sync.service is in a failed state\n   Command: systemctl status report-sync\n"
                "   Risk: low\n"
                "5. Finding: 40 failed logins from 172.17.0.4\n   Command: sshd -p /var/log/auth.log\n   Risk: low\n"
                "6. Finding: brute force from 172.17.0.4 against admin\n   Command: sshd -t\n   Risk: low\n"
                "7. Finding: /var/log/app holds 230M\n   Command: du -sh /var/log/app\n   Risk: low\n"
                "8. Finding: /var/log is 90% full; /var/log/app is the largest\n   Command: df -h /var/log\n   Risk: low\n"
                "9. Finding: no swap is configured\n   Command: free -m\n   Risk: low")
        out, changes, items = review(text, self.checker())
        self.assertEqual(len(items), 5)
        self.assertEqual(items[0]["level"], "medium")                     # the higher risk of the pair is kept
        self.assertIn("Command: sshd -t", out.split("3. Finding")[1])      # the verified command replaces a hidden one
        self.assertIn("merged 4 duplicate findings", changes)
        self.assertIn("[1 duplicate merged]", out)

    def test_summary_keeps_every_finding_sorted_by_risk(self):
        logs = review("1. Finding: 40 failed SSH logins from 172.17.0.4\n   Command: grep -c Failed /var/log/auth.log\n"
                      "   Risk: low\n2. Finding: report-sync.service failed\n   Command: systemctl status report-sync\n"
                      "   Risk: low", self.checker())[2]
        procs = review("1. Finding: PID 79 uses 99% CPU\n   Command: kill -3 79\n   Risk: low\n"
                       "2. Finding: report-sync.service is in a failed state\n   Command: systemctl status x\n"
                       "   Risk: low", self.checker())[2]
        net = review("1. Finding: python3 listens on 0.0.0.0:31337\n   Command: iptables -A INPUT -p tcp --dport 31337 "
                     "-j DROP\n   Risk: low", self.checker())[2]
        s = build_summary([("Logs", logs), ("Processes", procs), ("Network", net)])
        lines = s.splitlines()
        self.assertEqual(len(lines), 4)                                    # the failed unit appears once
        self.assertTrue(lines[0].startswith("1. [high] Network:"))
        self.assertTrue(lines[1].startswith("2. [medium] Processes: PID 79"))
        self.assertIn("SSH logins from 172.17.0.4", s)                      # a low finding is never dropped
        self.assertEqual(build_summary([("Logs", [])]), "No issues found.")

    def test_recorder_and_checkup_are_left_out_of_process_lists(self):
        ps = ("    PID USER %CPU %MEM RSS ELAPSED COMMAND\n  211 root 9.0 0.1 1 00:10 /usr/bin/python3 /usr/bin/asciinema rec x\n"
              "  212 root 8.0 0.1 1 00:10 python3 -m mechanic checkup --endpoint http://x\n"
              "   79 root 99.9 16.5 1 02:00 /usr/bin/python3 /opt/cache/warmer.py\n")
        col = Collector(runner=lambda argv, timeout=20: (0, ps if argv[0] == "ps" else ""), reader=lambda p: None)
        out = col.processes()
        self.assertIn("warmer.py", out)
        self.assertNotIn("asciinema", out)
        self.assertNotIn("mechanic checkup", out)


class ScheduleTest(unittest.TestCase):
    def test_time_and_unit_files(self):
        self.assertEqual(schedule.parse_time("07:00"), (7, 0))
        with self.assertRaises(ValueError):
            schedule.parse_time("25:00")
        svc, tmr = schedule.unit_files(7, 5, ["/usr/bin/mechanic", "checkup", "--report"])
        self.assertIn("ExecStart=/usr/bin/mechanic checkup --report", svc)
        self.assertIn("OnCalendar=*-*-* 07:05:00", tmr)
        self.assertIn("5 7 * * * /usr/bin/mechanic checkup --report", schedule.cron_line(7, 5, ["/usr/bin/mechanic", "checkup", "--report"]))

    def test_crontab_install_and_remove_keep_other_lines(self):
        tab = {"text": "0 1 * * * /usr/local/bin/backup\n"}

        def run(argv, inp=None):
            if argv[:2] == ["crontab", "-l"]:
                return 0, tab["text"]
            if argv[:2] == ["crontab", "-"]:
                tab["text"] = inp
                return 0, ""
            return 1, ""
        cfg = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cfg)
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": cfg}):
            self.assertTrue(schedule.install("07:00", run=run, say=lambda s: None, use_systemd=False))
            self.assertTrue(schedule.install("08:30", run=run, say=lambda s: None, use_systemd=False))
            self.assertEqual(tab["text"].count(schedule.MARK), 1)
            self.assertIn("30 8 * * *", tab["text"])
            self.assertIn("/usr/local/bin/backup", tab["text"])
            schedule.remove(run=run, say=lambda s: None)
            self.assertNotIn(schedule.MARK, tab["text"])
            self.assertIn("/usr/local/bin/backup", tab["text"])


if __name__ == "__main__":
    unittest.main()
