"""Redaction tests with real-looking (fake) secrets. Every secret here is invented for the test."""
import unittest

from mechanic.redact import Redactor

# Built by concatenation so that the source file itself does not look like a leaked key to scanners.
AWS = "AKIA" + "Q3EXAMPLE7KZ4N2B"
GH = "ghp_" + "9fKq2LmZ8xV1bN4cR7tY0uW3eA6sD5gH2jK8"
GH_PAT = "github_pat_" + "11ABCDE2F0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuV"
HF = "hf_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"
OPENAI = "sk-proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"
ANTHROPIC = "sk-ant-api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8Ba7"
SLACK = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
GOOGLE = "AIza" + "SyD3x4mpl3K3y-abcdefghijklmnopqrstu"
STRIPE = "sk_live_" + "51Hb2cD3eF4gH5iJ6kL7mN8o"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ." +
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
PEM = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
       "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
       "QyNTUxOQAAACBkZXhhbXBsZWtleWRhdGFmb3J0ZXN0aW5nb25seQAAAJgAAAAAAAAAAAAA\n"
       "-----END OPENSSH PRIVATE KEY-----")
SHADOW = "alice:$6$rOuNdS4lT$" + "Kq2N8vLmZp0xW3yT6uR9sE1dF4gH7jK0lM3nB6vC9xZ2aQ5wE8rT1yU4iO7pA0sD3fG6hJ9kL2zX5cV8bN1mQ" + ":19700:0:99999:7:::"


class RedactTest(unittest.TestCase):
    def r(self, text, **kw):
        kw.setdefault("use_local", False)
        red = Redactor(**kw)
        return red.text(text), red

    def assertGone(self, out, *secrets):
        for s in secrets:
            self.assertNotIn(s, out)

    def test_token_formats(self):
        for tok in (AWS, GH, GH_PAT, HF, OPENAI, ANTHROPIC, SLACK, GOOGLE, STRIPE, JWT):
            out, _ = self.r("export X=1; curl -H 'X-Key: z' https://api.example.com/?k=%s done" % tok)
            self.assertGone(out, tok)
            self.assertIn("done", out)

    def test_token_in_plain_output(self):
        out, red = self.r("Found token %s in ~/.cache/huggingface/token" % HF)
        self.assertGone(out, HF)
        self.assertIn("<SECRET>", out)
        self.assertEqual(red.counts["SECRET"], 1)

    def test_private_key_block(self):
        out, _ = self.r("cat ~/.ssh/id_ed25519\n" + PEM + "\nexit")
        self.assertGone(out, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ")
        self.assertIn("<PRIVATE_KEY>", out)
        self.assertTrue(out.endswith("exit"))

    def test_ssh_public_key_and_shadow_hash(self):
        pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq7cF2pD9wL0vX3kT6yB8nM1rS4uE7aZ0hJ5gQ2xW9c alice@laptop"
        out, _ = self.r(pub + "\n" + SHADOW)
        self.assertGone(out, "AAAAC3NzaC1lZDI1NTE5AAAAIGq7", "alice@laptop", "rOuNdS4lT")
        self.assertIn("<PASSWORD_HASH>", out)

    def test_assignments_headers_options(self):
        cases = {
            "DB_PASSWORD=Tr0ub4dor&3 ./start.sh": "Tr0ub4dor&3",
            '{"api_key": "q8Wz-31aa-77Lm"}': "q8Wz-31aa-77Lm",
            "password: hunter2hunter2": "hunter2hunter2",
            "secret_key = 'f00b4r-s3cr3t'": "f00b4r-s3cr3t",
            "curl -H 'Authorization: Bearer abc.def.ghi-123' https://x": "abc.def.ghi-123",
            "psql --password=Sup3rS3cret! -h db": "Sup3rS3cret!",
            "mysql -u root -pS3cretPw0rd mydb": "S3cretPw0rd",
            "pg_dump postgres://backup:Pa55w0rd@db.internal:5432/app": "Pa55w0rd",
        }
        for text, secret in cases.items():
            out, _ = self.r(text)
            self.assertNotIn(secret, out, text)

    def test_url_credentials_keep_shape(self):
        out, _ = self.r("git clone https://deploy:abc123XYZ@git.acme-corp.com/team/app.git")
        self.assertNotIn("abc123XYZ", out)
        self.assertNotIn("deploy:", out)
        self.assertNotIn("acme-corp.com", out)
        self.assertIn("https://<USER_1>:<SECRET>@<HOST_1>/team/app.git", out)

    def test_network_identifiers(self):
        text = ("inet 10.20.30.29/24 brd 10.20.30.255 scope global eth0\n"
                "link/ether 3c:7c:3f:1a:2b:9e brd ff:ff:ff:ff:ff:ff\n"
                "inet6 2601:281:8300:4bd0:1e2a:3b4c:5d6e:7f80/64 scope global\n"
                "listening on 127.0.0.1:8080 and 0.0.0.0:22\n"
                "mail to Jane.Doe@acme-corp.com failed")
        out, _ = self.r(text)
        self.assertGone(out, "10.20.30.29", "3c:7c:3f:1a:2b:9e", "2601:281:8300", "Jane.Doe@acme-corp.com")
        self.assertIn("<IP_1>/24", out)
        self.assertIn("127.0.0.1:8080", out)
        self.assertIn("0.0.0.0:22", out)
        self.assertIn("ff:ff:ff:ff:ff:ff", out)
        self.assertIn("<EMAIL_1>", out)

    def test_same_value_same_placeholder(self):
        red = Redactor(use_local=False)
        recs = red.session([{"command": "ping -c1 10.1.2.3"}, {"output": "64 bytes from 10.1.2.3: icmp_seq=1"},
                            {"output": "from 10.1.2.4"}])
        self.assertEqual(recs[0]["command"], "ping -c1 <IP_1>")
        self.assertIn("from <IP_1>:", recs[1]["output"])
        self.assertIn("<IP_2>", recs[2]["output"])

    def test_users_hosts_homes(self):
        text = ("alice@web-03:~$ ls /home/alice/projects /home/bob\n"
                "ssh alice@web-03.corp1234.internal\n"
                "-rw-r--r-- 1 alice alice 12 Nov 21 10:00 notes.txt\n"
                "Connected to build-07.corp.internal")
        out, _ = self.r(text, users=["alice"], hosts=["web-03"])
        self.assertGone(out, "alice", "web-03", "bob", "corp1234", "build-07")
        self.assertIn("/home/<USER_1>/projects", out)
        self.assertIn("notes.txt", out)

    def test_keeps_useful_text(self):
        text = ("mkdir -p /var/www/html && ssh -p 2222 host\n"
                "nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
                "Nov 21 12:30:45 systemd[1]: Started cron.service\n"
                "Get:1 http://archive.ubuntu.com/ubuntu noble InRelease\n"
                "Linux 6.8.0-49-generic x86_64; python3.12; tar -xzvf backup.tar.gz\n"
                "std::vector<int> and a::b in C++")
        out, _ = self.r(text)
        for keep in ("mkdir -p /var/www/html", "-p 2222", "/etc/nginx/nginx.conf", "12:30:45", "cron.service",
                     "archive.ubuntu.com", "6.8.0-49-generic", "backup.tar.gz", "std::vector"):
            self.assertIn(keep, out)

    def test_high_entropy_and_hex(self):
        rnd = "Zq8Lm2Xv9Rt4Wp7Ks1Nd6Fh3Jc5Bg0Ty8Ua"
        sha = "2e0c8b945614b407c594cbd92d671a249f725e8b53189bacd6eed988b80aa034"
        out, _ = self.r("token-ish %s and checksum %s" % (rnd, sha))
        self.assertGone(out, rnd, sha)
        self.assertIn("<HEX_1>", out)

    def test_user_patterns(self):
        out, red = self.r("ticket PROJ-4821 for customer ACME-77", extra_patterns=[r"\bPROJ-\d+\b", r"ACME-\d+"])
        self.assertGone(out, "PROJ-4821", "ACME-77")
        self.assertEqual(red.counts["CUSTOM"], 2)


if __name__ == "__main__":
    unittest.main()
