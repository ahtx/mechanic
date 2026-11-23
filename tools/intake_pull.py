#!/usr/bin/env python3
"""Pull new mechanic contributions from an R2 bucket (the intake Worker's bucket), then delete them from R2.

Uses the Cloudflare R2 REST API with stdlib only. Nothing about the deployment is built in; give it with flags or
environment variables (flags win):

  --bucket NAME   or  MECHANIC_INTAKE_BUCKET     the R2 bucket that the Worker writes to (required)
  --dest DIR      or  MECHANIC_INTAKE_DEST       where pulled files go (default: ./intake-incoming)
  --prefix P      or  MECHANIC_INTAKE_PREFIX     object key prefix (default: incoming/)
  CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID    credentials (environment only; never printed)

An object is deleted from R2 only after it was written to disk and its size matched the listing.

  intake_pull.py --bucket NAME [--dest DIR] [--prefix P] [--dry-run]
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEST = "intake-incoming"
PREFIX = "incoming/"


class R2:
    def __init__(self, bucket):
        try:
            self.token = os.environ["CLOUDFLARE_API_TOKEN"]
            acct = os.environ["CLOUDFLARE_ACCOUNT_ID"]
        except KeyError as e:
            sys.exit("missing environment variable %s" % e)
        self.base = "https://api.cloudflare.com/client/v4/accounts/%s/r2/buckets/%s/objects" % (acct, bucket)

    def _req(self, url, method="GET"):
        r = urllib.request.Request(url, method=method, headers={"Authorization": "Bearer " + self.token,
                                                                "User-Agent": "mechanic-intake-pull"})
        return urllib.request.urlopen(r, timeout=120)

    def list(self, prefix=PREFIX):
        cursor = None
        while True:
            q = {"prefix": prefix, "per_page": 1000}
            if cursor:
                q["cursor"] = cursor
            with self._req(self.base + "?" + urllib.parse.urlencode(q)) as r:
                d = json.loads(r.read().decode("utf-8"))
            yield from d.get("result") or []
            info = d.get("result_info") or {}
            cursor = info.get("cursor")
            if not cursor or not info.get("is_truncated"):
                return

    def _url(self, key):
        return self.base + "/" + urllib.parse.quote(key, safe="")

    def get(self, key, path):
        with self._req(self._url(key)) as r, open(path, "wb") as f:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b)

    def delete(self, key):
        self._req(self._url(key), "DELETE").close()


def pull(r2, dest, dry=False, log=print, prefix=PREFIX):
    n = 0
    for obj in list(r2.list(prefix)):
        k = obj["key"]
        parts = k[len(prefix):].split("/")                # <YYYYMMDD>/<uuid>.jsonl[.gz]
        if len(parts) != 2 or not all(parts) or ".." in parts:
            log("skip unexpected key %r" % k)
            continue
        out = os.path.join(dest, *parts)
        if dry:
            log("would pull %s (%d bytes)" % (k, obj["size"]))
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        tmp = out + ".part"
        r2.get(k, tmp)
        if os.path.getsize(tmp) != obj["size"]:
            os.remove(tmp)
            log("size mismatch for %s; left in R2" % k)
            continue
        os.replace(tmp, out)
        r2.delete(k)
        n += 1
    log("dry run done" if dry else "pulled %d object(s)" % n)
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    env = os.environ.get
    ap.add_argument("--bucket", default=env("MECHANIC_INTAKE_BUCKET"),
                    help="R2 bucket the intake Worker writes to (or MECHANIC_INTAKE_BUCKET); required")
    ap.add_argument("--dest", default=env("MECHANIC_INTAKE_DEST", DEST),
                    help="folder for pulled files (or MECHANIC_INTAKE_DEST; default ./%s)" % DEST)
    ap.add_argument("--prefix", default=env("MECHANIC_INTAKE_PREFIX", PREFIX),
                    help="object key prefix (or MECHANIC_INTAKE_PREFIX; default %s)" % PREFIX)
    ap.add_argument("--dry-run", action="store_true", help="list what would be pulled; change nothing")
    a = ap.parse_args()
    if not a.bucket:
        ap.error("give --bucket or set MECHANIC_INTAKE_BUCKET")
    pull(R2(a.bucket), a.dest, a.dry_run, prefix=a.prefix)


if __name__ == "__main__":
    main()
