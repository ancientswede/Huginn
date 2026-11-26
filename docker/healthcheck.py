# Docker health check for Huginn (part of Huginn, AGPL-3.0-or-later).
# Healthy = the web server answers. A 503 from /healthz only means the last honeypot sync is old; the page shows that.
import os, sys, urllib.error, urllib.request

port, bind = os.environ.get("HUGINN_PORT", "8095"), os.environ.get("HUGINN_BIND", "")
host = {"": "127.0.0.1", "0.0.0.0": "127.0.0.1", "::": "::1"}.get(bind, bind)      # where it listens (Codex rc2 M19)
try:
    urllib.request.urlopen(urllib.request.Request("http://%s:%s/healthz" % ("[%s]" % host if ":" in host else host, port),
                                                  headers={"Host": "localhost:%s" % port}), timeout=4)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 503 else 1)
except Exception:
    sys.exit(1)
