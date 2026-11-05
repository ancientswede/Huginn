# Docker health check for Huginn (part of Huginn, AGPL-3.0-or-later).
# Healthy = the web server answers. A 503 from /healthz only means the last honeypot sync is old; the page shows that.
import os, sys, urllib.error, urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:%s/healthz" % os.environ.get("HUGINN_PORT", "8095"), timeout=4)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 503 else 1)
except Exception:
    sys.exit(1)
