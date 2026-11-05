# Shared test setup: a throw-away Huginn home, demo address ranges (RFC 5737) and made-up bait.
import json, os, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = tempfile.mkdtemp(prefix="huginn-test-")
BAIT = {"mysql_backup": "Test-Bait-Value-0001", "redis": "test-bait-redis-0002"}
json.dump(BAIT, open(os.path.join(HOME, "bait.json"), "w"))
os.environ.update({"HUGINN_BASE": HOME, "HUGINN_DEMO": "1", "HUGINN_TZ": "UTC", "HUGINN_ENRICH": "0",
                   "HUGINN_UPDATE_CHECK": "0", "HUGINN_BAIT_FILE": os.path.join(HOME, "bait.json"),
                   "HUGINN_MASK": "203.0.113.250,victim.example", "HUGINN_PERSONAS": "2225=server,2323=camera"})
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "honeypot"))

import app  # noqa: E402

app.init_db()
