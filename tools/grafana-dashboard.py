# Builds Huginn's Grafana dashboard (part of Huginn, AGPL-3.0-or-later).
#   python3 tools/grafana-dashboard.py examples/grafana/huginn-dashboard.json
# Change this script, not the JSON. Optional: a uid and title, e.g. for a preview copy next to the real one.
import json, sys

OUT = sys.argv[1]
UID = sys.argv[2] if len(sys.argv) > 2 else "huginn"
TITLE = sys.argv[3] if len(sys.argv) > 3 else "Huginn"
DS = {"type": "prometheus", "uid": "${datasource}"}
pid = [0]
panels = []


def nid():
    pid[0] += 1
    return pid[0]


def tgt(expr, legend="", instant=False, ref="A", fmt=None):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref, "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def row(title, y):
    panels.append({"id": nid(), "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []})


def thresholds(steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


def stat(title, expr, x, y, w=3, h=4, unit="short", color=None, steps=None, desc="", spark=True, decimals=None, text_mode="value",
         legend="", reduce="lastNotNull", instant=False):
    fc = {"unit": unit, "color": {"mode": "fixed", "fixedColor": color} if color else {"mode": "thresholds"},
          "thresholds": thresholds(steps or [("text", None)])}
    if decimals is not None:
        fc["decimals"] = decimals
    panels.append({"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": DS,
                   "gridPos": {"x": x, "y": y, "w": w, "h": h},
                   "targets": [tgt(expr, legend, instant=instant)],
                   "fieldConfig": {"defaults": fc, "overrides": []},
                   "options": {"reduceOptions": {"calcs": [reduce], "fields": "", "values": False},
                               "colorMode": "value", "graphMode": "area" if spark else "none", "justifyMode": "auto",
                               "textMode": text_mode, "wideLayout": True, "showPercentChange": False, "orientation": "auto"}})


def series(title, targets, x, y, w, h, unit="short", bars=False, stack=False, desc="", overrides=None, interval=None, legend="bottom"):
    custom = {"drawStyle": "bars" if bars else "line", "lineWidth": 1 if bars else 2, "fillOpacity": 85 if bars else 12,
              "gradientMode": "none" if bars else "opacity", "showPoints": "never", "barAlignment": 0, "spanNulls": True,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}, "axisSoftMin": 0, "lineInterpolation": "smooth"}
    p = {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
         "fieldConfig": {"defaults": {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}, "overrides": overrides or []},
         "options": {"legend": {"displayMode": "list", "placement": legend, "showLegend": True},
                     "tooltip": {"mode": "multi", "sort": "desc"}}}
    if interval:
        p["interval"] = interval
    panels.append(p)


def bargauge(title, expr, legend, x, y, w, h, unit="short", steps=None, desc="", maxv=None, color=None):
    fc = {"unit": unit, "min": 0, "color": {"mode": "fixed", "fixedColor": color} if color else {"mode": "thresholds"},
          "thresholds": thresholds(steps or [("blue", None)]), "displayName": "${__field.labels.service}"}
    if maxv is not None:
        fc["max"] = maxv
    panels.append({"id": nid(), "type": "bargauge", "title": title, "description": desc, "datasource": DS,
                   "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": [tgt(expr, legend, instant=True)],
                   "fieldConfig": {"defaults": fc, "overrides": []},
                   "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                               "orientation": "horizontal", "displayMode": "gradient", "valueMode": "color",
                               "showUnfilled": True, "namePlacement": "top", "sizing": "auto", "minVizHeight": 10, "maxVizHeight": 22}})


# ------------------------------------------------------------------ Now
row("Now", 0)
stat("Attackers", 'huginn_attackers{window="24h"}', 0, 1, color="blue", desc="Addresses seen in the last 24 hours.")
stat("New", 'huginn_attackers_new{window="24h"}', 3, 1, color="purple", desc="Addresses seen for the first time in the last 24 hours.")
stat("Logged in", 'sum(huginn_sessions_last_24h{logged_in="yes"})', 6, 1, color="orange", desc="SSH and Telnet sessions that got in, last 24 hours.")
stat("Commands", 'sum(huginn_events_last_24h{kind="cmd"})', 9, 1, color="orange", desc="Commands typed in the fake shells, last 24 hours.")
stat("Files", 'huginn_files_captured', 12, 1, color="red", desc="Files captured so far (uploads and downloads).")
stat("Blocklist", 'huginn_blocklist_entries', 15, 1, color="green", desc="Addresses on the default blocklist.")
stat("Last sync", 'time() - huginn_last_sync_timestamp_seconds', 18, 1, unit="s", decimals=0, spark=False,
     steps=[("green", None), ("orange", 300), ("red", 900)], desc="Time since Huginn last collected from the honeypot (it syncs every 2 minutes).")
stat("Problems", 'huginn_collection_problems', 21, 1, spark=False, steps=[("green", None), ("red", 1)],
     desc="Collection problems: a source that went quiet for longer than usual, or no sync at all. 0 is good.")

# ------------------------------------------------------------------ Activity
row("Activity", 5)
series("Decoy hits per hour, by service",
       [tgt('sum by (service) (increase(huginn_events_ingested_total{source=~"canary|traps"}[1h]))', "{{service}}")],
       0, 6, 12, 9, bars=True, stack=True, interval="1h", legend="right",
       desc="Hits on the decoy services (OpenCanary and hp-traps), counted per hour.")
series("SSH and Telnet per hour",
       [tgt('sum by (kind) (increase(huginn_events_ingested_total{source="cowrie",kind=~"connect|login_fail|login_ok|cmd|file|exploit"}[1h]))', "{{kind}}")],
       12, 6, 12, 9, bars=True, stack=True, interval="1h", legend="right",
       desc="What happened in Cowrie, counted per hour: connections, failed and accepted logins, commands, files and exploits.")
series("Attackers", [tgt('huginn_attackers{window="24h"}', "active last 24 h", ref="A"), tgt('huginn_attackers_new{window="24h"}', "new last 24 h", ref="B"),
                     tgt('huginn_attackers{window="1h"}', "active last hour", ref="C")],
       0, 15, 12, 8, desc="Rolling counts of distinct addresses.",
       overrides=[{"matcher": {"id": "byName", "options": "active last 24 h"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
                  {"matcher": {"id": "byName", "options": "new last 24 h"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}}]},
                  {"matcher": {"id": "byName", "options": "active last hour"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}])
series("Tarpit catches per hour", [tgt('sum by (source) (increase(huginn_events_ingested_total{kind=~"tarpit|trap_end"}[1h]))', "{{source}}")],
       12, 15, 6, 8, bars=True, stack=True, interval="1h", desc="Connections that ended after being held in a tarpit (endlessh) or a slow trap reply.")
bargauge("Decoy tries counted, not stored (today)", 'sort_desc(huginn_decoy_dropped_today > 0)', "{{service}}", 18, 15, 6, 8,
         color="purple", desc="Repeated tries beyond the daily cap per address and service (HUGINN_DECOY_CAP): counted, not stored. Resets at midnight UTC.")

# ------------------------------------------------------------------ Huginn
row("Huginn", 23)
stat("Version", 'topk(1, huginn_info)', 0, 24, w=4, h=4, spark=False, text_mode="name", legend="{{version}}", color="text", instant=True,
     desc="The running Huginn version.")
stat("Last backup", 'time() - huginn_backup_last_timestamp_seconds', 4, 24, w=4, h=4, unit="s", decimals=0, spark=False,
     steps=[("green", None), ("orange", 26 * 3600), ("red", 50 * 3600)], desc="Age of the newest automatic database copy (daily by default).")
stat("Events stored", 'huginn_events_stored', 8, 24, w=4, h=4, color="blue", desc="Events in the database.")
stat("Lookup errors", 'sum(huginn_lookup_error)', 12, 24, w=4, h=4, spark=False,
     steps=[("green", None), ("orange", 1)], desc="Outside lookups whose last try failed: a refused key, a DNS problem, or a service that answers a used-up allowance with an error (GreyNoise). Settings, Lookups says why.")
stat("Database", 'huginn_database_bytes', 16, 24, w=4, h=4, unit="bytes", color="blue", desc="Size of the database file.")
stat("Sync took", 'huginn_last_sync_duration_seconds', 20, 24, w=4, h=4, unit="s", decimals=1, spark=True,
     steps=[("green", None), ("orange", 60), ("red", 180)], desc="How long the last sync took.")
bargauge("Lookups today, share of the daily limit", 'sort_desc(100 * huginn_lookups_used_today / (huginn_lookups_daily_limit > 0))', "{{service}}",
         0, 28, 8, 11, unit="percent", maxv=100, steps=[("green", None), ("orange", 75), ("red", 95)],
         desc="How much of each lookup's daily allowance is used today (UTC). A full bar means the rest waits until tomorrow.")
series("Sync", [tgt('huginn_last_sync_duration_seconds', "duration", ref="A"), tgt('huginn_last_sync_new_events', "new events", ref="B")],
       8, 28, 8, 11, unit="s", desc="Duration of each sync (left) and how many new events it brought (right, bars).",
       overrides=[{"matcher": {"id": "byName", "options": "new events"},
                   "properties": [{"id": "unit", "value": "short"}, {"id": "custom.axisPlacement", "value": "right"},
                                  {"id": "custom.drawStyle", "value": "bars"}, {"id": "custom.fillOpacity", "value": 40},
                                  {"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}}]},
                  {"matcher": {"id": "byName", "options": "duration"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]}])
series("Database size", [tgt('huginn_database_bytes', "database")], 16, 28, 8, 11, unit="bytes", desc="Size of the database file over time.",
       overrides=[{"matcher": {"id": "byName", "options": "database"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}},
                                                                                   {"id": "custom.axisSoftMin", "value": None}]}])

dash = {
    "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "description": "The Prometheus that scrapes Huginn's /metrics",
                  "type": "datasource", "pluginId": "prometheus", "pluginName": "Prometheus"}],
    "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
                   {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
                   {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
                   {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
                   {"type": "panel", "id": "bargauge", "name": "Bar gauge", "version": ""}],
    "title": TITLE, "uid": UID, "tags": ["huginn", "honeypot", "security", "homelab"], "editable": True,
    "schemaVersion": 39, "version": 1, "time": {"from": "now-24h", "to": "now"}, "refresh": "1m", "timezone": "browser",
    "graphTooltip": 1,
    "description": "Huginn honeypot metrics (https://github.com/ancientswede/Huginn). Counts only, never addresses or anything an attacker typed.",
    "templating": {"list": [{"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus",
                             "current": {"selected": False, "text": "${DS_PROMETHEUS}", "value": "${DS_PROMETHEUS}"}, "hide": 0, "refresh": 1, "options": []}]},
    "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
                              "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"}]},
    "links": [{"title": "Huginn on GitHub", "type": "link", "url": "https://github.com/ancientswede/Huginn", "targetBlank": True, "icon": "external link"}],
    "panels": panels,
}
json.dump(dash, open(OUT, "w"), indent=2)
print("panels:", len(panels))
