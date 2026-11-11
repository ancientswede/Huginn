#!/usr/bin/env python3
# krawl-rules.py — turn Krawl's YARA web rules into Huginn's static/web-rules.json.gz (part of Huginn, AGPL-3.0-or-later).
#
#   git clone --depth 1 https://github.com/BlessedRebuS/Krawl /tmp/krawl
#   python3 -I tools/krawl-rules.py /tmp/krawl/rules static/web-rules.json.gz
#
# The rules are Krawl's (MIT, see static/web-rules.LICENSE). Huginn has no YARA engine, so only rules of the common form
# "field X (or Y) and any of these strings" are taken; strings become a plain substring test or a Python regex.
# Rules with byte patterns, counts, offsets or header names are skipped and listed at the end.
import glob, gzip, json, os, re, sys, time

RULE = re.compile(r'^rule (\w+)[^{]*\{(.*?)\n\}', re.S | re.M)
CLAUSE = re.compile(r'\(?\s*\(?((?:scan_target == "[\w*]+"(?: or )?)+)\)?\s+and\s+(any of them|any of \(([^)]*)\)|\$\w+)\s*\)?')
STRING = re.compile(r'^\s+(\$\w*)\s*=\s*(".*"|/.*/[is]*|\{.*\})\s*(.*?)$', re.M)
FIELDS = {"path", "query", "body", "user_agent", "uri", "method", "*"}


def string(v, mods):
    # ("l", text, nocase) for a literal, ("r", regex, nocase) for a regex, None when Huginn cannot use it.
    nocase = "nocase" in mods.split()
    if v.startswith('"'):
        try:
            lit = json.loads(re.sub(r"\\x([0-9a-fA-F]{2})", r"\\u00\1", v))
        except ValueError:
            return None
        return ["l", lit.lower() if nocase else lit, nocase]
    if v.startswith("/"):
        body, flags = v[1:].rsplit("/", 1)
        try:
            re.compile(body)
        except re.error:
            return None
        return ["r", body, "i" in flags or nocase]
    return None


def convert(text):
    out, skipped = [], []
    for m in RULE.finditer(text):
        name, body = m.groups()
        if "strings:" not in body or "condition:" not in body:
            skipped.append(name)
            continue
        head, rest = body.split("strings:", 1)
        meta = dict(re.findall(r'^\s+(\w+) = "?(.*?)"?\s*$', head, re.M))
        strs_txt, cond = rest.split("condition:", 1)
        cond = " ".join(cond.split())
        strs = {}
        for sid, v, mods in STRING.findall(strs_txt):
            s = string(v, mods)
            if s is None:
                strs = None
                break
            strs[sid] = s
        if not strs or re.search(r"header_name|#|@|filesize|\bnot\b|\bfor\b", cond):
            skipped.append(name)
            continue
        # "and (any of ($sel_*) or true)" is always true: it only marks which strings say more about the reply.
        cond = re.sub(r"\s+and\s+\(any of \([^)]*\) or true\)", "", cond).strip()
        # No field named: the strings may match in any field.
        bare = re.fullmatch(r"\(?\s*(any of them|any of \(([^)]*)\)|\$\w+)\s*\)?", cond)
        if bare:
            cond = 'scan_target == "*" and ' + bare.group(1)
        clauses, left = [], cond
        for cm in CLAUSE.finditer(cond):
            targets = re.findall(r'"([\w*]+)"', cm.group(1))
            sel = cm.group(2)
            if sel == "any of them":
                ids = list(strs)
            elif sel.startswith("$"):
                ids = [sel]
            else:
                ids = []
                for p in (x.strip() for x in cm.group(3).split(",")):
                    ids += [k for k in strs if k.startswith(p[:-1])] if p.endswith("*") else [p]
            pats = [strs[i] for i in ids if i in strs]
            if not pats or not set(targets) <= FIELDS:
                clauses = None
                break
            clauses.append([targets, pats])
            left = left.replace(cm.group(0), "", 1)
        if not clauses or re.sub(r"[\s()]|\bor\b", "", left):
            skipped.append(name)
            continue
        try:
            sev = max(0, min(10, int(meta.get("severity") or 0)))
        except ValueError:
            sev = 0
        out.append({"rule": name, "type": meta.get("attack_type") or name, "sev": sev,
                    "cve": meta.get("cve", ""), "desc": meta.get("description", "")[:200], "clauses": clauses})
    return out, skipped


# Huginn's own rules, for things seen on our web trap that Krawl does not cover yet.
EXTRA = [
    {"rule": "huginn_mcp_probe", "type": "mcp_probe", "sev": 4, "cve": "",
     "desc": "Looks for an exposed MCP server (tools for AI assistants): /mcp, /sse and the MCP discovery file.",
     "clauses": [[["path"], [["r", r"^/(?:api/|v1/)?(?:mcp|sse)/?$", True], ["l", "/.well-known/mcp", True]]]]},
]

# Strings an attacker controls, used to throw out any regex that backtracks badly. Every field Huginn scans is under
# about 600 characters, so a rule that is slow here would be slow in real use.
PROBES = [c * 600 for c in "a/%.'\" =<>-_\\0x;:&?(){}[]|\t\n\r"] + [
    "/a" * 300, "a=" * 300, "'a'" * 200, "%2e" * 200, "<a " * 200, "a b " * 150, "ab" * 300, "${" * 200, "../" * 200, "0x41" * 150]
SLOW = 0.05


def too_slow(rule):
    for _targets, pats in rule["clauses"]:
        for kind, p, nocase in pats:
            if kind != "r":
                continue
            rx = re.compile(p, re.I if nocase else 0)
            for probe in PROBES:
                t = time.perf_counter()
                rx.search(probe)
                if time.perf_counter() - t > SLOW:
                    return True
    return False


def main(src, dst):
    rules, skipped = [], []
    for f in sorted(glob.glob(os.path.join(src, "*.yar"))):
        r, s = convert(open(f, encoding="utf-8").read())
        rules += r
        skipped += s
    if not rules:
        sys.exit("no rules found in %s" % src)
    rules += EXTRA
    slow = [r["rule"] for r in rules if too_slow(r)]
    rules = [r for r in rules if r["rule"] not in slow]
    skipped += ["%s (slow regex)" % n for n in slow]
    data = json.dumps({"source": "Krawl (github.com/BlessedRebuS/Krawl), MIT", "rules": rules}, ensure_ascii=False, separators=(",", ":"))
    with gzip.GzipFile(dst, "wb", mtime=0) as fh:
        fh.write(data.encode("utf-8"))
    print("%d rules written to %s, %d skipped: %s" % (len(rules), dst, len(skipped), ", ".join(skipped[:40])))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__ or "usage: krawl-rules.py RULES_DIR OUT.json.gz")
    main(sys.argv[1], sys.argv[2])
