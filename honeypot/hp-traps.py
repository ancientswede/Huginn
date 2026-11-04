#!/usr/bin/env python3
# hp-traps — small fake services for a honeypot (part of Huginn, AGPL-3.0-or-later).
# SMTP open-relay bait (NEVER delivers anything), POP3, IMAP, PostgreSQL and SOCKS5 (always refuses the connection).
# Python standard library only, asyncio, meant to run as an unprivileged systemd DynamicUser.
# One JSON line per event in $LOGS_DIRECTORY/traps-YYYY-MM-DD.json (removed after 30 days).
import asyncio, base64, datetime as dt, glob, json, os, random, string, struct, sys, time

LOGDIR = os.environ.get("LOGS_DIRECTORY", "/var/log/hp-traps")
HOST = os.environ.get("TRAPS_HOST", "0.0.0.0")
PORTS = {"smtp": 2525, "submission": 2587, "pop3": 2110, "imap": 2143, "postgres": 5432, "socks5": 1080}
MAX_CONN = 300
IDLE = 90          # seconds without data -> close
MAX_LINE = 4096
MAX_DATA = 1024 * 1024
KEEP_DAYS = 30
MAX_LOG_DAY = 200 * 1024 * 1024  # stop logging for the day past this size, so a flood cannot fill the disk
HOSTNAME = os.environ.get("TRAPS_HOSTNAME", "mail.example.com")
_active = 0


def log(peer, service, event, **kw):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
           "src_ip": peer[0], "src_port": peer[1], "service": service, "event": event}
    for k, v in kw.items():
        if isinstance(v, (bytes, bytearray)):
            v = v.decode("utf-8", "replace")
        if isinstance(v, str):
            v = v[:600]
        rec[k] = v
    path = os.path.join(LOGDIR, "traps-%s.json" % dt.date.today().isoformat())
    try:
        if os.path.getsize(path) > MAX_LOG_DAY:
            return
    except OSError:
        pass
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def cleanup():
    cutoff = time.time() - KEEP_DAYS * 86400
    for f in glob.glob(os.path.join(LOGDIR, "traps-*.json")):
        try:
            if os.path.getmtime(f) < cutoff:
                os.remove(f)
        except OSError:
            pass


async def readline(r):
    line = await asyncio.wait_for(r.readline(), IDLE)
    if not line:
        raise ConnectionError("closed")
    return line[:MAX_LINE].rstrip(b"\r\n")


async def readexactly(r, n):
    return await asyncio.wait_for(r.readexactly(n), IDLE)


def b64(s):
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "replace")
    except Exception:
        return ""


def qid():
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))


# ---------------------------------------------------------------- SMTP (open relay bait)
async def smtp(r, w, peer, service):
    w.write(b"220 %s ESMTP Postfix (Ubuntu)\r\n" % HOSTNAME.encode()); await w.drain()
    mail_from, rcpts, helo = "", [], ""
    while True:
        line = await readline(r)
        cmd = line[:4].upper()
        arg = line[5:].decode("utf-8", "replace") if len(line) > 5 else ""
        if cmd in (b"EHLO", b"HELO"):
            helo = arg
            log(peer, service, "helo", helo=helo)
            if cmd == b"EHLO":
                w.write(("250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-AUTH=PLAIN LOGIN\r\n"
                         "250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n" % HOSTNAME).encode())
            else:
                w.write(b"250 %s\r\n" % HOSTNAME.encode())
        elif cmd == b"AUTH":
            parts = arg.split()
            mech = parts[0].upper() if parts else ""
            user = pw = ""
            if mech == "PLAIN":
                if len(parts) > 1:
                    blob = b64(parts[1])
                else:
                    w.write(b"334 \r\n"); await w.drain()
                    blob = b64((await readline(r)).decode("ascii", "replace"))
                f = blob.split("\x00")
                user, pw = (f[1], f[2]) if len(f) >= 3 else (blob, "")
            elif mech == "LOGIN":
                if len(parts) > 1:
                    user = b64(parts[1])
                else:
                    w.write(b"334 VXNlcm5hbWU6\r\n"); await w.drain()
                    user = b64((await readline(r)).decode("ascii", "replace"))
                w.write(b"334 UGFzc3dvcmQ6\r\n"); await w.drain()
                pw = b64((await readline(r)).decode("ascii", "replace"))
            else:
                w.write(b"504 5.5.4 Unrecognized authentication type\r\n"); await w.drain(); continue
            log(peer, service, "login", username=user, password=pw, mech=mech)
            w.write(b"235 2.7.0 Authentication successful\r\n")
        elif cmd == b"MAIL":
            mail_from = (arg.split(":", 1)[-1].strip().split(" ") or [""])[0]; rcpts = []
            w.write(b"250 2.1.0 Ok\r\n")
        elif cmd == b"RCPT":
            if len(rcpts) < 100:
                rcpts.append(arg.split(":", 1)[-1].strip())
            w.write(b"250 2.1.5 Ok\r\n")
        elif cmd == b"DATA":
            w.write(b"354 End data with <CR><LF>.<CR><LF>\r\n"); await w.drain()
            buf, size = bytearray(), 0
            while True:
                chunk = await asyncio.wait_for(r.readline(), IDLE)
                if not chunk:
                    raise ConnectionError("closed")
                if chunk in (b".\r\n", b".\n"):
                    break
                size += len(chunk)
                if len(buf) < 4096:
                    buf += chunk
                if size > MAX_DATA:
                    w.write(b"552 5.3.4 Message size exceeds fixed limit\r\n"); await w.drain(); return
            text = buf.decode("utf-8", "replace")
            subj = next((l[8:].strip() for l in text.splitlines() if l.lower().startswith("subject:")), "")
            log(peer, service, "mail", mail_from=mail_from, rcpts=rcpts[:20], rcpt_count=len(rcpts), subject=subj,
                size=size, helo=helo, sample=text[:1500])
            # Pretend to queue — never delivered (the honeypot has no outbound internet, and there is no delivery code).
            w.write(b"250 2.0.0 Ok: queued as %s\r\n" % qid().encode())
        elif cmd == b"RSET":
            mail_from, rcpts = "", []; w.write(b"250 2.0.0 Ok\r\n")
        elif cmd == b"NOOP":
            w.write(b"250 2.0.0 Ok\r\n")
        elif cmd == b"VRFY":
            w.write(b"252 2.0.0 Cannot VRFY user\r\n")
        elif cmd == b"QUIT":
            w.write(b"221 2.0.0 Bye\r\n"); await w.drain(); return
        elif cmd == b"STAR":  # STARTTLS: no certificate, say no
            w.write(b"454 4.7.0 TLS not available due to local problem\r\n")
        else:
            w.write(b"502 5.5.2 Error: command not recognized\r\n")
        await w.drain()


# ---------------------------------------------------------------- POP3
async def pop3(r, w, peer, service):
    w.write(b"+OK Dovecot (Ubuntu) ready.\r\n"); await w.drain()
    user = ""
    while True:
        line = (await readline(r)).decode("utf-8", "replace")
        cmd, _, arg = line.partition(" ")
        cmd = cmd.upper()
        if cmd == "USER":
            user = arg; w.write(b"+OK\r\n")
        elif cmd == "PASS":
            log(peer, service, "login", username=user, password=arg)
            await asyncio.sleep(1.5)
            w.write(b"-ERR [AUTH] Authentication failed.\r\n")
        elif cmd == "CAPA":
            w.write(b"+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nAUTH-RESP-CODE\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n")
        elif cmd == "AUTH" and arg.upper().startswith("PLAIN"):
            p = arg.split()
            if len(p) < 2:
                w.write(b"+ \r\n"); await w.drain(); blob = b64((await readline(r)).decode("ascii", "replace"))
            else:
                blob = b64(p[1])
            f = blob.split("\x00")
            log(peer, service, "login", username=f[1] if len(f) > 2 else blob, password=f[2] if len(f) > 2 else "")
            await asyncio.sleep(1.5)
            w.write(b"-ERR [AUTH] Authentication failed.\r\n")
        elif cmd == "QUIT":
            w.write(b"+OK Logging out.\r\n"); await w.drain(); return
        else:
            w.write(b"-ERR Unknown command.\r\n")
        await w.drain()


# ---------------------------------------------------------------- IMAP
def imap_args(s):
    out, cur, q, i = [], "", False, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and i + 1 < len(s):
                cur += s[i + 1]; i += 2; continue
            if c == '"':
                q = False
            else:
                cur += c
        elif c == '"':
            q = True
        elif c == " ":
            if cur:
                out.append(cur); cur = ""
        else:
            cur += c
        i += 1
    if cur:
        out.append(cur)
    return out


async def imap(r, w, peer, service):
    w.write(b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.\r\n")
    await w.drain()
    while True:
        line = (await readline(r)).decode("utf-8", "replace")
        tag, _, rest = line.partition(" ")
        cmd, _, arg = rest.partition(" ")
        cmd = cmd.upper()
        if cmd == "CAPABILITY":
            w.write(b"* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN\r\n%s OK Capability completed.\r\n" % tag.encode())
        elif cmd == "LOGIN":
            a = imap_args(arg)
            log(peer, service, "login", username=a[0] if a else "", password=a[1] if len(a) > 1 else "")
            await asyncio.sleep(1.5)
            w.write(b"%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n" % tag.encode())
        elif cmd == "AUTHENTICATE" and arg.upper().startswith("PLAIN"):
            p = arg.split()
            if len(p) < 2:
                w.write(b"+ \r\n"); await w.drain(); blob = b64((await readline(r)).decode("ascii", "replace"))
            else:
                blob = b64(p[1])
            f = blob.split("\x00")
            log(peer, service, "login", username=f[1] if len(f) > 2 else blob, password=f[2] if len(f) > 2 else "")
            await asyncio.sleep(1.5)
            w.write(b"%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n" % tag.encode())
        elif cmd == "ID":
            w.write(b'* ID ("name" "Dovecot")\r\n%s OK ID completed.\r\n' % tag.encode())
        elif cmd == "LOGOUT":
            w.write(b"* BYE Logging out\r\n%s OK Logout completed.\r\n" % tag.encode()); await w.drain(); return
        else:
            w.write(b"%s BAD Error in IMAP command received by server.\r\n" % tag.encode())
        await w.drain()


# ---------------------------------------------------------------- PostgreSQL
async def postgres(r, w, peer, service):
    for _ in range(2):
        n = struct.unpack("!I", await readexactly(r, 4))[0]
        if n < 8 or n > 10000:
            return
        body = await readexactly(r, n - 4)
        code = struct.unpack("!I", body[:4])[0]
        if code in (80877103, 80877104):  # SSLRequest / GSSENCRequest -> no
            w.write(b"N"); await w.drain(); continue
        break
    else:
        return
    f = body[4:].split(b"\x00")
    params = {f[i].decode("utf-8", "replace"): f[i + 1].decode("utf-8", "replace") for i in range(0, len(f) - 1, 2) if f[i]}
    user = params.get("user", "")
    w.write(b"R" + struct.pack("!II", 8, 3)); await w.drain()   # AuthenticationCleartextPassword
    t = await readexactly(r, 1)
    if t != b"p":
        log(peer, service, "connect", username=user, database=params.get("database", ""), client=params.get("application_name", ""))
        return
    n = struct.unpack("!I", await readexactly(r, 4))[0]
    if n < 5 or n > 10000:
        return
    pw = (await readexactly(r, n - 4)).rstrip(b"\x00")
    log(peer, service, "login", username=user, password=pw, database=params.get("database", ""),
        client=params.get("application_name", ""))
    await asyncio.sleep(1)
    msg = b"SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed for user \"" + user.encode()[:100] + b"\"\x00\x00"
    w.write(b"E" + struct.pack("!I", len(msg) + 4) + msg); await w.drain()


# ---------------------------------------------------------------- SOCKS5 (and SOCKS4)
async def socks(r, w, peer, service):
    ver = (await readexactly(r, 1))[0]
    if ver == 4:
        hdr = await readexactly(r, 7)
        port, ip = struct.unpack("!H", hdr[1:3])[0], ".".join(str(b) for b in hdr[3:7])
        uid = await asyncio.wait_for(r.readuntil(b"\x00"), IDLE)
        target = ip
        if ip.startswith("0.0.0.") and ip != "0.0.0.0":  # SOCKS4a: hostname after userid
            target = (await asyncio.wait_for(r.readuntil(b"\x00"), IDLE))[:-1].decode("utf-8", "replace")
        log(peer, service, "proxy", version=4, target="%s:%d" % (target, port), username=uid[:-1])
        w.write(b"\x00\x5b" + b"\x00" * 6); await w.drain(); return
    if ver != 5:
        return
    nm = (await readexactly(r, 1))[0]
    methods = await readexactly(r, nm)
    user = pw = ""
    if 2 in methods:
        w.write(b"\x05\x02"); await w.drain()
        await readexactly(r, 1)
        ul = (await readexactly(r, 1))[0]; user = (await readexactly(r, ul)).decode("utf-8", "replace")
        pl = (await readexactly(r, 1))[0]; pw = (await readexactly(r, pl)).decode("utf-8", "replace")
        log(peer, service, "login", username=user, password=pw)
        w.write(b"\x01\x00"); await w.drain()
    elif 0 in methods:
        w.write(b"\x05\x00"); await w.drain()
    else:
        w.write(b"\x05\xff"); await w.drain(); return
    req = await readexactly(r, 4)
    atyp = req[3]
    if atyp == 1:
        host = ".".join(str(b) for b in await readexactly(r, 4))
    elif atyp == 3:
        ln = (await readexactly(r, 1))[0]; host = (await readexactly(r, ln)).decode("utf-8", "replace")
    elif atyp == 4:
        raw = await readexactly(r, 16); host = ":".join("%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2))
    else:
        return
    port = struct.unpack("!H", await readexactly(r, 2))[0]
    log(peer, service, "proxy", version=5, command=req[1], target="%s:%d" % (host, port), username=user)
    await asyncio.sleep(2)
    # 0x05 = connection refused. We NEVER connect onwards.
    w.write(b"\x05\x05\x00\x01" + b"\x00" * 6); await w.drain()


HANDLERS = {"smtp": smtp, "submission": smtp, "pop3": pop3, "imap": imap, "postgres": postgres, "socks5": socks}


def make(service):
    async def handle(r, w):
        global _active
        peer = w.get_extra_info("peername") or ("?", 0)
        if _active >= MAX_CONN:
            w.close(); return
        _active += 1
        try:
            log(peer, service, "connect")
            await HANDLERS[service](r, w, peer, service)
        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError, ValueError):
            pass
        except Exception as e:
            try:
                log(peer, service, "error", error=repr(e)[:200])
            except Exception:
                pass
        finally:
            _active -= 1
            try:
                w.close()
            except Exception:
                pass
    return handle


async def main():
    os.makedirs(LOGDIR, exist_ok=True)
    servers = []
    for svc, port in PORTS.items():
        servers.append(await asyncio.start_server(make(svc), HOST, port, limit=MAX_LINE * 2))
        print("hp-traps: %s on %s:%d" % (svc, HOST, port), flush=True)
    while True:
        cleanup()
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
