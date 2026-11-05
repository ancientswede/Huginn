#!/usr/bin/env python3
# personas.py — ready-made, randomised Cowrie personas with planted bait (part of Huginn, AGPL-3.0-or-later).
#
#   personas.py make PERSONA OUTDIR          write OUTDIR/honeyfs/... and OUTDIR/persona.json (PERSONA: server, nas, camera)
#   personas.py fs PICKLE_IN PICKLE_OUT HONEYFS
#                                            copy Cowrie's filesystem pickle and add/replace every file from HONEYFS
#   personas.py cfg OUTDIR COWRIE_DIR [--ssh PORT] [--telnet PORT] [--shared DIR]
#                                            write COWRIE_DIR/etc/cowrie.cfg for the persona in OUTDIR
#   personas.py list                         the personas and what they look like
#
# Every install gets its own hostname, network, hardware and bait values, so two Huginn honeypots never look the
# same (a fixed persona would let attackers fingerprint every Huginn install at once). The bait is made up and only
# exists inside the fake file systems: when an attacker later uses one of these values anywhere, Huginn knows where
# it came from (tag "took-bait"). Standard library only.
import json, os, pickle, random, string, sys, time

R = random.SystemRandom()
PERSONAS = {
    "server": "Ubuntu server with a web app, a database and backups to S3 (SSH)",
    "nas": "Debian file server with Samba, rsync backups and Nextcloud (SSH)",
    "camera": "Cheap ARM IP camera with BusyBox (Telnet)",
}

# Cowrie's pickle node layout
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2


def pick(xs):
    return R.choice(xs)


def rnd(n, alphabet=string.ascii_letters + string.digits):
    return "".join(R.choice(alphabet) for _ in range(n))


def password():
    # Looks like something a person chose and then made "strong": Word + year/digits + symbol + random tail.
    word = pick(["Summer", "Winter", "Backup", "Server", "Admin", "Welcome", "Company", "Storage", "Secure", "Deploy",
                 "Network", "Office", "Master", "Spring", "Autumn", "Dragon", "Falcon", "Phoenix", "Thunder", "Galaxy"])
    return "%s%s%s%s" % (word, pick(["2019", "2021", "2023", "2024", "2025", str(R.randint(10, 99))]), pick("!#$%&*@"), rnd(R.randint(5, 8)))


def token(n):
    return rnd(n, string.ascii_lowercase + string.digits)


def private_net():
    k = R.randint(0, 2)
    if k == 0:
        return "10.%d.%d." % (R.randint(0, 254), R.randint(0, 254))
    if k == 1:
        return "172.%d.%d." % (R.randint(16, 31), R.randint(0, 254))
    return "192.168.%d." % R.randint(2, 254)


def cpuinfo_x86(cores, model):
    flags = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx "
             "pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic "
             "movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch avx2 bmi1 bmi2 erms")
    return "".join("processor\t: %d\nvendor_id\t: %s\ncpu family\t: %d\nmodel name\t: %s\ncpu MHz\t\t: %s\ncache size\t: %d KB\n"
                   "physical id\t: 0\nsiblings\t: %d\ncore id\t\t: %d\ncpu cores\t: %d\nflags\t\t: %s\nbogomips\t: %s\n\n"
                   % (i, "AuthenticAMD" if "AMD" in model else "GenuineIntel", 25 if "AMD" in model else 6, model,
                      "2400.000", R.choice([16384, 24576, 32768]), cores, i, cores, flags, "4800.00") for i in range(cores))


def meminfo(total_kb):
    free = int(total_kb * R.uniform(0.25, 0.55))
    cached = int(total_kb * R.uniform(0.1, 0.25))
    buffers = int(total_kb * R.uniform(0.005, 0.02))
    swap = R.choice([0, 2097148, 4194300, 8388604])
    return ("MemTotal:       %d kB\nMemFree:        %d kB\nMemAvailable:   %d kB\nBuffers:        %d kB\nCached:         %d kB\n"
            "SwapCached:            0 kB\nShmem:          %d kB\nSwapTotal:      %d kB\nSwapFree:       %d kB\n"
            % (total_kb, free, free + cached + buffers, buffers, cached, int(total_kb * 0.01), swap, swap))


def passwd(users):
    base = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n")
    return base + "".join("%s:x:%d:%d:%s,,,:/home/%s:/bin/bash\n" % (u, 1000 + i, 1000 + i, u, u) for i, u in enumerate(users))


def group(users):
    base = ("root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:syslog%s\nsudo:x:27:%s\nwww-data:x:33:\nusers:x:100:\nnogroup:x:65534:\n"
            % ("," + users[0] if users else "", ",".join(users[-1:])))
    return base + "".join("%s:x:%d:\n" % (u, 1000 + i) for i, u in enumerate(users))


def shadow(users):
    # Random SHA-512-crypt-looking hashes: they belong to no password at all, so cracking them gets nowhere.
    alpha = string.ascii_letters + string.digits + "./"
    h = lambda: "$6$%s$%s" % (rnd(16, alpha), rnd(86, alpha))
    days = R.randint(19000, 20000)
    rows = ["root:%s:%d:0:99999:7:::" % (h(), days)] + ["%s:*:%d:0:99999:7:::" % (n, days) for n in ("daemon", "bin", "sys", "sync", "www-data", "nobody", "sshd")]
    rows += ["%s:%s:%d:0:99999:7:::" % (u, h(), days + R.randint(0, 300)) for u in users]
    return "\n".join(rows) + "\n"


# ---------------------------------------------------------------------------------------------------- personas

def server():
    ubuntu = pick([("22.04.5 LTS", "Jammy Jellyfish", "jammy", "5.15.0-%d-generic" % R.randint(105, 131), "8.9p1 Ubuntu-3ubuntu0.%d" % R.randint(6, 13),
                    "3.0.2 15 Mar 2022", "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38"),
                   ("24.04.1 LTS", "Noble Numbat", "noble", "6.8.0-%d-generic" % R.randint(40, 60), "9.6p1 Ubuntu-3ubuntu13.%d" % R.randint(3, 8),
                    "3.0.13 30 Jan 2024", "x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42")])
    ver, codename_long, codename, kernel, sshv, sslv, gcc = ubuntu
    app = pick(["store", "crm", "billing", "portal", "booking", "inventory", "helpdesk", "erp", "intranet", "payments"])
    role = pick(["app", "web", "sql", "api", "backend", "worker"])
    host = "%s-%s-%02d" % (pick([app, role]), pick(["prod", "live", "srv", "node"]), R.randint(1, 12))
    net = private_net()
    ip = {k: net + str(R.randint(10, 250)) for k in ("me", "db", "redis", "web", "registry", "smtp")}
    deploy = pick(["deploy", "ops", "app", "admin", "devops", "ci"])
    model, threads = pick([("Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz", 32), ("Intel(R) Xeon(R) Gold 6226R CPU @ 2.90GHz", 32),
                           ("Intel(R) Xeon(R) E-2288G CPU @ 3.70GHz", 16), ("AMD EPYC 7302P 16-Core Processor", 32),
                           ("AMD EPYC 7443P 24-Core Processor", 48)])
    cores = pick([n for n in (4, 8, 12, 16, 24, 32, 48) if n <= threads])   # a VM gets at most what the CPU has
    mem = pick([16, 32, 64, 128]) * 1024 * 1024 - R.randint(100000, 400000)
    region = pick(["eu-north-1", "eu-central-1", "eu-west-1", "us-east-1", "us-west-2"])
    bucket = "%s-%s-backups" % (app, pick(["prod", "live", "db"]))
    bait = {"mysql_backup": password(), "redis": token(24), "aws_key_id": "AKIA" + rnd(16, string.ascii_uppercase + "234567"),
            "aws_secret": rnd(40, string.ascii_letters + string.digits + "/+"), "env_db": password(), "smtp": password(),
            "registry": password(), "deploy_ssh": password(), "app_key": "base64:" + rnd(43, string.ascii_letters + string.digits + "+/") + "="}
    db = "%s_prod" % app
    f = {
        "etc/hostname": host + "\n",
        "etc/issue": "Ubuntu %s \\n \\l\n\n" % ver,
        "etc/os-release": 'PRETTY_NAME="Ubuntu %s"\nNAME="Ubuntu"\nVERSION_ID="%s"\nVERSION="%s (%s)"\nVERSION_CODENAME=%s\nID=ubuntu\n'
                          'ID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\nUBUNTU_CODENAME=%s\n' % (ver, ver[:5], ver, codename_long, codename, codename),
        "etc/motd": "Welcome to Ubuntu %s (GNU/Linux %s x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n"
                    " * Support:        https://ubuntu.com/pro\n\n%d updates can be applied immediately.\n\n*** System restart required ***\n" % (ver, kernel, R.randint(3, 40)),
        "etc/passwd": passwd(["ubuntu", deploy]) + "mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false\nredis:x:113:119::/var/lib/redis:/usr/sbin/nologin\n",
        "etc/hosts": "127.0.0.1 localhost\n%s %s\n%s db01\n%s redis01\n%s registry.internal\n" % (ip["me"], host, ip["db"], ip["redis"], ip["registry"]),
        "etc/group": group(["ubuntu", deploy]),
        "etc/shadow": shadow(["ubuntu", deploy]),
        "etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
                       "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n%d %d\t* * *\troot\t/opt/backup/backup.sh >> /var/log/backup.log 2>&1\n"
                       % (R.randint(0, 59), R.randint(1, 4)),
        "root/.bash_history": "\n".join([
            "systemctl status mysql", "mysql -u backup -p'%s' -h %s %s -e 'show tables;'" % (bait["mysql_backup"], ip["db"], db),
            "redis-cli -h %s -a '%s' info memory" % (ip["redis"], bait["redis"]), "df -h", "cd /var/www/%s" % app, "git pull origin main", "cat .env",
            "docker login registry.internal:5000 -u %s -p %s" % (deploy, bait["registry"]), "docker compose pull && docker compose up -d",
            "aws s3 ls s3://%s/" % bucket, "sshpass -p '%s' ssh %s@%s" % (bait["deploy_ssh"], deploy, ip["web"]), "crontab -l",
            "/opt/backup/backup.sh", "tail -f /var/log/backup.log", "htop", ""]),
        "root/.my.cnf": "[client]\nuser=backup\npassword=%s\nhost=%s\n" % (bait["mysql_backup"], ip["db"]),
        "root/.aws/credentials": "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = %s\n" % (bait["aws_key_id"], bait["aws_secret"], region),
        "root/.ssh/config": "Host db-replica\n    HostName %s\n    User %s\n\nHost web\n    HostName %s\n    User %s\n" % (ip["db"], deploy, ip["web"], deploy),
        "var/www/%s/.env" % app: "APP_NAME=%s\nAPP_ENV=production\nAPP_KEY=%s\nAPP_DEBUG=false\n\nDB_CONNECTION=mysql\nDB_HOST=%s\nDB_PORT=3306\n"
                                 "DB_DATABASE=%s\nDB_USERNAME=%s\nDB_PASSWORD=%s\n\nREDIS_HOST=%s\nREDIS_PASSWORD=%s\n\nMAIL_HOST=%s\nMAIL_PORT=587\n"
                                 "MAIL_USERNAME=noreply\nMAIL_PASSWORD=%s\n\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_DEFAULT_REGION=%s\nAWS_BUCKET=%s\n"
                                 % (app.capitalize(), bait["app_key"], ip["db"], db, app, bait["env_db"], ip["redis"], bait["redis"], ip["smtp"],
                                    bait["smtp"], bait["aws_key_id"], bait["aws_secret"], region, bucket),
        "opt/backup/backup.sh": "#!/bin/bash\n# nightly db backup -> s3\nset -e\nTS=$(date +%%F)\nmysqldump -u backup -p'%s' -h %s --single-transaction %s | gzip > /opt/backup/%s-$TS.sql.gz\n"
                                "aws s3 cp /opt/backup/%s-$TS.sql.gz s3://%s/db/\nfind /opt/backup -name '*.sql.gz' -mtime +7 -delete\n"
                                % (bait["mysql_backup"], ip["db"], db, db, db, bucket),
        "proc/cpuinfo": cpuinfo_x86(cores, model),
        "proc/meminfo": meminfo(mem),
        "proc/version": "Linux version %s (buildd@lcy02-amd64-%03d) (%s) #%d-Ubuntu SMP %s\n"
                        % (kernel, R.randint(1, 120), gcc, R.randint(100, 160), "Thu Aug 29 13:45:52 UTC 2024"),
    }
    return f, {"hostname": host, "kernel_version": kernel, "kernel_build_string": "#%d-Ubuntu SMP PREEMPT_DYNAMIC" % R.randint(100, 160),
               "hardware_platform": "x86_64", "arch": "linux-x64-lsb", "ssh_version": "OpenSSH_%s, OpenSSL %s" % (sshv.split()[0], sslv),
               "ssh_banner": "SSH-2.0-OpenSSH_" + sshv, "cpus": cores, "cpu_model": model,
               "users": ["ubuntu", deploy],
               "commands": {"usr/bin/mysql": "ERROR 2003 (HY000): Can't connect to MySQL server on '%s:3306' (110)\n" % ip["db"],
                            "usr/bin/mysqldump": "mysqldump: Got error: 2003: \"Can't connect to MySQL server on '%s:3306' (110)\" when trying to connect\n" % ip["db"],
                            "usr/bin/redis-cli": "Could not connect to Redis at %s:6379: Connection timed out\n" % ip["redis"],
                            "usr/local/bin/aws": "\nConnect timeout on endpoint URL: \"https://%s.s3.%s.amazonaws.com/?list-type=2&prefix=&delimiter=%%2F&encoding-type=url\"\n" % (bucket, region),
                            "usr/bin/docker": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n"}}, bait


def nas():
    host = pick(["nas", "storage", "files", "fileserver", "backup", "nas01", "store", "archive"]) + pick(["", "01", "02", "-01", "-main"])
    net = private_net()
    ip = {k: net + str(R.randint(10, 250)) for k in ("me", "db", "offsite")}
    user = pick(["admin", "backup", "media", "files", "family", "office"])
    kernel = "6.1.0-%d-amd64" % R.randint(18, 28)
    model, cores = pick([("Intel(R) Celeron(R) J4125 CPU @ 2.00GHz", 4), ("Intel(R) Pentium(R) Silver N6005 @ 2.00GHz", 4),
                         ("AMD Ryzen 5 PRO 4650G with Radeon Graphics", 12), ("Intel(R) Core(TM) i3-10100 CPU @ 3.60GHz", 8),
                         ("Intel(R) Xeon(R) E-2224 CPU @ 3.40GHz", 4)])     # bare metal: all threads
    mem = pick([4, 8, 16, 32]) * 1024 * 1024 - R.randint(100000, 300000)
    bait = {"nas_smb": password(), "nas_rsync": password(), "nc_db": password(), "nc_secret": rnd(48, string.ascii_letters + string.digits + "+/"),
            "nc_admin": password(), "b2_key_id": "005" + token(22), "b2_key": "K005" + rnd(27, string.ascii_letters + string.digits)}
    f = {
        "etc/hostname": host + "\n",
        "etc/issue": "Debian GNU/Linux 12 \\n \\l\n\n",
        "etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\n'
                          'VERSION_CODENAME=bookworm\nID=debian\nHOME_URL="https://www.debian.org/"\n',
        "etc/motd": "\nThe programs included with the Debian GNU/Linux system are free software;\nthe exact distribution terms for each program are described in the\n"
                    "individual files in /usr/share/doc/*/copyright.\n\nDebian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\npermitted by applicable law.\n",
        "etc/passwd": passwd([user]) + "www-nextcloud:x:998:998::/var/www/nextcloud:/usr/sbin/nologin\n",
        "etc/hosts": "127.0.0.1 localhost\n%s %s\n%s offsite-backup\n" % (ip["me"], host, ip["offsite"]),
        "etc/group": group([user]),
        "etc/shadow": shadow([user]),
        "etc/rsyncd.secrets": "%s:%s\n" % (user, bait["nas_rsync"]),
        "etc/samba/smb.conf": "[global]\n   workgroup = WORKGROUP\n   server string = %s\n   map to guest = bad user\n\n[backup]\n   path = /srv/backup\n"
                              "   valid users = %s\n   read only = no\n\n[media]\n   path = /srv/media\n   guest ok = yes\n" % (host, user),
        "root/.smbcredentials": "username=%s\npassword=%s\n" % (user, bait["nas_smb"]),
        "root/.bash_history": "\n".join([
            "zpool status", "df -h /srv", "rsync -av --password-file=/etc/rsyncd.secrets /srv/backup/ rsync://%s@%s/offsite/" % (user, ip["offsite"]),
            "rclone sync /srv/backup b2:%s-backup --transfers 8" % host, "cat /root/.smbcredentials", "smbpasswd -a %s" % user,
            "sudo -u www-nextcloud php /var/www/nextcloud/occ files:scan --all", "mysql -u nextcloud -p'%s' nextcloud" % bait["nc_db"],
            "systemctl restart smbd", "smartctl -a /dev/sda", ""]),
        "root/.config/rclone/rclone.conf": "[b2]\ntype = b2\naccount = %s\nkey = %s\nhard_delete = true\n" % (bait["b2_key_id"], bait["b2_key"]),
        "var/www/nextcloud/config/config.php": "<?php\n$CONFIG = array (\n  'instanceid' => 'oc%s',\n  'passwordsalt' => '%s',\n  'secret' => '%s',\n"
                                               "  'trusted_domains' => array (0 => '%s'),\n  'datadirectory' => '/srv/nextcloud-data',\n  'dbtype' => 'mysql',\n"
                                               "  'dbname' => 'nextcloud',\n  'dbhost' => 'localhost',\n  'dbuser' => 'nextcloud',\n  'dbpassword' => '%s',\n"
                                               "  'installed' => true,\n);\n" % (token(10), rnd(30), bait["nc_secret"], ip["me"], bait["nc_db"]),
        "root/nextcloud-admin.txt": "nextcloud admin login\nuser: admin\npass: %s\n" % bait["nc_admin"],
        "proc/cpuinfo": cpuinfo_x86(cores, model),
        "proc/meminfo": meminfo(mem),
        "proc/version": "Linux version %s (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) "
                        "#1 SMP PREEMPT_DYNAMIC Debian 6.1.%d-1 (2024-%02d-%02d)\n" % (kernel, R.randint(90, 130), R.randint(1, 12), R.randint(1, 28)),
    }
    sshv = "9.2p1 Debian-2+deb12u%d" % R.randint(2, 5)
    return f, {"hostname": host, "kernel_version": kernel, "kernel_build_string": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.%d-1" % R.randint(90, 130),
               "hardware_platform": "x86_64", "arch": "linux-x64-lsb", "ssh_version": "OpenSSH_%s, OpenSSL 3.0.15 3 Sep 2024" % sshv,
               "ssh_banner": "SSH-2.0-OpenSSH_" + sshv, "cpus": cores, "cpu_model": model, "users": [user],
               "commands": {"usr/bin/rclone": "ERROR : : error reading source root directory: couldn't list files: Get \"https://api.backblazeb2.com/\": dial tcp: i/o timeout\n",
                            "usr/bin/mysql": "ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)\n",
                            "usr/bin/smbpasswd": "Failed to find entry for user %s.\n" % user}}, bait


def camera():
    soc = pick(["hi3516ev300", "hi3518ev200", "hi3516cv300", "gk7205v300", "gk7205v200", "ak3918ev300", "sc2235"])
    host = pick([soc, "IPCAM", "ipc", "IPC-" + token(4).upper(), "cam" + str(R.randint(1, 16))])
    kernel = pick(["3.18.20", "4.9.37", "3.4.35", "4.4.73"])
    ssid = pick(["Warehouse", "Reception", "Workshop", "Garage", "Store", "Studio", "Backyard", "Guest"]) + pick(["-2G", "_2.4", "", "-IoT", "_Cam"])
    nvr = private_net() + str(R.randint(2, 250))
    bait = {"cam_admin": password(), "cam_wifi": password(), "cam_rtsp": password(), "cam_ftp": password(), "cam_cloud": token(20)}
    mem = pick([32, 64, 128]) * 1024 - R.randint(2000, 9000)
    f = {
        "etc/hostname": host + "\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n",
        "etc/group": "root:x:0:\ndaemon:x:1:\nnogroup:x:65534:\n",
        "etc/shadow": "root:$1$%s$%s:%d:0:99999:7:::\n" % (rnd(8), rnd(22, string.ascii_letters + string.digits + "./"), R.randint(17000, 18500)),
        "etc/hosts": "127.0.0.1 localhost\n127.0.1.1 %s\n" % host,
        "etc/motd": "\n\nBusyBox v1.%d.%d (2019-%02d-%02d 11:05:38 CST) built-in shell (ash)\nEnter 'help' for a list of built-in commands.\n\n"
                    % (R.choice([20, 22, 26]), R.randint(1, 2), R.randint(1, 12), R.randint(1, 28)),
        "mnt/mtd/Config/Account1": "[user]\nname=admin\npassword=%s\ngroup=admin\n[user]\nname=user\npassword=user\ngroup=user\n" % bait["cam_admin"],
        "mnt/mtd/Config/network.conf": "[wifi]\nssid=%s\npsk=%s\n[rtsp]\nurl=rtsp://admin:%s@127.0.0.1:554/stream1\n[ftp_upload]\nhost=%s\nuser=nvr\npass=%s\n"
                                       "[cloud]\ntoken=%s\n" % (ssid, bait["cam_wifi"], bait["cam_rtsp"], nvr, bait["cam_ftp"], bait["cam_cloud"]),
        "etc/wpa_supplicant.conf": 'ctrl_interface=/var/run/wpa_supplicant\nnetwork={\n\tssid="%s"\n\tpsk="%s"\n\tkey_mgmt=WPA-PSK\n}\n' % (ssid, bait["cam_wifi"]),
        "proc/cpuinfo": "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nBogoMIPS\t: %s\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm\n"
                        "CPU implementer\t: 0x41\nCPU architecture: 7\nCPU variant\t: 0x0\nCPU part\t: 0xc07\nCPU revision\t: 5\n\nHardware\t: %s\nRevision\t: 0000\nSerial\t\t: 0000000000000000\n"
                        % (pick(["1810.00", "1990.00", "2000.00"]), soc),
        "proc/meminfo": meminfo(mem),
        "proc/version": "Linux version %s (%s@build) (gcc version 4.9.4 (HC&C V100R002C00B032_20190114)) #%d SMP %s\n"
                        % (kernel, pick(["root", "build", "jenkins"]), R.randint(1, 9), "Wed Jun 12 11:11:05 CST 2019"),
    }
    return f, {"hostname": host, "kernel_version": kernel, "kernel_build_string": "#%d SMP" % R.randint(1, 9), "hardware_platform": "armv7l",
               "arch": "linux-arm-lsb", "ssh_version": "", "ssh_banner": "SSH-2.0-dropbear_2019.78", "cpus": 1, "cpu_model": "ARMv7 Processor rev 5 (v7l)",
               "users": []}, bait


MAKERS = {"server": server, "nas": nas, "camera": camera}
PRIVATE = ("root/", "etc/shadow", "etc/rsyncd.secrets", "etc/wpa_supplicant.conf", "mnt/mtd/Config/")


def make(persona, out):
    files, info, bait = MAKERS[persona]()
    for rel in info.get("commands", {}):
        files[rel] = b"\x7fELF\x02\x01\x01" + bytes(R.getrandbits(8) for _ in range(R.randint(30000, 90000)))
    for rel, text in files.items():
        p = os.path.join(out, "honeyfs", rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(text, bytes) else "w") as fh:
            fh.write(text)
        mode = 0o600 if rel.startswith(PRIVATE) or rel.endswith((".env", "config.php", ".my.cnf")) else 0o644
        if rel.endswith(".sh"):
            mode = 0o750
        if rel in info.get("commands", {}):
            mode = 0o755
        os.chmod(p, mode)
    info.update({"persona": persona, "bait": bait, "created": time.strftime("%Y-%m-%d")})
    with open(os.path.join(out, "persona.json"), "w") as fh:
        json.dump(info, fh, indent=2)
    os.chmod(os.path.join(out, "persona.json"), 0o600)
    return info


def add_to_pickle(src, dst, honeyfs, users=()):
    # Cowrie only shows files that exist in its filesystem pickle; newer Cowrie also keeps file contents there (bytes).
    with open(src, "rb") as fh:
        fs = pickle.load(fh)
    homes = {"/home/%s" % u: (1000 + i, 1000 + i) for i, u in enumerate(users)}
    now = time.time()

    def child(d, name):
        for c in d[A_CONTENTS]:
            if c[A_NAME] == name:
                return c
        return None

    def owner(path):
        for p, ug in homes.items():
            if path == p or path.startswith(p + "/"):
                return ug
        return (0, 0)

    added = updated = 0
    home = child(fs, "home")
    if home is not None:                 # Cowrie's own example users (e.g. "phil") do not belong to this persona
        home[A_CONTENTS] = [c for c in home[A_CONTENTS] if "/home/" + c[A_NAME] in homes]
    for u in homes:                      # home directories for the persona's users
        node = fs
        for part in u.strip("/").split("/"):
            c = child(node, part)
            if c is None:
                uid, gid = owner(u)
                c = [part, T_DIR, uid, gid, 4096, 0o40755, now - R.randint(100, 900) * 86400, [], None, None]
                node[A_CONTENTS].append(c)
                added += 1
            node = c
    for root, _dirs, names in os.walk(honeyfs):
        for name in sorted(names):
            real = os.path.join(root, name)
            vpath = "/" + os.path.relpath(real, honeyfs)
            parts = vpath.strip("/").split("/")
            node, cur = fs, ""
            for part in parts[:-1]:
                cur += "/" + part
                c = child(node, part)
                if c is None:
                    uid, gid = owner(cur)
                    mode = 0o40700 if part in (".ssh", ".aws", ".config", "root") else 0o40755
                    c = [part, T_DIR, uid, gid, 4096, mode, now - R.randint(30, 400) * 86400, [], None, None]
                    node[A_CONTENTS].append(c)
                    added += 1
                node = c
            with open(real, "rb") as fh:
                data = fh.read()
            st = os.stat(real)
            f = child(node, parts[-1])
            if f is None:
                uid, gid = owner(vpath)
                f = [parts[-1], T_FILE, uid, gid, len(data), 0o100000 | (st.st_mode & 0o777), now - R.randint(1, 60) * 86400, data, None, None]
                node[A_CONTENTS].append(f)
                added += 1
            else:
                f[A_SIZE] = len(data)
                if f[A_TYPE] == T_FILE:
                    f[A_CONTENTS] = data
                updated += 1
    with open(dst + ".tmp", "wb") as fh:
        pickle.dump(fs, fh)
    os.replace(dst + ".tmp", dst)
    return added, updated


def cowrie_cfg(out, cowrie_dir, ssh=None, telnet=None, shared=None):
    with open(os.path.join(out, "persona.json")) as fh:
        p = json.load(fh)
    state = shared or "var/lib/cowrie"
    lines = ["# Written by Huginn install-honeypot.sh: persona '%s' (%s)." % (p["persona"], PERSONAS[p["persona"]]),
             "# Full list of settings: src/cowrie/data/etc/cowrie.cfg.dist", "[honeypot]", "hostname = %s" % p["hostname"],
             "sensor_name = %s" % p["persona"], "contents_path = honeyfs", "txtcmds_path = txtcmds",
             "download_path = %s/downloads" % state, "ttylog_path = %s/tty" % state,
             "# Let attackers in after 2-5 tries (like a weak real device), remember each IP's password",
             "auth_class = AuthRandom", "auth_class_parameters = 2, 5, 10", "", "[shell]",
             "filesystem = var/lib/cowrie/fs-%s.pickle" % p["persona"], "kernel_version = %s" % p["kernel_version"],
             "kernel_build_string = %s" % p["kernel_build_string"], "hardware_platform = %s" % p["hardware_platform"],
             "operating_system = GNU/Linux", "arch = %s" % p["arch"]]
    if p.get("ssh_version"):
        lines.append("ssh_version = %s" % p["ssh_version"])
    lines += ["", "[ssh]", "enabled = %s" % ("true" if ssh else "false")]
    if ssh:
        lines += ["listen_endpoints = tcp:%d:interface=0.0.0.0" % ssh, "version = %s" % p["ssh_banner"]]
    lines += ["", "[telnet]", "enabled = %s" % ("true" if telnet else "false")]
    if telnet:
        lines.append("listen_endpoints = tcp:%d:interface=0.0.0.0" % telnet)
    with open(os.path.join(cowrie_dir, "etc", "cowrie.cfg"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def txtcmds(out, dst):
    # Cowrie's canned outputs for nproc/lscpu must agree with the persona's /proc/cpuinfo.
    with open(os.path.join(out, "persona.json")) as fh:
        p = json.load(fh)
    for rel, text in [("usr/bin/nproc", "%d\n" % p["cpus"])] + list(p.get("commands", {}).items()):
        os.makedirs(os.path.join(dst, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(dst, rel), "w") as fh:
            fh.write(text)
    lscpu = os.path.join(dst, "usr/bin/lscpu")
    if os.path.exists(lscpu):
        with open(lscpu) as fh:
            lines = fh.read().splitlines()
        new = []
        for l in lines:
            if l.startswith("CPU(s):"):
                l = "CPU(s):" + " " * max(1, len(l) - len("CPU(s):") - len(str(p["cpus"]))) + str(p["cpus"])
            elif l.strip().startswith("Model name:"):
                l = l[:l.index("Model name:") + len("Model name:")] + "            " + p["cpu_model"]
            elif l.startswith("Architecture:") and p["hardware_platform"] != "x86_64":
                l = "Architecture:            " + p["hardware_platform"]
            new.append(l)
        with open(lscpu, "w") as fh:
            fh.write("\n".join(new) + "\n")


def main(argv):
    if len(argv) >= 3 and argv[0] == "make" and argv[1] in MAKERS:
        info = make(argv[1], argv[2])
        print("%s: hostname %s, %d bait values" % (argv[1], info["hostname"], len(info["bait"])))
        return 0
    if len(argv) == 4 and argv[0] == "fs":
        users = []
        meta = os.path.join(os.path.dirname(os.path.abspath(argv[3])), "persona.json")
        if os.path.exists(meta):
            with open(meta) as fh:
                users = json.load(fh).get("users", [])
        a, u = add_to_pickle(argv[1], argv[2], argv[3], users)
        print("filesystem: %d added, %d replaced" % (a, u))
        return 0
    if len(argv) >= 3 and argv[0] == "cfg":
        opts = dict(zip(argv[3::2], argv[4::2]))
        cowrie_cfg(argv[1], argv[2], ssh=int(opts["--ssh"]) if "--ssh" in opts else None,
                   telnet=int(opts["--telnet"]) if "--telnet" in opts else None, shared=opts.get("--shared"))
        return 0
    if len(argv) == 3 and argv[0] == "txtcmds":
        txtcmds(argv[1], argv[2])
        return 0
    if argv[:1] == ["list"]:
        for k, v in PERSONAS.items():
            print("%-7s %s" % (k, v))
        return 0
    sys.stderr.write("usage: personas.py make|fs|cfg|txtcmds|list ... (see the top of this file)\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
