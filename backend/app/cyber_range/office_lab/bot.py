"""A simulated employee working at this workstation: the normal background activity a SOC has to tell apart from
attacks. Runs as the unprivileged local user `karyawan`. Each cycle does one ordinary office task:
  * Kerberos sign-in to the domain (kinit)                       -> 4624 on the DC
  * open the department or public file share (smbclient -k)      -> SMB session, file reads
  * use the intranet portal (sign in, open pages, request leave) -> web.access / web.auth
  * look up internal names (DNS to the DC)
  * now and then mistype the password once (a normal 4625, not an attack)
No traffic leaves the lab; nothing is exploited."""
# ruff: noqa: S603, S607, S311  (fixed argv lists of lab tools; randomness only shapes the simulated work day)
import os
import random
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import http.cookiejar

sys.path.insert(0, "/opt/cr")
from common import DOMAIN, EMPLOYEES, NODE, REALM, emit, password, peers  # noqa: E402

rng = random.Random(f"{NODE}:{os.getpid()}")
idx = sum(NODE.encode()) % len(EMPLOYEES)
USER, NAME, DEPT = EMPLOYEES[idx]
CC = tempfile.mkdtemp(prefix="krb-")
ENV = {**os.environ, "KRB5CCNAME": f"FILE:{CC}/cc"}


def run(argv, stdin=None, timeout=20):
    try:
        return subprocess.run(argv, input=stdin, text=True, env=ENV, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def kinit(pw):
    return run(["kinit", f"{USER}@{REALM}"], stdin=pw + "\n") == 0


def share(dc):
    if run(["klist", "-s"]) != 0 and not kinit(password(USER)):
        return
    name = "Keuangan" if DEPT == "Keuangan" and rng.random() < 0.6 else "Umum"
    host = f"{os.environ['CR_DC_HOST']}.{DOMAIN}" if os.environ.get("CR_DC_HOST") else dc   # Windows needs the name for Kerberos
    run(["smbclient", f"//{host}/{name}", "--use-kerberos=required", "-c", "ls; get Pengumuman-Kantor.txt /dev/null" if name == "Umum"
         else "ls", "--option=client min protocol=SMB2"], timeout=30)


def portal(ip):
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36")]
    base = f"http://{ip}"
    try:
        op.open(f"{base}/login", timeout=10).read()
        data = urllib.parse.urlencode({"u": USER, "p": password(USER)}).encode()
        op.open(f"{base}/login", data=data, timeout=15).read()
        for path in rng.sample(["/", "/direktori", "/cuti"], k=rng.randint(1, 3)):
            op.open(base + path, timeout=10).read()
            time.sleep(rng.uniform(1, 4))
        if rng.random() < 0.15:
            day = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 86400 * rng.randint(3, 30)))
            op.open(f"{base}/cuti", data=urllib.parse.urlencode({"dari": day, "hari": str(rng.choice([1, 2, 3]))}).encode(), timeout=10).read()
    except OSError:
        pass


def dns(dc):
    for name in rng.sample(["portal", "dc01", "_ldap._tcp", "intranet", "printer-lt2", "fileserver"], k=2):
        run(["nslookup", f"{name}.{DOMAIN}", dc], timeout=5)


def main():
    if os.geteuid() == 0:   # drop to the employee account; the agent keeps running as root
        import pwd
        pw = pwd.getpwnam("karyawan")
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
        os.environ["HOME"] = pw.pw_dir
        ENV["HOME"] = pw.pw_dir
    time.sleep(rng.uniform(20, 60))   # the domain controller needs time to provision
    p = peers()
    emit(dataset="host.session", category="host", action="user_session", outcome="success", user=USER,
         message=f"{NAME} ({DEPT}) mulai bekerja di {NODE}")
    while True:
        dc = (p.get("dc") or [None])[0]
        web = (p.get("portal") or [None])[0]
        tasks = []
        if dc:
            tasks += [lambda: kinit(password(USER)), lambda dc=dc: share(dc), lambda dc=dc: dns(dc)]
            if rng.random() < 0.08:
                tasks.append(lambda: kinit(password(USER)[::-1]))   # a typo: one failed logon, then work continues
        if web:
            tasks += [lambda web=web: portal(web)] * 2
        if tasks:
            rng.choice(tasks)()
        time.sleep(rng.uniform(15, 75))


if __name__ == "__main__":
    main()
