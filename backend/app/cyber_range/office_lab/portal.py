"""Intranet portal of the DEMO company (stdlib only). Employees sign in with their domain account (Kerberos against the
lab domain controller), read announcements, look up colleagues and submit leave requests.
Every request is written to the telemetry file as web.access; sign-ins as web.auth."""
# ruff: noqa: S603, S607, S104  (fixed kinit argv; the portal listens on the lab network only)
import html
import os
import secrets
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, "/opt/cr")
from common import DOMAIN, EMPLOYEES, REALM, emit, my_ip  # noqa: E402

IP = my_ip()
SESSIONS: dict[str, dict] = {}
LEAVES: list[dict] = []
NEWS = [("Rapat bulanan", "Rapat bulanan seluruh karyawan setiap Senin pukul 09.00 di ruang serbaguna."),
        ("Pembaruan kebijakan password", "Tim IT mengingatkan: jangan pernah membagikan password, termasuk kepada orang yang mengaku dari IT."),
        ("Libur nasional", "Kantor tutup pada hari libur nasional. Pengajuan cuti tetap lewat portal ini.")]
CSS = ("body{font-family:system-ui,sans-serif;margin:0;background:#f4f6f9;color:#1d2733}header{background:#123b63;color:#fff;padding:12px 24px;"
       "display:flex;justify-content:space-between}main{max-width:860px;margin:24px auto;background:#fff;padding:24px;border-radius:8px}"
       "a{color:#123b63}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #dde3ea;padding:6px;text-align:left}"
       ".demo{background:#fff3cd;padding:6px 10px;border-radius:4px;font-size:13px}input,select{padding:6px;margin:4px 0 10px;width:100%}"
       "button{background:#123b63;color:#fff;border:0;padding:8px 16px;border-radius:4px}")


def kerberos_login(user: str, pw: str) -> bool:
    """Real Kerberos AS exchange against the lab DC (creates a 4624/4625 event there). The password goes over stdin."""
    if not user.replace(".", "").replace("-", "").isalnum() or len(user) > 64:
        return False
    with tempfile.TemporaryDirectory() as d:
        env = {**os.environ, "KRB5CCNAME": f"FILE:{d}/cc"}
        try:
            r = subprocess.run(["kinit", f"{user}@{REALM}"], input=pw + "\n", text=True, env=env, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


def page(title: str, body: str, user: str | None) -> bytes:
    who = f"{html.escape(user)} · <a style='color:#fff' href='/logout'>Keluar</a>" if user else "Belum masuk"
    return (f"<!doctype html><html lang=id><meta charset=utf-8><title>{html.escape(title)} - Intranet</title><style>{CSS}</style>"
            f"<header><b>Intranet PT Contoh Sejahtera (DEMO)</b><span>{who}</span></header><main>"
            f"<p class=demo>Lingkungan lab simulasi. Semua data di portal ini adalah DEMO.</p>{body}</main></html>").encode()


class H(BaseHTTPRequestHandler):
    server_version = "IntranetPortal/1.4"
    sys_version = ""

    def log_message(self, *a):   # access logging goes to telemetry instead of stderr
        pass

    def _user(self):
        c = self.headers.get("Cookie", "")
        for part in c.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v in SESSIONS and SESSIONS[v]["exp"] > time.time():
                return SESSIONS[v]["user"]
        return None

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        emit(dataset="web.access", category="http", action=self.command, outcome="success" if code < 400 else "failure",
             severity="info", src_ip=self.client_address[0], src_port=self.client_address[1], dst_ip=IP, dst_port=80, protocol="http",
             user=self._user(), signature=f"HTTP {code}", signature_id=str(code),
             message=f"{self.command} {self.path[:400]} {code} {len(body)} \"{(self.headers.get('User-Agent') or '-')[:160]}\"")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlsplit(self.path)
        user = self._user()
        if u.path == "/":
            if not user:
                return self._send(302, headers={"Location": "/login"})
            news = "".join(f"<h3>{html.escape(t)}</h3><p>{html.escape(b)}</p>" for t, b in NEWS)
            return self._send(200, page("Beranda", f"<h2>Selamat datang, {html.escape(user)}</h2>{news}"
                                         "<p><a href='/direktori'>Direktori karyawan</a> · <a href='/cuti'>Pengajuan cuti</a></p>", user))
        if u.path == "/login":
            q = parse_qs(u.query)
            err = "<p style='color:#b00'>Login gagal. Periksa nama pengguna dan password.</p>" if q.get("e") else ""
            form = (f"<h2>Masuk dengan akun domain {html.escape(DOMAIN)}</h2>{err}<form method=post action=/login>"
                    "<label>Nama pengguna<input name=u autocomplete=username></label><label>Password<input name=p type=password "
                    "autocomplete=current-password></label><button>Masuk</button></form>")
            return self._send(200, page("Masuk", form, None))
        if u.path == "/logout":
            return self._send(302, headers={"Location": "/login", "Set-Cookie": "sid=; Max-Age=0; HttpOnly; Path=/"})
        if not user:
            return self._send(302, headers={"Location": "/login"})
        if u.path == "/direktori":
            rows = "".join(f"<tr><td>{html.escape(n)}</td><td>{html.escape(d)}</td><td>{html.escape(x)}@{html.escape(DOMAIN)}</td></tr>"
                           for x, n, d in EMPLOYEES)
            return self._send(200, page("Direktori", f"<h2>Direktori karyawan</h2><table><tr><th>Nama</th><th>Departemen</th><th>Email</th></tr>{rows}</table>", user))
        if u.path == "/cuti":
            mine = "".join(f"<tr><td>{html.escape(x['dari'])}</td><td>{html.escape(x['hari'])}</td><td>Menunggu</td></tr>" for x in LEAVES if x["user"] == user)
            form = ("<h2>Pengajuan cuti</h2><form method=post action=/cuti><label>Mulai tanggal<input name=dari type=date></label>"
                    "<label>Jumlah hari<select name=hari><option>1<option>2<option>3<option>5</select></label><button>Kirim</button></form>"
                    f"<h3>Pengajuan saya</h3><table><tr><th>Mulai</th><th>Hari</th><th>Status</th></tr>{mine}</table>")
            return self._send(200, page("Cuti", form, user))
        if u.path == "/health":
            return self._send(200, b"ok", "text/plain")
        return self._send(404, page("Tidak ditemukan", "<h2>Halaman tidak ditemukan</h2>", user))

    def do_POST(self):
        u = urlsplit(self.path)
        n = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode(errors="replace")).items()}
        if u.path == "/login":
            name = (form.get("u") or "").strip().lower().split("@")[0][:64]
            ok = kerberos_login(name, form.get("p") or "")
            emit(dataset="web.auth", category="auth", action="portal_login", outcome="success" if ok else "failure",
                 severity="info" if ok else "low", src_ip=self.client_address[0], dst_ip=IP, dst_port=80, protocol="http", user=name or None,
                 message=f"Intranet portal sign-in {'succeeded' if ok else 'failed'} for {name or '-'} from {self.client_address[0]}")
            if not ok:
                return self._send(302, headers={"Location": "/login?e=1"})
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid] = {"user": name, "exp": time.time() + 3600}
            return self._send(302, headers={"Location": "/", "Set-Cookie": f"sid={sid}; HttpOnly; SameSite=Lax; Path=/"})
        user = self._user()
        if u.path == "/cuti" and user:
            LEAVES.append({"user": user, "dari": (form.get("dari") or "-")[:10], "hari": (form.get("hari") or "1")[:2]})
            del LEAVES[:-200]
            return self._send(302, headers={"Location": "/cuti"})
        return self._send(403, page("Ditolak", "<h2>Akses ditolak</h2>", user))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
