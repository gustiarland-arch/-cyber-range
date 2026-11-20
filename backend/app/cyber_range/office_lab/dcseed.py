"""Create the DEMO organisation in the freshly provisioned domain (runs offline against sam.ldb)."""
# ruff: noqa: S603, S607  (fixed samba-tool argv)
import subprocess
import sys

sys.path.insert(0, "/opt/cr")
from common import EMPLOYEES, GROUPS, SHARE_DOCS, password  # noqa: E402


def tool(*args):
    subprocess.run(["samba-tool", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


for g in GROUPS:
    tool("group", "add", g, f"--description=Departemen {g} (DEMO)")
for user, name, dept in EMPLOYEES:
    first, _, last = name.partition(" ")
    tool("user", "create", user, password(user), f"--given-name={first}", f"--surname={last}",
         f"--department={dept}", f"--description=Karyawan DEMO ({dept})")
    tool("group", "addmembers", dept, user)
tool("group", "addmembers", "Domain Admins", "andi.saputra")   # the IT admin: a realistic privileged account to watch
for share, docs in SHARE_DOCS.items():
    for name, text in docs.items():
        with open(f"/srv/share/{share.lower()}/{name}", "w") as f:
            f.write(text)
print("DEMO organisation created")
