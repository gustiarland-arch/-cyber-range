"""Print shell assignments for dc.sh. The administrator password is random per start and never written anywhere."""
import os
import shlex
import sys

sys.path.insert(0, "/opt/cr")
from common import DOMAIN, NETBIOS, REALM  # noqa: E402

admin = "Adm-" + os.urandom(12).hex() + "-X9!"
for k, v in (("DOMAIN", DOMAIN), ("REALM", REALM), ("NETBIOS", NETBIOS), ("ADMINPASS", admin)):
    print(f"{k}={shlex.quote(v)}")
