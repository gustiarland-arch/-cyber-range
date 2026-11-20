"""Compact MITRE ATT&CK Enterprise reference (tactics and a curated set of common techniques).

Used to name techniques, place rules and red team actions on the matrix and compute detection coverage. It is a subset
of ATT&CK (about 100 techniques that matter for network, host and web detection in labs); unknown technique IDs are still
accepted on rules and shown under their ID. Source: MITRE ATT&CK Enterprise (attack.mitre.org), names as published.
"""
import re

TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"), ("TA0002", "Execution"),
    ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_NAMES = [n for _, n in TACTICS]

# id: (name, [tactics])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1595": ("Active Scanning", ["Reconnaissance"]),
    "T1595.001": ("Scanning IP Blocks", ["Reconnaissance"]),
    "T1595.002": ("Vulnerability Scanning", ["Reconnaissance"]),
    "T1595.003": ("Wordlist Scanning", ["Reconnaissance"]),
    "T1592": ("Gather Victim Host Information", ["Reconnaissance"]),
    "T1590": ("Gather Victim Network Information", ["Reconnaissance"]),
    "T1589": ("Gather Victim Identity Information", ["Reconnaissance"]),
    "T1598": ("Phishing for Information", ["Reconnaissance"]),
    "T1583": ("Acquire Infrastructure", ["Resource Development"]),
    "T1584": ("Compromise Infrastructure", ["Resource Development"]),
    "T1587": ("Develop Capabilities", ["Resource Development"]),
    "T1588": ("Obtain Capabilities", ["Resource Development"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1133": ("External Remote Services", ["Initial Access", "Persistence"]),
    "T1566": ("Phishing", ["Initial Access"]),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"]),
    "T1566.002": ("Spearphishing Link", ["Initial Access"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1189": ("Drive-by Compromise", ["Initial Access"]),
    "T1195": ("Supply Chain Compromise", ["Initial Access"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1059.004": ("Unix Shell", ["Execution"]),
    "T1059.006": ("Python", ["Execution"]),
    "T1203": ("Exploitation for Client Execution", ["Execution"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.003": ("Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1047": ("Windows Management Instrumentation", ["Execution"]),
    "T1569": ("System Services", ["Execution"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1543": ("Create or Modify System Process", ["Persistence", "Privilege Escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"]),
    "T1505.003": ("Web Shell", ["Persistence"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["Privilege Escalation", "Defense Evasion"]),
    "T1548.003": ("Sudo and Sudo Caching", ["Privilege Escalation", "Defense Evasion"]),
    "T1068": ("Exploitation for Privilege Escalation", ["Privilege Escalation"]),
    "T1055": ("Process Injection", ["Privilege Escalation", "Defense Evasion"]),
    "T1070": ("Indicator Removal", ["Defense Evasion"]),
    "T1070.001": ("Clear Windows Event Logs", ["Defense Evasion"]),
    "T1562": ("Impair Defenses", ["Defense Evasion"]),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"]),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"]),
    "T1036": ("Masquerading", ["Defense Evasion"]),
    "T1218": ("System Binary Proxy Execution", ["Defense Evasion"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1110.003": ("Password Spraying", ["Credential Access"]),
    "T1110.004": ("Credential Stuffing", ["Credential Access"]),
    "T1003": ("OS Credential Dumping", ["Credential Access"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1555": ("Credentials from Password Stores", ["Credential Access"]),
    "T1552": ("Unsecured Credentials", ["Credential Access"]),
    "T1558": ("Steal or Forge Kerberos Tickets", ["Credential Access"]),
    "T1557": ("Adversary-in-the-Middle", ["Credential Access", "Collection"]),
    "T1040": ("Network Sniffing", ["Credential Access", "Discovery"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1018": ("Remote System Discovery", ["Discovery"]),
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1087": ("Account Discovery", ["Discovery"]),
    "T1069": ("Permission Groups Discovery", ["Discovery"]),
    "T1016": ("System Network Configuration Discovery", ["Discovery"]),
    "T1049": ("System Network Connections Discovery", ["Discovery"]),
    "T1057": ("Process Discovery", ["Discovery"]),
    "T1135": ("Network Share Discovery", ["Discovery"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.001": ("Remote Desktop Protocol", ["Lateral Movement"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1210": ("Exploitation of Remote Services", ["Lateral Movement"]),
    "T1570": ("Lateral Tool Transfer", ["Lateral Movement"]),
    "T1550": ("Use Alternate Authentication Material", ["Lateral Movement", "Defense Evasion"]),
    "T1005": ("Data from Local System", ["Collection"]),
    "T1039": ("Data from Network Shared Drive", ["Collection"]),
    "T1114": ("Email Collection", ["Collection"]),
    "T1560": ("Archive Collected Data", ["Collection"]),
    "T1071": ("Application Layer Protocol", ["Command and Control"]),
    "T1071.001": ("Web Protocols", ["Command and Control"]),
    "T1071.004": ("DNS", ["Command and Control"]),
    "T1095": ("Non-Application Layer Protocol", ["Command and Control"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1571": ("Non-Standard Port", ["Command and Control"]),
    "T1572": ("Protocol Tunneling", ["Command and Control"]),
    "T1573": ("Encrypted Channel", ["Command and Control"]),
    "T1090": ("Proxy", ["Command and Control"]),
    "T1568": ("Dynamic Resolution", ["Command and Control"]),
    "T1568.002": ("Domain Generation Algorithms", ["Command and Control"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"]),
    "T1567": ("Exfiltration Over Web Service", ["Exfiltration"]),
    "T1030": ("Data Transfer Size Limits", ["Exfiltration"]),
    "T1485": ("Data Destruction", ["Impact"]),
    "T1486": ("Data Encrypted for Impact", ["Impact"]),
    "T1489": ("Service Stop", ["Impact"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1498": ("Network Denial of Service", ["Impact"]),
    "T1499": ("Endpoint Denial of Service", ["Impact"]),
    "T1496": ("Resource Hijacking", ["Impact"]),
}

TECH_RX = re.compile(r"^t\d{4}(\.\d{3})?$", re.I)


def technique_name(tid: str | None) -> str | None:
    if not tid:
        return None
    t = TECHNIQUES.get(tid.upper())
    if t:
        return t[0]
    parent = TECHNIQUES.get(tid.upper().split(".")[0])
    return parent[0] if parent else None


def tactic_from_tag(tag: str) -> str | None:
    """Sigma tag `attack.credential_access` / `attack.command-and-control` -> 'Credential Access'."""
    slug = tag.lower().removeprefix("attack.").replace("-", "_")
    for n in TACTIC_NAMES:
        if n.lower().replace(" ", "_") == slug:
            return n
    return None


def tactics_for(tid: str) -> list[str]:
    t = TECHNIQUES.get(tid.upper()) or TECHNIQUES.get(tid.upper().split(".")[0])
    return list(t[1]) if t else []
