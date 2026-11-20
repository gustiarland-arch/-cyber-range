"""Permission catalog for the local edition.

The local edition has one account, the local operator, holding the OPERATOR role: every permission below. The catalog
is kept so that every endpoint still checks a named permission (default deny) and every sensitive action is audited
with the permission it used.
"""

# code: (domain, description, sensitive)
PERMISSIONS: dict[str, tuple[str, str, bool]] = {
    "dashboard.view": ("dashboard", "View Command Center dashboards", False),
    "system.health.view": ("system", "View system and dependency health", False),
    "system.settings.view": ("system", "View system settings", False),
    "system.settings.manage": ("system", "Change system settings", True),
    "audit.view": ("audit", "View and verify audit logs", False),
    "lab.view": ("cyber_range", "View labs and topology", False),
    "lab.operate": ("cyber_range", "Deploy and operate own labs (start, stop, reset, snapshot, destroy)", True),
    "lab.manage": ("cyber_range", "Operate every lab and manage the image allowlist", True),
    "lab.terminal": ("cyber_range", "Open brokered terminal sessions inside containers of labs the user may operate", True),
    "lab.kit.download": ("cyber_range", "Download a lab as a Docker Compose or Vagrant Lab Kit to run on another computer", False),
    "lab.killswitch": ("cyber_range", "Engage or release the global lab kill switch", True),
    "network.topology.edit": ("network", "Create and edit own network topologies", False),
    "network.topology.admin": ("network", "View and edit every network topology (incl. private)", True),
    "redteam.assessment.view": ("red_team", "View assessments and findings", False),
    "redteam.assessment.request": ("red_team", "Request an assessment against an authorised lab target", True),
    "redteam.assessment.approve": ("red_team", "Approve assessment scope", True),
    "redteam.assessment.execute": ("red_team", "Execute an approved, in-scope lab simulation", True),
    "blueteam.alerts.view": ("blue_team", "View alerts and events", False),
    "blueteam.alerts.triage": ("blue_team", "Triage and assign alerts", False),
    "blueteam.rules.manage": ("blue_team", "Manage detection rules", True),
    "blueteam.sources.manage": ("blue_team", "Register log sources, issue ingest keys and upload logs", True),
    "incident.view": ("incidents", "View incidents", False),
    "incident.respond": ("incidents", "Work incidents and run response playbooks", True),
    "vuln.view": ("vulnerability", "View vulnerability findings, scans and remediation", False),
    "vuln.scan": ("vulnerability", "Run non-destructive vulnerability scans inside own running labs", True),
    "vuln.manage": ("vulnerability", "Triage findings, accept risk, manage remediation tasks and the catalogue", True),
    "malware.view": ("malware", "View quarantined samples, static analysis and YARA results", False),
    "malware.submit": ("malware", "Submit files to quarantine and record analyst verdicts", True),
    "malware.rules.manage": ("malware", "Author and enable YARA rulesets", True),
    "malware.sandbox.submit": ("malware", "Send a sample to the external isolated sandbox for dynamic analysis", True),
    "evidence.view": ("forensics", "View cases, evidence and chain of custody", False),
    "evidence.manage": ("forensics", "Collect evidence and record custody events", True),
    "soar.manage": ("incidents", "Create, edit and enable SOAR playbooks (steps come from a fixed safe catalogue)", True),
    "intel.view": ("intel", "View threat intelligence indicators, sources and sightings", False),
    "intel.manage": ("intel", "Add, import and retire indicators; run retro-hunts", True),
    "training.participate": ("training", "Solve CTF challenges and run missions", False),
    "training.manage": ("training", "Author CTF challenges and missions", False),
    "reports.view": ("reporting", "View reports", False),
    "reports.generate": ("reporting", "Generate reports (limited to data you can access)", False),
    "reports.manage": ("reporting", "View and delete every user's generated reports", False),
}

OPERATOR_ROLE = "OPERATOR"

ROLES: dict[str, tuple[str, str, list[str]]] = {
    OPERATOR_ROLE: ("Operator lokal", "The single local user of this computer: every operational and settings permission.", sorted(PERMISSIONS)),
}
