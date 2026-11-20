"""Import every domain model so Alembic autogenerate sees the full metadata."""
from app.audit.models import AuditChainHead, AuditLog  # noqa: F401
from app.governance.models import SystemSetting  # noqa: F401
from app.iam.models import ApiToken, Permission, Role, User, UserSession  # noqa: F401
from app.blueteam.models import Alert, AlertEvent, DetectionRule, Incident, IncidentEntry, LogSource, SecurityEvent  # noqa: F401
from app.cyber_range.models import Lab, LabContainer, LabEvent, LabImage, LabInstance, LabRuntimeNetwork, LabSensor, Snapshot, VirtualMachine  # noqa: F401
from app.redteam.models import Assessment, AssessmentEvent, Finding, Scenario  # noqa: F401
from app.network.models import LabNetwork, NetworkLink, NetworkNode, NetworkZone, NodeInterface, NodePosition, Subnet  # noqa: F401
from app.intel.models import Indicator, IndicatorRelation, IntelFeed, IntelSource, Sighting  # noqa: F401
from app.vuln.models import FindingEvent, RemediationTask, ScanFinding, ScanJob, Vulnerability  # noqa: F401
from app.malware.models import FileSample, SampleEvent, SandboxRun, YaraMatch, YaraRule  # noqa: F401
from app.forensics.models import CustodyEvent, Evidence, EvidenceHash, ForensicCase  # noqa: F401
from app.training.models import Challenge, Hint, HintUnlock, Mission, Objective, ScoreEvent, Submission  # noqa: F401
from app.reports.models import BackupRun, Report  # noqa: F401
from app.soar.models import Playbook, PlaybookRun  # noqa: F401
from app.terminal.models import TerminalSession  # noqa: F401
