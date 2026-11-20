"""local edition: drop multi-user, AI, notification, course/quiz and class tables

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-19

The local edition has one operator and no AI analyst, notifications, courses/quizzes, CTF events, classes, self
sign-up or SSO. Their tables and columns are removed. CTF challenges and missions stay.
The multi-user roles and the permissions of removed features are deleted; existing accounts other than the local
operator are deactivated (kept, so audit history still names them). The OPERATOR role is created at startup.
This step cannot be downgraded (the removed features no longer exist in the code).
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0020'
down_revision: str | None = '0019'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_ROLES = ("SYSTEM_ADMIN", "SECURITY_ADMIN", "RED_TEAM_OPERATOR", "BLUE_TEAM_ANALYST", "INCIDENT_RESPONDER",
             "LAB_MANAGER", "INSTRUCTOR", "TRAINEE", "AUDITOR")
OLD_PERMISSIONS = ("ai.analyst.use", "ai.knowledge.manage", "iam.roles.manage", "iam.roles.view", "iam.sessions.manage",
                   "iam.users.manage", "iam.users.view", "notify.manage", "training.instruct")
TABLES = ("ai_citations", "ai_messages", "ai_sessions", "ai_chunks", "ai_documents",
          "notification_deliveries", "notification_channels",
          "class_assignment_labs", "class_assignments", "class_members", "classrooms",
          "lesson_progress", "course_lessons", "courses", "role_requests")


def upgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP TABLE IF EXISTS `{t}`")
    op.drop_constraint('fk_challenges_event_id_ctf_events', 'challenges', type_='foreignkey')
    op.drop_index('ix_challenges_event_id', table_name='challenges')
    op.drop_column('challenges', 'event_id')
    op.execute("DROP TABLE IF EXISTS `ctf_events`")
    for col in ("profile", "registration_status", "sso_roles"):
        op.drop_column('users', col)
    op.execute("DELETE FROM system_settings WHERE `key` IN ('registration.mode', 'registration.allowed_domains', "
               "'lab.self_signup_server_labs', 'ai.enabled', 'ai.ollama_model')")
    roles = ", ".join(f"'{r}'" for r in OLD_ROLES)
    perms = ", ".join(f"'{p}'" for p in OLD_PERMISSIONS)
    op.execute(f"DELETE ur FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.code IN ({roles})")
    op.execute(f"DELETE rp FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.code IN ({roles})")
    op.execute(f"DELETE FROM roles WHERE code IN ({roles})")
    op.execute(f"DELETE rp FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE p.code IN ({perms})")
    op.execute(f"DELETE FROM permissions WHERE code IN ({perms})")
    # one local operator: every other account is switched off and its sessions revoked (rows kept for the audit trail)
    op.execute("UPDATE users SET is_active = 0 WHERE username <> 'operator'")
    op.execute("UPDATE sessions SET revoked_at = UTC_TIMESTAMP(6), revoke_reason = 'local_edition' "
               "WHERE revoked_at IS NULL")


def downgrade() -> None:
    raise NotImplementedError("The local edition schema cannot be downgraded")
