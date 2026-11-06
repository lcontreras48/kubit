import json
import os
from datetime import datetime, timezone
from pathlib import Path


UTC = timezone.utc

SCHEMA = """
CREATE TABLE IF NOT EXISTS kubit_schema_migrations (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kubit_users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kubit_sessions (
    token_hash text PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES kubit_users(id) ON DELETE CASCADE,
    csrf_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kubit_sessions_expires_idx ON kubit_sessions(expires_at);

CREATE TABLE IF NOT EXISTS kubit_source_proposals (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    component text NOT NULL,
    source_url text NOT NULL,
    notes text NOT NULL DEFAULT '',
    state text NOT NULL DEFAULT 'candidate'
        CHECK (state IN ('candidate', 'validating', 'valid', 'rejected', 'approved')),
    validation jsonb NOT NULL DEFAULT '{}'::jsonb,
    proposed_by bigint NOT NULL REFERENCES kubit_users(id),
    reviewed_by bigint REFERENCES kubit_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kubit_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id bigint REFERENCES kubit_users(id),
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kubit_audit_created_idx ON kubit_audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS kubit_scan_reports (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cluster_name text NOT NULL,
    collected_at timestamptz NOT NULL,
    component_count integer NOT NULL,
    result_count integer NOT NULL,
    report jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kubit_scan_cluster_time_idx
    ON kubit_scan_reports(cluster_name, collected_at DESC);

INSERT INTO kubit_schema_migrations(version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
"""


def _read_secret(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def configured_database_url() -> str:
    path = os.getenv("KUBIT_DATABASE_URL_FILE", "")
    if path:
        return _read_secret(path)
    return os.getenv("DATABASE_URL", "")


class PostgresStore:
    def __init__(self, database_url: str, retention_days: int = 30):
        self.database_url = database_url
        self.retention_days = retention_days

    def _connection(self):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError("PostgreSQL support requires psycopg") from error
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(SCHEMA)
            connection.execute("DELETE FROM kubit_sessions WHERE expires_at <= now()")

    def user_count(self) -> int:
        with self._connection() as connection:
            return connection.execute("SELECT count(*) AS count FROM kubit_users").fetchone()["count"]

    def bootstrap_admin(self, username: str, password_hash: str) -> bool:
        with self._connection() as connection:
            if connection.execute("SELECT count(*) AS count FROM kubit_users").fetchone()["count"]:
                return False
            connection.execute(
                "INSERT INTO kubit_users(username, password_hash, role) VALUES (%s, %s, 'admin')",
                (username, password_hash),
            )
            connection.execute(
                "INSERT INTO kubit_audit_events(action, target_type, target_id, details) "
                "VALUES ('user.bootstrap_admin', 'user', %s, '{}'::jsonb)",
                (username,),
            )
            return True

    def user_by_username(self, username: str):
        with self._connection() as connection:
            return connection.execute(
                "SELECT id, username, password_hash, role, enabled FROM kubit_users WHERE username = %s",
                (username,),
            ).fetchone()

    def create_user(self, username: str, password_hash: str, role: str, actor_id: int) -> dict:
        with self._connection() as connection:
            user = connection.execute(
                "INSERT INTO kubit_users(username, password_hash, role) VALUES (%s, %s, %s) "
                "RETURNING id, username, role, enabled, created_at",
                (username, password_hash, role),
            ).fetchone()
            connection.execute(
                "INSERT INTO kubit_audit_events(actor_user_id, action, target_type, target_id, details) "
                "VALUES (%s, 'user.create', 'user', %s, %s::jsonb)",
                (actor_id, str(user["id"]), json.dumps({"username": username, "role": role})),
            )
            return dict(user)

    def list_users(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, username, role, enabled, created_at, updated_at FROM kubit_users ORDER BY username"
            ).fetchall()
            return [dict(row) for row in rows]

    def create_source_proposal(
        self,
        component: str,
        source_url: str,
        notes: str,
        validation: dict,
        actor_id: int,
    ) -> dict:
        with self._connection() as connection:
            proposal = connection.execute(
                "INSERT INTO kubit_source_proposals(component, source_url, notes, validation, proposed_by) "
                "VALUES (%s, %s, %s, %s::jsonb, %s) "
                "RETURNING id, component, source_url, notes, state, validation, proposed_by, reviewed_by, created_at, updated_at",
                (component, source_url, notes, json.dumps(validation), actor_id),
            ).fetchone()
            connection.execute(
                "INSERT INTO kubit_audit_events(actor_user_id, action, target_type, target_id, details) "
                "VALUES (%s, 'source.propose', 'source_proposal', %s, %s::jsonb)",
                (
                    actor_id,
                    str(proposal["id"]),
                    json.dumps({
                        "component": component,
                        "source_url": source_url,
                        "content_sha256": validation.get("content_sha256", ""),
                    }),
                ),
            )
            return dict(proposal)

    def list_source_proposals(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT p.id, p.component, p.source_url, p.notes, p.state, p.validation, "
                "p.proposed_by, proposer.username AS proposed_by_username, p.reviewed_by, "
                "reviewer.username AS reviewed_by_username, p.created_at, p.updated_at "
                "FROM kubit_source_proposals p "
                "JOIN kubit_users proposer ON proposer.id = p.proposed_by "
                "LEFT JOIN kubit_users reviewer ON reviewer.id = p.reviewed_by "
                "ORDER BY p.created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def create_session(self, user_id: int, session_hash: str, csrf_hash: str, expires_at) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO kubit_sessions(token_hash, user_id, csrf_hash, expires_at) VALUES (%s, %s, %s, %s)",
                (session_hash, user_id, csrf_hash, expires_at),
            )

    def session(self, session_hash: str):
        with self._connection() as connection:
            session = connection.execute(
                "SELECT s.user_id, s.csrf_hash, u.username, u.role "
                "FROM kubit_sessions s JOIN kubit_users u ON u.id = s.user_id "
                "WHERE s.token_hash = %s AND s.expires_at > now() AND u.enabled",
                (session_hash,),
            ).fetchone()
            if session:
                connection.execute(
                    "UPDATE kubit_sessions SET last_seen_at = now() WHERE token_hash = %s",
                    (session_hash,),
                )
            return session

    def update_session_csrf(self, session_hash: str, csrf_hash: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE kubit_sessions SET csrf_hash = %s, last_seen_at = now() WHERE token_hash = %s",
                (csrf_hash, session_hash),
            )

    def delete_session(self, session_hash: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM kubit_sessions WHERE token_hash = %s", (session_hash,))

    def audit(self, actor_id, action: str, target_type: str, target_id: str, details: dict) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO kubit_audit_events(actor_user_id, action, target_type, target_id, details) "
                "VALUES (%s, %s, %s, %s, %s::jsonb)",
                (actor_id, action, target_type, target_id, json.dumps(details)),
            )

    def record_scan(self, report: dict) -> None:
        now = datetime.now(UTC)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO kubit_scan_reports(cluster_name, collected_at, component_count, result_count, report) "
                "VALUES (%s, %s, %s, %s, %s::jsonb)",
                (
                    report["cluster"],
                    now,
                    len(report["components"]),
                    len(report["results"]),
                    json.dumps(report),
                ),
            )
            connection.execute(
                "DELETE FROM kubit_scan_reports WHERE created_at < now() - (%s * interval '1 day')",
                (self.retention_days,),
            )
