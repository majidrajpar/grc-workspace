"""SQLite storage for one GRC organization."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from grc_app.catalog import STARTER_CONTROLS

DEMO_ADMIN_EMAIL = "admin@localhost"
DEMO_ADMIN_PASSWORD = "admin-change-me"
DEMO_MEMBER_EMAIL = "member@localhost"
DEMO_MEMBER_PASSWORD = "member-change-me"


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return salt.hex(), digest.hex()


def password_matches(password: str, salt_hex: str, digest_hex: str) -> bool:
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return secrets.compare_digest(digest, digest_hex)


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        create table if not exists organization (
            id integer primary key check (id = 1),
            name text not null
        );
        create table if not exists users (
            id integer primary key,
            email text not null unique,
            name text not null,
            salt text not null,
            password_hash text not null,
            role text not null check (role in ('admin', 'member'))
        );
        create table if not exists assets (
            id integer primary key,
            name text not null,
            kind text not null check (kind in ('asset', 'third_party', 'business_unit', 'process')),
            description text not null default ''
        );
        create table if not exists policies (
            id integer primary key,
            title text not null,
            purpose text not null,
            statements text not null,
            audience text not null,
            framework_refs text not null,
            updated_at text not null
        );
        create table if not exists risks (
            id integer primary key,
            title text not null,
            asset_id integer not null references assets(id),
            threat text not null,
            trigger text not null,
            response text not null,
            treatment text not null,
            residual_summary text not null,
            appetite_note text not null,
            owner_acceptance text not null,
            owner_role text not null,
            accepted integer not null default 0,
            updated_at text not null
        );
        create table if not exists controls (
            id integer primary key,
            framework text not null,
            control_id text not null,
            title text not null,
            tracks text not null,
            applicable integer not null,
            status text not null,
            evidence_needed text not null,
            gap text not null,
            unique (framework, control_id)
        );
        create table if not exists evidence (
            id integer primary key,
            control_pk integer not null references controls(id) on delete cascade,
            note text not null,
            filename text,
            stored_name text,
            created_at text not null
        );
        create table if not exists tasks (
            id integer primary key,
            title text not null,
            owner text not null,
            due_on text,
            closes_gap text not null,
            done integer not null default 0,
            updated_at text not null
        );
        create table if not exists incidents (
            id integer primary key,
            title text not null,
            summary text not null,
            response_authority text not null,
            response_and_recovery text not null,
            lessons_learned text not null,
            may_harm integer not null,
            discovered_at text,
            circumstances text not null,
            data_categories text not null,
            approximate_record_count integer,
            risks text not null,
            measures text not null,
            data_subjects_notified text not null,
            controller_contact text not null,
            dpo_contact text not null,
            advice_to_subjects text not null,
            updated_at text not null
        );
        create table if not exists suppliers (
            id integer primary key,
            name text not null,
            service text not null,
            reviewed_before_contract integer not null check (reviewed_before_contract = 1),
            questionnaire_basis text not null,
            findings text not null,
            decision text not null,
            updated_at text not null
        );
        """
    )
    conn.execute(
        "insert or ignore into organization (id, name) values (1, 'My organization')"
    )
    if conn.execute("select count(*) from users").fetchone()[0] == 0:
        _insert_user(conn, DEMO_ADMIN_EMAIL, "Admin", DEMO_ADMIN_PASSWORD, "admin")
        _insert_user(conn, DEMO_MEMBER_EMAIL, "Member", DEMO_MEMBER_PASSWORD, "member")
    for control in STARTER_CONTROLS:
        conn.execute(
            """
            insert or ignore into controls (
                framework, control_id, title, tracks, applicable, status, evidence_needed, gap
            ) values (?, ?, ?, ?, 1, 'not_started', '[]', '')
            """,
            (control.framework.value, control.control_id, control.title, control.tracks),
        )


def _insert_user(
    conn: sqlite3.Connection, email: str, name: str, password: str, role: str
) -> None:
    salt, digest = hash_password(password)
    conn.execute(
        """
        insert into users (email, name, salt, password_hash, role)
        values (?, ?, ?, ?, ?)
        """,
        (email, name, salt, digest, role),
    )


def organization_name(conn: sqlite3.Connection) -> str:
    row = conn.execute("select name from organization where id = 1").fetchone()
    return row["name"]


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = ("policies", "assets", "risks", "tasks", "incidents", "suppliers", "evidence")
    result = {table: conn.execute(f"select count(*) from {table}").fetchone()[0] for table in tables}
    result["open_tasks"] = conn.execute("select count(*) from tasks where done = 0").fetchone()[0]
    result["applicable_controls"] = conn.execute(
        "select count(*) from controls where applicable = 1"
    ).fetchone()[0]
    return result


def dump_json(value: list[str]) -> str:
    return json.dumps(value)


def load_json(value: str) -> list[str]:
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]
