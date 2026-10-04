#!/usr/bin/env python3
"""OrgGraph — Passive OSINT Intelligence & Correlation Framework.

Single-file tool: CLI, collectors, storage, correlation, scoring, diff engine
and the local web UI all live in this module. The only files it creates, next
to itself (or under $ORGGRAPH_HOME), are orggraph.db, config.json and exports/.

Sources are public and passive only: DNS resolution through your own resolver,
Certificate Transparency (crt.sh), RDAP, and a handful of plain HTTP GETs on
hostnames that were observed elsewhere. Nothing is brute-forced, crawled,
fingerprinted aggressively or bypassed.

"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import html
import ipaddress
import json
import logging
import os
import random
import re
import sqlite3
import string
import sys
import tempfile
import time
import traceback
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlsplit

import httpx
import typer
from rich import box
from rich.console import Console
from rich.live import Live
from rich.logging import RichHandler
from rich.spinner import Spinner
from rich.style import Style
from rich.table import Table
from rich.text import Text

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    HAVE_DNSPYTHON = True
except ImportError: 
    HAVE_DNSPYTHON = False



VERSION = "2 , By https://x.com/maxennce"
TAGLINE = "Passive OSINT Intelligence & Correlation Framework"
SUBTITLE = "[ passive intelligence • correlation • graph analysis ]"

BANNER = r"""
    ...                      .,-:::::/                          ::        
 .;;;;;;;.                 ,;;-'````'                           ;;;       
,[[     \[[,=,,[[== ,ccc,  [[[   [[[[[[/=,,[[== ,ccc,           [[[[cc,,. 
$$$,     $$$`$$$"``$$$cc$$$"$$c.    "$$ `$$$"``$$$cc$$$ ,$$$$$. $$$ 
888,_ _,88P 888   888   888`Y8bo,,,o88o 888   888   8888888888   "88o
  YMMMMMP  "MM,   YUM MP  `'YMUP"YMM MM,   YUM MPMMoooMM'MMM    YMM
                         MMM                            MMMP              
                   ,c.   ###                            ###               
                   \M###MMU                             "##b              
"""

GRADIENT = ["#D8B4FE", "#A855F7", "#7C3AED", "#4C1D95"]
C_PRIMARY = "#A855F7"
C_LIGHT = "#D8B4FE"
C_DIM = "#A1A1AA"
C_TRACK = "#3F3F46"
C_OK = "green"
C_WARN = "yellow"
C_ERR = "red"

DEFAULT_HOME = (
    Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    / "orggraph"
)

BASE_DIR = Path(os.environ.get("ORGGRAPH_HOME") or DEFAULT_HOME).expanduser()

DB_PATH = BASE_DIR / "orggraph.db"
CONFIG_PATH = BASE_DIR / "config.json"
EXPORT_DIR = BASE_DIR / "exports"

ORGANIZATION = "Organization"
DOMAIN = "Domain"
SUBDOMAIN = "Subdomain"
IP_ADDRESS = "IPAddress"
ASN = "ASN"
CERTIFICATE = "Certificate"
NAMESERVER = "Nameserver"
MAIL_SERVER = "MailServer"
WEB_SERVICE = "WebService"
TECHNOLOGY = "Technology"
ENTITY_TYPES = [
    ORGANIZATION, DOMAIN, SUBDOMAIN, IP_ADDRESS, ASN, CERTIFICATE,
    NAMESERVER, MAIL_SERVER, WEB_SERVICE, TECHNOLOGY,
]
HOST_TYPES = (DOMAIN, SUBDOMAIN)

HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
RESOLVES_TO = "RESOLVES_TO"
CNAME_TO = "CNAME_TO"
USES_NAMESERVER = "USES_NAMESERVER"
USES_MAIL_SERVER = "USES_MAIL_SERVER"
PRESENT_IN_CERTIFICATE = "PRESENT_IN_CERTIFICATE"
REGISTERED_WITH = "REGISTERED_WITH"
SERVES = "SERVES"
REDIRECTS_TO = "REDIRECTS_TO"
USES_TECHNOLOGY = "USES_TECHNOLOGY"

KIND_OBSERVED = "observed"
KIND_INFERRED = "inferred"
KIND_HYPOTHESIS = "hypothesis"

TRACKED_RELATIONS = {
    RESOLVES_TO: "IP",
    CNAME_TO: "CNAME",
    USES_NAMESERVER: "nameserver",
    USES_MAIL_SERVER: "mail server",
}

COLLECTOR_LABELS = {
    "dns": "DNS",
    "certificate_transparency": "Certificate Transparency",
    "rdap": "RDAP",
    "http": "HTTP",
}
COLLECTOR_SHORT = {"dns": "DNS", "certificate_transparency": "CT", "rdap": "RDAP", "http": "HTTP"}

log = logging.getLogger("orggraph")


class OrgGraphError(Exception):
    """User-facing error: printed as one line, never as a traceback."""




@dataclass
class Config:
    request_timeout: float = 10.0
    ct_timeout: float = 45.0
    max_concurrency: int = 5
    dns_concurrency: int = 10
    max_retries: int = 2
    user_agent: str = f"OrgGraph/{VERSION} Passive-OSINT"
    max_hostnames: int = 500
    http_max_hosts: int = 20
    ui_host: str = "127.0.0.1"
    ui_port: int = 8765

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> Config:
        """Read config.json, creating it with defaults on first run."""
        if not path.exists():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(asdict(cls()), indent=2) + "\n", encoding="utf-8")
            except OSError as exc:
                log.warning("could not write %s: %s", path, exc)
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable %s: %s", path, exc)
            return cls()
        if not isinstance(data, dict):
            return cls()
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        try:
            return cls(**known)
        except TypeError as exc:
            log.warning("invalid values in %s: %s", path, exc)
            return cls()




def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Quiet by default; --verbose shows progress, --debug shows everything with tracebacks."""
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.ERROR
    handler = RichHandler(
        console=Console(stderr=True),
        show_path=debug,
        show_time=debug,
        rich_tracebacks=debug,
        markup=False,
    )
    logging.basicConfig(level=level, format="%(message)s", handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.DEBUG if debug else logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)




def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def fmt_dt(value: str | None) -> str:
    parsed = parse_iso(value)
    if parsed is None:
        return value or "-"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic id: the same (target, type, value) always maps to the same id."""
    digest = hashlib.blake2b("|".join(parts).encode("utf-8"), digest_size=6).hexdigest()
    return f"{prefix}_{digest}"


def json_dumps(obj: Any, **kwargs: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str, **kwargs)


def json_loads(text: Any, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def normalize_ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_hostname(value: str) -> str | None:
    """Canonical hostname (lowercase, punycode, no trailing dot, wildcard prefix removed).

    Returns None for anything that is not a plausible DNS name with at least two labels.
    """
    host = value.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or is_ip(host):
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2:
        return None
    if not all(_HOST_LABEL.match(label) for label in labels):
        return None
    return host


def classify_host(host: str, target: str) -> tuple[str, bool]:
    """Return (entity type, in_scope) for a hostname relative to the scanned target."""
    if host == target:
        return DOMAIN, True
    if host.endswith("." + target):
        return SUBDOMAIN, True
    return DOMAIN, False


def parse_target(raw: str) -> tuple[str, str | None]:
    """Validate a user-supplied target. Returns (domain, note-for-the-user)."""
    text = raw.strip()
    note = None
    if "://" in text or "/" in text:
        parts = urlsplit(text if "://" in text else "//" + text)
        host = parts.hostname or ""
        if host:
            note = f"extracted domain '{host}' from '{raw}'"
        text = host
    if is_ip(text):
        raise OrgGraphError("IP addresses are not supported as targets; provide a domain name")
    host = normalize_hostname(text)
    if not host:
        raise OrgGraphError(f"'{raw}' is not a valid domain name (expected something like example.com)")
    return host, note


def merge_attributes(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Merge attribute dicts: None is ignored, lists are unioned, scalars are overwritten."""
    for key, value in extra.items():
        if value is None:
            continue
        if isinstance(value, list):
            current = base.setdefault(key, [])
            if not isinstance(current, list):
                current = base[key] = [current]
            for item in value:
                if item not in current:
                    current.append(item)
        else:
            base[key] = value
    return base


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def gradient_color(t: float) -> str:
    """Interpolate the violet gradient at t in [0, 1]."""
    t = min(max(t, 0.0), 1.0)
    segments = len(GRADIENT) - 1
    position = t * segments
    index = min(int(position), segments - 1)
    local = position - index
    start, end = _hex_to_rgb(GRADIENT[index]), _hex_to_rgb(GRADIENT[index + 1])
    r, g, b = (round(start[i] + (end[i] - start[i]) * local) for i in range(3))
    return f"#{r:02x}{g:02x}{b:02x}"


def render_banner() -> Text:
    """The ASCII banner with a diagonal light-to-dark violet gradient, one colour per character."""
    lines = BANNER.strip("\n").splitlines()
    width = max(len(line) for line in lines)
    height = len(lines)
    text = Text()
    for row, line in enumerate(lines):
        for col, char in enumerate(line):
            t = 0.75 * col / max(width - 1, 1) + 0.25 * row / max(height - 1, 1)
            text.append(char, style=Style(color=gradient_color(t), bold=True))
        text.append("\n")
    return text


def print_banner(console: Console) -> None:
    console.print()
    console.print(render_banner(), end="")
    console.print(Text(TAGLINE, style=C_DIM))
    console.print()
    console.print(Text(f"v{VERSION}", style=f"bold {C_PRIMARY}"))
    console.print(Text(SUBTITLE, style="dim"))
    console.print()


def confidence_bar(score: int, width: int = 20) -> Text:
    filled = round(max(0, min(100, score)) / 100 * width)
    bar = Text()
    for i in range(filled):
        bar.append("█", style=gradient_color(i / max(width - 1, 1)))
    bar.append("░" * (width - filled), style=C_TRACK)
    bar.append(f" {score}/100", style="bold")
    return bar


def status_icon(status: str) -> Text:
    return {
        "ok": Text("✓", style=C_OK),
        "completed": Text("✓", style=C_OK),
        "warning": Text("⚠", style=C_WARN),
        "partial": Text("⚠", style=C_WARN),
        "error": Text("✗", style=C_ERR),
        "failed": Text("✗", style=C_ERR),
    }.get(status, Text("·", style="dim"))




@dataclass
class Observation:
    """Something that was actually returned by a source, with full provenance."""

    collector: str
    type: str
    value: str
    source: str
    source_url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utcnow_iso)
    id: str = field(default_factory=lambda: "obs_" + uuid.uuid4().hex[:16])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Scan:
    id: str
    target_id: int
    started_at: str
    finished_at: str | None = None
    status: str = "running"
    collector_stats: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorReport:
    name: str
    label: str
    status: str = "waiting"  # waiting | running | ok | warning | error
    message: str = ""
    findings: int = 0
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label, "status": self.status, "message": self.message,
            "findings": self.findings, "duration": round(self.duration, 2),
        }


@dataclass
class EntityDraft:
    """An entity as assembled by the correlation engine, before it is stored."""

    type: str
    value: str
    in_scope: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)
    observation_ids: list[str] = field(default_factory=list)
    score: int = 0
    breakdown: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.value)


@dataclass
class RelationDraft:
    source: tuple[str, str]
    target: tuple[str, str]
    type: str
    kind: str
    confidence: int = 100
    observation_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


class Graph:
    """In-memory, deduplicated result of one scan: entities keyed by (type, value)."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.entities: dict[tuple[str, str], EntityDraft] = {}
        self.relations: dict[tuple[Any, ...], RelationDraft] = {}
        self.entity(DOMAIN, target, True)

    def entity(
        self, etype: str, value: str, in_scope: bool = True,
        obs: Observation | None = None, **attrs: Any,
    ) -> EntityDraft:
        draft = self.entities.get((etype, value))
        if draft is None:
            draft = EntityDraft(etype, value, in_scope)
            self.entities[draft.key] = draft
        if obs is not None and obs.id not in draft.observation_ids:
            draft.observation_ids.append(obs.id)
        merge_attributes(draft.attributes, attrs)
        return draft

    def host(self, hostname: str, obs: Observation | None = None, **attrs: Any) -> EntityDraft:
        etype, in_scope = classify_host(hostname, self.target)
        return self.entity(etype, hostname, in_scope, obs, **attrs)

    def relate(
        self, source: EntityDraft, rtype: str, target: EntityDraft,
        kind: str = KIND_OBSERVED, obs: Observation | None = None, **attrs: Any,
    ) -> RelationDraft:
        key = (source.key, rtype, target.key)
        rel = self.relations.get(key)
        if rel is None:
            rel = RelationDraft(source.key, target.key, rtype, kind)
            self.relations[key] = rel
        if obs is not None and obs.id not in rel.observation_ids:
            rel.observation_ids.append(obs.id)
        merge_attributes(rel.attributes, attrs)
        return rel


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    collector_stats TEXT NOT NULL DEFAULT '{}',
    summary TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    collector TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    source_url TEXT,
    observed_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    in_scope INTEGER NOT NULL DEFAULT 1,
    attributes TEXT NOT NULL DEFAULT '{}',
    score INTEGER NOT NULL DEFAULT 0,
    score_breakdown TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (target_id, type, value)
);
CREATE TABLE IF NOT EXISTS entity_observations (
    entity_id TEXT NOT NULL REFERENCES entities(id),
    observation_id TEXT NOT NULL REFERENCES observations(id),
    PRIMARY KEY (entity_id, observation_id)
);
CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    source_entity_id TEXT NOT NULL REFERENCES entities(id),
    target_entity_id TEXT NOT NULL REFERENCES entities(id),
    relation_type TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 100,
    attributes TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (source_entity_id, relation_type, target_entity_id)
);
CREATE TABLE IF NOT EXISTS relationship_evidence (
    relationship_id TEXT NOT NULL REFERENCES relationships(id),
    observation_id TEXT NOT NULL REFERENCES observations(id),
    PRIMARY KEY (relationship_id, observation_id)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    scan_id TEXT,
    event_type TEXT NOT NULL,
    entity_id TEXT,
    description TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    UNIQUE (target_id, event_type, entity_id, occurred_at)
);
CREATE INDEX IF NOT EXISTS ix_scans_target ON scans(target_id, started_at);
CREATE INDEX IF NOT EXISTS ix_observations_scan ON observations(scan_id);
CREATE INDEX IF NOT EXISTS ix_observations_value ON observations(type, value);
CREATE INDEX IF NOT EXISTS ix_entities_target ON entities(target_id, type);
CREATE INDEX IF NOT EXISTS ix_entities_score ON entities(target_id, score);
CREATE INDEX IF NOT EXISTS ix_entity_obs_observation ON entity_observations(observation_id);
CREATE INDEX IF NOT EXISTS ix_relationships_target ON relationships(target_id);
CREATE INDEX IF NOT EXISTS ix_relationships_source ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS ix_relationships_dest ON relationships(target_entity_id);
CREATE INDEX IF NOT EXISTS ix_rel_evidence_observation ON relationship_evidence(observation_id);
CREATE INDEX IF NOT EXISTS ix_events_target ON events(target_id, occurred_at);
"""


def db_connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    if isinstance(path, Path):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def db_init(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def open_database(path: Path = DB_PATH) -> sqlite3.Connection:
    try:
        conn = db_connect(path)
        db_init(conn)
    except sqlite3.Error as exc:
        raise OrgGraphError(f"cannot open database {path}: {exc}") from exc
    return conn


def db_get_target(conn: sqlite3.Connection, domain: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM targets WHERE domain = ?", (domain,)).fetchone()


def db_get_or_create_target(conn: sqlite3.Connection, domain: str) -> sqlite3.Row:
    conn.execute(
        "INSERT OR IGNORE INTO targets (domain, created_at) VALUES (?, ?)", (domain, utcnow_iso())
    )
    conn.commit()
    row = db_get_target(conn, domain)
    assert row is not None
    return row


def db_list_targets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT t.domain, COUNT(s.id) AS scans, MAX(s.started_at) AS last_scan
        FROM targets t LEFT JOIN scans s ON s.target_id = t.id
        GROUP BY t.id ORDER BY t.domain
        """
    ).fetchall()
    return [dict(row) for row in rows]


def db_create_scan(conn: sqlite3.Connection, scan: Scan) -> None:
    conn.execute(
        """
        INSERT INTO scans (id, target_id, started_at, finished_at, status, collector_stats, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan.id, scan.target_id, scan.started_at, scan.finished_at, scan.status,
            json_dumps(scan.collector_stats), json_dumps(scan.summary),
        ),
    )
    conn.commit()


def db_update_scan(conn: sqlite3.Connection, scan: Scan) -> None:
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = ?, collector_stats = ?, summary = ? WHERE id = ?",
        (
            scan.finished_at, scan.status, json_dumps(scan.collector_stats),
            json_dumps(scan.summary), scan.id,
        ),
    )
    conn.commit()


def db_scan(conn: sqlite3.Connection, scan_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def db_scans(
    conn: sqlite3.Connection, target_id: int, *, finished_only: bool = False,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    """Scans for a target, newest first."""
    sql = "SELECT * FROM scans WHERE target_id = ?"
    if finished_only:
        sql += " AND status IN ('completed', 'partial')"
    sql += " ORDER BY started_at DESC, rowid DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql, (target_id,)).fetchall()


def scan_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["collector_stats"] = json_loads(data.get("collector_stats"), {})
    data["summary"] = json_loads(data.get("summary"), {})
    return data




def db_insert_observations(conn: sqlite3.Connection, scan_id: str, observations: list[Observation]) -> None:
    conn.executemany(
        """
        INSERT OR IGNORE INTO observations
            (id, scan_id, collector, type, value, source, source_url, observed_at, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                o.id, scan_id, o.collector, o.type, o.value, o.source, o.source_url,
                o.observed_at, json_dumps(o.metadata),
            )
            for o in observations
        ],
    )


def observation_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["metadata"] = json_loads(data.get("metadata"), {})
    return data


def db_observations_in_scan(conn: sqlite3.Connection, scan_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM observations WHERE scan_id = ? ORDER BY collector, type, value", (scan_id,)
    ).fetchall()


def db_entity_observations(conn: sqlite3.Connection, entity_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT o.* FROM observations o
        JOIN entity_observations eo ON eo.observation_id = o.id
        WHERE eo.entity_id = ? ORDER BY o.collector, o.type, o.value, o.observed_at
        """,
        (entity_id,),
    ).fetchall()


def db_relationship_observations(conn: sqlite3.Connection, relationship_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT o.* FROM observations o
        JOIN relationship_evidence re ON re.observation_id = o.id
        WHERE re.relationship_id = ? ORDER BY o.collector, o.type, o.value, o.observed_at
        """,
        (relationship_id,),
    ).fetchall()




def entity_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["in_scope"] = bool(data.get("in_scope"))
    data["attributes"] = json_loads(data.get("attributes"), {})
    data["score_breakdown"] = json_loads(data.get("score_breakdown"), [])
    return data


def db_entity(conn: sqlite3.Connection, entity_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()


def db_entities(conn: sqlite3.Connection, target_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM entities WHERE target_id = ? ORDER BY score DESC, type, value", (target_id,)
    ).fetchall()


def db_entities_in_scan(conn: sqlite3.Connection, scan_id: str) -> list[sqlite3.Row]:
    """Entities supported by at least one observation of the given scan."""
    return conn.execute(
        """
        SELECT DISTINCT e.* FROM entities e
        JOIN entity_observations eo ON eo.entity_id = e.id
        JOIN observations o ON o.id = eo.observation_id
        WHERE o.scan_id = ? ORDER BY e.type, e.value
        """,
        (scan_id,),
    ).fetchall()


def db_entity_collectors(conn: sqlite3.Connection, target_id: int) -> dict[str, list[str]]:
    """entity id -> sorted list of collectors that observed it (one query for a whole target)."""
    rows = conn.execute(
        """
        SELECT eo.entity_id, o.collector FROM entity_observations eo
        JOIN observations o ON o.id = eo.observation_id
        JOIN entities e ON e.id = eo.entity_id
        WHERE e.target_id = ? GROUP BY eo.entity_id, o.collector
        """,
        (target_id,),
    ).fetchall()
    result: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        result[row["entity_id"]].append(row["collector"])
    return result



_REL_SELECT = """
    SELECT r.*, se.type AS source_type, se.value AS source_value,
           te.type AS target_type, te.value AS target_value
    FROM relationships r
    JOIN entities se ON se.id = r.source_entity_id
    JOIN entities te ON te.id = r.target_entity_id
"""


def relationship_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["attributes"] = json_loads(data.get("attributes"), {})
    return data


def db_relationship(conn: sqlite3.Connection, relationship_id: str) -> sqlite3.Row | None:
    return conn.execute(_REL_SELECT + " WHERE r.id = ?", (relationship_id,)).fetchone()


def db_relationships(conn: sqlite3.Connection, target_id: int) -> list[sqlite3.Row]:
    return conn.execute(_REL_SELECT + " WHERE r.target_id = ?", (target_id,)).fetchall()


def db_relationships_in_scan(conn: sqlite3.Connection, scan_id: str) -> list[sqlite3.Row]:
    """Relationships supported by at least one observation of the given scan."""
    return conn.execute(
        """
        SELECT DISTINCT r.*, se.type AS source_type, se.value AS source_value,
               te.type AS target_type, te.value AS target_value
        FROM relationships r
        JOIN relationship_evidence re ON re.relationship_id = r.id
        JOIN observations o ON o.id = re.observation_id
        JOIN entities se ON se.id = r.source_entity_id
        JOIN entities te ON te.id = r.target_entity_id
        WHERE o.scan_id = ?
        """,
        (scan_id,),
    ).fetchall()


def db_entity_relationships(conn: sqlite3.Connection, entity_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        _REL_SELECT + " WHERE r.source_entity_id = ? OR r.target_entity_id = ?"
        " ORDER BY r.relation_type, te.value",
        (entity_id, entity_id),
    ).fetchall()




def db_insert_event(
    conn: sqlite3.Connection, target_id: int, scan_id: str | None, event_type: str,
    entity_id: str | None, description: str, occurred_at: str, details: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO events
            (target_id, scan_id, event_type, entity_id, description, occurred_at, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (target_id, scan_id, event_type, entity_id, description, occurred_at, json_dumps(details or {})),
    )


def db_events(conn: sqlite3.Connection, target_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE target_id = ? ORDER BY occurred_at, id", (target_id,)
    ).fetchall()




def _retry_after_seconds(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("retry-after", "")
    if header.strip().isdigit():
        return float(min(int(header), 60))
    return 2.0 * (attempt + 1)


class HttpClient:
    """The only way collectors reach the network.

    Politeness lives here and nowhere else: identifiable User-Agent, bounded
    concurrency, a small delay between requests to the same host, bounded
    retries that honour Retry-After, and a hard timeout on every request.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.requests = 0
        self._client = httpx.AsyncClient(
            headers={"User-Agent": config.user_agent, "Accept": "*/*"},
            timeout=httpx.Timeout(config.request_timeout),
            follow_redirects=False,
        )
        self._semaphore = asyncio.Semaphore(max(1, int(config.max_concurrency)))
        self._last_request: dict[str, float] = {}

    async def get(
        self, url: str, *, params: dict[str, str] | None = None,
        timeout: float | None = None, follow_redirects: bool = False,
    ) -> httpx.Response:
        host = urlsplit(url).hostname or ""
        attempts = max(0, int(self.config.max_retries)) + 1
        for attempt in range(attempts):
            response: httpx.Response | None = None
            async with self._semaphore:
                await self._throttle(host)
                self.requests += 1
                try:
                    response = await self._client.get(
                        url, params=params, timeout=timeout or self.config.request_timeout,
                        follow_redirects=follow_redirects,
                    )
                except httpx.TransportError as exc:
                    if attempt == attempts - 1:
                        raise
                    log.debug("retrying %s after %s", url, exc.__class__.__name__)
            if response is None:
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            if response.status_code in (429, 503) and attempt < attempts - 1:
                delay = _retry_after_seconds(response, attempt)
                log.debug("HTTP %s from %s, waiting %.1fs", response.status_code, host, delay)
                await asyncio.sleep(delay)
                continue
            return response
        raise httpx.TransportError(f"no response from {url}")

    async def fetch_page(self, url: str, max_bytes: int = 256 * 1024) -> tuple[httpx.Response, str]:
        """Single GET with a bounded body read (no retries: one request per URL, period)."""
        host = urlsplit(url).hostname or ""
        async with self._semaphore:
            await self._throttle(host)
            self.requests += 1
            async with self._client.stream("GET", url) as response:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= max_bytes:
                        break
        body = b"".join(chunks)
        encoding = response.charset_encoding or "utf-8"
        try:
            text = body.decode(encoding, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        return response, text

    async def _throttle(self, host: str) -> None:
        elapsed = time.monotonic() - self._last_request.get(host, 0.0)
        if elapsed < 0.3:
            await asyncio.sleep(0.3 - elapsed)
        self._last_request[host] = time.monotonic()

    async def aclose(self) -> None:
        await self._client.aclose()




class CollectorError(Exception):
    """Recoverable failure: reported for this collector, the scan continues."""


class SourceUnavailable(CollectorError):
    """The upstream source did not answer usefully (timeout, 5xx, bad payload)."""


class RateLimited(CollectorError):
    """The upstream source throttled us."""


class NoData(CollectorError):
    """The source answered but has nothing about this target."""


@dataclass
class ScanContext:
    """What collectors may use. They never touch the database."""

    target: str
    scan_id: str
    config: Config
    http: HttpClient
    hostnames: set[str]  # in-scope hostnames known so far (grows during the scan)
    seeded: set[str]  # hostnames we guessed ourselves (www) rather than observed
    resolving: set[str] = field(default_factory=set)  # hostnames with an A/AAAA answer
    notes: list[str] = field(default_factory=list)
    dns_semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(10))
    progress: Callable[[str, str], None] = lambda name, message: None


class Collector:
    """Base class. `phase` orders collectors: later phases see what earlier ones found."""

    name = ""
    label = ""
    phase = 1

    async def collect(self, ctx: ScanContext) -> list[Observation]:
        raise NotImplementedError

    def observe(
        self, otype: str, value: str, source: str, source_url: str = "", **metadata: Any
    ) -> Observation:
        return Observation(
            collector=self.name, type=otype, value=value, source=source,
            source_url=source_url, metadata=metadata,
        )




_TXT_STRINGS = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt_to_text(record: str) -> str:
    parts = _TXT_STRINGS.findall(record)
    text = "".join(parts).replace('\\"', '"') if parts else record
    return text[:500]


class DNSCollector(Collector):
    """Resolve A/AAAA/CNAME for every known hostname and MX/NS/TXT for the apex.

    Queries go to the system resolver, never to the target's servers. Names come
    exclusively from other collectors (no wordlists, no brute force).
    """

    name = "dns"
    label = "DNS"
    phase = 2

    async def collect(self, ctx: ScanContext) -> list[Observation]:
        if not HAVE_DNSPYTHON:
            raise CollectorError("dnspython is not installed")
        try:
            resolver = dns.asyncresolver.Resolver()
        except dns.exception.DNSException as exc:
            raise CollectorError(f"no usable system resolver ({exc.__class__.__name__})") from exc
        resolver.lifetime = ctx.config.request_timeout
        wildcard_ips = await self._wildcard_ips(resolver, ctx.target)
        hosts = sorted(ctx.hostnames)
        total = len(hosts)
        done = 0

        async def resolve_one(host: str) -> list[Observation]:
            nonlocal done
            async with ctx.dns_semaphore:
                found = await self._query_host(resolver, host, ctx, wildcard_ips)
            done += 1
            if done % 10 == 0 or done == total:
                ctx.progress(self.name, f"resolving {done}/{total}")
            return found

        groups = await asyncio.gather(*(resolve_one(host) for host in hosts))
        observations = [obs for group in groups for obs in group]
        for obs in observations:
            if obs.type in ("dns_a", "dns_aaaa"):
                ctx.resolving.add(obs.metadata["host"])
        if wildcard_ips:
            ctx.notes.append(
                f"wildcard DNS detected on *.{ctx.target} ({', '.join(sorted(wildcard_ips))}); "
                "matching answers are scored lower"
            )
        return observations

    async def _query(self, resolver: Any, name: str, rdtype: str) -> list[str] | None:
        """None means NXDOMAIN; an empty list means no records of that type."""
        try:
            answer = await resolver.resolve(name, rdtype)
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException as exc:
            log.debug("DNS %s %s: %s", rdtype, name, exc.__class__.__name__)
            return []
        return [rdata.to_text() for rdata in answer]

    async def _wildcard_ips(self, resolver: Any, target: str) -> set[str]:
        label = "orggraph-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        ips: set[str] = set()
        for rdtype in ("A", "AAAA"):
            records = await self._query(resolver, f"{label}.{target}", rdtype)
            for record in records or []:
                normalized = normalize_ip(record)
                if normalized:
                    ips.add(normalized)
        return ips

    async def _query_host(
        self, resolver: Any, host: str, ctx: ScanContext, wildcard_ips: set[str]
    ) -> list[Observation]:
        observations: list[Observation] = []
        rdtypes = ["A", "AAAA", "CNAME"] + (["MX", "NS", "TXT"] if host == ctx.target else [])
        addresses: set[str] = set()
        for rdtype in rdtypes:
            records = await self._query(resolver, host, rdtype)
            if records is None:
                if host not in ctx.seeded:
                    observations.append(
                        self.observe("dns_nxdomain", host, "system-resolver", f"A {host}", host=host)
                    )
                return observations
            for record in records:
                obs = self._record_observation(host, rdtype, record)
                if obs is None:
                    continue
                if obs.type in ("dns_a", "dns_aaaa"):
                    addresses.add(obs.value)
                observations.append(obs)
        if addresses and wildcard_ips and addresses <= wildcard_ips:
            for obs in observations:
                if obs.type in ("dns_a", "dns_aaaa"):
                    obs.metadata["wildcard_match"] = True
        return observations

    def _record_observation(self, host: str, rdtype: str, record: str) -> Observation | None:
        query = f"{rdtype} {host}"
        if rdtype in ("A", "AAAA"):
            ip = normalize_ip(record)
            if not ip:
                return None
            return self.observe(f"dns_{rdtype.lower()}", ip, "system-resolver", query, host=host, record=rdtype)
        if rdtype == "CNAME":
            cname = normalize_hostname(record)
            return self.observe("dns_cname", cname, "system-resolver", query, host=host) if cname else None
        if rdtype == "MX":
            parts = record.split(maxsplit=1)
            if len(parts) != 2:
                return None
            mx = normalize_hostname(parts[1])
            if not mx:
                return None
            priority = int(parts[0]) if parts[0].isdigit() else None
            return self.observe("dns_mx", mx, "system-resolver", query, host=host, priority=priority)
        if rdtype == "NS":
            ns = normalize_hostname(record)
            return self.observe("dns_ns", ns, "system-resolver", query, host=host) if ns else None
        if rdtype == "TXT":
            text = _txt_to_text(record)
            return self.observe("dns_txt", text, "system-resolver", query, host=host) if text else None
        return None




class CertificateTransparencyCollector(Collector):
    """Hostnames and certificates for %.target from crt.sh (one request, deduplicated)."""

    name = "certificate_transparency"
    label = "Certificate Transparency"
    phase = 1
    url = "https://crt.sh/"

    async def collect(self, ctx: ScanContext) -> list[Observation]:
        params = {"q": f"%.{ctx.target}", "output": "json", "deduplicate": "Y"}
        try:
            response = await ctx.http.get(self.url, params=params, timeout=ctx.config.ct_timeout)
        except httpx.TimeoutException as exc:
            raise SourceUnavailable("crt.sh timed out") from exc
        except httpx.HTTPError as exc:
            raise SourceUnavailable(f"crt.sh unreachable ({exc.__class__.__name__})") from exc
        if response.status_code == 429:
            raise RateLimited("crt.sh rate limited")
        if response.status_code in (401, 403):
            raise SourceUnavailable(f"crt.sh refused the request (HTTP {response.status_code})")
        if response.status_code >= 500:
            raise SourceUnavailable(f"crt.sh unavailable (HTTP {response.status_code})")
        if response.status_code != 200:
            raise CollectorError(f"crt.sh returned HTTP {response.status_code}")
        try:
            rows = response.json()
        except ValueError as exc:
            raise SourceUnavailable("crt.sh returned invalid JSON") from exc
        if not isinstance(rows, list):
            raise SourceUnavailable("crt.sh returned an unexpected payload")
        return self._parse(rows, str(response.url), ctx)

    def _parse(self, rows: list[Any], source_url: str, ctx: ScanContext) -> list[Observation]:
        certificates: dict[Any, dict[str, Any]] = {}
        names: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("id") is None or row["id"] in certificates:
                continue
            candidates = str(row.get("name_value") or "").split("\n") + [str(row.get("common_name") or "")]
            cert_names: set[str] = set()
            for raw in candidates:
                raw = raw.strip()
                if not raw or "@" in raw:
                    continue
                host = normalize_hostname(raw)
                if not host or not classify_host(host, ctx.target)[1]:
                    continue
                entry = names.setdefault(host, {"wildcard": False, "certificate_ids": []})
                if raw.startswith("*."):
                    entry["wildcard"] = True
                if len(entry["certificate_ids"]) < 20:
                    entry["certificate_ids"].append(row["id"])
                cert_names.add(host)
            certificates[row["id"]] = {"row": row, "names": cert_names}

        hosts = sorted(names)
        limit = int(ctx.config.max_hostnames)
        if len(hosts) > limit:
            ctx.notes.append(f"crt.sh listed {len(hosts)} hostnames; keeping the first {limit} (max_hostnames)")
            hosts = hosts[:limit]
        kept = set(hosts)
        observations = [
            self.observe("hostname", host, "crt.sh", source_url, **names[host]) for host in hosts
        ]
        for cert_id, item in certificates.items():
            row = item["row"]
            cert_names = sorted(item["names"] & kept)
            if not cert_names:
                continue
            serial = str(row.get("serial_number") or "").strip()
            value = f"serial:{serial}" if serial else f"crt.sh:{cert_id}"
            observations.append(
                self.observe(
                    "certificate", value, "crt.sh", f"https://crt.sh/?id={cert_id}",
                    crtsh_id=cert_id, names=cert_names, issuer=row.get("issuer_name"),
                    common_name=row.get("common_name"), not_before=row.get("not_before"),
                    not_after=row.get("not_after"), serial_number=serial or None,
                    logged_at=row.get("entry_timestamp"),
                )
            )
        ctx.hostnames.update(hosts)
        return observations




def _vcard_fn(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and isinstance(item[3], str):
                return item[3].strip() or None
    handle = entity.get("handle")
    return str(handle) if handle else None


class RDAPCollector(Collector):
    """Public registration data through the rdap.org bootstrap (redirects to the registry)."""

    name = "rdap"
    label = "RDAP"
    phase = 1

    async def collect(self, ctx: ScanContext) -> list[Observation]:
        url = f"https://rdap.org/domain/{ctx.target}"
        try:
            response = await ctx.http.get(url, follow_redirects=True)
        except httpx.TimeoutException as exc:
            raise SourceUnavailable("RDAP timed out") from exc
        except httpx.HTTPError as exc:
            raise SourceUnavailable(f"RDAP unreachable ({exc.__class__.__name__})") from exc
        if response.status_code == 404:
            raise NoData("no RDAP record for this domain")
        if response.status_code == 429:
            raise RateLimited("RDAP rate limited")
        if response.status_code in (401, 403):
            raise SourceUnavailable(f"RDAP refused the request (HTTP {response.status_code})")
        if response.status_code >= 500:
            raise SourceUnavailable(f"RDAP unavailable (HTTP {response.status_code})")
        if response.status_code != 200:
            raise CollectorError(f"RDAP returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceUnavailable("RDAP returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise SourceUnavailable("RDAP returned an unexpected payload")
        return self._parse(data, str(response.url), ctx)

    def _parse(self, data: dict[str, Any], source_url: str, ctx: ScanContext) -> list[Observation]:
        server = urlsplit(source_url).hostname or "rdap"
        events = {
            str(e.get("eventAction")): e.get("eventDate")
            for e in data.get("events") or []
            if isinstance(e, dict) and e.get("eventAction") and e.get("eventDate")
        }
        nameservers = sorted(
            {
                host
                for ns in data.get("nameservers") or []
                if isinstance(ns, dict)
                for host in [normalize_hostname(str(ns.get("ldhName") or ""))]
                if host
            }
        )
        registrar, iana_id = self._registrar(data)
        secure = data.get("secureDNS") if isinstance(data.get("secureDNS"), dict) else {}
        observations = [
            self.observe(
                "rdap_domain", ctx.target, server, source_url,
                ldh_name=data.get("ldhName"), statuses=list(data.get("status") or []),
                events=events, nameservers=nameservers, dnssec=secure.get("delegationSigned"),
                registrar=registrar, registrar_iana_id=iana_id, rdap_server=server,
            )
        ]
        for ns in nameservers:
            observations.append(self.observe("rdap_nameserver", ns, server, source_url, host=ctx.target))
        if registrar:
            observations.append(
                self.observe(
                    "organization", registrar, server, source_url,
                    role="registrar", domain=ctx.target, iana_id=iana_id,
                )
            )
        return observations

    @staticmethod
    def _registrar(data: dict[str, Any]) -> tuple[str | None, str | None]:
        for entity in data.get("entities") or []:
            if not isinstance(entity, dict):
                continue
            roles = [str(r).lower() for r in entity.get("roles") or []]
            if "registrar" not in roles:
                continue
            iana_id = None
            for public_id in entity.get("publicIds") or []:
                if isinstance(public_id, dict) and "iana" in str(public_id.get("type", "")).lower():
                    iana_id = str(public_id.get("identifier") or "") or None
            return _vcard_fn(entity), iana_id
        return None, None



SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
)
TECHNOLOGY_HEADERS = ("server", "x-powered-by", "x-generator")
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-vercel-id": "Vercel",
    "x-github-request-id": "GitHub Pages",
}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LINK_RE = re.compile(r"<link[^>]+>", re.I)
_REL_ICON_RE = re.compile(r"""rel\s*=\s*["']?[^"'>]*icon""", re.I)
_HREF_RE = re.compile(r"""href\s*=\s*["']?([^"' >]+)""", re.I)
MAX_REDIRECTS = 5


def extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return title[:200] or None


def extract_favicon(body: str, base_url: str) -> str:
    for tag in _LINK_RE.findall(body):
        if _REL_ICON_RE.search(tag):
            href = _HREF_RE.search(tag)
            if href:
                return urljoin(base_url, html.unescape(href.group(1)))
    return urljoin(base_url, "/favicon.ico")


def technologies_from_headers(headers: httpx.Headers) -> list[dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for header in TECHNOLOGY_HEADERS:
        raw = headers.get(header)
        if not raw:
            continue
        name = re.split(r"[/\s(;,]", raw.strip(), maxsplit=1)[0]
        if name and name.lower() not in found:
            found[name.lower()] = {"name": name, "header": header, "raw": raw[:200]}
    for header, name in CDN_HEADERS.items():
        if headers.get(header) and name.lower() not in found:
            found[name.lower()] = {"name": name, "header": header, "raw": ""}
    return list(found.values())


class HTTPCollector(Collector):
    """One GET on the root of hostnames that actually resolve (apex, www, then a capped list).

    No crawling, no path guessing: the only URL ever requested is `<scheme>://<host>/`,
    followed through at most MAX_REDIRECTS redirects.
    """

    name = "http"
    label = "HTTP"
    phase = 3

    async def collect(self, ctx: ScanContext) -> list[Observation]:
        primary = [ctx.target, f"www.{ctx.target}"]
        hosts = [h for h in primary if h in ctx.resolving]
        extra = sorted(h for h in ctx.resolving if h in ctx.hostnames and h not in primary)
        limit = int(ctx.config.http_max_hosts)
        if len(extra) > limit:
            ctx.notes.append(f"HTTP queried {limit} of {len(extra)} resolving hosts (http_max_hosts)")
            extra = extra[:limit]
        hosts.extend(extra)
        if not hosts:
            raise NoData("no resolving hostname to query")
        total = len(hosts)
        done = 0

        async def probe(host: str) -> list[Observation]:
            nonlocal done
            found = await self._probe_host(ctx, host)
            done += 1
            ctx.progress(self.name, f"querying {done}/{total}")
            return found

        groups = await asyncio.gather(*(probe(host) for host in hosts))
        return [obs for group in groups for obs in group]

    async def _probe_host(self, ctx: ScanContext, host: str) -> list[Observation]:
        for scheme in ("https", "http"):
            observations = await self._follow(ctx, f"{scheme}://{host}/", host)
            if observations is not None:
                return observations
        log.info("HTTP: %s did not answer over https or http", host)
        return []

    async def _follow(self, ctx: ScanContext, start_url: str, host: str) -> list[Observation] | None:
        url = start_url
        chain: list[dict[str, Any]] = []
        response: httpx.Response | None = None
        body = ""
        for _ in range(MAX_REDIRECTS + 1):
            try:
                response, body = await ctx.http.fetch_page(url)
            except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
                if not chain:
                    log.debug("HTTP %s: %s", url, exc.__class__.__name__)
                    return None
                log.debug("HTTP redirect target %s failed: %s", url, exc.__class__.__name__)
                break
            location = response.headers.get("location")
            if 300 <= response.status_code < 400 and location:
                next_url = urljoin(url, location)
                chain.append({"url": url, "status": response.status_code, "location": next_url})
                url = next_url
                continue
            break
        if response is None:
            return None
        origin = start_url.rstrip("/")
        present = {h: response.headers[h][:200] for h in SECURITY_HEADERS if h in response.headers}
        observations = [
            self.observe(
                "http_response", origin, host, start_url,
                host=host, url=start_url, final_url=url,
                status=chain[0]["status"] if chain else response.status_code,
                final_status=response.status_code, title=extract_title(body),
                server=response.headers.get("server"),
                content_type=response.headers.get("content-type"),
                security_headers=present,
                missing_security_headers=[h for h in SECURITY_HEADERS if h not in present],
                favicon=extract_favicon(body, url) if body else None,
                redirects=[hop["location"] for hop in chain],
            )
        ]
        seen = {host}
        for hop in chain:
            to_host = normalize_hostname(urlsplit(hop["location"]).hostname or "")
            if to_host and to_host not in seen:
                seen.add(to_host)
                observations.append(
                    self.observe(
                        "http_redirect", to_host, host, hop["url"], from_origin=origin,
                        from_url=hop["url"], to_url=hop["location"], status=hop["status"],
                    )
                )
        for tech in technologies_from_headers(response.headers):
            observations.append(
                self.observe(
                    "technology", tech["name"], host, url, origin=origin,
                    header=tech["header"], raw=tech["raw"],
                )
            )
        return observations


COLLECTORS: list[type[Collector]] = [
    CertificateTransparencyCollector,
    RDAPCollector,
    DNSCollector,
    HTTPCollector,
]


class Correlator:
    """Turns raw observations into one deduplicated graph.

    Each observation type has an `on_<type>` handler. Several observations of the
    same (type, value) always land on the same EntityDraft, which is what makes
    "api.example.com seen by CT, DNS and HTTP" one entity with three pieces of evidence.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self.graph = Graph(target)

    def run(self, observations: list[Observation]) -> Graph:
        for obs in observations:
            handler = getattr(self, f"on_{obs.type}", None)
            if handler is None:
                log.debug("no correlation handler for observation type %s", obs.type)
                continue
            try:
                handler(obs)
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("could not correlate %s observation %r: %s", obs.type, obs.value, exc)
        self._link_subdomains()
        return self.graph

    def on_hostname(self, obs: Observation) -> None:
        attrs: dict[str, Any] = {}
        if obs.metadata.get("wildcard"):
            attrs["wildcard_certificate"] = True
        self.graph.host(obs.value, obs, **attrs)

    def on_dns_nxdomain(self, obs: Observation) -> None:
        self.graph.host(obs.value, obs, resolves=False)

    def on_dns_a(self, obs: Observation) -> None:
        self._address(obs)

    def on_dns_aaaa(self, obs: Observation) -> None:
        self._address(obs)

    def _address(self, obs: Observation) -> None:
        attrs: dict[str, Any] = {"resolves": True}
        if obs.metadata.get("wildcard_match"):
            attrs["wildcard_match"] = True
        host = self.graph.host(obs.metadata["host"], obs, **attrs)
        ip = self.graph.entity(IP_ADDRESS, obs.value, False, obs, version=6 if ":" in obs.value else 4)
        self.graph.relate(host, RESOLVES_TO, ip, KIND_OBSERVED, obs)

    def on_dns_cname(self, obs: Observation) -> None:
        host = self.graph.host(obs.metadata["host"], obs)
        alias_target = self.graph.host(obs.value, obs)
        self.graph.relate(host, CNAME_TO, alias_target, KIND_OBSERVED, obs)

    def on_dns_ns(self, obs: Observation) -> None:
        self._server(obs, NAMESERVER, USES_NAMESERVER)

    def on_rdap_nameserver(self, obs: Observation) -> None:
        self._server(obs, NAMESERVER, USES_NAMESERVER)

    def on_dns_mx(self, obs: Observation) -> None:
        self._server(obs, MAIL_SERVER, USES_MAIL_SERVER, priority=obs.metadata.get("priority"))

    def _server(self, obs: Observation, etype: str, rtype: str, **rel_attrs: Any) -> None:
        host = self.graph.host(obs.metadata["host"], obs)
        in_scope = classify_host(obs.value, self.target)[1]
        server = self.graph.entity(etype, obs.value, in_scope, obs)
        self.graph.relate(host, rtype, server, KIND_OBSERVED, obs, **rel_attrs)

    def on_dns_txt(self, obs: Observation) -> None:
        attrs: dict[str, Any] = {"txt_records": [obs.value]}
        lowered = obs.value.lower()
        if lowered.startswith("v=spf1"):
            attrs["spf"] = obs.value
            attrs["spf_includes"] = re.findall(r"include:(\S+)", lowered)
        if "-site-verification=" in lowered or lowered.startswith("ms="):
            attrs["verification_tokens"] = [obs.value.split("=", 1)[0]]
        self.graph.host(obs.metadata["host"], obs, **attrs)

    def on_certificate(self, obs: Observation) -> None:
        meta = obs.metadata
        cert = self.graph.entity(
            CERTIFICATE, obs.value, True, obs,
            crtsh_id=meta.get("crtsh_id"), issuer=meta.get("issuer"),
            common_name=meta.get("common_name"), not_before=meta.get("not_before"),
            not_after=meta.get("not_after"), serial_number=meta.get("serial_number"),
            logged_at=meta.get("logged_at"), names=list(meta.get("names") or []),
        )
        for name in meta.get("names") or []:
            host = self.graph.host(name)  # its own hostname observation carries the evidence
            self.graph.relate(host, PRESENT_IN_CERTIFICATE, cert, KIND_OBSERVED, obs)

    def on_rdap_domain(self, obs: Observation) -> None:
        meta = obs.metadata
        self.graph.host(
            obs.value, obs, registrar=meta.get("registrar"), rdap_statuses=meta.get("statuses"),
            rdap_events=meta.get("events"), dnssec=meta.get("dnssec"), rdap_server=meta.get("rdap_server"),
        )

    def on_organization(self, obs: Observation) -> None:
        org = self.graph.entity(
            ORGANIZATION, obs.value, False, obs, role=obs.metadata.get("role"), iana_id=obs.metadata.get("iana_id")
        )
        domain = self.graph.host(obs.metadata["domain"])
        self.graph.relate(domain, REGISTERED_WITH, org, KIND_OBSERVED, obs)

    def on_http_response(self, obs: Observation) -> None:
        meta = obs.metadata
        host = self.graph.host(meta["host"], obs, http=True)
        service = self.graph.entity(
            WEB_SERVICE, obs.value, host.in_scope, obs,
            **{k: meta.get(k) for k in (
                "url", "final_url", "status", "final_status", "title", "server", "content_type",
                "security_headers", "missing_security_headers", "favicon", "redirects",
            )},
        )
        self.graph.relate(host, SERVES, service, KIND_OBSERVED, obs)

    def on_http_redirect(self, obs: Observation) -> None:
        service = self.graph.entity(WEB_SERVICE, obs.metadata["from_origin"], True)
        target_host = self.graph.host(obs.value, obs)
        self.graph.relate(
            service, REDIRECTS_TO, target_host, KIND_OBSERVED, obs,
            status=obs.metadata.get("status"), to_url=obs.metadata.get("to_url"),
        )

    def on_technology(self, obs: Observation) -> None:
        tech = self.graph.entity(TECHNOLOGY, obs.value, False, obs, headers=[obs.metadata.get("header")])
        service = self.graph.entity(WEB_SERVICE, obs.metadata["origin"], True)
        self.graph.relate(service, USES_TECHNOLOGY, tech, KIND_OBSERVED, obs)

    def _link_subdomains(self) -> None:
        """HAS_SUBDOMAIN edges (inferred from the name) towards the nearest known ancestor."""
        hosts = {
            draft.value: draft
            for draft in self.graph.entities.values()
            if draft.type in HOST_TYPES and draft.in_scope
        }
        for value, draft in hosts.items():
            if value == self.target:
                continue
            parent = self._nearest_parent(value, hosts)
            rel = self.graph.relate(parent, HAS_SUBDOMAIN, draft, KIND_INFERRED)
            for obs_id in draft.observation_ids:
                if obs_id not in rel.observation_ids:
                    rel.observation_ids.append(obs_id)

    def _nearest_parent(self, value: str, hosts: dict[str, EntityDraft]) -> EntityDraft:
        labels = value.split(".")
        for i in range(1, len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in hosts:
                return hosts[candidate]
        return hosts[self.target]


def correlate(target: str, observations: list[Observation]) -> Graph:
    return Correlator(target).run(observations)



SCORE_RULES: dict[str, tuple[int, str]] = {
    "namespace": (35, "belongs to target namespace"),
    "linked": (30, "referenced by an in-scope entity"),
    "multi_link": (10, "referenced by several in-scope entities"),
    "dns": (25, "DNS confirmation"),
    "dns_wildcard": (10, "DNS answer matches a wildcard record"),
    "certificate": (20, "certificate evidence"),
    "http": (10, "HTTP confirmation"),
    "rdap": (10, "RDAP registration data"),
    "external": (-15, "outside target namespace"),
    "unresolved": (-10, "does not currently resolve"),
}
SCORE_MAX = 100
HIGH_CONFIDENCE = 80


def score_entity(draft: EntityDraft, collectors: set[str], inbound_links: int) -> tuple[int, list[dict[str, Any]]]:
    signals: list[dict[str, Any]] = []

    def add(rule: str) -> None:
        weight, label = SCORE_RULES[rule]
        signals.append({"rule": rule, "weight": weight, "label": label})

    if draft.type in HOST_TYPES:
        add("namespace" if draft.in_scope else "external")
        if inbound_links and not draft.in_scope:
            add("linked")
    else:
        if inbound_links:
            add("linked")
        if inbound_links >= 2:
            add("multi_link")
    resolves = draft.attributes.get("resolves")
    if "dns" in collectors and resolves is not False:
        add("dns_wildcard" if draft.attributes.get("wildcard_match") else "dns")
    if "certificate_transparency" in collectors:
        add("certificate")
    if "http" in collectors:
        add("http")
    if "rdap" in collectors:
        add("rdap")
    if resolves is False:
        add("unresolved")
    score = max(0, min(SCORE_MAX, sum(s["weight"] for s in signals)))
    return score, signals


def score_graph(graph: Graph, observations: list[Observation]) -> None:
    collector_of = {obs.id: obs.collector for obs in observations}
    inbound: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    for rel in graph.relations.values():
        source = graph.entities.get(rel.source)
        if source is not None and source.in_scope and rel.type != HAS_SUBDOMAIN:
            inbound[rel.target].add(rel.source)
    for draft in graph.entities.values():
        collectors = {collector_of[o] for o in draft.observation_ids if o in collector_of}
        draft.score, draft.breakdown = score_entity(draft, collectors, len(inbound.get(draft.key, ())))




def persist_graph(
    conn: sqlite3.Connection, target_row: sqlite3.Row, scan: Scan,
    observations: list[Observation], graph: Graph,
) -> set[str]:
    """Store everything from one scan. Returns the ids of entities seen for the first time."""
    target_id = int(target_row["id"])
    target = str(target_row["domain"])
    now = scan.started_at
    new_ids: set[str] = set()
    ids: dict[tuple[str, str], str] = {}
    db_insert_observations(conn, scan.id, observations)
    for draft in graph.entities.values():
        entity_id = stable_id("ent", target, draft.type, draft.value)
        ids[draft.key] = entity_id
        existing = conn.execute("SELECT attributes FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if existing is None:
            new_ids.add(entity_id)
            conn.execute(
                """
                INSERT INTO entities (id, target_id, type, value, in_scope, attributes, score,
                                      score_breakdown, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity_id, target_id, draft.type, draft.value, int(draft.in_scope),
                    json_dumps(draft.attributes), draft.score, json_dumps(draft.breakdown), now, now,
                ),
            )
        else:
            attributes = {**json_loads(existing["attributes"], {}), **draft.attributes}
            conn.execute(
                """
                UPDATE entities SET in_scope = ?, attributes = ?, score = ?, score_breakdown = ?,
                                    last_seen = ?
                WHERE id = ?
                """,
                (
                    int(draft.in_scope), json_dumps(attributes), draft.score,
                    json_dumps(draft.breakdown), now, entity_id,
                ),
            )
        conn.executemany(
            "INSERT OR IGNORE INTO entity_observations (entity_id, observation_id) VALUES (?, ?)",
            [(entity_id, obs_id) for obs_id in draft.observation_ids],
        )
    for rel in graph.relations.values():
        source_id, target_entity_id = ids[rel.source], ids[rel.target]
        rel_id = stable_id("rel", source_id, rel.type, target_entity_id)
        conn.execute(
            """
            INSERT INTO relationships (id, target_id, source_entity_id, target_entity_id, relation_type,
                                       relation_kind, confidence, attributes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_entity_id, relation_type, target_entity_id) DO UPDATE SET
                relation_kind = excluded.relation_kind, confidence = excluded.confidence,
                attributes = excluded.attributes, updated_at = excluded.updated_at
            """,
            (
                rel_id, target_id, source_id, target_entity_id, rel.type, rel.kind, rel.confidence,
                json_dumps(rel.attributes), now, now,
            ),
        )
        conn.executemany(
            "INSERT OR IGNORE INTO relationship_evidence (relationship_id, observation_id) VALUES (?, ?)",
            [(rel_id, obs_id) for obs_id in rel.observation_ids],
        )
    conn.commit()
    return new_ids




@dataclass
class EntityChange:
    entity_id: str
    type: str
    value: str
    changes: list[dict[str, Any]]  # {"relation": ..., "label": ..., "before": [...], "after": [...]}


@dataclass
class DiffResult:
    older_scan: dict[str, Any]
    newer_scan: dict[str, Any]
    new: list[dict[str, Any]] = field(default_factory=list)
    not_observed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[EntityChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": True,
            "older_scan": self.older_scan, "newer_scan": self.newer_scan,
            "new": self.new, "not_observed": self.not_observed,
            "changed": [asdict(change) for change in self.changed],
            "warnings": self.warnings,
        }


def _relation_map(rows: list[sqlite3.Row]) -> dict[str, dict[str, set[str]]]:
    mapping: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in rows:
        if row["relation_type"] in TRACKED_RELATIONS:
            mapping[row["source_entity_id"]][row["relation_type"]].add(row["target_value"])
    return mapping


def _brief(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "type": row["type"], "value": row["value"], "score": row["score"]}


def compute_diff(
    conn: sqlite3.Connection, older_scan_id: str, newer_scan_id: str,
    newer_stats: dict[str, Any] | None = None,
) -> DiffResult:
    """Compare what two scans observed. Cautious vocabulary: absent != deleted."""
    older_row, newer_row = db_scan(conn, older_scan_id), db_scan(conn, newer_scan_id)
    if older_row is None or newer_row is None:
        raise OrgGraphError("scan not found")
    older_scan, newer_scan = scan_to_dict(older_row), scan_to_dict(newer_row)
    stats = newer_stats if newer_stats is not None else newer_scan["collector_stats"]
    result = DiffResult(
        older_scan={k: older_scan[k] for k in ("id", "started_at", "status")},
        newer_scan={k: newer_scan[k] for k in ("id", "started_at", "status")},
    )
    failed = sorted(name for name, stat in stats.items() if stat.get("status") == "error")
    skipped = sorted(name for name in older_scan["collector_stats"] if name not in stats)
    for name in failed:
        result.warnings.append(
            f"{COLLECTOR_LABELS.get(name, name)} failed in the newer scan: entities it would have "
            "observed may appear as not observed"
        )
    for name in skipped:
        result.warnings.append(
            f"{COLLECTOR_LABELS.get(name, name)} did not run in the newer scan: its entities may appear as not observed"
        )
    failed.extend(skipped)
    older = {row["id"]: row for row in db_entities_in_scan(conn, older_scan_id)}
    newer = {row["id"]: row for row in db_entities_in_scan(conn, newer_scan_id)}
    result.new = [_brief(row) for eid, row in newer.items() if eid not in older]
    result.not_observed = [_brief(row) for eid, row in older.items() if eid not in newer]
    if "dns" in failed:
        result.warnings.append("DNS failed in the newer scan: IP/CNAME/NS/MX changes were not evaluated")
        return result
    before = _relation_map(db_relationships_in_scan(conn, older_scan_id))
    after = _relation_map(db_relationships_in_scan(conn, newer_scan_id))
    for eid, row in newer.items():
        if eid not in older or row["type"] not in HOST_TYPES:
            continue
        changes = []
        for rtype, label in TRACKED_RELATIONS.items():
            was, now = before[eid].get(rtype, set()), after[eid].get(rtype, set())
            if was != now and (was or now):
                changes.append({"relation": rtype, "label": label, "before": sorted(was), "after": sorted(now)})
        if changes:
            result.changed.append(EntityChange(eid, row["type"], row["value"], changes))
    return result


def latest_diff(conn: sqlite3.Connection, target_id: int) -> tuple[DiffResult | None, str | None]:
    scans = db_scans(conn, target_id, finished_only=True, limit=2)
    if len(scans) < 2:
        return None, "at least two finished scans are needed to compute changes"
    return compute_diff(conn, scans[1]["id"], scans[0]["id"]), None



RDAP_EVENT_LABELS = {
    "registration": "domain registered (RDAP)",
    "expiration": "domain registration expires (RDAP)",
    "last changed": "domain record updated (RDAP)",
    "transfer": "domain transferred (RDAP)",
}


def _describe_change(change: EntityChange) -> str:
    parts = []
    for item in change.changes:
        before = ", ".join(item["before"]) or "none"
        after = ", ".join(item["after"]) or "none"
        parts.append(f"{item['label']} changed: {before} → {after}")
    return f"{change.value} " + "; ".join(parts)


def record_events(
    conn: sqlite3.Connection, target_id: int, scan: Scan, new_ids: set[str],
    diff: DiffResult | None, graph: Graph,
) -> None:
    rows = [row for row in (db_entity(conn, entity_id) for entity_id in new_ids) if row is not None]
    order = {etype: index for index, etype in enumerate(ENTITY_TYPES)}
    for row in sorted(rows, key=lambda r: (order.get(r["type"], 99), r["value"])):
        db_insert_event(
            conn, target_id, scan.id, "first_seen", row["id"],
            f"first seen: {row['value']}", scan.started_at, {"type": row["type"]},
        )
    if diff is not None:
        for change in diff.changed:
            db_insert_event(
                conn, target_id, scan.id, "changed", change.entity_id, _describe_change(change),
                scan.started_at, {"changes": change.changes},
            )
        for item in diff.not_observed:
            db_insert_event(
                conn, target_id, scan.id, "not_observed", item["id"],
                f"not observed: {item['value']}", scan.started_at, {"type": item["type"]},
            )
    apex = graph.entities.get((DOMAIN, graph.target))
    events = apex.attributes.get("rdap_events") if apex else None
    if isinstance(events, dict):
        apex_id = stable_id("ent", graph.target, DOMAIN, graph.target)
        for action, date in events.items():
            label = RDAP_EVENT_LABELS.get(str(action).lower())
            when = parse_iso(str(date))
            if label and when:
                db_insert_event(conn, target_id, scan.id, "rdap_" + str(action).replace(" ", "_"), apex_id,
                                label, when.astimezone(timezone.utc).replace(microsecond=0).isoformat())
    conn.commit()


def timeline_groups(conn: sqlite3.Connection, target_id: int) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in db_events(conn, target_id):
        day = row["occurred_at"][:10]
        details = json_loads(row["details"], {})
        groups[day].append(
            {
                "time": row["occurred_at"][11:16], "type": row["event_type"],
                "entity_id": row["entity_id"], "entity_type": details.get("type"),
                "description": row["description"], "scan_id": row["scan_id"],
            }
        )
    return [{"date": day, "items": items} for day, items in sorted(groups.items())]




def build_export(conn: sqlite3.Connection, target_row: sqlite3.Row, scan_row: sqlite3.Row) -> dict[str, Any]:
    target_id = int(target_row["id"])
    return {
        "generated_at": utcnow_iso(),
        "orggraph_version": VERSION,
        "note": "entities/relationships reflect the current state; observations are those of the scan",
        "target": dict(target_row),
        "scan": scan_to_dict(scan_row),
        "entities": [entity_to_dict(row) for row in db_entities(conn, target_id)],
        "relationships": [relationship_to_dict(row) for row in db_relationships(conn, target_id)],
        "observations": [observation_to_dict(row) for row in db_observations_in_scan(conn, scan_row["id"])],
    }


def write_export(data: dict[str, Any], domain: str, output: Path | None = None) -> Path:
    path = output or EXPORT_DIR / f"{domain}-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise OrgGraphError(f"cannot write {path}: {exc}") from exc
    return path




class ScanReporter:
    """Progress sink. The CLI subclasses it; --json uses this silent base class."""

    def collector(self, report: CollectorReport) -> None:
        pass

    def collectors_done(self) -> None:
        pass

    def stage(self, message: str) -> None:
        pass


def new_scan_id(conn: sqlite3.Connection) -> str:
    for _ in range(10):
        candidate = uuid.uuid4().hex[:8]
        if db_scan(conn, candidate) is None:
            return candidate
    return uuid.uuid4().hex[:16]


async def _run_collector(collector: Collector, ctx: ScanContext, report: CollectorReport) -> list[Observation]:
    started = time.monotonic()
    observations: list[Observation] = []
    try:
        observations = await collector.collect(ctx)
        report.status, report.findings = "ok", len(observations)
        report.message = f"{len(observations)} findings" if observations else "no data"
    except NoData as exc:
        report.status, report.message = "ok", f"no data ({exc})"
    except (RateLimited, SourceUnavailable) as exc:
        report.status, report.message = "warning", str(exc)
    except CollectorError as exc:
        report.status, report.message = "error", str(exc)
    except Exception as exc: 
        report.status, report.message = "error", f"{exc.__class__.__name__}: {exc}"
        log.debug("collector %s crashed:\n%s", collector.name, traceback.format_exc())
    report.duration = time.monotonic() - started
    log.info("%s: %s (%.1fs)", collector.label, report.message, report.duration)
    return observations


def finalize_scan(
    conn: sqlite3.Connection, target_row: sqlite3.Row, scan: Scan,
    observations: list[Observation], reports: dict[str, CollectorReport],
    notes: list[str] | None = None, reporter: ScanReporter | None = None,
) -> dict[str, Any]:
    """Correlate, score, persist, diff against the previous scan and record events."""
    reporter = reporter or ScanReporter()
    target_id = int(target_row["id"])
    reporter.stage("Correlating observations...")
    graph = correlate(str(target_row["domain"]), observations)
    reporter.stage("Scoring relationships...")
    score_graph(graph, observations)
    reporter.stage("Saving scan...")
    previous = db_scans(conn, target_id, finished_only=True, limit=1)
    new_ids = persist_graph(conn, target_row, scan, observations, graph)
    scan.collector_stats = {name: report.to_dict() for name, report in reports.items()}
    diff = compute_diff(conn, previous[0]["id"], scan.id, scan.collector_stats) if previous else None
    record_events(conn, target_id, scan, new_ids, diff, graph)
    counts: dict[str, int] = defaultdict(int)
    for draft in graph.entities.values():
        counts[draft.type] += 1
    scan.summary = {
        "entities": len(graph.entities),
        "relationships": len(graph.relations),
        "new_findings": len(new_ids),
        "high_confidence": sum(1 for d in graph.entities.values() if d.score >= HIGH_CONFIDENCE),
        "observations": len(observations),
        "counts": dict(sorted(counts.items())),
        "notes": list(notes or []),
        "changes": {
            "new": len(diff.new), "changed": len(diff.changed), "not_observed": len(diff.not_observed),
        } if diff else None,
    }
    statuses = {report.status for report in reports.values()}
    scan.status = "completed" if not (statuses & {"error", "warning"}) else "partial"
    scan.finished_at = utcnow_iso()
    db_update_scan(conn, scan)
    return scan.summary


async def run_scan(
    conn: sqlite3.Connection, target: str, config: Config, reporter: ScanReporter | None = None,
    only: set[str] | None = None,
) -> dict[str, Any]:
    reporter = reporter or ScanReporter()
    target_row = db_get_or_create_target(conn, target)
    scan = Scan(id=new_scan_id(conn), target_id=int(target_row["id"]), started_at=utcnow_iso())
    db_create_scan(conn, scan)
    collectors = [cls() for cls in COLLECTORS if only is None or cls.name in only]
    reports = {c.name: CollectorReport(c.name, c.label) for c in collectors}
    for report in reports.values():
        reporter.collector(report)
    http = HttpClient(config)
    ctx = ScanContext(
        target=target, scan_id=scan.id, config=config, http=http,
        hostnames={target, f"www.{target}"}, seeded={f"www.{target}"},
        dns_semaphore=asyncio.Semaphore(max(1, int(config.dns_concurrency))),
    )

    def progress(name: str, message: str) -> None:
        reports[name].message = message
        reporter.collector(reports[name])

    ctx.progress = progress
    observations: list[Observation] = []
    try:
        for phase in sorted({c.phase for c in collectors}):
            batch = [c for c in collectors if c.phase == phase]
            for collector in batch:
                reports[collector.name].status, reports[collector.name].message = "running", "running..."
                reporter.collector(reports[collector.name])
            groups = await asyncio.gather(*(_run_collector(c, ctx, reports[c.name]) for c in batch))
            for collector, group in zip(batch, groups):
                observations.extend(group)
                reporter.collector(reports[collector.name])
        reporter.collectors_done()
        summary = finalize_scan(conn, target_row, scan, observations, reports, ctx.notes, reporter)
    except BaseException:
        scan.status, scan.finished_at = "failed", utcnow_iso()
        scan.collector_stats = {name: report.to_dict() for name, report in reports.items()}
        db_update_scan(conn, scan)
        raise
    finally:
        await http.aclose()
    return {
        "target": target, "scan": {"id": scan.id, "started_at": scan.started_at,
                                   "finished_at": scan.finished_at, "status": scan.status},
        "collectors": scan.collector_stats, "summary": summary, "requests": http.requests,
    }




def require_target(conn: sqlite3.Connection, domain: str) -> sqlite3.Row:
    row = db_get_target(conn, domain)
    if row is None:
        raise OrgGraphError(f"no data for {domain}. Run: python orggraph.py scan {domain}")
    return row


def entity_list(conn: sqlite3.Connection, target_id: int) -> list[dict[str, Any]]:
    evidence = db_entity_collectors(conn, target_id)
    result = []
    for row in db_entities(conn, target_id):
        data = entity_to_dict(row)
        data["evidence"] = evidence.get(data["id"], [])
        result.append(data)
    return result


def target_summary(conn: sqlite3.Connection, target_row: sqlite3.Row) -> dict[str, Any]:
    target_id = int(target_row["id"])
    scans = db_scans(conn, target_id)
    last = scan_to_dict(scans[0]) if scans else None
    entities = entity_list(conn, target_id)
    counts: dict[str, int] = defaultdict(int)
    for entity in entities:
        counts[entity["type"]] += 1
    return {
        "target": target_row["domain"],
        "scans": len(scans),
        "last_scan": last,
        "counts": dict(sorted(counts.items())),
        "entities": len(entities),
        "relationships": len(db_relationships(conn, target_id)),
        "high_confidence": sum(1 for e in entities if e["score"] >= HIGH_CONFIDENCE),
        "new_findings": (last or {}).get("summary", {}).get("new_findings", 0),
        "top_entities": entities[:15],
    }


def entity_detail(conn: sqlite3.Connection, entity_id: str) -> dict[str, Any] | None:
    row = db_entity(conn, entity_id)
    if row is None:
        return None
    entity = entity_to_dict(row)
    observations = [observation_to_dict(o) for o in db_entity_observations(conn, entity_id)]
    relationships = []
    for rel in db_entity_relationships(conn, entity_id):
        outgoing = rel["source_entity_id"] == entity_id
        relationships.append(
            {
                "id": rel["id"], "type": rel["relation_type"], "kind": rel["relation_kind"],
                "confidence": rel["confidence"], "direction": "out" if outgoing else "in",
                "other": {
                    "id": rel["target_entity_id"] if outgoing else rel["source_entity_id"],
                    "type": rel["target_type"] if outgoing else rel["source_type"],
                    "value": rel["target_value"] if outgoing else rel["source_value"],
                },
                "updated_at": rel["updated_at"],
            }
        )
    return {
        "entity": entity,
        "evidence": sorted({o["collector"] for o in observations}),
        "observations": observations,
        "relationships": relationships,
    }


def relationship_detail(conn: sqlite3.Connection, relationship_id: str) -> dict[str, Any] | None:
    row = db_relationship(conn, relationship_id)
    if row is None:
        return None
    return {
        "relationship": relationship_to_dict(row),
        "observations": [observation_to_dict(o) for o in db_relationship_observations(conn, relationship_id)],
    }


def graph_payload(conn: sqlite3.Connection, target_id: int, scope: str = "latest") -> dict[str, Any]:
    scans = db_scans(conn, target_id, finished_only=True, limit=1)
    if scope == "latest" and scans:
        entity_rows = db_entities_in_scan(conn, scans[0]["id"])
        relation_rows = db_relationships_in_scan(conn, scans[0]["id"])
    else:
        entity_rows = db_entities(conn, target_id)
        relation_rows = db_relationships(conn, target_id)
    nodes = []
    for row in entity_rows:
        attributes = json_loads(row["attributes"], {})
        label = row["value"]
        if row["type"] == CERTIFICATE:
            label = attributes.get("common_name") or row["value"]
        nodes.append(
            {
                "id": row["id"], "type": row["type"], "value": row["value"], "label": label,
                "score": row["score"], "in_scope": bool(row["in_scope"]),
            }
        )
    node_ids = {n["id"] for n in nodes}
    edges = [
        {
            "id": row["id"], "source": row["source_entity_id"], "target": row["target_entity_id"],
            "type": row["relation_type"], "kind": row["relation_kind"], "confidence": row["confidence"],
        }
        for row in relation_rows
        if row["source_entity_id"] in node_ids and row["target_entity_id"] in node_ids
    ]
    return {"scope": scope, "scan_id": scans[0]["id"] if scans else None, "nodes": nodes, "edges": edges}



WEB_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OrgGraph</title>
<script src="https://unpkg.com/cytoscape@3/dist/cytoscape.min.js"></script>
<style>
:root{--bg:#09090B;--bg2:#111116;--bg3:#18181B;--border:#27272A;--v1:#D8B4FE;--v2:#A855F7;--v3:#7C3AED;--v4:#4C1D95;--text:#F4F4F5;--muted:#A1A1AA;--ok:#22C55E;--warn:#EAB308;--err:#EF4444}
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
.app{display:grid;grid-template-columns:220px 1fr;height:100vh}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:20px 14px}
.brand{font-weight:700;letter-spacing:.22em;font-size:13px;color:var(--v1);margin:0 8px 18px}
.brand small{display:block;color:var(--muted);letter-spacing:0;font-weight:400;font-size:11px;margin-top:2px}
.nav button{display:block;width:100%;text-align:left;background:none;border:0;color:var(--muted);padding:9px 10px;border-radius:6px;cursor:pointer;font-size:14px;font-family:inherit}
.nav button:hover{color:var(--text);background:var(--bg3)}
.nav button.active{color:var(--text);background:var(--v4)}
.sidebar .foot{margin-top:auto;color:var(--muted);font-size:11px;padding:0 10px;line-height:1.4}
main{display:flex;flex-direction:column;min-width:0;overflow:hidden}
header{display:flex;align-items:center;gap:16px;padding:12px 24px;border-bottom:1px solid var(--border);background:var(--bg2);font-size:13px}
header .muted{color:var(--muted)}
select,input[type=text],input[type=search]{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px;font-family:inherit}
input[type=range]{accent-color:var(--v2)}
button.btn{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:13px}
button.btn:hover{border-color:var(--v3)}
.view{display:none;padding:24px;overflow:auto;flex:1}
.view.active{display:block}
#view-graph{padding:0}
#view-graph.active{display:grid;grid-template-rows:auto 1fr;overflow:hidden}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin-bottom:8px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.card .v{font-size:26px;font-weight:600;margin-top:4px;color:var(--v1)}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin:26px 0 10px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid #1C1C21;vertical-align:top}
tr.row:hover td{background:var(--bg3);cursor:pointer}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;background:var(--bg3);border:1px solid var(--border);color:var(--muted);margin-right:4px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle}
.bar{height:7px;background:#27272A;border-radius:4px;overflow:hidden;min-width:80px}
.bar .fill{height:100%;background:linear-gradient(90deg,var(--v1),var(--v3));border-radius:4px}
.bar-label{font-size:11px;color:var(--muted);margin-top:3px}
.toolbar{display:flex;flex-wrap:wrap;gap:14px;align-items:center;padding:10px 20px;border-bottom:1px solid var(--border);background:var(--bg2);font-size:12px}
.toolbar label{color:var(--muted);display:flex;align-items:center;gap:5px;white-space:nowrap}
.toolbar .types{display:flex;flex-wrap:wrap;gap:8px}
#cy{width:100%;height:100%;background:var(--bg)}
.inspector{position:fixed;top:0;right:0;height:100vh;width:360px;background:var(--bg2);border-left:1px solid var(--border);padding:20px;overflow:auto;font-size:13px;transform:translateX(100%);transition:transform .18s ease;z-index:20;box-shadow:-8px 0 30px rgba(0,0,0,.4)}
.inspector.open{transform:translateX(0)}
.inspector .close{float:right;background:none;border:0;color:var(--muted);font-size:18px;cursor:pointer}
.inspector .title{font-size:16px;font-weight:600;word-break:break-all;margin-top:4px}
.inspector .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:16px}
.inspector .v{margin-top:3px;word-break:break-all}
.inspector ul{margin:4px 0 0;padding-left:16px}
.inspector li{margin:3px 0}
.inspector .rel{cursor:pointer;color:var(--v1)}
.inspector .rel:hover{text-decoration:underline}
.inspector .sig{display:flex;justify-content:space-between;gap:10px;padding:2px 0;border-bottom:1px dashed #1C1C21}
.inspector .sig span:first-child{color:var(--muted)}
.empty{color:var(--muted);padding:40px;text-align:center}
.tl-date{color:var(--v1);font-weight:600;margin-top:18px}
.tl-item{padding:3px 0 3px 14px;border-left:1px solid var(--border);margin-left:6px}
.tl-item .t{color:var(--muted);font-size:11px;margin-right:8px;font-family:ui-monospace,Menlo,monospace}
.diff h3{font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin:20px 0 8px;color:var(--muted)}
.diff .new{color:var(--ok)}.diff .chg{color:var(--warn)}.diff .gone{color:var(--muted)}
.diff pre{margin:0;background:var(--bg2);border:1px solid var(--border);padding:10px 12px;border-radius:8px;white-space:pre-wrap;font-size:12px;font-family:ui-monospace,Menlo,monospace}
.warn{color:var(--warn);font-size:12px}
.status-ok{color:var(--ok)}.status-warning{color:var(--warn)}.status-error{color:var(--err)}.status-completed{color:var(--ok)}.status-partial{color:var(--warn)}.status-failed{color:var(--err)}.status-running{color:var(--muted)}
code{color:var(--v1);font-size:12px;font-family:ui-monospace,Menlo,monospace}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--muted)}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">ORGGRAPH<small>v__VERSION__</small></div>
    <nav class="nav">
      <button data-view="overview" class="active">Overview</button>
      <button data-view="graph">Graph</button>
      <button data-view="entities">Entities</button>
      <button data-view="timeline">Timeline</button>
      <button data-view="changes">Changes</button>
      <button data-view="scans">Scans</button>
    </nav>
    <div class="foot">passive intelligence<br>correlation<br>graph analysis</div>
  </aside>
  <main>
    <header>
      <span class="muted">Target</span>
      <select id="target"></select>
      <span class="muted" id="lastscan"></span>
    </header>
    <section id="view-overview" class="view active"><div class="empty">Loading…</div></section>
    <section id="view-graph" class="view">
      <div class="toolbar">
        <input type="search" id="g-search" placeholder="Search nodes…">
        <label>Min score <input type="range" id="g-score" min="0" max="100" value="0"> <span id="g-score-v">0</span></label>
        <label><input type="checkbox" id="g-labels"> Edge labels</label>
        <button class="btn" id="g-layout">Re-layout</button>
        <button class="btn" id="g-fit">Fit</button>
        <div class="types" id="g-types"></div>
        <div class="legend"><span>— observed</span><span>- - inferred</span><span>· · hypothesis</span></div>
      </div>
      <div id="cy"></div>
    </section>
    <section id="view-entities" class="view">
      <div style="display:flex;gap:12px;margin-bottom:14px">
        <input type="search" id="e-search" placeholder="Filter…" style="flex:1;max-width:320px">
        <select id="e-type"><option value="">All types</option></select>
      </div>
      <div id="e-table"></div>
    </section>
    <section id="view-timeline" class="view"></section>
    <section id="view-changes" class="view diff"></section>
    <section id="view-scans" class="view"></section>
  </main>
</div>
<aside class="inspector" id="inspector"><button class="close" id="i-close">×</button><div id="i-body"></div></aside>
<script>
const TYPE_COLORS = {Domain:"#A855F7",Subdomain:"#7C3AED",IPAddress:"#38BDF8",Certificate:"#F59E0B",Nameserver:"#14B8A6",MailServer:"#F472B6",WebService:"#C084FC",Technology:"#71717A",Organization:"#FCD34D",ASN:"#FB923C",Repository:"#34D399",Package:"#4ADE80"};
const COLLECTOR_LABELS = {dns:"DNS",certificate_transparency:"Certificate Transparency",rdap:"RDAP",http:"HTTP"};
const state = {target:null, cy:null, graph:null, entities:[], view:"overview", hidden:new Set()};
const $ = (sel, el=document) => el.querySelector(sel);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = iso => iso ? String(iso).replace("T"," ").slice(0,16) : "-";
const color = t => TYPE_COLORS[t] || "#71717A";
async function api(path){ const r = await fetch(path); if(!r.ok) throw new Error(path + " → HTTP " + r.status); return r.json(); }
function bar(score){ return `<div class="bar"><div class="fill" style="width:${Math.max(0,Math.min(100,score))}%"></div></div><div class="bar-label">${score} / 100</div>`; }
function typeBadge(t){ return `<span class="dot" style="background:${color(t)}"></span>${esc(t)}`; }

function showView(name){
  state.view = name;
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + name));
  document.querySelectorAll(".nav button").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  location.hash = name;
  if(name === "graph") ensureGraph();
}

async function loadTargets(){
  const targets = await api("/api/targets");
  const select = $("#target");
  select.innerHTML = targets.map(t => `<option value="${esc(t.domain)}">${esc(t.domain)}</option>`).join("");
  if(!targets.length){
    $("#view-overview").innerHTML = '<div class="empty">No data yet. Run <code>python orggraph.py scan example.com</code> then reload.</div>';
    return;
  }
  const wanted = new URLSearchParams(location.search).get("target");
  select.value = targets.some(t => t.domain === wanted) ? wanted : targets[0].domain;
  await loadTarget(select.value);
}

async function loadTarget(domain){
  state.target = domain;
  if(state.cy){ state.cy.destroy(); state.cy = null; }
  state.graph = null;
  const enc = encodeURIComponent(domain);
  const safe = p => api(p).catch(err => ({error: err.message}));
  const [summary, entities, timeline, diff, scans] = await Promise.all([
    safe(`/api/target/${enc}`), safe(`/api/entities/${enc}`), safe(`/api/timeline/${enc}`),
    safe(`/api/diff/${enc}`), safe(`/api/scans/${enc}`)]);
  state.entities = Array.isArray(entities) ? entities : [];
  renderOverview(summary); renderEntities(); renderTimeline(timeline); renderDiff(diff); renderScans(scans);
  if(state.view === "graph") ensureGraph();
}

function renderOverview(s){
  const el = $("#view-overview");
  if(!s || s.error){ el.innerHTML = `<div class="empty">${esc(s && s.error || "no data")}</div>`; return; }
  const last = s.last_scan;
  $("#lastscan").textContent = last ? `Last scan: ${fmt(last.started_at)} · ${last.status} · ${last.id}` : "No scan yet";
  const cards = [["Domains", s.counts.Domain||0],["Subdomains", s.counts.Subdomain||0],["IPs", s.counts.IPAddress||0],
    ["Relations", s.relationships],["Certificates", s.counts.Certificate||0],["Web services", s.counts.WebService||0],
    ["New findings", s.new_findings],["High confidence", s.high_confidence]];
  let html = `<div class="cards">${cards.map(([k,v]) => `<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("")}</div>`;
  if(last && last.collector_stats){
    html += `<h2>Collectors (last scan)</h2><table><tr><th>Collector</th><th>Status</th><th>Result</th><th>Duration</th></tr>` +
      Object.entries(last.collector_stats).map(([k,c]) => `<tr><td>${esc(c.label||k)}</td><td class="status-${esc(c.status)}">${esc(c.status)}</td><td>${esc(c.message)}</td><td>${c.duration}s</td></tr>`).join("") + `</table>`;
  }
  if(last && last.summary && last.summary.notes && last.summary.notes.length){
    html += `<h2>Notes</h2>` + last.summary.notes.map(n => `<div class="warn">${esc(n)}</div>`).join("");
  }
  html += `<h2>Top entities</h2>` + entityTable((s.top_entities||[]));
  el.innerHTML = html;
  bindRows(el);
}

function entityTable(list){
  if(!list.length) return '<div class="empty">No entities</div>';
  return `<table><tr><th>Type</th><th>Value</th><th style="width:140px">Confidence</th><th>Evidence</th><th>First seen</th><th>Last seen</th></tr>` +
    list.map(e => `<tr class="row" data-id="${esc(e.id)}"><td>${typeBadge(e.type)}</td><td>${esc(e.value)}</td><td>${bar(e.score)}</td>` +
      `<td>${(e.evidence||[]).map(c => `<span class="badge">${esc(COLLECTOR_LABELS[c]||c)}</span>`).join("")}</td><td>${fmt(e.first_seen)}</td><td>${fmt(e.last_seen)}</td></tr>`).join("") + `</table>`;
}

function bindRows(el){ el.querySelectorAll("tr.row").forEach(r => r.addEventListener("click", () => openInspector(r.dataset.id))); }

function renderEntities(){
  const q = $("#e-search").value.trim().toLowerCase();
  const t = $("#e-type").value;
  const types = [...new Set(state.entities.map(e => e.type))].sort();
  const select = $("#e-type");
  if(select.options.length !== types.length + 1){
    select.innerHTML = '<option value="">All types</option>' + types.map(x => `<option value="${esc(x)}">${esc(x)}</option>`).join("");
    select.value = t;
  }
  const list = state.entities.filter(e => (!t || e.type === t) && (!q || e.value.toLowerCase().includes(q)));
  $("#e-table").innerHTML = `<div class="bar-label" style="margin-bottom:8px">${list.length} entities</div>` + entityTable(list);
  bindRows($("#e-table"));
}

function renderTimeline(groups){
  const el = $("#view-timeline");
  if(!Array.isArray(groups) || !groups.length){ el.innerHTML = '<div class="empty">No events yet</div>'; return; }
  el.innerHTML = groups.map(g => `<div class="tl-date">${esc(g.date)}</div>` +
    g.items.map(i => `<div class="tl-item"><span class="t">${esc(i.time)}</span>${i.entity_id ? `<span class="rel" data-id="${esc(i.entity_id)}">${esc(i.description)}</span>` : esc(i.description)}</div>`).join("")).join("");
  el.querySelectorAll(".rel").forEach(r => r.addEventListener("click", () => openInspector(r.dataset.id)));
}

function renderDiff(d){
  const el = $("#view-changes");
  if(!d || d.error || d.available === false){ el.innerHTML = `<div class="empty">${esc((d && (d.reason || d.error)) || "no data")}</div>`; return; }
  let html = `<div class="bar-label">Comparing scan ${esc(d.older_scan.id)} (${fmt(d.older_scan.started_at)}) → ${esc(d.newer_scan.id)} (${fmt(d.newer_scan.started_at)})</div>`;
  html += d.warnings.map(w => `<div class="warn">⚠ ${esc(w)}</div>`).join("");
  html += `<h3>New (${d.new.length})</h3><pre class="new">${d.new.map(e => "+ " + esc(e.value) + "  [" + esc(e.type) + "]").join("\n") || "none"}</pre>`;
  html += `<h3>Changed (${d.changed.length})</h3><pre class="chg">${d.changed.map(c => "~ " + esc(c.value) + "\n" + c.changes.map(x => "  " + esc(x.label) + " changed:\n  " + esc(x.before.join(", ") || "none") + "\n  →\n  " + esc(x.after.join(", ") || "none")).join("\n")).join("\n\n") || "none"}</pre>`;
  html += `<h3>Removed / not observed (${d.not_observed.length})</h3><pre class="gone">${d.not_observed.map(e => "- " + esc(e.value) + "  [" + esc(e.type) + "]").join("\n") || "none"}</pre>`;
  html += `<div class="bar-label" style="margin-top:12px">"Not observed" means the newer scan did not see it; it does not necessarily mean it was deleted.</div>`;
  el.innerHTML = html;
}

function renderScans(list){
  const el = $("#view-scans");
  if(!Array.isArray(list) || !list.length){ el.innerHTML = '<div class="empty">No scans</div>'; return; }
  el.innerHTML = `<table><tr><th>Scan</th><th>Started</th><th>Finished</th><th>Status</th><th>Entities</th><th>Relations</th><th>New</th><th>Collectors</th></tr>` +
    list.map(s => `<tr><td><code>${esc(s.id)}</code></td><td>${fmt(s.started_at)}</td><td>${fmt(s.finished_at)}</td><td class="status-${esc(s.status)}">${esc(s.status)}</td>` +
      `<td>${s.summary.entities ?? "-"}</td><td>${s.summary.relationships ?? "-"}</td><td>${s.summary.new_findings ?? "-"}</td>` +
      `<td>${Object.entries(s.collector_stats||{}).map(([k,c]) => `<span class="badge status-${esc(c.status)}">${esc(c.label||k)}</span>`).join("")}</td></tr>`).join("") + `</table>`;
}

async function ensureGraph(){
  if(!state.target) return;
  if(state.cy){ state.cy.resize(); return; }
  try { state.graph = await api(`/api/graph/${encodeURIComponent(state.target)}`); }
  catch(err){ $("#cy").innerHTML = `<div class="empty">${esc(err.message)}</div>`; return; }
  if(typeof cytoscape === "undefined"){ $("#cy").innerHTML = '<div class="empty">Cytoscape.js could not be loaded (CDN unreachable). The rest of the UI still works.</div>'; return; }
  const g = state.graph;
  const types = [...new Set(g.nodes.map(n => n.type))].sort();
  $("#g-types").innerHTML = types.map(t => `<label><input type="checkbox" data-type="${esc(t)}" ${t === "Certificate" && g.nodes.length > 60 ? "" : "checked"}> <span class="dot" style="background:${color(t)}"></span>${esc(t)}</label>`).join("");
  state.hidden = new Set(types.filter(t => t === "Certificate" && g.nodes.length > 60));
  $("#g-types").querySelectorAll("input").forEach(cb => cb.addEventListener("change", () => { cb.checked ? state.hidden.delete(cb.dataset.type) : state.hidden.add(cb.dataset.type); applyFilters(); }));
  const degree = {};
  g.edges.forEach(e => { degree[e.source] = (degree[e.source]||0)+1; degree[e.target] = (degree[e.target]||0)+1; });
  state.cy = cytoscape({
    container: $("#cy"),
    elements: [
      ...g.nodes.map(n => ({data:{...n, color:color(n.type), size: 14 + Math.min(26, 3*(degree[n.id]||0))}})),
      ...g.edges.map(e => ({data:e}))],
    style: [
      {selector:"node", style:{"background-color":"data(color)","label":"data(label)","color":"#A1A1AA","font-size":9,"text-valign":"bottom","text-margin-y":4,"width":"data(size)","height":"data(size)","border-width":1,"border-color":"#27272A","text-max-width":"140px","text-wrap":"ellipsis","min-zoomed-font-size":6}},
      {selector:"node:selected", style:{"border-color":"#D8B4FE","border-width":3,"color":"#F4F4F5"}},
      {selector:"edge", style:{"width":1,"line-color":"#3F3F46","curve-style":"bezier","target-arrow-shape":"triangle","target-arrow-color":"#3F3F46","arrow-scale":0.6,"font-size":7,"color":"#71717A","text-rotation":"autorotate","text-background-color":"#09090B","text-background-opacity":1,"text-background-padding":"1px"}},
      {selector:"edge[kind = 'inferred']", style:{"line-style":"dashed"}},
      {selector:"edge[kind = 'hypothesis']", style:{"line-style":"dotted","line-color":"#7C3AED","target-arrow-color":"#7C3AED"}},
      {selector:"edge.labeled", style:{"label":"data(type)"}}
    ],
    layout: layoutOptions(),
    wheelSensitivity: 0.2
  });
  state.cy.on("tap", "node", evt => openInspector(evt.target.id()));
  applyFilters();
}

function layoutOptions(){ return {name:"cose", animate:false, padding:30, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, gravity: 0.5, numIter: 800}; }

function applyFilters(){
  if(!state.cy) return;
  const q = $("#g-search").value.trim().toLowerCase();
  const min = Number($("#g-score").value);
  state.cy.batch(() => {
    state.cy.nodes().forEach(n => {
      const d = n.data();
      const ok = !state.hidden.has(d.type) && d.score >= min && (!q || String(d.label).toLowerCase().includes(q) || String(d.value).toLowerCase().includes(q));
      n.style("display", ok ? "element" : "none");
    });
  });
}

async function openInspector(id){
  let d;
  try { d = await api(`/api/entity/${encodeURIComponent(id)}`); } catch(err){ d = {error: err.message}; }
  const body = $("#i-body");
  if(d.error){ body.innerHTML = `<div class="empty">${esc(d.error)}</div>`; }
  else {
    const e = d.entity;
    const attrs = Object.entries(e.attributes||{}).filter(([k,v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length));
    body.innerHTML = `
      <div class="k">${typeBadge(e.type)}${e.in_scope ? "" : ' <span class="badge">external</span>'}</div>
      <div class="title">${esc(e.value)}</div>
      <div class="k">Association confidence</div><div class="v">${bar(e.score)}</div>
      <div class="v">${(e.score_breakdown||[]).map(s => `<div class="sig"><span>${esc(s.label)}</span><span>${s.weight > 0 ? "+" : ""}${s.weight}</span></div>`).join("")}</div>
      <div class="k">First seen</div><div class="v">${fmt(e.first_seen)}</div>
      <div class="k">Last seen</div><div class="v">${fmt(e.last_seen)}</div>
      <div class="k">Evidence</div><div class="v">${d.evidence.map(c => `<span class="badge">${esc(COLLECTOR_LABELS[c]||c)}</span>`).join("") || "—"}</div>
      <div class="k">Observations (${d.observations.length})</div><ul>${d.observations.slice(0,40).map(o => `<li><span class="badge">${esc(COLLECTOR_LABELS[o.collector]||o.collector)}</span>${esc(o.type)} · ${esc(o.source)} · ${fmt(o.observed_at)}${o.source_url ? ` · <span style="color:var(--muted);word-break:break-all">${esc(o.source_url)}</span>` : ""}</li>`).join("")}</ul>
      <div class="k">Relations (${d.relationships.length})</div><ul>${d.relationships.slice(0,80).map(r => `<li><code>${r.direction === "in" ? "← " : ""}${esc(r.type)}${r.direction === "out" ? " →" : ""}</code> <span class="rel" data-id="${esc(r.other.id)}">${esc(r.other.value)}</span> <span class="badge">${esc(r.kind)}${r.kind === "hypothesis" ? " " + r.confidence : ""}</span></li>`).join("") || "<li>—</li>"}</ul>
      ${attrs.length ? `<div class="k">Attributes</div><ul>${attrs.map(([k,v]) => `<li><span style="color:var(--muted)">${esc(k)}</span>: ${esc(typeof v === "object" ? JSON.stringify(v) : v)}</li>`).join("")}</ul>` : ""}
      <div class="k">Id</div><div class="v"><code>${esc(e.id)}</code></div>`;
    body.querySelectorAll(".rel").forEach(r => r.addEventListener("click", () => openInspector(r.dataset.id)));
    if(state.cy){ const n = state.cy.getElementById(id); if(n.length){ state.cy.elements().unselect(); n.select(); } }
  }
  $("#inspector").classList.add("open");
}

document.querySelectorAll(".nav button").forEach(b => b.addEventListener("click", () => showView(b.dataset.view)));
$("#target").addEventListener("change", ev => loadTarget(ev.target.value));
$("#e-search").addEventListener("input", renderEntities);
$("#e-type").addEventListener("change", renderEntities);
$("#g-search").addEventListener("input", applyFilters);
$("#g-score").addEventListener("input", ev => { $("#g-score-v").textContent = ev.target.value; applyFilters(); });
$("#g-labels").addEventListener("change", ev => { if(state.cy) state.cy.edges().toggleClass("labeled", ev.target.checked); });
$("#g-layout").addEventListener("click", () => { if(state.cy) state.cy.layout(layoutOptions()).run(); });
$("#g-fit").addEventListener("click", () => { if(state.cy) state.cy.fit(undefined, 30); });
$("#i-close").addEventListener("click", () => $("#inspector").classList.remove("open"));
document.addEventListener("keydown", ev => { if(ev.key === "Escape") $("#inspector").classList.remove("open"); });
loadTargets().then(() => showView((location.hash || "#overview").slice(1) || "overview")).catch(err => { $("#view-overview").innerHTML = `<div class="empty">${esc(err.message)}</div>`; });
</script>
</body>
</html>
"""


def build_web_app(db_path: Path) -> Any:
    """FastAPI application. Imported lazily so the CLI works without fastapi/uvicorn."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:
        raise OrgGraphError("the web UI needs fastapi and uvicorn: pip install fastapi uvicorn") from exc

    app = FastAPI(title="OrgGraph", version=VERSION, docs_url=None, redoc_url=None)

    def connect() -> sqlite3.Connection:
        return open_database(db_path)

    def target_or_404(conn: sqlite3.Connection, domain: str) -> sqlite3.Row:
        row = db_get_target(conn, domain.strip().lower())
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown target {domain}")
        return row

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return WEB_UI.replace("__VERSION__", VERSION)

    @app.get("/api/targets")
    def api_targets() -> Any:
        conn = connect()
        try:
            return JSONResponse(db_list_targets(conn))
        finally:
            conn.close()

    @app.get("/api/target/{domain}")
    def api_target(domain: str) -> Any:
        conn = connect()
        try:
            return JSONResponse(target_summary(conn, target_or_404(conn, domain)))
        finally:
            conn.close()

    @app.get("/api/graph/{domain}")
    def api_graph(domain: str, scope: str = "latest") -> Any:
        conn = connect()
        try:
            row = target_or_404(conn, domain)
            return JSONResponse(graph_payload(conn, int(row["id"]), "all" if scope == "all" else "latest"))
        finally:
            conn.close()

    @app.get("/api/entities/{domain}")
    def api_entities(domain: str) -> Any:
        conn = connect()
        try:
            return JSONResponse(entity_list(conn, int(target_or_404(conn, domain)["id"])))
        finally:
            conn.close()

    @app.get("/api/scans/{domain}")
    def api_scans(domain: str) -> Any:
        conn = connect()
        try:
            row = target_or_404(conn, domain)
            return JSONResponse([scan_to_dict(s) for s in db_scans(conn, int(row["id"]))])
        finally:
            conn.close()

    @app.get("/api/diff/{domain}")
    def api_diff(domain: str) -> Any:
        conn = connect()
        try:
            row = target_or_404(conn, domain)
            diff, reason = latest_diff(conn, int(row["id"]))
            return JSONResponse(diff.to_dict() if diff else {"available": False, "reason": reason})
        finally:
            conn.close()

    @app.get("/api/timeline/{domain}")
    def api_timeline(domain: str) -> Any:
        conn = connect()
        try:
            return JSONResponse(timeline_groups(conn, int(target_or_404(conn, domain)["id"])))
        finally:
            conn.close()

    @app.get("/api/entity/{entity_id}")
    def api_entity(entity_id: str) -> Any:
        conn = connect()
        try:
            data = entity_detail(conn, entity_id) if entity_id.startswith("ent_") else relationship_detail(conn, entity_id)
            if data is None:
                raise HTTPException(status_code=404, detail=f"unknown id {entity_id}")
            return JSONResponse(data)
        finally:
            conn.close()

    return app

app = typer.Typer(
    help=TAGLINE,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)
RULE = "─" * 40
STATE = {"debug": False}


def opt_no_banner() -> Any:
    return typer.Option(False, "--no-banner", help="Do not print the startup banner.")


def opt_verbose() -> Any:
    return typer.Option(False, "--verbose", "-v", help="Show progress logs on stderr.")


def opt_debug() -> Any:
    return typer.Option(False, "--debug", help="Debug logs and full tracebacks.")


def opt_json() -> Any:
    return typer.Option(False, "--json", help="Machine-readable JSON on stdout (no banner, no spinner).")


def startup(no_banner: bool, verbose: bool, debug: bool, json_mode: bool = False) -> tuple[Config, sqlite3.Connection]:
    """Shared start of every command: logging, banner, config, database."""
    STATE["debug"] = debug
    setup_logging(verbose, debug)
    if not no_banner and not json_mode:
        print_banner(console)
    return Config.load(), open_database(DB_PATH)


def cli_command(func: Callable[..., Any]) -> Callable[..., Any]:
    """Turn OrgGraphError into a one-line message; keep tracebacks for --debug only."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except OrgGraphError as exc:
            err_console.print(Text(f"error: {exc}", style=C_ERR))
            raise typer.Exit(code=1)
        except (typer.Exit, SystemExit):
            raise
        except KeyboardInterrupt:
            err_console.print(Text("interrupted", style=C_WARN))
            raise typer.Exit(code=130)
        except Exception as exc:
            if STATE["debug"]:
                raise
            err_console.print(Text(f"error: {exc.__class__.__name__}: {exc}", style=C_ERR))
            err_console.print(Text("run again with --debug for a traceback", style="dim"))
            raise typer.Exit(code=1)

    return wrapper


def emit_json(data: Any) -> None:
    text = json_dumps(data, indent=2) + "\n"
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError: 
        sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=True, default=str) + "\n")
    sys.stdout.flush()


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(f"orggraph {VERSION}\n")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """Passive OSINT Intelligence & Correlation Framework.

    Collects public, passive signals about a domain (DNS, Certificate Transparency,
    RDAP, HTTP), correlates them into entities and relationships, scores them and
    keeps the history in a local SQLite database.
    """




class RichReporter(ScanReporter):
    """Live collector table, then stage lines, in the terminal."""

    def __init__(self, console_: Console) -> None:
        self.console = console_
        self.reports: dict[str, CollectorReport] = {}
        self.live = Live(self._table(), console=console_, refresh_per_second=10, transient=False)
        self.started = False

    def collector(self, report: CollectorReport) -> None:
        self.reports[report.name] = report
        if not self.started:
            self.live.start()
            self.started = True
        self.live.update(self._table())

    def collectors_done(self) -> None:
        self.close()
        if not self.console.is_terminal:
            self.console.print() 
        self.console.print(Text(RULE, style=C_TRACK))

    def stage(self, message: str) -> None:
        self.console.print(Text(message, style=C_DIM))

    def close(self) -> None:
        if self.started:
            self.live.update(self._table())
            self.live.stop()
            self.started = False

    def _table(self) -> Table:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column(width=2, no_wrap=True)
        table.add_column(min_width=26, no_wrap=True)
        table.add_column(no_wrap=True)
        for report in self.reports.values():
            if report.status == "waiting":
                icon: Any = Text("·", style="dim")
                message = Text("waiting", style="dim")
            elif report.status == "running":
                icon = Spinner("dots", style=C_PRIMARY)
                message = Text(report.message or "running...", style=C_DIM)
            else:
                icon = status_icon(report.status)
                style = {"ok": C_OK, "warning": C_WARN}.get(report.status, C_ERR)
                message = Text(report.message, style=style if report.status != "ok" else "")
            table.add_row(icon, Text(report.label), message)
        return table


def _parse_collector_filter(value: str | None) -> set[str] | None:
    if not value:
        return None
    wanted = {part.strip().lower() for part in value.split(",") if part.strip()}
    known = {cls.name for cls in COLLECTORS}
    unknown = wanted - known
    if unknown:
        raise OrgGraphError(f"unknown collector(s): {', '.join(sorted(unknown))}. Known: {', '.join(sorted(known))}")
    return wanted


def _print_scan_summary(result: dict[str, Any]) -> None:
    summary = result["summary"]
    console.print()
    console.print(Text(RULE, style=C_TRACK))
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    table.add_column(min_width=26)
    table.add_column(justify="right", style="bold")
    table.add_row("Entities", str(summary["entities"]))
    table.add_row("Relationships", str(summary["relationships"]))
    table.add_row("New findings", str(summary["new_findings"]))
    table.add_row("High confidence", str(summary["high_confidence"]))
    if summary.get("changes"):
        changes = summary["changes"]
        table.add_row("Changes vs previous", f"+{changes['new']} ~{changes['changed']} -{changes['not_observed']}")
    console.print(table)
    console.print()
    status = result["scan"]["status"]
    console.print(Text.assemble(("Scan ID: ", ""), (result["scan"]["id"], f"bold {C_PRIMARY}"), (f"  ({status})", "dim")))
    for note in summary.get("notes") or []:
        console.print(Text(f"note: {note}", style=C_WARN))


@app.command()
@cli_command
def scan(
    target: str = typer.Argument(..., help="Domain to scan, e.g. example.com"),
    collectors: Optional[str] = typer.Option(
        None, "--collectors", help="Comma-separated subset (dns,certificate_transparency,rdap,http)."
    ),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Scan a target domain using passive sources only."""
    config, conn = startup(no_banner, verbose, debug, json_mode)
    domain, note = parse_target(target)
    only = _parse_collector_filter(collectors)
    reporter: ScanReporter = ScanReporter() if json_mode else RichReporter(console)
    if not json_mode:
        console.print(Text.assemble(("Target: ", C_DIM), (domain, "bold")))
        if note:
            console.print(Text(f"note: {note}", style=C_WARN))
        console.print()
        console.print(Text("Collectors", style=f"bold {C_PRIMARY}"))
        console.print(Text(RULE, style=C_TRACK))
    try:
        result = asyncio.run(run_scan(conn, domain, config, reporter, only))
    except KeyboardInterrupt:
        if isinstance(reporter, RichReporter):
            reporter.close()
        raise OrgGraphError("scan interrupted; it is recorded as failed")
    finally:
        if isinstance(reporter, RichReporter):
            reporter.close()
    if json_mode:
        emit_json(result)
        return
    _print_scan_summary(result)




def _collector_lines(stats: dict[str, Any]) -> Table:
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    table.add_column(width=2)
    table.add_column(min_width=26)
    table.add_column()
    for name, stat in stats.items():
        style = {"ok": "", "warning": C_WARN}.get(stat.get("status", ""), C_ERR)
        table.add_row(
            status_icon(stat.get("status", "")), Text(stat.get("label") or COLLECTOR_LABELS.get(name, name)),
            Text(f"{stat.get('message', '')}  ({stat.get('duration', 0)}s)", style=style),
        )
    return table


def _entity_table(entities: list[dict[str, Any]], title: str | None = None) -> Table:
    table = Table(box=box.SIMPLE_HEAD, title=title, title_style=f"bold {C_PRIMARY}", title_justify="left",
                  header_style=C_DIM, padding=(0, 1), pad_edge=False)
    table.add_column("Type", no_wrap=True)
    table.add_column("Value", overflow="fold", min_width=18, ratio=1)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Evidence", overflow="fold")
    table.add_column("Id", style="dim", no_wrap=True, min_width=16)
    for entity in entities:
        evidence = ",".join(COLLECTOR_SHORT.get(c, c) for c in entity.get("evidence", []))
        external = entity["type"] in HOST_TYPES and not entity["in_scope"]
        table.add_row(
            Text(entity["type"], style="dim" if external else ""),
            Text(entity["value"] + (" (external)" if external else "")),
            confidence_bar(entity["score"], 8), evidence, entity["id"],
        )
    return table


@app.command()
@cli_command
def show(
    target: str = typer.Argument(..., help="Domain previously scanned"),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Show target summary."""
    _, conn = startup(no_banner, verbose, debug, json_mode)
    domain, _ = parse_target(target)
    summary = target_summary(conn, require_target(conn, domain))
    if json_mode:
        emit_json(summary)
        return
    last = summary["last_scan"]
    console.print(Text.assemble(("Target: ", C_DIM), (domain, "bold")))
    if last:
        console.print(Text.assemble(
            ("Last scan: ", C_DIM), (fmt_dt(last["started_at"]), ""), ("  ·  ", C_DIM), (last["status"], ""),
            ("  ·  ", C_DIM), (last["id"], C_PRIMARY), ("  ·  ", C_DIM), (f"{summary['scans']} scan(s) total", ""),
        ))
    else:
        console.print(Text("No scan recorded yet.", style=C_DIM))
    if last and last.get("collector_stats"):
        console.print()
        console.print(Text("Collectors (last scan)", style=f"bold {C_PRIMARY}"))
        console.print(_collector_lines(last["collector_stats"]))
        for note in (last.get("summary") or {}).get("notes") or []:
            console.print(Text(f"note: {note}", style=C_WARN))
    console.print()
    overview = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    overview.add_column(min_width=26)
    overview.add_column(justify="right", style="bold")
    overview.add_row("Entities", str(summary["entities"]))
    overview.add_row("Relationships", str(summary["relationships"]))
    overview.add_row("High confidence (≥80)", str(summary["high_confidence"]))
    for etype in ENTITY_TYPES:
        if summary["counts"].get(etype):
            overview.add_row(f"  {etype}", str(summary["counts"][etype]))
    console.print(Text("Overview", style=f"bold {C_PRIMARY}"))
    console.print(overview)
    console.print()
    console.print(_entity_table(summary["top_entities"], "Top entities"))
    console.print(Text(f"More: python orggraph.py entities {domain}  ·  python orggraph.py explain ENTITY_ID", style="dim"))




@app.command()
@cli_command
def entities(
    target: str = typer.Argument(..., help="Domain previously scanned"),
    etype: Optional[str] = typer.Option(None, "--type", help="Only this entity type (e.g. Subdomain)."),
    min_score: int = typer.Option(0, "--min-score", help="Only entities with this confidence or more."),
    limit: int = typer.Option(0, "--limit", help="Maximum rows (0 = all)."),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """List known entities."""
    _, conn = startup(no_banner, verbose, debug, json_mode)
    domain, _ = parse_target(target)
    row = require_target(conn, domain)
    rows = entity_list(conn, int(row["id"]))
    if etype:
        wanted = etype.strip().lower()
        rows = [e for e in rows if e["type"].lower() == wanted]
    rows = [e for e in rows if e["score"] >= min_score]
    if limit > 0:
        rows = rows[:limit]
    if json_mode:
        emit_json(rows)
        return
    console.print(Text.assemble(("Target: ", C_DIM), (domain, "bold"), (f"   {len(rows)} entities", C_DIM)))
    if not rows:
        console.print(Text("No data", style=C_DIM))
        return
    console.print(_entity_table(rows))




def _print_observations(observations: list[dict[str, Any]]) -> None:
    table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold", ratio=1)
    table.add_column(style="dim", no_wrap=True)
    table.add_column(style="dim", overflow="fold", ratio=1)
    for obs in observations[:40]:
        table.add_row(
            COLLECTOR_SHORT.get(obs["collector"], obs["collector"]), f"{obs['type']}: {obs['value']}",
            fmt_dt(obs["observed_at"])[:16], obs.get("source_url") or obs["source"],
        )
    console.print(table)
    if len(observations) > 40:
        console.print(Text(f"  … {len(observations) - 40} more observations", style="dim"))


def _explain_entity(data: dict[str, Any]) -> None:
    entity = data["entity"]
    scope = "in target namespace" if entity["in_scope"] else "external"
    console.print(Text.assemble((entity["value"], "bold"), (f"   {entity['type']} · {scope} · ", C_DIM), (entity["id"], "dim")))
    console.print()
    meta = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    meta.add_column(min_width=14, style=C_DIM)
    meta.add_column()
    meta.add_row("First seen", fmt_dt(entity["first_seen"]))
    meta.add_row("Last seen", fmt_dt(entity["last_seen"]))
    console.print(meta)
    console.print()
    console.print(Text("Association confidence", style=f"bold {C_PRIMARY}"))
    console.print(confidence_bar(entity["score"]))
    console.print()
    console.print(Text("Evidence", style=f"bold {C_PRIMARY}"))
    if not entity["score_breakdown"]:
        console.print(Text("No scoring signals", style=C_DIM))
    for signal in entity["score_breakdown"]:
        weight = signal["weight"]
        console.print(Text.assemble((f"{weight:+4d} ", C_OK if weight > 0 else C_WARN), (signal["label"], "")))
    console.print()
    console.print(Text("Observed by", style=f"bold {C_PRIMARY}"))
    observations = data["observations"]
    if observations:
        latest_scan = max(observations, key=lambda o: o["observed_at"])["scan_id"]
        current = [o for o in observations if o["scan_id"] == latest_scan]
        _print_observations(current)
        scans = {o["scan_id"] for o in observations}
        if len(observations) > len(current):
            console.print(Text(
                f"  … {len(observations) - len(current)} earlier observations across "
                f"{len(scans) - 1} previous scan(s) (full list with --json)", style="dim",
            ))
    else:
        console.print(Text("No data", style=C_DIM))
    console.print()
    console.print(Text("Relations", style=f"bold {C_PRIMARY}"))
    if not data["relationships"]:
        console.print(Text("No data", style=C_DIM))
    rel_table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    rel_table.add_column(width=2)
    rel_table.add_column(min_width=22)
    rel_table.add_column(overflow="fold")
    rel_table.add_column(style="dim")
    rel_table.add_column(style="dim", no_wrap=True)
    for rel in data["relationships"][:80]:
        arrow = "→" if rel["direction"] == "out" else "←"
        kind = rel["kind"] if rel["kind"] != KIND_HYPOTHESIS else f"hypothesis {rel['confidence']}"
        rel_table.add_row(arrow, rel["type"], rel["other"]["value"], kind, rel["id"])
    console.print(rel_table)
    attributes = {
        k: v for k, v in entity["attributes"].items()
        if v not in (None, "", [], {}) and k not in ("names",)
    }
    if attributes:
        console.print()
        console.print(Text("Attributes", style=f"bold {C_PRIMARY}"))
        attr_table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        attr_table.add_column(min_width=22, style=C_DIM)
        attr_table.add_column(overflow="fold")
        for key, value in attributes.items():
            rendered = json_dumps(value) if isinstance(value, (dict, list)) else str(value)
            attr_table.add_row(key, rendered[:300])
        console.print(attr_table)


def _explain_relationship(data: dict[str, Any]) -> None:
    rel = data["relationship"]
    console.print(Text.assemble(
        (rel["source_value"], "bold"), ("  ", ""), (rel["relation_type"], f"bold {C_PRIMARY}"), ("  ", ""),
        (rel["target_value"], "bold"), (f"   {rel['id']}", "dim"),
    ))
    console.print()
    meta = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
    meta.add_column(min_width=14, style=C_DIM)
    meta.add_column()
    meta.add_row("Source", f"{rel['source_type']} {rel['source_value']}  ({rel['source_entity_id']})")
    meta.add_row("Target", f"{rel['target_type']} {rel['target_value']}  ({rel['target_entity_id']})")
    meta.add_row("Kind", rel["relation_kind"])
    meta.add_row("Confidence", f"{rel['confidence']}/100")
    meta.add_row("Created", fmt_dt(rel["created_at"]))
    meta.add_row("Updated", fmt_dt(rel["updated_at"]))
    if rel["attributes"]:
        meta.add_row("Attributes", json_dumps(rel["attributes"])[:300])
    console.print(meta)
    console.print()
    console.print(Text("Evidence", style=f"bold {C_PRIMARY}"))
    if data["observations"]:
        _print_observations(data["observations"])
    else:
        console.print(Text("No data", style=C_DIM))


@app.command()
@cli_command
def explain(
    entity_id: str = typer.Argument(..., help="Entity id (ent_...) or relationship id (rel_...)"),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Explain an entity or relationship: score breakdown, evidence, relations."""
    _, conn = startup(no_banner, verbose, debug, json_mode)
    identifier = entity_id.strip()
    if identifier.startswith("rel_"):
        data = relationship_detail(conn, identifier)
    else:
        data = entity_detail(conn, identifier)
    if data is None:
        raise OrgGraphError(f"unknown id '{identifier}' (ids look like ent_xxxxxxxxxxxx or rel_xxxxxxxxxxxx)")
    if json_mode:
        emit_json(data)
        return
    if "relationship" in data:
        _explain_relationship(data)
    else:
        _explain_entity(data)




def _print_diff(diff: DiffResult) -> None:
    console.print(Text("Changes since previous scan", style=f"bold {C_PRIMARY}"))
    console.print(Text.assemble(
        ("scan ", C_DIM), (diff.older_scan["id"], ""), (f" ({fmt_dt(diff.older_scan['started_at'])})  →  scan ", C_DIM),
        (diff.newer_scan["id"], ""), (f" ({fmt_dt(diff.newer_scan['started_at'])})", C_DIM),
    ))
    for warning in diff.warnings:
        console.print(Text(f"⚠ {warning}", style=C_WARN))
    if not (diff.new or diff.changed or diff.not_observed):
        console.print()
        console.print(Text("No differences between the two scans.", style=C_DIM))
        return
    console.print()
    console.print(Text("NEW", style=f"bold {C_OK}"))
    console.print(Text(RULE, style=C_TRACK))
    for item in diff.new:
        console.print(Text.assemble(("+ ", C_OK), (item["value"], ""), (f"   [{item['type']}]", "dim")))
    if not diff.new:
        console.print(Text("none", style="dim"))
    console.print()
    console.print(Text("CHANGED", style=f"bold {C_WARN}"))
    console.print(Text(RULE, style=C_TRACK))
    for change in diff.changed:
        console.print(Text.assemble(("~ ", C_WARN), (change.value, "")))
        for item in change.changes:
            console.print(Text(f"  {item['label']} changed:", style=C_DIM))
            console.print(Text("  " + (", ".join(item["before"]) or "none")))
            console.print(Text("  →", style=C_DIM))
            console.print(Text("  " + (", ".join(item["after"]) or "none")))
    if not diff.changed:
        console.print(Text("none", style="dim"))
    console.print()
    console.print(Text("REMOVED / NOT OBSERVED", style="bold"))
    console.print(Text(RULE, style=C_TRACK))
    for item in diff.not_observed:
        console.print(Text.assemble(("- ", C_DIM), (item["value"], ""), (f"   [{item['type']}]", "dim")))
    if not diff.not_observed:
        console.print(Text("none", style="dim"))
    console.print()
    console.print(Text("\"Not observed\" means the newer scan did not see it. That is not proof of removal.", style="dim"))


@app.command()
@cli_command
def diff(
    target: str = typer.Argument(..., help="Domain previously scanned at least twice"),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Compare the two most recent scans."""
    _, conn = startup(no_banner, verbose, debug, json_mode)
    domain, _ = parse_target(target)
    row = require_target(conn, domain)
    result, reason = latest_diff(conn, int(row["id"]))
    if json_mode:
        emit_json(result.to_dict() if result else {"available": False, "reason": reason})
        return
    console.print(Text.assemble(("Target: ", C_DIM), (domain, "bold")))
    console.print()
    if result is None:
        console.print(Text(f"No data: {reason}", style=C_DIM))
        return
    _print_diff(result)



TIMELINE_PER_DAY = 15


@app.command()
@cli_command
def timeline(
    target: str = typer.Argument(..., help="Domain previously scanned"),
    show_all: bool = typer.Option(False, "--all", help=f"Show every event (default caps at {TIMELINE_PER_DAY} per day)."),
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Show the target timeline (first sightings, changes, RDAP dates)."""
    _, conn = startup(no_banner, verbose, debug, json_mode)
    domain, _ = parse_target(target)
    row = require_target(conn, domain)
    groups = timeline_groups(conn, int(row["id"]))
    if json_mode:
        emit_json(groups)
        return
    console.print(Text.assemble(("Target: ", C_DIM), (domain, "bold")))
    console.print()
    if not groups:
        console.print(Text("No events yet", style=C_DIM))
        return
    styles = {"first_seen": C_OK, "changed": C_WARN, "not_observed": C_DIM}
    for index, group in enumerate(groups):
        last_group = index == len(groups) - 1
        items = group["items"] if show_all else group["items"][:TIMELINE_PER_DAY]
        hidden = len(group["items"]) - len(items)
        console.print(Text(group["date"], style=f"bold {C_LIGHT}"))
        console.print(Text("│", style=C_TRACK))
        for j, item in enumerate(items):
            last_item = j == len(items) - 1 and hidden == 0
            branch = "└─" if last_group and last_item else "├─"
            console.print(Text.assemble(
                (branch + " ", C_TRACK), (item["time"] + "  ", "dim"),
                (item["description"], styles.get(item["type"], "")),
                (f"  [{item['entity_type']}]" if item.get("entity_type") else "", "dim"),
            ))
        if hidden:
            branch = "└─" if last_group else "├─"
            console.print(Text(f"{branch} … {hidden} more (use --all)", style="dim"))
        if not last_group:
            console.print(Text("│", style=C_TRACK))




@app.command()
@cli_command
def export(
    target: str = typer.Argument(..., help="Domain previously scanned"),
    fmt: str = typer.Option("json", "--format", help="Export format (json)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Destination file (default: exports/<domain>-<date>.json)."),
    to_stdout: bool = typer.Option(False, "--stdout", help="Print the export on stdout instead of writing a file."),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Export collected intelligence (target, scan, entities, relationships, observations)."""
    _, conn = startup(no_banner, verbose, debug, to_stdout)
    if fmt.lower() != "json":
        raise OrgGraphError(f"unsupported format '{fmt}' (only json is available in this version)")
    domain, _ = parse_target(target)
    row = require_target(conn, domain)
    scans = db_scans(conn, int(row["id"]), finished_only=True, limit=1) or db_scans(conn, int(row["id"]), limit=1)
    if not scans:
        raise OrgGraphError(f"no scan recorded for {domain}")
    data = build_export(conn, row, scans[0])
    if to_stdout:
        emit_json(data)
        return
    path = write_export(data, domain, output)
    console.print(Text.assemble(("Exported ", C_DIM), (str(path), "bold"),
                                (f"  ({len(data['entities'])} entities, {len(data['relationships'])} relationships, "
                                 f"{len(data['observations'])} observations)", C_DIM)))




@app.command()
@cli_command
def ui(
    host: Optional[str] = typer.Option(None, "--host", help="Bind address (default 127.0.0.1)."),
    port: Optional[int] = typer.Option(None, "--port", help="Port (default 8765)."),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Launch the local web interface."""
    config, conn = startup(no_banner, verbose, debug)
    conn.close()
    bind_host = host or config.ui_host
    bind_port = port or int(config.ui_port)
    try:
        import uvicorn
    except ImportError as exc:
        raise OrgGraphError("the web UI needs fastapi and uvicorn: pip install fastapi uvicorn") from exc
    web_app = build_web_app(DB_PATH)
    if bind_host not in ("127.0.0.1", "localhost", "::1"):
        console.print(Text(f"warning: binding to {bind_host} exposes the UI beyond this machine", style=C_WARN))
    console.print(Text.assemble(("Web UI: ", C_DIM), (f"http://{bind_host}:{bind_port}", f"bold {C_PRIMARY}"),
                                ("   (Ctrl+C to stop)", "dim")))
    uvicorn.run(web_app, host=bind_host, port=bind_port, log_level="info" if verbose or debug else "warning")



TEST_TARGET = "example.com"  


def _obs(collector: str, otype: str, value: str, source: str, source_url: str = "", **meta: Any) -> Observation:
    return Observation(collector=collector, type=otype, value=value, source=source, source_url=source_url, metadata=meta)


def _synthetic_scan(conn: sqlite3.Connection, scan_id: str, started_at: str, observations: list[Observation]) -> dict[str, Any]:
    target_row = db_get_or_create_target(conn, TEST_TARGET)
    scan = Scan(id=scan_id, target_id=int(target_row["id"]), started_at=started_at)
    db_create_scan(conn, scan)
    reports = {"dns": CollectorReport("dns", "DNS", "ok", f"{len(observations)} findings", len(observations))}
    return finalize_scan(conn, target_row, scan, observations, reports)


def _memory_db() -> sqlite3.Connection:
    conn = db_connect(":memory:")
    db_init(conn)
    return conn


def test_database_initialization(tmp: Path) -> str:
    conn = _memory_db()
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    expected = {"targets", "scans", "observations", "entities", "entity_observations",
                "relationships", "relationship_evidence", "events"}
    missing = expected - tables
    assert not missing, f"missing tables: {missing}"
    db_init(conn)  
    return f"{len(expected)} tables"


def test_domain_normalization(tmp: Path) -> str:
    cases = {
        "Example.COM": "example.com", "example.com.": "example.com", "*.example.com": "example.com",
        "  API.Example.com  ": "api.example.com", "*.dev.example.com": "dev.example.com",
        "bücher.example": "xn--bcher-kva.example", "not a host": None, "": None, "192.0.2.1": None,
        "-bad.example.com": None, "localhost": None, "a..b": None,
    }
    for raw, expected in cases.items():
        got = normalize_hostname(raw)
        assert got == expected, f"{raw!r}: expected {expected!r}, got {got!r}"
    assert classify_host("api.example.com", "example.com") == (SUBDOMAIN, True)
    assert classify_host("example.com", "example.com") == (DOMAIN, True)
    assert classify_host("notexample.com", "example.com") == (DOMAIN, False)
    assert _txt_to_text('"v=spf1 " "include:_spf.example.net ~all"') == "v=spf1 include:_spf.example.net ~all"
    return f"{len(cases)} cases"


def test_target_validation(tmp: Path) -> str:
    assert parse_target("Example.com") == ("example.com", None)
    domain, note = parse_target("https://example.com/page/test?x=1")
    assert domain == "example.com" and note and "extracted" in note
    for bad in ("192.0.2.1", "localhost", "http://", "not a domain"):
        try:
            parse_target(bad)
        except OrgGraphError:
            continue
        raise AssertionError(f"{bad!r} should have been rejected")
    return "url extraction + rejects"


def _three_source_observations() -> list[Observation]:
    return [
        _obs("certificate_transparency", "hostname", "api.example.com", "crt.sh", "https://crt.sh/?q=%25.example.com"),
        _obs("dns", "dns_a", "192.0.2.10", "system-resolver", "A api.example.com", host="api.example.com", record="A"),
        _obs("http", "http_response", "https://api.example.com", "api.example.com", "https://api.example.com/",
             host="api.example.com", status=200, final_status=200, title="API", url="https://api.example.com/",
             final_url="https://api.example.com/", server="nginx"),
    ]


def test_entity_deduplication(tmp: Path) -> str:
    observations = _three_source_observations()
    graph = correlate(TEST_TARGET, observations)
    matches = [d for d in graph.entities.values() if d.value == "api.example.com"]
    assert len(matches) == 1, f"expected one entity, got {len(matches)}"
    assert matches[0].type == SUBDOMAIN and len(matches[0].observation_ids) == 3
    conn = _memory_db()
    _synthetic_scan(conn, "dedup001", "2026-09-01T10:00:00+00:00", observations)
    rows = conn.execute("SELECT COUNT(*) AS n FROM entities WHERE value = 'api.example.com'").fetchone()
    assert rows["n"] == 1
    entity_id = stable_id("ent", TEST_TARGET, SUBDOMAIN, "api.example.com")
    collectors = {o["collector"] for o in db_entity_observations(conn, entity_id)}
    assert collectors == {"certificate_transparency", "dns", "http"}, collectors
    return "3 observations → 1 entity, 3 evidence"


def test_scoring(tmp: Path) -> str:
    observations = _three_source_observations()
    graph = correlate(TEST_TARGET, observations)
    score_graph(graph, observations)
    draft = graph.entities[(SUBDOMAIN, "api.example.com")]
    rules = [s["rule"] for s in draft.breakdown]
    assert draft.score == 90, f"expected 90, got {draft.score} ({rules})"
    assert rules == ["namespace", "dns", "certificate", "http"], rules
    ip = graph.entities[(IP_ADDRESS, "192.0.2.10")]
    assert ip.score == 55 and [s["rule"] for s in ip.breakdown] == ["linked", "dns"], ip.breakdown
    assert all(0 <= d.score <= SCORE_MAX for d in graph.entities.values())
    return "api.example.com = 90/100"


def test_diff_engine(tmp: Path) -> str:
    conn = _memory_db()
    first = [
        _obs("certificate_transparency", "hostname", "api.example.com", "crt.sh"),
        _obs("dns", "dns_a", "192.0.2.10", "system-resolver", "A api.example.com", host="api.example.com"),
        _obs("certificate_transparency", "hostname", "old-api.example.com", "crt.sh"),
        _obs("dns", "dns_a", "192.0.2.20", "system-resolver", "A old-api.example.com", host="old-api.example.com"),
    ]
    second = [
        _obs("certificate_transparency", "hostname", "api.example.com", "crt.sh"),
        _obs("dns", "dns_a", "192.0.2.42", "system-resolver", "A api.example.com", host="api.example.com"),
        _obs("certificate_transparency", "hostname", "api-v2.example.com", "crt.sh"),
        _obs("dns", "dns_a", "192.0.2.50", "system-resolver", "A api-v2.example.com", host="api-v2.example.com"),
    ]
    _synthetic_scan(conn, "diff0001", "2026-09-01T10:00:00+00:00", first)
    summary = _synthetic_scan(conn, "diff0002", "2026-09-03T10:00:00+00:00", second)
    target_row = db_get_target(conn, TEST_TARGET)
    assert target_row is not None
    result, reason = latest_diff(conn, int(target_row["id"]))
    assert result is not None, reason
    new_values = {e["value"] for e in result.new}
    gone_values = {e["value"] for e in result.not_observed}
    assert "api-v2.example.com" in new_values, new_values
    assert "old-api.example.com" in gone_values, gone_values
    assert "api.example.com" not in new_values and "api.example.com" not in gone_values
    assert len(result.changed) == 1 and result.changed[0].value == "api.example.com"
    change = result.changed[0].changes[0]
    assert change == {"relation": RESOLVES_TO, "label": "IP", "before": ["192.0.2.10"], "after": ["192.0.2.42"]}, change
    assert summary["changes"] == {"new": len(result.new), "changed": 1, "not_observed": len(result.not_observed)}
    json.loads(json_dumps(result.to_dict()))
    return "new / changed / not observed detected"


def test_events_and_timeline(tmp: Path) -> str:
    conn = _memory_db()
    _synthetic_scan(conn, "tl000001", "2026-09-01T10:00:00+00:00", [
        _obs("dns", "dns_a", "192.0.2.10", "system-resolver", "A example.com", host="example.com"),
        _obs("rdap", "rdap_domain", "example.com", "rdap.example", "https://rdap.example/domain/example.com",
             events={"registration": "1995-08-14T04:00:00Z", "expiration": "2027-08-13T04:00:00Z"}),
    ])
    _synthetic_scan(conn, "tl000002", "2026-09-03T10:00:00+00:00", [
        _obs("dns", "dns_a", "192.0.2.42", "system-resolver", "A example.com", host="example.com"),
    ])
    target_row = db_get_target(conn, TEST_TARGET)
    assert target_row is not None
    groups = timeline_groups(conn, int(target_row["id"]))
    dates = [g["date"] for g in groups]
    assert dates == ["1995-08-14", "2026-09-01", "2026-09-03", "2027-08-13"], dates
    types = {i["type"] for g in groups for i in g["items"]}
    assert {"first_seen", "changed", "rdap_registration", "rdap_expiration"} <= types, types
    return f"{sum(len(g['items']) for g in groups)} events over {len(groups)} dates"


def test_serialization(tmp: Path) -> str:
    conn = _memory_db()
    _synthetic_scan(conn, "ser00001", "2026-09-01T10:00:00+00:00", _three_source_observations())
    target_row = db_get_target(conn, TEST_TARGET)
    scan_row = db_scan(conn, "ser00001")
    assert target_row is not None and scan_row is not None
    data = json.loads(json_dumps(build_export(conn, target_row, scan_row)))
    assert set(data) >= {"target", "scan", "entities", "relationships", "observations"}
    assert len(data["observations"]) == 3 and data["scan"]["status"] == "completed"
    assert all("score_breakdown" in e for e in data["entities"])
    json.loads(json_dumps(target_summary(conn, target_row)))
    entity_id = stable_id("ent", TEST_TARGET, SUBDOMAIN, "api.example.com")
    detail = entity_detail(conn, entity_id)
    assert detail is not None and json.loads(json_dumps(detail))["entity"]["score"] == 90
    graph = json.loads(json_dumps(graph_payload(conn, int(target_row["id"]))))
    assert graph["nodes"] and graph["edges"]
    return "export / summary / entity / graph round-trip"


def test_collector_parsers(tmp: Path) -> str:
    ctx = ScanContext(target=TEST_TARGET, scan_id="parse001", config=Config(), http=None,
                      hostnames=set(), seeded=set())
    rows = [
        {"id": 1, "issuer_name": "C=US, O=Test CA", "common_name": "*.example.com",
         "name_value": "*.example.com\napi.example.com\nExample.COM.\nother.org\nadmin@example.com",
         "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "serial_number": "0abc"},
        {"id": 1, "name_value": "dup.example.com"},
        {"id": 2, "common_name": "dev.example.com", "name_value": "dev.example.com", "serial_number": ""},
    ]
    ct = CertificateTransparencyCollector()._parse(rows, "https://crt.sh/?q=%25.example.com", ctx)
    hostnames = sorted(o.value for o in ct if o.type == "hostname")
    assert hostnames == ["api.example.com", "dev.example.com", "example.com"], hostnames
    certs = {o.value: o for o in ct if o.type == "certificate"}
    assert set(certs) == {"serial:0abc", "crt.sh:2"}, set(certs)
    assert certs["serial:0abc"].metadata["names"] == ["api.example.com", "example.com"]
    assert ctx.hostnames == set(hostnames)
    rdap = RDAPCollector()._parse({
        "ldhName": "example.com", "status": ["client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "b.iana-servers.net."}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]],
                      "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]}],
        "secureDNS": {"delegationSigned": True},
    }, "https://rdap.example/domain/example.com", ctx)
    kinds = sorted((o.type, o.value) for o in rdap)
    assert kinds == [("organization", "Test Registrar"), ("rdap_domain", "example.com"),
                     ("rdap_nameserver", "a.iana-servers.net"), ("rdap_nameserver", "b.iana-servers.net")], kinds
    assert rdap[0].metadata["registrar_iana_id"] == "376" and rdap[0].metadata["dnssec"] is True
    body = '<html><head><title>\n  Hello &amp; <b>World</b> </title><link rel="shortcut icon" href="/static/fav.png"></head></html>'
    assert extract_title(body) == "Hello &amp; <b>World</b>".replace("&amp;", "&"), extract_title(body)
    assert extract_favicon(body, "https://www.example.com/index") == "https://www.example.com/static/fav.png"
    assert extract_favicon("<html></html>", "https://example.com/") == "https://example.com/favicon.ico"
    techs = technologies_from_headers(httpx.Headers({"server": "nginx/1.25.3 (Ubuntu)", "cf-ray": "abc", "x-powered-by": "PHP/8.3"}))
    assert [t["name"] for t in techs] == ["nginx", "PHP", "Cloudflare"], techs
    return "crt.sh / RDAP / HTTP parsers"


def test_banner_and_config(tmp: Path) -> str:
    text = render_banner()
    assert text.plain.strip("\n") == BANNER.strip("\n")
    assert gradient_color(0.0) == "#d8b4fe" and gradient_color(1.0) == "#4c1d95"
    assert len(confidence_bar(90).plain) == 20 + len(" 90/100")
    path = tmp / "config.json"
    config = Config.load(path)
    assert path.exists() and config.max_concurrency == 5
    path.write_text(json.dumps({"max_concurrency": 2, "unknown": 1}), encoding="utf-8")
    assert Config.load(path).max_concurrency == 2
    return "gradient, bar, config.json defaults"


SELFTESTS: list[tuple[str, Callable[[Path], str]]] = [
    ("database initialization", test_database_initialization),
    ("domain normalization", test_domain_normalization),
    ("target validation", test_target_validation),
    ("entity deduplication", test_entity_deduplication),
    ("scoring", test_scoring),
    ("diff engine", test_diff_engine),
    ("events & timeline", test_events_and_timeline),
    ("serialization", test_serialization),
    ("collector parsers (offline)", test_collector_parsers),
    ("banner & config", test_banner_and_config),
]


@app.command()
@cli_command
def selftest(
    json_mode: bool = opt_json(),
    no_banner: bool = opt_no_banner(),
    verbose: bool = opt_verbose(),
    debug: bool = opt_debug(),
) -> None:
    """Run internal tests (no network needed; uses an in-memory database)."""
    STATE["debug"] = debug
    setup_logging(verbose, debug)
    if not no_banner and not json_mode:
        print_banner(console)
    results = []
    with tempfile.TemporaryDirectory(prefix="orggraph-selftest-") as tmp:
        for name, func in SELFTESTS:
            started = time.monotonic()
            try:
                detail = func(Path(tmp))
                results.append({"name": name, "ok": True, "detail": detail, "duration": time.monotonic() - started})
            except Exception as exc:  # report, do not abort the suite
                detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
                results.append({"name": name, "ok": False, "detail": detail, "duration": time.monotonic() - started})
                if debug:
                    err_console.print(traceback.format_exc())
    failed = [r for r in results if not r["ok"]]
    if json_mode:
        emit_json({"passed": len(results) - len(failed), "failed": len(failed), "results": results})
    else:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column(width=2)
        table.add_column(min_width=30)
        table.add_column()
        for result in results:
            table.add_row(status_icon("ok" if result["ok"] else "error"), result["name"],
                          Text(result["detail"], style="" if result["ok"] else C_ERR))
        console.print(Text("Self-test", style=f"bold {C_PRIMARY}"))
        console.print(Text(RULE, style=C_TRACK))
        console.print(table)
        console.print()
        style = C_OK if not failed else C_ERR
        console.print(Text(f"{len(results) - len(failed)} passed, {len(failed)} failed", style=f"bold {style}"))
    if failed:
        raise typer.Exit(code=1)



def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
