"""
ActivityWatch
=============

This module implements a data donation platform for `ActivityWatch
<https://activitywatch.net/>`_ exports.  ActivityWatch tracks application
usage, AFK status, and screen-unlock events across Windows, macOS, and
Android devices.

Participants export their data from ActivityWatch as a single JSON file
and upload it directly (no zipping required).

The platform discovers all buckets inside the JSON and groups them by
*bucket type*:

* **afkstatus** — away-from-keyboard periods (Windows / macOS).
* **currentwindow** — active application / window title events.
* **os.lockscreen.unlocks** — screen unlock timestamps (Android).

Multiple devices may be present in a single export; events from matching
buckets are concatenated into a single table while preserving the
originating bucket id and hostname so each device remains
distinguishable.

Window titles are hashed with a per-donation random salt to protect
participant privacy while still enabling frequency analysis.

Configuration
-------------
The ``extraction`` function is driven by ``port_config.json``.  Generate one
with::

    pnpm generate-config activitywatch

Each extractor function carries its own table config in a ``Table config::``
JSON block inside its docstring.  The generator reads those blocks and
assembles the JSON file.

Platform info::

    {
        "name": "ActivityWatch",
        "filetypes": ["json"],
        "languages": ["en"],
        "description": "Handles ActivityWatch JSON exports from Windows, macOS, and Android devices. Participants upload their exported JSON file directly.",
        "time_last_tested": "24-09-2026"
    }
"""
import hashlib
import json
import logging
import re
import secrets
from collections import Counter
from typing import Any, Callable

import pandas as pd

import port.helpers.port_helpers as ph
from port.helpers.flow_builder import FlowBuilder
from port.helpers.validate import StatusCode, ValidateInput
from port.api.d3i_props import ExtractionResult
from port.api.file_utils import SeekableBinaryReader
from port.helpers.table_extractor import load_port_config, run_extraction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_buckets(archive: SeekableBinaryReader) -> list[dict[str, Any]]:
    """Parse the uploaded JSON file and return a flat list of bucket dicts.

    Each returned dict is one bucket object with an extra key injected:

    * ``_bucket_id`` – the key under which the bucket appeared in the
      ``"buckets"`` dict.
    """
    archive.seek(0)
    raw = archive.read()
    data = json.loads(raw)
    all_buckets: list[dict[str, Any]] = []
    buckets = data.get("buckets", {})
    if not isinstance(buckets, dict):
        return all_buckets
    for bucket_id, bucket in buckets.items():
        if not isinstance(bucket, dict):
            continue
        bucket["_bucket_id"] = bucket_id
        all_buckets.append(bucket)
    return all_buckets


def _buckets_by_type(buckets: list[dict[str, Any]], pattern: str) -> list[dict[str, Any]]:
    """Return buckets whose ``type`` field matches *pattern* (case-insensitive)."""
    return [b for b in buckets if re.search(pattern, b.get("type", ""), re.IGNORECASE)]


def _hash_value(value: str, salt: str) -> str:
    """Return a truncated SHA-256 hex digest of *salt* + *value*."""
    return hashlib.sha256(f"{salt}{value}".encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

def _validate_json(archive: SeekableBinaryReader) -> ValidateInput:
    """Accept a valid JSON file that contains at least one bucket with events."""
    status_codes = [
        StatusCode(id=0, description="Valid ActivityWatch JSON with extractable data"),
        StatusCode(id=1, description="Not valid JSON or no extractable data found"),
    ]
    v = ValidateInput(status_codes, [])
    try:
        archive.seek(0)
        data = json.loads(archive.read())
        if not isinstance(data, dict) or "buckets" not in data:
            v.set_current_status_code_by_id(1)
            return v
        buckets = data["buckets"]
        if not isinstance(buckets, dict):
            v.set_current_status_code_by_id(1)
            return v
        has_events = any(
            isinstance(b, dict) and len(b.get("events", []))> 0
            for b in buckets.values()
        )
        v.set_current_status_code_by_id(0 if has_events else 1)
    except Exception:
        v.set_current_status_code_by_id(1)
    return v


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------
# Each extractor receives the parsed bucket list as its first argument
# (the ``reader`` slot in run_extraction) and an ``errors`` counter.
# ---------------------------------------------------------------------------

_KNOWN_BUCKET_PATTERNS = [r"afk", r"currentwindow", r"unlock"]


def bucket_info_to_df(buckets: list[dict[str, Any]], errors: Counter) -> pd.DataFrame:
    """Extract metadata for buckets that this platform can process.

    Only buckets whose type matches one of the known patterns
    (``afk``, ``currentwindow``, ``unlock``) are included.

    Parameters
    ----------
    buckets:
        Parsed list of bucket dicts from the uploaded JSON.
    errors:
        Mutable counter that accumulates error type counts.

    Returns
    -------
    pd.DataFrame
        Columns: ``Bucket ID``, ``Type``, ``Client``, ``Hostname``,
        ``Created``.

    Table documentation::

        {
          "summary": "Each row describes one ActivityWatch bucket found in the donated file, including its type, the client that created it, the hostname of the device, and the creation timestamp.",
          "source_file": "the uploaded JSON file",
          "columns": {
            "Bucket ID": "Unique identifier of the bucket (e.g. aw-watcher-window_MSI).",
            "Type": "Bucket type such as afkstatus, currentwindow, or os.lockscreen.unlocks.",
            "Client": "Name of the ActivityWatch watcher client that produced the bucket.",
            "Hostname": "Hostname of the device the bucket was recorded on.",
            "Created": "ISO 8601 timestamp of when the bucket was created."
          }
        }

    Table config::

        {
          "id": "aw_bucket_info",
          "title": {
            "en": "Bucket information",
            "nl": "Bucket-informatie"
          },
          "description": {
            "en": "Overview of all ActivityWatch buckets found in your data, showing what type of data was collected and on which device.",
            "nl": "Overzicht van alle ActivityWatch-buckets in uw gegevens, met het type verzamelde data en het apparaat."
          },
          "headers": {
            "Bucket ID":   {"en": "Bucket ID",   "nl": "Bucket-ID"},
            "Type":        {"en": "Type",         "nl": "Type"},
            "Client":      {"en": "Client",       "nl": "Client"},
            "Hostname":    {"en": "Hostname",     "nl": "Hostnaam"},
            "Created":     {"en": "Created",      "nl": "Aangemaakt"}
          }
        }
    """
    out = pd.DataFrame()
    try:
        if not buckets:
            return out
        relevant_buckets: list[dict[str, Any]] = []
        for pattern in _KNOWN_BUCKET_PATTERNS:
            relevant_buckets.extend(_buckets_by_type(buckets, pattern))
        rows = []
        for b in relevant_buckets:
            rows.append({
                "Bucket ID": b.get("_bucket_id", ""),
                "Type": b.get("type", ""),
                "Client": b.get("client", ""),
                "Hostname": b.get("hostname", ""),
                "Created": b.get("created", ""),
            })
        out = pd.DataFrame(rows)
    except Exception as e:
        logger.error("bucket_info_to_df error: %s", e)
        errors[type(e).__name__] += 1
    return out


def afk_events_to_df(buckets: list[dict[str, Any]], errors: Counter) -> pd.DataFrame:
    """Extract AFK (away-from-keyboard) events from all ``afkstatus`` buckets.

    Events from multiple buckets (i.e. multiple devices) are
    concatenated.  The ``Bucket ID`` and ``Hostname`` columns allow
    downstream analysis to distinguish devices.

    Parameters
    ----------
    buckets:
        Parsed list of bucket dicts from the uploaded JSON.
    errors:
        Mutable counter that accumulates error type counts.

    Returns
    -------
    pd.DataFrame
        Columns: ``Timestamp``, ``Duration (s)``, ``Status``,
        ``Bucket ID``, ``Hostname``.

    Table documentation::

        {
          "summary": "Each row represents one AFK (away-from-keyboard) event, recording when the participant was idle or active at their device.",
          "source_file": "the uploaded JSON file — buckets with type containing 'afk'",
          "columns": {
            "Timestamp": "ISO 8601 timestamp of the start of the AFK event.",
            "Duration (s)": "Duration of the event in seconds.",
            "Status": "AFK status: 'afk' (idle) or 'not-afk' (active).",
            "Bucket ID": "Identifier of the bucket this event came from.",
            "Hostname": "Hostname of the device."
          }
        }

    Table config::

        {
          "id": "aw_afk_events",
          "title": {
            "en": "AFK events",
            "nl": "AFK-gebeurtenissen"
          },
          "description": {
            "en": "Periods when you were away from (or returned to) your keyboard, as recorded by ActivityWatch.",
            "nl": "Perioden waarin u weg was van (of terugkeerde naar) uw toetsenbord, zoals geregistreerd door ActivityWatch."
          },
          "headers": {
            "Timestamp":    {"en": "Timestamp",       "nl": "Tijdstip"},
            "Duration (s)": {"en": "Duration (s)",    "nl": "Duur (s)"},
            "Status":       {"en": "Status",          "nl": "Status"},
            "Bucket ID":    {"en": "Bucket ID",       "nl": "Bucket-ID"},
            "Hostname":     {"en": "Hostname",        "nl": "Hostnaam"}
          },
          "visualizations": []
        }
    """
    out = pd.DataFrame()
    try:
        afk_buckets = _buckets_by_type(buckets, r"afk")
        if not afk_buckets:
            return out
        rows = []
        for b in afk_buckets:
            bucket_id = b.get("_bucket_id", "")
            hostname = b.get("hostname", "")
            for event in b.get("events", []):
                data = event.get("data", {})
                rows.append({
                    "Timestamp": event.get("timestamp", ""),
                    "Duration (s)": event.get("duration", 0),
                    "Status": data.get("status", ""),
                    "Bucket ID": bucket_id,
                    "Hostname": hostname,
                })
        out = pd.DataFrame(rows)
        if not out.empty:
            out = out.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    except Exception as e:
        logger.error("afk_events_to_df error: %s", e)
        errors[type(e).__name__] += 1
    return out


def window_events_to_df(buckets: list[dict[str, Any]], errors: Counter) -> pd.DataFrame:
    """Extract window/app-usage events from all ``currentwindow`` buckets.

    Events from multiple buckets (i.e. multiple devices) are
    concatenated.  Window titles are replaced by a salted SHA-256 hash
    (truncated to 16 hex characters) to protect participant privacy.

    The ``data`` field in ActivityWatch events may contain varying keys
    depending on the platform (e.g. ``app``, ``title``, ``url`` on
    macOS; ``app``, ``title`` on Windows; ``app``, ``package``,
    ``classname`` on Android).  All data keys are expanded into columns;
    missing keys become empty strings.

    Parameters
    ----------
    buckets:
        Parsed list of bucket dicts from the uploaded JSON.
    errors:
        Mutable counter that accumulates error type counts.

    Returns
    -------
    pd.DataFrame
        Columns: ``Timestamp``, ``Duration (s)``, ``App``,
        ``Title Hash``, ``Bucket ID``, ``Hostname``,
        and any additional data-field columns.

    Table documentation::

        {
          "summary": "Each row represents one window-focus or app-usage event. Window titles are hashed for privacy. Additional data fields (url, package, classname) are included when present.",
          "source_file": "the uploaded JSON file — buckets with type containing 'currentwindow'",
          "columns": {
            "Timestamp": "ISO 8601 timestamp of the start of the event.",
            "Duration (s)": "Duration of the event in seconds.",
            "App": "Name of the active application.",
            "Title Hash": "Salted SHA-256 hash (16 hex chars) of the window title.",
            "Bucket ID": "Identifier of the bucket this event came from.",
            "Hostname": "Hostname of the device."
          }
        }

    Table config::

        {
          "id": "aw_window_events",
          "title": {
            "en": "Window / app usage events",
            "nl": "Venster- / app-gebruiksgebeurtenissen"
          },
          "description": {
            "en": "Active application and window events as recorded by ActivityWatch. Window titles are hashed for privacy.",
            "nl": "Actieve applicatie- en venstergebeurtenissen zoals geregistreerd door ActivityWatch. Venstertitels zijn gehasht voor privacy."
          },
          "headers": {
            "Timestamp":    {"en": "Timestamp",    "nl": "Tijdstip"},
            "Duration (s)": {"en": "Duration (s)", "nl": "Duur (s)"},
            "App":          {"en": "Application",  "nl": "Applicatie"},
            "Title Hash":   {"en": "Title hash",   "nl": "Titelhash"},
            "Bucket ID":    {"en": "Bucket ID",    "nl": "Bucket-ID"},
            "Hostname":     {"en": "Hostname",     "nl": "Hostnaam"}
          },
          "visualizations": [
            {
              "title": {"en": "Most used applications", "nl": "Meest gebruikte applicaties"},
              "type": "wordcloud",
              "textColumn": "App",
              "tokenize": false
            }
          ]
        }
    """
    out = pd.DataFrame()
    try:
        window_buckets = _buckets_by_type(buckets, r"currentwindow")
        if not window_buckets:
            return out

        salt = secrets.token_hex(16)
        rows = []
        for b in window_buckets:
            bucket_id = b.get("_bucket_id", "")
            hostname = b.get("hostname", "")
            for event in b.get("events", []):
                data = event.get("data", {})
                if not isinstance(data, dict):
                    data = {}
                title = data.get("title", "")
                row: dict[str, Any] = {
                    "Timestamp": event.get("timestamp", ""),
                    "Duration (s)": event.get("duration", 0),
                    "App": data.get("app", ""),
                    "Title Hash": _hash_value(title, salt) if title else "",
                    "Bucket ID": bucket_id,
                    "Hostname": hostname,
                }
                # Expand any additional data keys beyond app/title
                for key, value in data.items():
                    if key in ("app", "title"):
                        continue
                    col_name = key.replace("_", " ").title()
                    row[col_name] = value
                rows.append(row)

        out = pd.DataFrame(rows)
        if not out.empty:
            out = out.fillna("")
            out = out.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    except Exception as e:
        logger.error("window_events_to_df error: %s", e)
        errors[type(e).__name__] += 1
    return out


def unlock_events_to_df(buckets: list[dict[str, Any]], errors: Counter) -> pd.DataFrame:
    """Extract screen-unlock events from all ``os.lockscreen.unlocks`` buckets.

    These events are typically produced by the Android ActivityWatch
    client.  Each event records the timestamp of a screen unlock; the
    ``data`` payload is usually empty.

    Parameters
    ----------
    buckets:
        Parsed list of bucket dicts from the uploaded JSON.
    errors:
        Mutable counter that accumulates error type counts.

    Returns
    -------
    pd.DataFrame
        Columns: ``Timestamp``, ``Bucket ID``, ``Hostname``.

    Table documentation::

        {
          "summary": "Each row represents one screen-unlock event, typically from an Android device.",
          "source_file": "the uploaded JSON file — buckets with type containing 'unlock'",
          "columns": {
            "Timestamp": "ISO 8601 timestamp of the unlock event.",
            "Bucket ID": "Identifier of the bucket this event came from.",
            "Hostname": "Hostname of the device."
          }
        }

    Table config::

        {
          "id": "aw_unlock_events",
          "title": {
            "en": "Screen unlock events",
            "nl": "Scherm-ontgrendelingsgebeurtenissen"
          },
          "description": {
            "en": "Timestamps of screen unlocks, typically from Android devices running ActivityWatch.",
            "nl": "Tijdstippen van schermontgrendelingen, meestal van Android-apparaten met ActivityWatch."
          },
          "headers": {
            "Timestamp": {"en": "Timestamp", "nl": "Tijdstip"},
            "Bucket ID": {"en": "Bucket ID", "nl": "Bucket-ID"},
            "Hostname":  {"en": "Hostname",  "nl": "Hostnaam"}
          }
        }
    """
    out = pd.DataFrame()
    try:
        unlock_buckets = _buckets_by_type(buckets, r"unlock")
        if not unlock_buckets:
            return out
        rows = []
        for b in unlock_buckets:
            bucket_id = b.get("_bucket_id", "")
            hostname = b.get("hostname", "")
            for event in b.get("events", []):
                rows.append({
                    "Timestamp": event.get("timestamp", ""),
                    "Bucket ID": bucket_id,
                    "Hostname": hostname,
                })
        out = pd.DataFrame(rows)
        if not out.empty:
            out = out.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    except Exception as e:
        logger.error("unlock_events_to_df error: %s", e)
        errors[type(e).__name__] += 1
    return out


# ---------------------------------------------------------------------------
# Extractor registry & platform wiring
# ---------------------------------------------------------------------------

EXTRACTOR_REGISTRY: dict[str, Callable[..., pd.DataFrame]] = {
    "bucket_info_to_df": bucket_info_to_df,
    "afk_events_to_df": afk_events_to_df,
    "window_events_to_df": window_events_to_df,
    "unlock_events_to_df": unlock_events_to_df,
}


def extraction(archive: SeekableBinaryReader, validation: ValidateInput) -> ExtractionResult:
    """Extract ActivityWatch data from the donated JSON file.

    Parses the JSON, extracts the bucket list, and passes it directly
    to each extractor via ``run_extraction`` (the bucket list occupies
    the ``reader`` slot — no ``ZipArchiveReader`` is involved).

    Parameters
    ----------
    archive:
        Seekable binary reader over the JSON upload — the adapter itself,
        never a path (ADR-0026).
    validation:
        Validation result (used for status only; no archive members).
    """
    config = load_port_config(EXTRACTOR_REGISTRY, "activitywatch")
    errors: Counter = Counter()
    buckets = _parse_buckets(archive)
    return run_extraction(buckets, errors, config)


class ActivityWatchFlow(FlowBuilder):
    """Flow implementation for the ActivityWatch data donation study."""

    def __init__(self, session_id: str):
        super().__init__(session_id, "ActivityWatch")

    def generate_file_prompt(self):
        return ph.generate_file_prompt("application/json")

    def validate_file(self, file: SeekableBinaryReader) -> ValidateInput:
        return _validate_json(file)

    def extract_data(self, file_value: SeekableBinaryReader, validation: ValidateInput) -> ExtractionResult:
        return extraction(file_value, validation)


def process(session_id: str):
    flow = ActivityWatchFlow(session_id)
    return flow.start_flow()
