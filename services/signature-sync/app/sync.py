from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from rule_catalog import load_rule_catalog


DEFAULT_SOURCE_URL = "https://s3.amazonaws.com/NSAppFwSignatures/SignaturesMapping.xml"
DEFAULT_INTERVAL_SECONDS = 3600
MAX_MAPPING_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SyncConfig:
    source_url: str = DEFAULT_SOURCE_URL
    target_release: str = "14.1"
    target_build: str = "0"
    data_dir: Path = Path("/var/lib/signature-sync")
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    request_timeout_seconds: int = 60
    run_on_start: bool = True
    verify_sha1: bool = True

    @classmethod
    def from_env(cls) -> "SyncConfig":
        return cls(
            source_url=os.getenv("SIGNATURE_SOURCE_URL", DEFAULT_SOURCE_URL).strip(),
            target_release=os.getenv("SIGNATURE_TARGET_RELEASE", "14.1").strip(),
            target_build=os.getenv("SIGNATURE_TARGET_BUILD", "0").strip(),
            data_dir=Path(os.getenv("SIGNATURE_SYNC_DATA_DIR", "/var/lib/signature-sync")),
            interval_seconds=max(60, int(os.getenv("SIGNATURE_SYNC_INTERVAL_SECONDS", str(DEFAULT_INTERVAL_SECONDS)))),
            request_timeout_seconds=max(5, int(os.getenv("SIGNATURE_SYNC_TIMEOUT_SECONDS", "60"))),
            run_on_start=os.getenv("SIGNATURE_SYNC_RUN_ON_START", "true").strip().lower() == "true",
            verify_sha1=os.getenv("SIGNATURE_SYNC_VERIFY_SHA1", "true").strip().lower() == "true",
        )

    @property
    def upstream_dir(self) -> Path:
        return self.data_dir / "upstream"

    @property
    def raw_dir(self) -> Path:
        return self.upstream_dir / "raw"

    @property
    def index_dir(self) -> Path:
        return self.upstream_dir / "index"

    @property
    def state_path(self) -> Path:
        return self.upstream_dir / "state.json"

    @property
    def history_path(self) -> Path:
        return self.upstream_dir / "sync-history.jsonl"


def _fetch(url: str, timeout: int) -> bytes:
    request = Request(url, headers={"User-Agent": "waf-intelligence-signature-sync/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def _bounded_fetch(url: str, timeout: int, limit: int) -> bytes:
    payload = _fetch(url, timeout)
    if len(payload) > limit:
        raise ValueError(f"download exceeds configured limit: {url}")
    return payload


def _local_name(tag: object) -> str:
    return str(tag).casefold().split("}")[-1]


def _text(element: ET.Element | None) -> str:
    return " ".join((element.text or "").split()) if element is not None else ""


def _same_origin(base_url: str, child_url: str) -> bool:
    base = urlparse(base_url)
    child = urlparse(child_url)
    return child.scheme in {"http", "https"} and child.netloc == base.netloc


def _source_url(mapping_url: str, relative_path: str) -> str:
    value = (relative_path or "").strip()
    if not value or value.startswith("/") or "\\" in value:
        raise ValueError("signature mapping contains an invalid relative path")
    resolved = urljoin(mapping_url, value)
    if not _same_origin(mapping_url, resolved):
        raise ValueError("signature mapping points outside the configured source origin")
    return resolved


def _extract_sha1(payload: bytes) -> str:
    match = re.search(r"\b[a-fA-F0-9]{40}\b", payload.decode("utf-8", errors="replace"))
    if not match:
        raise ValueError("signature source did not provide a valid SHA-1 value")
    return match.group(0).casefold()


def parse_mapping(payload: bytes, *, source_url: str, target_release: str, target_build: str) -> dict[str, str]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError("signature mapping is not valid XML") from exc
    candidates: list[ET.Element] = []
    for element in root.iter():
        if _local_name(element.tag) != "signature":
            continue
        if str(element.attrib.get("release", "")).strip() != target_release:
            continue
        if str(element.attrib.get("build", "")).strip() != target_build:
            continue
        candidates.append(element)
    if len(candidates) != 1:
        raise ValueError(f"expected exactly one mapping for release {target_release} build {target_build}, found {len(candidates)}")
    signature = candidates[0]
    files = {
        _local_name(child.tag): _text(child)
        for child in signature.iter()
        if _local_name(child.tag) in {"file", "sha1", "digest"}
    }
    file_path = files.get("file", "")
    sha1_path = files.get("sha1", "")
    if not file_path or not sha1_path:
        raise ValueError("signature mapping entry is missing file or sha1 path")
    return {
        "release": target_release,
        "build": target_build,
        "version": str(signature.attrib.get("version", "")).strip(),
        "schema_version": str(signature.attrib.get("schema_version", "")).strip(),
        "mapping_date": str(root.attrib.get("date", "")).strip(),
        "file_path": file_path,
        "file_url": _source_url(source_url, file_path),
        "sha1_path": sha1_path,
        "sha1_url": _source_url(source_url, sha1_path),
        "digest_path": files.get("digest", ""),
        "digest_url": _source_url(source_url, files["digest"]) if files.get("digest") else "",
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    _atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _append_history(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


def _index_payload(raw_path: Path, mapping: dict[str, str], source_sha1: str, mapping_sha256: str) -> tuple[dict[str, object], dict[str, object]]:
    catalog = load_rule_catalog(str(raw_path))
    if catalog.get("status") != "enumerated":
        raise ValueError(f"signature XML produced no rule metadata: {catalog.get('status')}")
    raw_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    index = {
        "schema_version": "1.1.0",
        "generated_at": utc_now(),
        "source": "citrix-netscaler-signature-mapping",
        "source_url": mapping["file_url"],
        "mapping_url": mapping["mapping_url"],
        "mapping_sha256": mapping_sha256,
        "release": mapping["release"],
        "build": mapping["build"],
        "version": mapping["version"],
        "signature_schema_version": mapping["schema_version"],
        "source_file": mapping["file_path"],
        "source_sha1": source_sha1,
        "source_sha256": raw_sha256,
        "raw_payload_retained": False,
        "catalogs": [{
            "file": Path(mapping["file_path"]).name,
            "size_bytes": raw_path.stat().st_size,
            "rule_count": catalog["rule_count"],
            "catalog_fingerprint": catalog["catalog_fingerprint"],
        }],
        "rule_count": catalog["rule_count"],
        "category_counts": catalog.get("category_counts", {}),
        "attack_class_counts": catalog.get("attack_class_counts", {}),
        "rules": catalog["rules"],
    }
    state = {
        "status": "updated",
        "last_result": "updated",
        "checked_at": utc_now(),
        "source_url": mapping["mapping_url"],
        "source_file_url": mapping["file_url"],
        "source_file": mapping["file_path"],
        "release": mapping["release"],
        "build": mapping["build"],
        "version": mapping["version"],
        "signature_schema_version": mapping["schema_version"],
        "source_sha1": source_sha1,
        "source_sha256": raw_sha256,
        "mapping_sha256": mapping_sha256,
        "rule_count": catalog["rule_count"],
        "catalog_fingerprint": catalog["catalog_fingerprint"],
    }
    return index, state


def sync_once(config: SyncConfig, fetcher: Callable[[str, int, int], bytes] = _bounded_fetch) -> dict[str, object]:
    mapping_payload = fetcher(config.source_url, config.request_timeout_seconds, MAX_MAPPING_BYTES)
    mapping_sha256 = hashlib.sha256(mapping_payload).hexdigest()
    mapping = parse_mapping(mapping_payload, source_url=config.source_url, target_release=config.target_release, target_build=config.target_build)
    mapping["mapping_url"] = config.source_url
    sha1_payload = fetcher(mapping["sha1_url"], config.request_timeout_seconds, 64 * 1024)
    source_sha1 = _extract_sha1(sha1_payload)
    previous = _read_json(config.state_path)
    raw_path = config.raw_dir / Path(mapping["file_path"]).name
    latest_path = config.index_dir / "latest.json"
    same_source = (
        previous.get("source_file") == mapping["file_path"]
        and previous.get("source_sha1") == source_sha1
        and previous.get("version") == mapping["version"]
        and raw_path.is_file()
        and latest_path.is_file()
    )
    if same_source:
        result = dict(previous)
        result.update({"status": "ok", "last_result": "not-modified", "checked_at": utc_now(), "mapping_sha256": mapping_sha256})
        _atomic_json(config.state_path, result)
        _append_history(config.history_path, result)
        return result

    signature_payload = fetcher(mapping["file_url"], config.request_timeout_seconds, MAX_SIGNATURE_BYTES)
    downloaded_sha1 = hashlib.sha1(signature_payload).hexdigest()
    if config.verify_sha1 and downloaded_sha1 != source_sha1:
        raise ValueError("downloaded signature XML failed the published SHA-1 check")
    _atomic_write(raw_path, signature_payload)
    if mapping.get("digest_url"):
        _atomic_write(config.raw_dir / f"{raw_path.name}.digest", fetcher(mapping["digest_url"], config.request_timeout_seconds, 64 * 1024))
    index, state = _index_payload(raw_path, mapping, source_sha1, mapping_sha256)
    versioned_index = config.index_dir / f"{raw_path.stem}.json"
    _atomic_json(versioned_index, index)
    _atomic_json(latest_path, index)
    _atomic_json(config.state_path, state)
    _append_history(config.history_path, state)
    return state


class SyncRunner:
    def __init__(self, config: SyncConfig):
        self.config = config
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = _read_json(config.state_path)

    @property
    def state(self) -> dict[str, object]:
        with self._lock:
            return dict(self._state)

    def run_once(self) -> dict[str, object]:
        with self._lock:
            try:
                self._state = sync_once(self.config)
            except Exception as exc:
                self._state = {
                    **self._state,
                    "status": "error",
                    "last_result": "error",
                    "checked_at": utc_now(),
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
                _atomic_json(self.config.state_path, self._state)
                _append_history(self.config.history_path, self._state)
            return dict(self._state)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="signature-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        if self.config.run_on_start:
            self.run_once()
        while not self._stop.wait(self.config.interval_seconds):
            self.run_once()
