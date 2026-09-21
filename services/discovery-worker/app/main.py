from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field
from psycopg.types.json import Jsonb
from app.technology_detection import DETECTOR_VERSION, detect_technology_signals
from app.signature_technology import build_signature_technology_context

app = FastAPI(title="WAF Discovery Worker", version="0.4.0")
DATABASE_URL = os.getenv("DATABASE_URL", "")
running_tasks: dict[str, asyncio.Task[Any]] = {}
MAX_ASSETS_PER_RUN = 50
MAX_ASSET_BYTES = 2_000_000
ASSET_EXTENSIONS = {".js", ".mjs", ".css"}
ASSET_CONTENT_TYPES = {"application/javascript", "application/x-javascript", "text/javascript", "text/css"}


class DiscoveryScope(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    seed_url: str = Field(min_length=8, max_length=2048)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    rate_limit_per_second: float = Field(default=1.0, gt=0, le=10)
    max_pages: int = Field(default=25, gt=0, le=200)


class DiscoveryJob(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    created_at: str | None = None
    scope: DiscoveryScope


class SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.assets: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.controls: list[dict[str, Any]] = []
        self.search_surfaces: list[dict[str, Any]] = []
        self.metas: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self._in_title = False
        self.inline_script_parts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag in {"script", "link", "img", "source"}:
            value = values.get("src") or values.get("href")
            if value:
                self.assets.append(value)
        elif tag == "form":
            self.forms.append({
                "action": values.get("action", ""),
                "method": values.get("method", "get").upper(),
                "enctype": values.get("enctype", ""),
            })
        elif tag in {"input", "button", "select", "textarea"}:
            control = {
                "tag": tag,
                "type": values.get("type", "")[:50],
                "name": values.get("name", "")[:100],
                "id": values.get("id", "")[:100],
                "required": "required" in values,
                "autocomplete": values.get("autocomplete", "")[:100],
                "aria_label": values.get("aria-label", "")[:150],
                "placeholder": values.get("placeholder", "")[:150],
                "pattern": values.get("pattern", "")[:300],
                "inputmode": values.get("inputmode", "")[:50],
                "minlength": values.get("minlength", "")[:20],
                "maxlength": values.get("maxlength", "")[:20],
                "accept": values.get("accept", "")[:200],
            }
            self.controls.append(control)
            search_text = " ".join(control[key] for key in ("type", "name", "id", "aria_label")).lower()
            if tag == "input" and (control["type"].lower() == "search" or "search" in search_text):
                self.search_surfaces.append({"tag": tag, "type": control["type"], "name": control["name"], "id": control["id"], "aria_label": control["aria_label"]})
        elif tag.endswith("search-bar") or "search-bar" in tag:
            self.search_surfaces.append({"tag": tag, "type": "search-component", "name": values.get("name", "")[:100], "id": values.get("id", "")[:100], "aria_label": values.get("aria-label", "")[:150]})
        elif tag == "script" and not values.get("src"):
            self._in_script = True
        elif tag == "meta":
            name = values.get("name") or values.get("property")
            if name and values.get("content"):
                self.metas.append({"name": name.lower(), "content": values["content"][:500]})
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data.strip())
        elif self._in_script and sum(len(part) for part in self.inline_script_parts) < 1_000_000:
            self.inline_script_parts.append(data[:100_000])


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def confidence_label(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


def allowed_path(path: str, prefixes: list[str]) -> bool:
    normalized = path or "/"
    for prefix in prefixes or ["/"]:
        prefix = "/" + prefix.lstrip("/")
        if prefix == "/" or normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def in_scope(candidate: str, seed: str, prefixes: list[str]) -> bool:
    parsed = urlparse(candidate)
    seed_parsed = urlparse(seed)
    logical_path = parsed.fragment if parsed.fragment.startswith("/") else parsed.path
    return bool(
        parsed.scheme in {"http", "https"}
        and parsed.hostname
        and seed_parsed.hostname
        and parsed.hostname.lower() == seed_parsed.hostname.lower()
        and allowed_path(logical_path, prefixes)
    )


def normalize_url(candidate: str, current: str, seed: str, prefixes: list[str]) -> str | None:
    if not candidate or (candidate.startswith("#") and not candidate.startswith("#/")) or candidate.startswith(("mailto:", "javascript:", "data:")):
        return None
    joined = urljoin(current, candidate)
    parsed = urlparse(joined)
    absolute = parsed.geturl() if parsed.fragment.startswith("/") else parsed._replace(fragment="").geturl()
    return absolute if in_scope(absolute, seed, prefixes) else None


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.query:
        return value
    redacted_query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, redacted_query, ""))


def safe_headers(response: httpx.Response) -> dict[str, str]:
    names = {"server", "x-powered-by", "x-generator", "x-aspnet-version", "x-aspnetmvc-version", "x-drupal-cache", "x-runtime", "x-request-id", "content-type", "content-length", "cache-control", "via", "x-cache", "age", "cf-ray", "strict-transport-security", "content-security-policy", "content-security-policy-report-only", "permissions-policy", "referrer-policy", "x-frame-options", "x-content-type-options", "location", "allow", "www-authenticate", "vary"}
    return {key: value[:500] for key, value in response.headers.items() if key.lower() in names}


def cookie_names(response: httpx.Response) -> list[str]:
    names: list[str] = []
    for value in response.headers.get_list("set-cookie"):
        name = value.split("=", 1)[0].strip()
        if name and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            names.append(name)
    return sorted(set(names))


def cookie_observations(response: httpx.Response) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for value in response.headers.get_list("set-cookie"):
        parts = [part.strip() for part in value.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        if not name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            continue
        attributes = {part.split("=", 1)[0].lower(): True for part in parts[1:] if part}
        observations.append({
            "name": name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": next((part.split("=", 1)[1] for part in parts[1:] if part.lower().startswith("samesite=")), None),
            "path_present": "path" in attributes,
            "domain_present": "domain" in attributes,
        })
    return observations


def asset_type(url: str) -> str | None:
    suffix = os.path.splitext(urlparse(url).path.lower())[1]
    return "javascript" if suffix in {".js", ".mjs"} else "css" if suffix == ".css" else None


def asset_fingerprint(url: str, content_type: str, content: bytes) -> list[dict[str, Any]]:
    return detect_technology_signals(
        url=url,
        headers={"content-type": content_type},
        body=content.decode("utf-8", errors="ignore")[:2_000_000],
        assets=[url],
    )


def static_route_candidates(asset_url: str, content: bytes, seed: str, prefixes: list[str]) -> list[str]:
    text = content.decode("utf-8", errors="ignore")[:2_000_000]
    patterns = (
        r"\b(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*[`\'\"]([^`\'\"]+)",
        r"\b(?:url|uri|endpoint|apiUrl|baseUrl)\s*[:=]\s*[`\'\"]([^`\'\"]+)",
    )
    candidates: set[str] = set()
    for pattern in patterns:
        for value in re.findall(pattern, text, flags=re.IGNORECASE):
            value = value.strip()
            if not value or value.startswith(("#", "data:", "javascript:")) or len(value) > 200:
                continue
            normalized = normalize_url(value, asset_url, seed, prefixes)
            lowered = value.lower()
            if normalized and ("/api/" in lowered or "/graphql" in lowered or "/rest/" in lowered or "/v1/" in lowered or "/auth" in lowered or "/login" in lowered):
                candidates.add(normalized)
    return sorted(candidates)


def static_auth_endpoint_candidates(asset_url: str, content: bytes, seed: str, prefixes: list[str]) -> list[dict[str, str]]:
    """Find likely auth/API URL literals without executing or requesting them.

    This is intentionally conservative: only URL-like string literals containing
    an authentication/API marker are retained, and normalization enforces the
    existing same-host/scope boundary. Query values are redacted before storage.
    """
    text = content.decode("utf-8", errors="ignore")[:2_000_000]
    literal_pattern = r"[`'\"]((?:https?://|/|\./|\.\./)[^`'\"]{1,240})[`'\"]"
    markers = {
        "api": ("/api", "/rest", "/graphql", "/v1", "/v2"),
        "authentication": ("/auth", "/login", "/signin", "/sign-in", "/oauth", "/token", "/logout", "/register", "/2fa", "/forgot-password", "/change-password"),
    }
    candidates: dict[str, dict[str, str]] = {}
    for match in re.finditer(literal_pattern, text, flags=re.IGNORECASE):
        value = match.group(1).strip()
        if any(token in value for token in ("{", "}", "${", "\\n", "\\r")):
            continue
        lowered = value.casefold()
        endpoint_class = next((name for name, tokens in markers.items() if any(token in lowered for token in tokens)), None)
        if not endpoint_class:
            continue
        normalized = normalize_url(value, asset_url, seed, prefixes)
        if not normalized:
            continue
        redacted = redact_url(normalized)
        candidates[redacted] = {"url": redacted, "endpoint_class": endpoint_class}
    return sorted(candidates.values(), key=lambda item: (item["endpoint_class"], item["url"]))


def static_page_candidates(source_url: str, content: bytes | str, seed: str, prefixes: list[str]) -> list[str]:
    text = content if isinstance(content, str) else content.decode("utf-8", errors="ignore")
    text = text[:2_000_000]
    patterns = (
        r"\brouterLink\s*[:=]\s*[`\'\"]([^`\'\"]+)",
        r"[`\'\"]routerLink[`\'\"]\s*,\s*[`\'\"]([^`\'\"]+)",
        r"\bnavigate(?:ByUrl)?\s*\(\s*[`\'\"]([^`\'\"]+)",
        r"\b(?:route|path)\s*[:=]\s*[`\'\"]([^`\'\"]+)",
        r"[`\'\"]path[`\'\"]\s*,\s*[`\'\"]([^`\'\"]+)",
        r"\bhref\s*[:=]\s*[`\'\"]([^`\'\"]+)",
        r"<a\b[^>]*\bhref\s*=\s*[`\'\"]([^`\'\"]+)",
        r"\b(?:window\.)?location(?:\.href)?\s*=\s*[`\'\"]([^`\'\"]+)",
        r"\b(?:location\.(?:assign|replace)|window\.open)\s*\(\s*[`\'\"]([^`\'\"]+)",
    )
    candidates: set[str] = set()
    parsed_source = urlparse(source_url)
    root = f"{parsed_source.scheme}://{parsed_source.netloc}/"
    hash_routing = bool(re.search(r"useHash\s*:\s*!?(?:0|1)|HashLocationStrategy|#/", text, flags=re.IGNORECASE))
    for pattern in patterns:
        for value in re.findall(pattern, text, flags=re.IGNORECASE):
            value = value.strip()
            if not value or (value.startswith("#") and not value.startswith("#/")) or value.startswith(("mailto:", "javascript:", "data:")) or len(value) > 200:
                continue
            if not (value.startswith(("#", "/", "./", "../", "http://", "https://")) or re.match(r"^[A-Za-z0-9]", value)):
                continue
            if any(token in value for token in ("(", ")", "{", "}", "[", "]", "*", "||", "&&", "=>")):
                continue
            if hash_routing and not value.startswith(("http://", "https://")):
                logical_route = value[1:] if value.startswith("#/") else re.sub(r"^(?:\.\/)+", "", value.lstrip("/"))
                absolute = f"{root}#/{logical_route}"
            else:
                absolute = value if value.startswith(("http://", "https://", "/", "#/")) else urljoin(root, value.lstrip("/"))
            normalized = normalize_url(absolute, source_url, seed, prefixes)
            suffix = urlparse(absolute).path.lower()
            if normalized and suffix.rsplit("/", 1)[-1].count(".") == 0:
                candidates.add(normalized)
    return sorted(candidates)


def static_search_markers(content: bytes | str) -> list[str]:
    text = content if isinstance(content, str) else content.decode("utf-8", errors="ignore")
    text = text[:2_000_000]
    markers = []
    for pattern, label in (
        (r"searchQuery", "searchQuery identifier"),
        (r"search-bar", "search-bar component"),
        (r"aria-label.{0,80}search", "search aria-label"),
        (r"\btype[`'\"]?\s*[,=:]\s*[`'\"]search", "search input type"),
    ):
        if re.search(pattern, text, flags=re.IGNORECASE):
            markers.append(label)
    return markers


async def fetch_asset(client: httpx.AsyncClient, url: str, user_agent: str) -> tuple[httpx.Response, bytes, bool, float]:
    started = time.perf_counter()
    async with client.stream("GET", url, headers={"User-Agent": user_agent}) as response:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        async for chunk in response.aiter_bytes():
            remaining = MAX_ASSET_BYTES - total
            if remaining <= 0:
                truncated = True
                break
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
                break
        content = b"".join(chunks)
        await response.aclose()
    return response, content, truncated, round((time.perf_counter() - started) * 1000, 2)


def fingerprint(response: httpx.Response, parser: SurfaceParser | None) -> list[dict[str, Any]]:
    return detect_technology_signals(
        url=str(response.url),
        headers=dict(response.headers.items()),
        cookies=cookie_names(response),
        body=response.text[:2_000_000] if parser is not None else "",
        assets=parser.assets if parser else [],
        meta=parser.metas if parser else [],
        title=" ".join(parser.title_parts) if parser else "",
        forms=parser.forms if parser else [],
    )

    signals: list[dict[str, Any]] = []
    headers = {key.lower(): value.lower() for key, value in response.headers.items()}
    content_type = headers.get("content-type", "")
    body_sample = response.text[:500_000].lower() if parser is not None else ""
    assets = [item.lower() for item in (parser.assets if parser else [])]
    meta = {item["name"]: item["content"] for item in (parser.metas if parser else [])}
    cookies = [item.lower() for item in cookie_names(response)]

    def add(technology: str, signal: str, source: str, score: float, value: str = "") -> None:
        signals.append({"technology": technology, "signal": signal, "source": source, "score": score, "value": value[:500]})

    if headers.get("server"):
        add("Web server", "Server response header", "response.headers.server", 0.65, response.headers["server"])
    if headers.get("x-powered-by"):
        add("Application runtime", "X-Powered-By response header", "response.headers.x-powered-by", 0.72, response.headers["x-powered-by"])
    if "wp-content/" in body_sample or any("wp-content/" in item for item in assets):
        add("WordPress", "WordPress asset path", "html_or_asset_path", 0.93)
    if "drupalsettings" in body_sample or any("drupal" in item for item in assets):
        add("Drupal", "Drupal client-side marker", "html_or_asset_path", 0.90)
    if "__next_data__" in body_sample or any("/_next/" in item for item in assets):
        add("Next.js", "Next.js application marker", "html_or_asset_path", 0.94)
    if any("/_nuxt/" in item for item in assets):
        add("Nuxt", "Nuxt asset path", "asset_path", 0.94)
    if any("jquery" in item for item in assets):
        add("jQuery", "jQuery asset reference", "asset_path", 0.88)
    if any("react" in item for item in assets) or "data-reactroot" in body_sample:
        add("React", "React asset or DOM marker", "html_or_asset_path", 0.82)
    if any("vue" in item for item in assets):
        add("Vue.js", "Vue asset reference", "asset_path", 0.82)
    if any("angular" in item for item in assets) or "ng-version" in body_sample:
        add("Angular", "Angular asset or DOM marker", "html_or_asset_path", 0.86)
    if meta.get("generator"):
        add("Generated platform", "HTML generator metadata", "html.meta.generator", 0.78, meta["generator"])
    if "application/json" in content_type:
        add("REST or JSON API", "JSON response content type", "response.headers.content-type", 0.78)
    if "graphql" in content_type or "graphql" in body_sample:
        add("GraphQL", "GraphQL content or marker", "content_type_or_body_marker", 0.84)
    if "xml" in content_type or "soap" in body_sample:
        add("XML or SOAP", "XML/SOAP content or marker", "content_type_or_body_marker", 0.78)
    if "phpsessid" in cookies or "laravel_session" in cookies:
        add("PHP runtime", "PHP session cookie", "response.headers.set-cookie.name", 0.90)
    if "jsessionid" in cookies:
        add("Java runtime", "Java session cookie", "response.headers.set-cookie.name", 0.88)
    if "asp.net_sessionid" in cookies or ".aspxauth" in cookies or ".aspnetcore" in " ".join(cookies):
        add("ASP.NET runtime", "ASP.NET session cookie", "response.headers.set-cookie.name", 0.90)
    if "laravel_session" in cookies:
        add("Laravel", "Laravel session cookie", "response.headers.set-cookie.name", 0.90)
    if headers.get("cf-ray") or "cloudflare" in headers.get("server", ""):
        add("Cloudflare", "Cloudflare delivery header", "response.headers", 0.92)
    if headers.get("via") or headers.get("x-cache"):
        add("Reverse proxy or cache", "Proxy/cache response header", "response.headers", 0.62)
    if parser and parser.forms:
        add("HTML forms", "HTML form controls observed", "html.form", 0.95, str(len(parser.forms)))
        if any(item.get("method") == "POST" for item in parser.forms):
            add("State-changing form surface", "POST form observed but not submitted", "html.form.method", 0.88)
        if any("multipart/form-data" in item.get("enctype", "").lower() for item in parser.forms):
            add("File upload surface", "Multipart form observed but not submitted", "html.form.enctype", 0.90)
    if parser and re.search(r"type\s*=\s*[\"']password[\"']", body_sample):
        add("Authentication boundary", "Password input marker observed", "html.body_marker", 0.72)
    return signals


def evidence_row(run_id: str, evidence_type: str, source_url: str, method: str, status: int | None, signal: str, metadata: dict[str, Any], technology: str | None = None, score: float | None = None) -> dict[str, Any]:
    return {"run_id": run_id, "evidence_type": evidence_type, "source_url": redact_url(source_url), "request_method": method, "status_code": status, "technology": technology, "signal": signal, "confidence": confidence_label(score) if score is not None else None, "confidence_score": score, "observed_at": now(), "metadata": metadata}


def signal_metadata(signal: dict[str, Any], **extra: Any) -> dict[str, Any]:
    metadata = {key: value for key, value in signal.items() if key not in {"technology", "signal", "source", "score"} and value is not None}
    metadata.update(extra)
    return metadata


def db_connect() -> psycopg.Connection[Any]:
    return psycopg.connect(DATABASE_URL)


def init_db_sync() -> None:
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS discovery_runs (id TEXT PRIMARY KEY, status TEXT NOT NULL, scope JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, pages_visited INTEGER NOT NULL DEFAULT 0, assets_fetched INTEGER NOT NULL DEFAULT 0, evidence_count INTEGER NOT NULL DEFAULT 0, phase TEXT, current_url TEXT, error TEXT)""")
        conn.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS assets_fetched INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS evidence_count INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS phase TEXT")
        conn.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS current_url TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS discovery_evidence (id BIGSERIAL PRIMARY KEY, run_id TEXT NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE, evidence_type TEXT NOT NULL, source_url TEXT NOT NULL, request_method TEXT NOT NULL, status_code INTEGER, technology TEXT, signal TEXT NOT NULL, confidence TEXT, confidence_score NUMERIC, observed_at TIMESTAMPTZ NOT NULL, metadata JSONB NOT NULL DEFAULT '{}'::jsonb)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_evidence_run ON discovery_evidence(run_id)")
        conn.execute("""CREATE TABLE IF NOT EXISTS discovery_observations (id BIGSERIAL PRIMARY KEY, run_id TEXT NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE, observed_at TIMESTAMPTZ NOT NULL, source_url TEXT NOT NULL, status_code INTEGER, duration_ms NUMERIC, observation JSONB NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_observations_run ON discovery_observations(run_id)")
        conn.commit()


def save_run_sync(job: DiscoveryJob, status: str, **fields: Any) -> None:
    with db_connect() as conn:
        conn.execute("INSERT INTO discovery_runs (id, status, scope, created_at) VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status", (job.id, status, Jsonb(job.scope.model_dump()), job.created_at or now()))
        if fields:
            assignments = ", ".join(f"{key} = %s" for key in fields)
            conn.execute(f"UPDATE discovery_runs SET {assignments} WHERE id = %s", (*fields.values(), job.id))
        conn.commit()


def update_run_sync(job_id: str, status: str, **fields: Any) -> bool:
    assignments = ["status = %s"]
    values: list[Any] = [status]
    for key, value in fields.items():
        assignments.append(f"{key} = %s")
        values.append(value)
    values.append(job_id)
    with db_connect() as conn:
        result = conn.execute(f"UPDATE discovery_runs SET {', '.join(assignments)} WHERE id = %s", values)
        conn.commit()
    return result.rowcount > 0


def reconcile_incomplete_runs_sync() -> int:
    """Mark jobs that lost their in-memory task during a worker restart."""
    with db_connect() as conn:
        result = conn.execute(
            """UPDATE discovery_runs
               SET status = 'interrupted', completed_at = %s, phase = 'interrupted',
                   current_url = NULL, error = 'Worker restarted before scan completed'
             WHERE status IN ('queued', 'running')""",
            (now(),),
        )
        conn.commit()
    return result.rowcount


def save_evidence_sync(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with db_connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany("""INSERT INTO discovery_evidence (run_id, evidence_type, source_url, request_method, status_code, technology, signal, confidence, confidence_score, observed_at, metadata) VALUES (%(run_id)s, %(evidence_type)s, %(source_url)s, %(request_method)s, %(status_code)s, %(technology)s, %(signal)s, %(confidence)s, %(confidence_score)s, %(observed_at)s, %(metadata)s)""", [{**row, "metadata": Jsonb(row["metadata"])} for row in rows])
        conn.commit()


def save_observations_sync(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with db_connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany("INSERT INTO discovery_observations (run_id, observed_at, source_url, status_code, duration_ms, observation) VALUES (%(run_id)s, %(observed_at)s, %(source_url)s, %(status_code)s, %(duration_ms)s, %(observation)s)", [{**row, "observation": Jsonb(row["observation"]), "source_url": redact_url(row["source_url"])} for row in rows])
        conn.commit()


def list_runs_sync() -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute("SELECT id, status, scope, created_at, started_at, completed_at, pages_visited, assets_fetched, evidence_count, phase, current_url, error FROM discovery_runs ORDER BY created_at DESC").fetchall()
    columns = ["id", "status", "scope", "created_at", "started_at", "completed_at", "pages_visited", "assets_fetched", "evidence_count", "phase", "current_url", "error"]
    return [dict(zip(columns, row)) for row in rows]


def delete_run_sync(job_id: str) -> str:
    with db_connect() as conn:
        row = conn.execute("SELECT status FROM discovery_runs WHERE id = %s", (job_id,)).fetchone()
        if not row:
            return "missing"
        if row[0] in {"queued", "running"}:
            return "active"
        conn.execute("DELETE FROM discovery_runs WHERE id = %s", (job_id,))
        conn.commit()
    return "deleted"


def evidence_sync(job_id: str) -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute("SELECT id, evidence_type, source_url, request_method, status_code, technology, signal, confidence, confidence_score, observed_at, metadata FROM discovery_evidence WHERE run_id = %s ORDER BY id", (job_id,)).fetchall()
    columns = ["id", "evidence_type", "source_url", "request_method", "status_code", "technology", "signal", "confidence", "confidence_score", "observed_at", "metadata"]
    return [dict(zip(columns, row)) for row in rows]


def observations_sync(job_id: str) -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute("SELECT id, run_id, observed_at, source_url, status_code, duration_ms, observation FROM discovery_observations WHERE run_id = %s ORDER BY id", (job_id,)).fetchall()
    columns = ["id", "run_id", "observed_at", "source_url", "status_code", "duration_ms", "observation"]
    return [dict(zip(columns, row)) for row in rows]


def profile_sync(job_id: str) -> dict[str, Any]:
    evidence = evidence_sync(job_id)
    technology_rows = [row for row in evidence if row["evidence_type"] == "technology" and row["technology"]]
    route_candidates = [row for row in evidence if row["evidence_type"] == "route_candidate"]
    auth_endpoint_candidates = [row for row in evidence if row["evidence_type"] == "auth_endpoint_candidate"]
    route_inventory = [row for row in evidence if row["evidence_type"] in {"route", "route_discovered", "redirect"}]
    search_surfaces = []
    field_formats = []
    auth_surfaces = []
    api_endpoint_map = {}
    runtime_security = []
    for row in evidence:
        if row["evidence_type"] in {"interaction", "runtime_inspection"} and row["metadata"].get("search_surface_count", 0):
            search_surfaces.append({"source_url": row["source_url"], "surfaces": row["metadata"].get("search_surfaces", [])})
        if row["evidence_type"] in {"interaction", "runtime_inspection"}:
            metadata = row.get("metadata") or {}
            if metadata.get("auth_surface", {}).get("detected"):
                auth_surfaces.append({
                    "source_url": row["source_url"],
                    "final_url": metadata.get("final_url", ""),
                    **metadata.get("auth_surface", {}),
                    "headings": metadata.get("headings", [])[:20],
                    "button_labels": metadata.get("button_labels", [])[:50],
                    "network_requests": metadata.get("api_requests", [])[:100],
                })
            for endpoint in metadata.get("api_requests", []):
                key = (endpoint.get("method"), endpoint.get("url"), endpoint.get("resource_type"), endpoint.get("status_code"))
                item = api_endpoint_map.setdefault(key, {**endpoint, "source_urls": []})
                if row["source_url"] not in item["source_urls"]:
                    item["source_urls"].append(row["source_url"])
            if metadata.get("security_headers"):
                runtime_security.append({"source_url": row["source_url"], "headers": metadata.get("security_headers", {})})
            for control in row["metadata"].get("controls", []):
                field_formats.append({
                    "source_url": row["source_url"],
                    "tag": control.get("tag", ""),
                    "name": control.get("name", ""),
                    "id": control.get("id", ""),
                    "required": bool(control.get("required", False)),
                    "format": {
                        "type": control.get("type", ""),
                        "pattern": control.get("pattern", ""),
                        "inputmode": control.get("inputmode", ""),
                        "autocomplete": control.get("autocomplete", ""),
                        "minlength": control.get("minlength", ""),
                        "maxlength": control.get("maxlength", ""),
                        "accept": control.get("accept", ""),
                        "placeholder": control.get("placeholder", ""),
                    },
                })
    grouped: dict[str, dict[str, Any]] = {}
    for row in technology_rows:
        technology = row["technology"]
        metadata = row.get("metadata") or {}
        item = grouped.setdefault(technology, {
            "technology": technology,
            "technology_key": metadata.get("technology_key") or re.sub(r"[^a-z0-9]+", "-", technology.casefold()).strip("-"),
            "category": metadata.get("category", "application-platform"),
            "confidence": row["confidence"],
            "confidence_score": 0.0,
            "evidence_count": 0,
            "signals": [],
            "signal_families": [],
            "versions": [],
            "source_urls": [],
            "_scores": [],
            "_families": set(),
            "_versions": set(),
        })
        item["evidence_count"] += 1
        item["_scores"].append(float(row["confidence_score"] or 0))
        family = str(metadata.get("signal_family") or metadata.get("source") or "unknown")
        item["_families"].add(family)
        version = str(metadata.get("version") or "").strip()
        if version:
            item["_versions"].add(version)
        signal = row["signal"]
        if signal not in item["signals"]:
            item["signals"].append(signal)
        if row["source_url"] not in item["source_urls"]:
            item["source_urls"].append(row["source_url"])
    category_rank = {"application-platform": 0, "cms": 0, "framework": 1, "server-runtime": 2, "web-server": 3, "protocol": 4, "library": 5, "delivery": 6, "application-surface": 7}
    for item in grouped.values():
        base_score = max(item.pop("_scores") or [0.0])
        families = sorted(item.pop("_families"))
        family_bonus = min(0.16, max(0, len(families) - 1) * 0.05)
        item["confidence_score"] = round(min(0.99, base_score + family_bonus), 2)
        item["confidence"] = "high" if item["confidence_score"] >= 0.85 else "medium" if item["confidence_score"] >= 0.60 else "low"
        versions = sorted(item.pop("_versions"))
        item["versions"] = versions
        item["version"] = versions[0] if len(versions) == 1 else None
        item["signal_families"] = families
    technologies = sorted(grouped.values(), key=lambda item: (category_rank.get(item.get("category", ""), 8), -item["confidence_score"], item["technology"]))
    signature_technology_context = build_signature_technology_context(technologies)
    confidence_counts = {label: sum(1 for item in technologies if item["confidence"] == label) for label in ("high", "medium", "low")}
    return {
        "run_id": job_id,
        "technology_detector_version": DETECTOR_VERSION,
        "technology_count": len(technologies),
        "evidence_count": len(evidence),
        "confidence_counts": confidence_counts,
        "technologies": technologies,
        "signature_technology_context": signature_technology_context,
        "route_candidates": route_candidates,
        "auth_endpoint_candidates": auth_endpoint_candidates,
        "route_inventory": route_inventory,
        "search_surfaces": search_surfaces,
        "field_formats": field_formats,
        "auth_surfaces": auth_surfaces,
        "api_endpoints": list(api_endpoint_map.values()),
        "runtime_security": runtime_security,
        "evidence": evidence,
    }


async def run_discovery(job: DiscoveryJob) -> None:
    scope = job.scope
    seed = scope.seed_url
    seed_host = urlparse(seed).hostname
    if not seed_host or seed_host.lower() != scope.hostname.lower():
        await asyncio.to_thread(save_run_sync, job, "rejected", error="seed_url hostname does not match scope hostname")
        return
    queue = [seed]
    visited: set[str] = set()
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    assets_seen: set[str] = set()
    route_candidates_seen: set[str] = set()
    auth_endpoint_candidates_seen: set[tuple[str, str]] = set()
    page_routes_seen: set[str] = {seed}
    fetched_assets = 0
    pages = 0
    delay = 1.0 / scope.rate_limit_per_second
    user_agent = "WAF-Intelligence-Discovery/0.4"
    try:
        await asyncio.to_thread(save_run_sync, job, "running", started_at=now(), phase="crawling", current_url=redact_url(seed), pages_visited=pages, assets_fetched=fetched_assets, evidence_count=len(rows))
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, headers={"User-Agent": user_agent}) as client:
            while queue and pages < scope.max_pages:
                url = queue.pop(0)
                if url in visited or not in_scope(url, seed, scope.allowed_paths):
                    continue
                visited.add(url)
                await asyncio.to_thread(save_run_sync, job, "running", phase="crawling", current_url=redact_url(url), pages_visited=pages, assets_fetched=fetched_assets, evidence_count=len(rows))
                await asyncio.sleep(delay if pages else 0)
                started = time.perf_counter()
                try:
                    response = await client.get(url, headers={"User-Agent": user_agent})
                except httpx.HTTPError as exc:
                    observations.append({"run_id": job.id, "observed_at": now(), "source_url": url, "status_code": None, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "observation": {"request": {"method": "GET", "url": redact_url(url), "headers": {"user-agent": user_agent}}, "error": {"type": type(exc).__name__}, "response": None, "body_retained": False}})
                    rows.append(evidence_row(job.id, "request_error", url, "GET", None, "Request failed", {"error_type": type(exc).__name__}))
                    continue
                pages += 1
                rows.append(evidence_row(job.id, "route", url, "GET", response.status_code, "Reachable route observed", {"content_type": response.headers.get("content-type", ""), "response_size": len(response.content), "headers": safe_headers(response), "cookie_names": cookie_names(response)}))
                content_type = response.headers.get("content-type", "").lower()
                parser: SurfaceParser | None = None
                if "text/html" in content_type or "application/xhtml" in content_type:
                    parser = SurfaceParser()
                    parser.feed(response.text[:2_000_000])
                    for item in parser.links:
                        candidate = normalize_url(item, url, seed, scope.allowed_paths)
                        if candidate and candidate not in visited and candidate not in queue:
                            queue.append(candidate)
                            page_routes_seen.add(candidate)
                            rows.append(evidence_row(job.id, "route_discovered", candidate, "GET", None, "Subpage route discovered in HTML link", {"source_page": redact_url(url), "discovery_source": "html_link", "candidate_only": False, "not_fetched": False}, score=0.90))
                    for candidate_route in static_page_candidates(url, "".join(parser.inline_script_parts), seed, scope.allowed_paths):
                        if candidate_route not in page_routes_seen:
                            page_routes_seen.add(candidate_route)
                            queue.append(candidate_route)
                            rows.append(evidence_row(job.id, "route_discovered", candidate_route, "GET", None, "Subpage route discovered in inline JavaScript", {"source_page": redact_url(url), "discovery_source": "inline_javascript", "candidate_only": False, "not_fetched": False}, score=0.72))
                    for item in parser.assets:
                        candidate = normalize_url(item, url, seed, scope.allowed_paths)
                        if candidate and candidate not in assets_seen:
                            assets_seen.add(candidate)
                            kind = asset_type(candidate)
                            should_fetch = bool(kind and fetched_assets < MAX_ASSETS_PER_RUN)
                            rows.append(evidence_row(job.id, "asset", candidate, "GET", None, "Referenced asset", {"source_page": url, "asset_type": kind or "other", "fetched_for_fingerprinting": should_fetch}))
                            if should_fetch:
                                fetched_assets += 1
                                await asyncio.to_thread(save_run_sync, job, "running", phase="asset-analysis", current_url=redact_url(candidate), pages_visited=pages, assets_fetched=fetched_assets, evidence_count=len(rows))
                                try:
                                    asset_response, asset_content, truncated, duration_ms = await fetch_asset(client, candidate, user_agent)
                                    asset_content_type = asset_response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                                    rows.append(evidence_row(job.id, "asset", candidate, "GET", asset_response.status_code, "Asset fetched for passive fingerprinting", {"source_page": url, "asset_type": kind, "content_type": asset_content_type, "bytes_inspected": len(asset_content), "truncated": truncated}))
                                    observations.append({"run_id": job.id, "observed_at": now(), "source_url": candidate, "status_code": asset_response.status_code, "duration_ms": duration_ms, "observation": {"request": {"method": "GET", "url": redact_url(candidate), "headers": {"user-agent": user_agent}}, "response": {"status": asset_response.status_code, "headers": safe_headers(asset_response), "cookies": cookie_observations(asset_response)}, "asset": {"type": kind, "content_type": asset_content_type, "bytes_inspected": len(asset_content), "truncated": truncated}, "body_retained": False}})
                                    for signal in asset_fingerprint(candidate, asset_content_type, asset_content):
                                        rows.append(evidence_row(job.id, "technology", candidate, "GET", asset_response.status_code, signal["signal"], signal_metadata(signal, asset_type=kind), signal["technology"], signal["score"]))
                                    search_markers = static_search_markers(asset_content)
                                    if search_markers:
                                        rows.append(evidence_row(job.id, "interaction", candidate, "GET", asset_response.status_code, "Search surface marker observed in JavaScript bundle", {"source_asset": redact_url(candidate), "search_surface_count": len(search_markers), "search_surfaces": [{"tag": "javascript", "type": "search-component", "name": "", "id": "", "aria_label": marker} for marker in search_markers], "values_submitted": False}))
                                    for candidate_route in static_route_candidates(candidate, asset_content, seed, scope.allowed_paths):
                                        if candidate_route not in route_candidates_seen:
                                            route_candidates_seen.add(candidate_route)
                                            rows.append(evidence_row(job.id, "route_candidate", candidate_route, "GET", None, "API or application route candidate found in JavaScript bundle", {"source_asset": redact_url(candidate), "candidate_only": True, "not_fetched": True}, score=0.65))
                                    for endpoint in static_auth_endpoint_candidates(candidate, asset_content, seed, scope.allowed_paths):
                                        endpoint_key = (endpoint["endpoint_class"], endpoint["url"])
                                        if endpoint_key not in auth_endpoint_candidates_seen:
                                            auth_endpoint_candidates_seen.add(endpoint_key)
                                            rows.append(evidence_row(job.id, "auth_endpoint_candidate", endpoint["url"], "GET", None, "Authentication/API endpoint candidate found in JavaScript bundle", {"source_asset": redact_url(candidate), "endpoint_class": endpoint["endpoint_class"], "candidate_only": True, "not_fetched": True, "values_submitted": False}, score=0.70))
                                    for page_route in static_page_candidates(candidate, asset_content, seed, scope.allowed_paths):
                                        if page_route not in page_routes_seen:
                                            page_routes_seen.add(page_route)
                                            queue.append(page_route)
                                            rows.append(evidence_row(job.id, "route_discovered", page_route, "GET", None, "Subpage route discovered in JavaScript bundle", {"source_asset": redact_url(candidate), "discovery_source": "javascript_bundle", "candidate_only": False, "not_fetched": False}, score=0.72))
                                except httpx.HTTPError as exc:
                                    rows.append(evidence_row(job.id, "asset_request_error", candidate, "GET", None, "Asset request failed", {"error_type": type(exc).__name__, "asset_type": kind}))
                    rows.append(evidence_row(job.id, "interaction", url, "GET", response.status_code, "Interaction surface observed", {"form_count": len(parser.forms), "forms": parser.forms[:50], "control_count": len(parser.controls), "controls": parser.controls[:100], "search_surface_count": len(parser.search_surfaces), "search_surfaces": parser.search_surfaces[:25], "title": " ".join(parser.title_parts)[:500], "meta_names": [item["name"] for item in parser.metas[:50]]}))
                observations.append({"run_id": job.id, "observed_at": now(), "source_url": url, "status_code": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "observation": {"request": {"method": "GET", "url": redact_url(url), "headers": {"user-agent": user_agent}}, "response": {"status": response.status_code, "headers": safe_headers(response), "cookies": cookie_observations(response), "redirect": redact_url(response.headers.get("location", "")) if response.headers.get("location") else None}, "document": {"content_type": content_type, "response_size": len(response.content), "title": " ".join(parser.title_parts)[:500] if parser else None, "link_count": len(parser.links) if parser else 0, "asset_count": len(parser.assets) if parser else 0, "form_count": len(parser.forms) if parser else 0, "search_surface_count": len(parser.search_surfaces) if parser else 0, "meta_names": [item["name"] for item in parser.metas[:50]] if parser else []}, "body_retained": False}})
                for signal in fingerprint(response, parser):
                    rows.append(evidence_row(job.id, "technology", url, "GET", response.status_code, signal["signal"], signal_metadata(signal), signal["technology"], signal["score"]))
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    target = normalize_url(location, url, seed, scope.allowed_paths)
                    rows.append(evidence_row(job.id, "redirect", url, "GET", response.status_code, "Redirect observed", {"location_in_scope": bool(target), "target": redact_url(target) if target else "external_or_out_of_scope"}))
                    if target and target not in visited and target not in queue:
                        queue.append(target)
        await asyncio.to_thread(save_evidence_sync, rows)
        await asyncio.to_thread(save_observations_sync, observations)
        await asyncio.to_thread(save_run_sync, job, "completed", completed_at=now(), pages_visited=pages, assets_fetched=fetched_assets, evidence_count=len(rows), phase="complete", current_url=None)
    except Exception as exc:
        if rows:
            await asyncio.to_thread(save_evidence_sync, rows)
        if observations:
            await asyncio.to_thread(save_observations_sync, observations)
        await asyncio.to_thread(save_run_sync, job, "failed", completed_at=now(), pages_visited=pages, assets_fetched=fetched_assets, evidence_count=len(rows), phase="failed", current_url=None, error=type(exc).__name__)


@app.on_event("startup")
async def startup() -> None:
    await asyncio.to_thread(init_db_sync)
    await asyncio.to_thread(reconcile_incomplete_runs_sync)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    try:
        await asyncio.to_thread(init_db_sync)
        database = True
    except psycopg.Error:
        database = False
    return {"status": "ok" if database else "degraded", "service": "discovery-worker", "mode": "passive-only", "database": database}


@app.post("/jobs", status_code=202)
async def receive_job(job: DiscoveryJob) -> dict[str, Any]:
    await asyncio.to_thread(save_run_sync, job, "queued")
    task = asyncio.create_task(run_discovery(job))
    running_tasks[job.id] = task
    task.add_done_callback(lambda completed, job_id=job.id: running_tasks.pop(job_id, None))
    return {"id": job.id, "status": "queued", "scope": job.scope.model_dump()}


@app.get("/jobs")
async def list_jobs() -> list[dict[str, Any]]:
    return await asyncio.to_thread(list_runs_sync)


@app.get("/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = next((item for item in await asyncio.to_thread(list_runs_sync) if item["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return job


@app.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str) -> dict[str, Any]:
    job = next((item for item in await asyncio.to_thread(list_runs_sync) if item["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    if job["status"] not in {"queued", "running"}:
        return {"id": job_id, "status": job["status"], "cancelled": False}
    task = running_tasks.get(job_id)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await asyncio.to_thread(update_run_sync, job_id, "cancelled", completed_at=now(), phase="cancelled", current_url=None, error="Cancelled by user")
    return {"id": job_id, "status": "cancelled", "cancelled": True}


@app.delete("/jobs/{job_id}", status_code=204)
async def delete_job(job_id: str) -> Response:
    result = await asyncio.to_thread(delete_run_sync, job_id)
    if result == "missing":
        raise HTTPException(status_code=404, detail="Discovery job not found")
    if result == "active":
        raise HTTPException(status_code=409, detail="Active discovery jobs cannot be deleted")
    return Response(status_code=204)


@app.get("/jobs/{job_id}/evidence")
async def get_evidence(job_id: str) -> list[dict[str, Any]]:
    job = next((item for item in await asyncio.to_thread(list_runs_sync) if item["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return await asyncio.to_thread(evidence_sync, job_id)


@app.get("/jobs/{job_id}/profile")
async def get_profile(job_id: str) -> dict[str, Any]:
    job = next((item for item in await asyncio.to_thread(list_runs_sync) if item["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return await asyncio.to_thread(profile_sync, job_id)


@app.get("/jobs/{job_id}/observations")
async def get_observations(job_id: str) -> list[dict[str, Any]]:
    job = next((item for item in await asyncio.to_thread(list_runs_sync) if item["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return await asyncio.to_thread(observations_sync, job_id)
