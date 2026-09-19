from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse


DETECTOR_VERSION = "1.0.0"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _version(patterns: Sequence[str], values: Sequence[str]) -> str | None:
    for pattern in patterns:
        compiled = re.compile(pattern, re.IGNORECASE)
        for value in values:
            match = compiled.search(value)
            if match:
                return next((group for group in match.groups() if group), None)
    return None


def _meta_values(meta: Mapping[str, str] | Sequence[Mapping[str, str]] | None) -> dict[str, str]:
    if isinstance(meta, Mapping):
        return {str(key).casefold(): str(value)[:500] for key, value in meta.items()}
    result: dict[str, str] = {}
    for item in meta or ():
        name = str(item.get("name", "")).casefold()
        content = str(item.get("content", ""))
        if name and content:
            result[name] = content[:500]
    return result


def _cookie_names(cookies: Sequence[str | Mapping[str, Any]] | None) -> set[str]:
    names: set[str] = set()
    for cookie in cookies or ():
        value = cookie.get("name", "") if isinstance(cookie, Mapping) else cookie
        if value:
            names.add(str(value).casefold())
    return names


def detect_technology_signals(
    *,
    url: str,
    headers: Mapping[str, str] | None = None,
    cookies: Sequence[str | Mapping[str, Any]] | None = None,
    body: str = "",
    assets: Sequence[str] | None = None,
    meta: Mapping[str, str] | Sequence[Mapping[str, str]] | None = None,
    title: str = "",
    forms: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return deterministic, explainable technology signals from passive HTTP evidence.

    The detector never submits values or probes technology-specific endpoints. A signal
    contains its evidence family and category so the profile builder can distinguish an
    application platform from a generic form, library, or web-server observation.
    """
    raw_headers = {str(key).casefold(): str(value)[:500] for key, value in (headers or {}).items()}
    lowered_headers = {key: value.casefold() for key, value in raw_headers.items()}
    cookie_set = _cookie_names(cookies)
    asset_values = [str(value) for value in (assets or ()) if value]
    lowered_assets = [value.casefold() for value in asset_values]
    body_text = (body or "")[:2_000_000]
    body_lower = body_text.casefold()
    title_lower = (title or "").casefold()
    meta_values = _meta_values(meta)
    generator = meta_values.get("generator", "")
    parsed_path = urlparse(url).path.casefold() or "/"
    signals: list[dict[str, Any]] = []

    def add(
        technology: str,
        signal: str,
        source: str,
        score: float,
        value: str = "",
        *,
        category: str = "application-platform",
        family: str = "body",
        version: str | None = None,
    ) -> None:
        signals.append({
            "technology": technology,
            "technology_key": _slug(technology),
            "category": category,
            "signal": signal,
            "source": source,
            "signal_family": family,
            "score": round(score, 2),
            "value": value[:500],
            "version": version,
        })

    def path_is(*paths: str) -> bool:
        normalized = parsed_path.rstrip("/") or "/"
        return normalized in paths or any(normalized.startswith(path.rstrip("/") + "/") for path in paths)

    # Web servers and delivery layers. Keep these separate from the application product.
    server = raw_headers.get("server", "")
    server_lower = server.casefold()
    if "microsoft-iis" in server_lower or server_lower.startswith("iis"):
        add("Microsoft IIS", "IIS Server response header", "response.headers.server", 0.92, server, category="web-server", family="header", version=_version((r"(?:microsoft-iis|iis)[/ ]([0-9][\w.]*)",), (server,)))
    elif "nginx" in server_lower:
        add("nginx", "nginx Server response header", "response.headers.server", 0.92, server, category="web-server", family="header", version=_version((r"nginx[/ ]([0-9][\w.]*)",), (server,)))
    elif "apache" in server_lower:
        add("Apache HTTP Server", "Apache Server response header", "response.headers.server", 0.92, server, category="web-server", family="header", version=_version((r"apache[/ ]([0-9][\w.]*)",), (server,)))
    elif "caddy" in server_lower:
        add("Caddy", "Caddy Server response header", "response.headers.server", 0.92, server, category="web-server", family="header", version=_version((r"caddy[/ ]([0-9][\w.]*)",), (server,)))
    elif "litespeed" in server_lower:
        add("LiteSpeed", "LiteSpeed Server response header", "response.headers.server", 0.92, server, category="web-server", family="header")
    elif server:
        add("Web server", "Server response header", "response.headers.server", 0.65, server, category="web-server", family="header")

    powered_by = raw_headers.get("x-powered-by", "")
    powered_lower = powered_by.casefold()
    if powered_lower:
        if "asp.net core" in powered_lower:
            technology = "ASP.NET Core"
            category = "server-runtime"
        elif "asp.net" in powered_lower:
            technology = "ASP.NET"
            category = "server-runtime"
        elif "php" in powered_lower:
            technology = "PHP"
            category = "server-runtime"
        elif "express" in powered_lower:
            technology = "Express / Node.js"
            category = "server-runtime"
        else:
            technology = "Application runtime"
            category = "server-runtime"
        add(technology, "X-Powered-By response header", "response.headers.x-powered-by", 0.86 if technology != "Application runtime" else 0.72, powered_by, category=category, family="header", version=_version((r"(?:php|asp\.net core|asp\.net|express)[/ ]?([0-9][\w.]*)",), (powered_by,)))

    # Microsoft Exchange web applications. Paths are deliberately segment-bound to avoid
    # treating arbitrary marketing text containing 'owa' or 'outlook' as Exchange.
    owa_path = path_is("/owa", "/ecp", "/microsoft-server-activesync")
    owa_cookie = bool(cookie_set & {"x-owa-canary", "outlooksession", "exchangecookie"})
    owa_header = any(key in raw_headers for key in ("x-owa-version", "x-feserver", "x-beserver"))
    owa_body = any(marker in body_lower for marker in ("outlook web app", "microsoft exchange", "owa/auth.owa", "owa/service.svc"))
    if owa_path:
        add("Microsoft Exchange OWA", "Exchange OWA/ECP path", "url.path", 0.99, parsed_path, family="url")
    if owa_cookie:
        add("Microsoft Exchange OWA", "Exchange OWA session/canary cookie", "response.headers.set-cookie.name", 0.98, ", ".join(sorted(cookie_set & {"x-owa-canary", "outlooksession", "exchangecookie"})), family="cookie")
    if owa_header:
        owa_version = raw_headers.get("x-owa-version")
        add("Microsoft Exchange OWA", "Exchange OWA response header", "response.headers", 0.98, "x-owa-version" if not owa_version else owa_version, family="header", version=_version((r"([0-9]{1,4}(?:\.[0-9]{1,4}){1,4})",), (owa_version or "",)))
    if owa_body or "outlook web app" in title_lower:
        add("Microsoft Exchange OWA", "Exchange OWA document marker", "html.title_or_body", 0.95, "Outlook Web App / Microsoft Exchange", family="body")

    # CMS and application-platform fingerprints. Prefer explicit generator metadata,
    # canonical asset paths, cookies, and route markers over generic page text.
    wordpress_version = _version((r"wordpress\s*([0-9][\w.-]*)",), (generator, body_text))
    wordpress_meta = "wordpress" in generator.casefold()
    wordpress_path = any(marker in body_lower or any(marker in asset for asset in lowered_assets) for marker in ("wp-content/", "wp-includes/", "wp-json/")) or path_is("/wp-admin", "/wp-login.php", "/wp-json")
    wordpress_cookie = any(name.startswith("wordpress_") or name.startswith("wp-settings-") for name in cookie_set)
    if wordpress_meta:
        add("WordPress", "WordPress generator metadata", "html.meta.generator", 0.99, generator, category="cms", family="meta", version=wordpress_version)
    if wordpress_path:
        add("WordPress", "WordPress canonical asset or route", "html_or_asset_path", 0.96, "/wp-content/ or /wp-includes/", category="cms", family="url", version=wordpress_version)
    if wordpress_cookie:
        add("WordPress", "WordPress session or settings cookie", "response.headers.set-cookie.name", 0.94, "wordpress_ / wp-settings-", category="cms", family="cookie", version=wordpress_version)

    drupal_version = _version((r"drupal\s*([0-9][\w.-]*)",), (generator, body_text))
    drupal_meta = "drupal" in generator.casefold()
    drupal_path = any(marker in body_lower or any(marker in asset for asset in lowered_assets) for marker in ("drupalsettings", "sites/default/files", "/misc/drupal", "core/misc/drupal"))
    drupal_cookie = any(name.startswith("sess") or name.startswith("ssess") or name == "has_js" for name in cookie_set)
    if drupal_meta:
        add("Drupal", "Drupal generator metadata", "html.meta.generator", 0.99, generator, category="cms", family="meta", version=drupal_version)
    if drupal_path:
        add("Drupal", "Drupal canonical asset or settings marker", "html_or_asset_path", 0.96, "Drupal asset/settings marker", category="cms", family="url", version=drupal_version)
    if drupal_cookie:
        add("Drupal", "Drupal session or JavaScript cookie", "response.headers.set-cookie.name", 0.93, "Drupal session cookie", category="cms", family="cookie", version=drupal_version)

    joomla_version = _version((r"joomla!?\s*([0-9][\w.-]*)",), (generator, body_text))
    joomla_meta = "joomla" in generator.casefold()
    joomla_path = path_is("/administrator") or any(marker in body_lower or any(marker in asset for asset in lowered_assets) for marker in ("/media/system/js/", "/media/jui/", "com_content"))
    if joomla_meta:
        add("Joomla", "Joomla generator metadata", "html.meta.generator", 0.99, generator, category="cms", family="meta", version=joomla_version)
    if joomla_path:
        add("Joomla", "Joomla administrator or asset marker", "html_or_asset_path", 0.94, "Joomla route/asset marker", category="cms", family="url", version=joomla_version)

    magento_version = _version((r"magento\s*([0-9][\w.-]*)",), (generator, body_text))
    magento_marker = any(marker in body_lower or any(marker in asset for asset in lowered_assets) for marker in ("x-magento-init", "mage/requirejs", "magento_", "/static/version"))
    magento_cookie = any(name in {"private_content_version", "section_data_ids", "mage-cache-storage", "mage-cache-sessid"} for name in cookie_set)
    if "magento" in generator.casefold():
        add("Magento", "Magento generator metadata", "html.meta.generator", 0.99, generator, category="cms", family="meta", version=magento_version)
    if magento_marker:
        add("Magento", "Magento client or asset marker", "html_or_asset_path", 0.95, "Magento client/asset marker", category="cms", family="asset", version=magento_version)
    if magento_cookie:
        add("Magento", "Magento cache/session cookie", "response.headers.set-cookie.name", 0.94, "Magento cache/session cookie", category="cms", family="cookie", version=magento_version)

    # Common server-side runtimes and frameworks.
    php_cookie = "phpsessid" in cookie_set or "laravel_session" in cookie_set
    java_cookie = "jsessionid" in cookie_set
    asp_cookie = bool(cookie_set & {"asp.net_sessionid", ".aspxauth", ".aspnetcore"})
    if php_cookie:
        add("PHP", "PHP session cookie", "response.headers.set-cookie.name", 0.90, "PHP session cookie", category="server-runtime", family="cookie")
    if java_cookie:
        add("Java", "Java session cookie", "response.headers.set-cookie.name", 0.90, "JSESSIONID", category="server-runtime", family="cookie")
    if asp_cookie:
        add("ASP.NET", "ASP.NET session or authentication cookie", "response.headers.set-cookie.name", 0.93, "ASP.NET session/auth cookie", category="server-runtime", family="cookie")
    laravel_cookie = "laravel_session" in cookie_set
    laravel_body = any(marker in body_lower for marker in ("laravel mix", "laravel-vite-plugin", "laravel framework"))
    laravel_asset = any(re.search(r"/(?:vendor/)?laravel(?:[./_-]|/)", asset) for asset in lowered_assets)
    if laravel_cookie or laravel_body or laravel_asset:
        family = "cookie" if laravel_cookie else ("body" if laravel_body else "asset")
        add("Laravel", "Laravel session or explicit framework marker", "cookie_or_explicit_marker", 0.91, "Laravel marker", category="framework", family=family)
    if "asp.netmvc" in lowered_headers.get("x-powered-by", "") or "asp.net mvc" in body_lower:
        add("ASP.NET MVC", "ASP.NET MVC marker", "header_or_body_marker", 0.90, "ASP.NET MVC", category="framework", family="body")

    # Frontend frameworks and libraries.
    if "ng-version" in body_lower or any("angular" in asset for asset in lowered_assets) or any(marker in body_lower for marker in ("ngdevmode", "@angular/core", "zone.js")):
        add("Angular", "Angular DOM or asset marker", "html_or_asset_path", 0.94, "Angular marker", category="framework", family="body" if "ng-version" in body_lower else "asset")
    if "data-reactroot" in body_lower or any(marker in body_lower for marker in ("__reactfiber", "reactdom", "react/jsx-runtime", "react.production", "createroot")) or any("react" in asset for asset in lowered_assets):
        add("React", "React DOM or asset marker", "html_or_asset_path", 0.92, "React marker", category="framework", family="body" if "data-reactroot" in body_lower else "asset")
    if any("/_next/" in asset or "next/static" in asset for asset in lowered_assets) or "__next_data__" in body_lower or "__next_f.push" in body_lower:
        add("Next.js", "Next.js application marker", "html_or_asset_path", 0.97, "Next.js marker", category="framework", family="url" if any("/_next/" in asset for asset in lowered_assets) else "body")
    if any("/_nuxt/" in asset for asset in lowered_assets) or any(marker in body_lower for marker in ("__nuxt__", "nuxtapp")):
        add("Nuxt", "Nuxt application marker", "html_or_asset_path", 0.97, "Nuxt marker", category="framework", family="url" if any("/_nuxt/" in asset for asset in lowered_assets) else "body")
    if any("vue" in asset for asset in lowered_assets) or "data-v-" in body_lower or "__vue__" in body_lower:
        add("Vue.js", "Vue DOM or asset marker", "html_or_asset_path", 0.92, "Vue marker", category="framework", family="body" if "data-v-" in body_lower or "__vue__" in body_lower else "asset")
    if any("jquery" in asset for asset in lowered_assets) or any(marker in body_lower for marker in ("jquery.fn", "jquery v")):
        add("jQuery", "jQuery asset or runtime marker", "asset_path_or_body", 0.88, "jQuery marker", category="library", family="asset")
    if any("bootstrap" in asset for asset in lowered_assets) or ("bootstrap" in body_lower and ".container" in body_lower):
        add("Bootstrap", "Bootstrap asset or CSS marker", "asset_path_or_body", 0.88, "Bootstrap marker", category="library", family="asset")
    if "webpackruntime" in body_lower or "__webpack_require__" in body_lower:
        add("Webpack", "Webpack runtime marker", "asset.content_marker", 0.84, "Webpack marker", category="library", family="body")
    if "vite" in body_lower and "import.meta" in body_lower:
        add("Vite", "Vite bundle marker", "asset.content_marker", 0.88, "Vite marker", category="library", family="body")
    if any(marker in body_lower for marker in ("tailwind", "--tw-")):
        add("Tailwind CSS", "Tailwind CSS marker", "asset.content_marker", 0.90, "Tailwind marker", category="library", family="body")

    # Protocol and application-surface signals remain useful for WAF planning.
    content_type = lowered_headers.get("content-type", "")
    if "application/json" in content_type:
        add("REST or JSON API", "JSON response content type", "response.headers.content-type", 0.78, content_type, category="protocol", family="header")
    if "graphql" in content_type or "graphql" in body_lower or any("graphql" in asset for asset in lowered_assets):
        add("GraphQL", "GraphQL content or route marker", "content_type_or_body_marker", 0.86, "GraphQL marker", category="protocol", family="body")
    if "xml" in content_type or "soap" in body_lower:
        add("XML or SOAP", "XML/SOAP content or marker", "content_type_or_body_marker", 0.78, content_type or "SOAP marker", category="protocol", family="body")
    if generator and not any(item["source"] == "html.meta.generator" for item in signals):
        add("Generated platform", "HTML generator metadata", "html.meta.generator", 0.78, generator, category="application-platform", family="meta")
    if "cf-ray" in raw_headers or "cloudflare" in server_lower:
        add("Cloudflare", "Cloudflare delivery header", "response.headers", 0.92, "Cloudflare marker", category="delivery", family="header")
    if raw_headers.get("via") or raw_headers.get("x-cache"):
        add("Reverse proxy or cache", "Proxy/cache response header", "response.headers", 0.62, raw_headers.get("via") or raw_headers.get("x-cache", ""), category="delivery", family="header")
    if forms:
        add("HTML forms", "HTML form controls observed", "html.form", 0.95, str(len(forms)), category="application-surface", family="html")
        if any(str(item.get("method", "GET")).upper() == "POST" for item in forms):
            add("State-changing form surface", "POST form observed but not submitted", "html.form.method", 0.88, "POST", category="application-surface", family="html")
        if any("multipart/form-data" in str(item.get("enctype", "")).casefold() for item in forms):
            add("File upload surface", "Multipart form observed but not submitted", "html.form.enctype", 0.90, "multipart/form-data", category="application-surface", family="html")
    if re.search(r"type\s*=\s*[\"']password[\"']", body_text, re.IGNORECASE):
        add("Authentication boundary", "Password input marker observed", "html.body_marker", 0.72, "password input", category="application-surface", family="html")

    return signals
