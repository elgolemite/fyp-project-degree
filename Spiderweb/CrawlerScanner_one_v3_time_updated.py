# -----------------------------------------------------------------------------
# CrawlerScanner_allinone.py
# - Single-file scanner for OWASP Juice Shop and WebGoat (and generic targets)
# - ACTIVE checks only for XSS/SQLi (heuristics are disabled in the workflow)
# - Includes: form active probes, query-param active probes, Selenium executed XSS,
#             Juice Shop /rest/user/login auth-bypass check, WebGoat auto-login.
# -----------------------------------------------------------------------------

# CrawlerScanner_generic_local_v6.py
# Flask UI + Local-only blackbox crawler + lightweight scanner
#
# v6 improvements:
# - Removes CSRF posture scanning (too noisy/low confidence in black-box).
# - Adds SQL Injection error-based detection (high confidence when DB errors are exposed).
# - Improves XSS reflection classification (escaped vs unescaped + context-aware).
# - Keeps Confidence + Proof bundle per finding.
# - Keeps high-confidence checks: Security Misconfiguration + Exceptional Conditions.
#
# Intended for LOCAL/LAB targets you control (WebGoat/NodeGoat/DVWA/Juice Shop).

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Set
import secrets

AuthCtx = Dict[str, Any]  # carries auth cookies/session state from crawler

from flask import Flask, render_template_string, render_template, jsonify, request, send_file
import subprocess, sys, threading, os, json, re, time, urllib.parse, ipaddress, secrets, uuid
import string
# Convenience imports used by multiple scanners (some call urlparse/urlunparse directly)
from urllib.parse import urlparse, urlunparse, parse_qs, parse_qsl, urlencode, urljoin, quote, unquote
from html import unescape
import html
import requests

# Optional Selenium (for DOM-based form discovery on JS-heavy apps like WebGoat/Juice Shop)
try:
    from selenium import webdriver  # type: ignore
    from selenium.webdriver.chrome.service import Service as ChromeService  # type: ignore
    from selenium.webdriver.chrome.options import Options as ChromeOptions  # type: ignore
except Exception:
    webdriver = None  # type: ignore
    ChromeService = None  # type: ignore
    ChromeOptions = None  # type: ignore

# -----------------------------
# Configuration
# -----------------------------
def _default_crawler_script() -> str:
    # Prefer offline-friendly crawler if present (avoids webdriver_manager internet download)
    here = os.path.dirname(os.path.abspath(__file__))
    offline_short = os.path.join(here, "crawler_offline.py")
    offline_latest = os.path.join(here, "crawler_generic_v3_offline_latest.py")
    if os.path.exists(offline_short):
        return "crawler_offline.py"
    if os.path.exists(offline_latest):
        return "crawler_generic_v3_offline_latest.py"
    offline_v5 = os.path.join(here, "crawler_generic_v3_offline_v5.py")
    offline_v4 = os.path.join(here, "crawler_generic_v3_offline_v4.py")
    offline_v3 = os.path.join(here, "crawler_generic_v3_offline_v3.py")
    offline = os.path.join(here, "crawler_generic_v3_offline.py")
    if os.path.exists(offline_v5):
        return "crawler_generic_v3_offline_v5.py"
    if os.path.exists(offline_v4):
        return "crawler_generic_v3_offline_v4.py"
    if os.path.exists(offline_v3):
        return "crawler_generic_v3_offline_v3.py"
    if os.path.exists(offline):
        return "crawler_generic_v3_offline.py"
    return "crawler_generic_v3.py"

CRAWLER_SCRIPT = os.getenv("CRAWLER_SCRIPT", _default_crawler_script())
ENDPOINTS_FILE = os.getenv("ENDPOINTS_FILE", "endpoints.txt")
COOKIES_FILE = os.getenv("COOKIES_FILE", "cookies.json")
RESULTS_FILE = os.getenv("RESULTS_FILE", "scan_results.json")

MAX_PAGES = int(os.getenv("MAX_PAGES", "250"))
MAX_URLS = int(os.getenv("MAX_URLS", "150"))

# If set, the crawler will open a browser and wait for you to login manually.
MANUAL_LOGIN = os.getenv("MANUAL_LOGIN", "1") == "1"
LOGIN_WAIT_SECONDS = int(os.getenv("LOGIN_WAIT_SECONDS", "120"))

# WebGoat convenience (optional)
WEBGOAT_AUTOLOGIN = os.getenv("WEBGOAT_AUTOLOGIN", "0") == "1"
WEBGOAT_USER = os.getenv("WEBGOAT_USER", "guest")
WEBGOAT_PASS = os.getenv("WEBGOAT_PASS", "guest")

# HTTP defaults
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "15"))

SQLI_SLEEP = int(os.getenv("SQLI_SLEEP", "3"))  # seconds used for time-based SQLi probes
SQLI_TIME_THRESHOLD = float(os.getenv("SQLI_TIME_THRESHOLD", "2.2"))  # seconds over baseline to consider delayed
ENABLE_SELENIUM_XSS = os.getenv("ENABLE_SELENIUM_XSS", "1") == "1"
VERIFY_SSL = os.getenv("VERIFY_SSL", "1") == "1"  # 1=verify TLS certs, 0=disable
MAX_PARAMS_PER_URL = int(os.getenv("MAX_PARAMS_PER_URL", "6"))  # limit query params tested per URL

# --- Small helpers (added for stability) ---
def rand_token(n: int = 10) -> str:
    """Random URL-safe-ish token for probes."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(max(1, int(n))))

def dedupe_preserve_order(items):
    seen = set()
    out = []
    for x in items or []:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out

def dedup(items):
    # Backwards-compatible alias used in a few places
    return dedupe_preserve_order(items)

SQL_ERROR_SIGS_EXTRA = [
    r"java\.sql\.[a-z]*exception",
    r"sqlsyntaxerrorexception",
    r"badsqlgrammar",
    r"org\.h2\.jdbc",
    r"org\.springframework\.jdbc",
    r"jdbc.*syntax",

    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"mysql_fetch",
    r"pg_query\(",
    r"postgresql",
    r"sqlstate\[",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{4,}",
    r"sqlite\s*exception",
    r"sqlite_error",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"jdbc exception",
]

def detect_sqli_error(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    for pat in SQL_ERROR_SIGS_EXTRA:
        if re.search(pat, t, re.I):
            return True
    return False

def do_req(url: str, auth: AuthCtx, *, method: str = "GET", params=None, data=None, json_body=None, headers=None, allow_redirects: bool = True, timeout: int = DEFAULT_TIMEOUT):
    """Thin wrapper around requests to keep cookies/headers consistent."""
    h = {}
    try:
        h.update(DEFAULT_HEADERS)
    except Exception:
        pass
    if headers:
        h.update(headers)
    sess = auth.sess if getattr(auth, 'sess', None) is not None else requests.Session()
    return sess.request(
        method=method,
        url=url,
        params=params,
        data=data,
        json=json_body,
        headers=h,
        allow_redirects=allow_redirects,
        timeout=timeout,
        verify=getattr(auth, 'verify_ssl', True),
    )

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Lab-only restriction
ALLOWED_NETLOCS = os.getenv("ALLOWED_NETLOCS", "localhost:3000,127.0.0.1:3000,localhost:4000,127.0.0.1:4000,localhost:8080,127.0.0.1:8080")
ALLOW_PUBLIC = os.getenv("ALLOW_PUBLIC", "0") == "1"  # keep default off

# -----------------------------
# App state
# -----------------------------
app = Flask(__name__)
_status = {
    "running": False,
    "stage": "idle",   # idle|crawling|scanning|done|error
    "message": "",
    "target": "",
    "log": "",
    "warnings": [],
    "findings_count": 0
}


# -----------------------------
# Results store (in-memory)
# -----------------------------
_RESULTS_LOCK = threading.RLock()
_LAST_RESULTS: Optional[Dict[str, Any]] = None
_LAST_RESULTS_AT: Optional[float] = None

def _set_last_results(r: Dict[str, Any]) -> None:
    global _LAST_RESULTS, _LAST_RESULTS_AT
    with _RESULTS_LOCK:
        _LAST_RESULTS = r
        _LAST_RESULTS_AT = time.time()

def _get_last_results() -> Optional[Dict[str, Any]]:
    with _RESULTS_LOCK:
        return dict(_LAST_RESULTS) if isinstance(_LAST_RESULTS, dict) else None
_results_cache = None
_stop_event = threading.Event()

# -----------------------------
# Helpers
# -----------------------------
def append_log(line: str):
    _status["log"] += line.rstrip() + "\n"

def normalize_base(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    p = urllib.parse.urlparse(url)
    # normalize: keep scheme/netloc, ensure path
    path = p.path or "/"
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, "", "", ""))


def _canonical_netloc(netloc: str) -> str:
    """Canonicalize localhost/127.0.0.1 to avoid target mismatch in UI refresh."""
    nl = (netloc or "").strip()
    if not nl:
        return nl
    # drop userinfo
    if "@" in nl:
        nl = nl.split("@", 1)[1]
    host = nl
    port = ""
    if nl.startswith("[") and "]" in nl:
        # IPv6 like [::1]:8080
        end = nl.find("]")
        host = nl[1:end]
        rest = nl[end+1:]
        if rest.startswith(":"):
            port = rest[1:]
    else:
        if ":" in nl:
            host, port = nl.rsplit(":", 1)
        else:
            host = nl
            port = ""
    host_l = host.lower().strip()
    if host_l in ("127.0.0.1", "localhost", "::1"):
        host_l = "localhost"
    if port:
        return f"{host_l}:{port}"
    return host_l

def normalize_target_key(url: str) -> str:
    """Stable key for matching results to a target (ignores fragments, normalizes trailing slashes + localhost)."""
    u = (url or "").strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    p = urllib.parse.urlparse(u)
    scheme = (p.scheme or "http").lower()
    netloc = _canonical_netloc(p.netloc)
    path = p.path or "/"
    # collapse trailing slash except root
    if path != "/":
        path = path.rstrip("/")
    if not path:
        path = "/"
    return urllib.parse.urlunparse((scheme, netloc, path, "", "", ""))


def is_private_or_local_host(netloc: str) -> bool:
    host = netloc.split("@")[-1].split(":")[0].strip().lower()
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False

def host_allowed(netloc: str) -> bool:
    if ALLOW_PUBLIC:
        return True
    # explicit allowlist first
    allow = {x.strip().lower() for x in ALLOWED_NETLOCS.split(",") if x.strip()}
    if netloc.lower() in allow:
        return True
    # private ip / localhost allowed
    return is_private_or_local_host(netloc)

def is_static(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in [
        ".png",".jpg",".jpeg",".gif",".svg",".ico",".css",".js",".woff",".woff2",".ttf",".eot",".map",".pdf"
    ])




LOGOUT_HINT_RE = re.compile(r"/(?:logout|logoff|signout)(?:\b|/)", re.IGNORECASE)
def is_logoutish(u: str) -> bool:
    try:
        p = urllib.parse.urlparse(u)
    except Exception:
        return False
    if LOGOUT_HINT_RE.search(p.path or ""):
        return True
    q = (p.query or "").lower()
    if "logout" in q or "logoff" in q or "signout" in q:
        return True
    return False


def similarity_ratio(a: str, b: str) -> float:
    """Return a rough similarity score between two strings (0.0 - 1.0).
    Used to compare responses for Access Control heuristics.
    """
    try:
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a or "", b or "").ratio()
    except Exception:
        return 0.0


def looks_sensitive_path(url: str) -> bool:
    """
    Heuristic: return True for URLs that are *more likely* to be access-controlled.
    This is only used to reduce noisy BAC checks, not to decide exploitability.
    """
    try:
        p = urllib.parse.urlparse(url)
        path = (p.path or "/").lower()
        q = (p.query or "").lower()
    except Exception:
        return True

    # Obvious public/static content is not "sensitive"
    if is_static(url):
        return False

    # Common sensitive keywords / areas
    sensitive_markers = [
        "/admin", "/manage", "/internal", "/private", "/account", "/profile", "/settings",
        "/dashboard", "/users", "/user", "/api", "/rest", "/graphql",
        "/orders", "/order", "/checkout", "/payment", "/wallet",
        "/config", "/configuration", "/debug", "/metrics",
        "/upload", "/download", "/files", "/ftp",
        "/reset", "password", "token", "jwt", "session"
    ]

    # Also treat "id-like" paths as potentially sensitive (e.g., /allocations/5)
    if re.search(r"/\d{1,10}(/|$)", path):
        return True

    hay = path + "?" + q
    return any(m in hay for m in sensitive_markers)


def set_query_param(url: str, key: str, value: str) -> str:
    """Return URL with query param `key` set to `value` (preserves order + fragment)."""
    p = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    new_pairs = []
    found = False
    for k, v in pairs:
        if k == key:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((key, value))
    new_q = urllib.parse.urlencode(new_pairs, doseq=True)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def expand_webgoat_lessons(auth_sess: requests.Session, base_url: str, xhrs: list[str]) -> list[str]:
    """WebGoat is a SPA; lesson URLs are often discovered via lesson menu JSON, not <a href>.
    This helper tries to expand lesson entrypoints from the captured XHRs (lab only).

    Returns a list of additional URLs (lesson entrypoints + overview/info) to improve coverage.
    """
    def _collect_strings(obj):
        out = []
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                out.extend(_collect_strings(k))
                out.extend(_collect_strings(v))
        elif isinstance(obj, list):
            for it in obj:
                out.extend(_collect_strings(it))
        return out

    try:
        base_root = normalize_base(base_url).rstrip("/")
        # Best-effort: locate lessonmenu endpoint from XHRs, else guess it
        menu = None
        for x in xhrs or []:
            if "service/lessonmenu.mvc" in (x or ""):
                menu = x
                break
        if not menu:
            menu = f"{base_root}/service/lessonmenu.mvc"

        # Fetch lesson menu
        r = auth_sess.get(
            menu,
            timeout=20,
            allow_redirects=True,
            headers={
                "Accept": "application/json,text/plain,*/*",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{base_root}/start.mvc",
            },
        )

        tokens: list[str] = []
        # Try JSON parse first (most robust)
        try:
            data = r.json()
            joined = "\n".join(_collect_strings(data))
            tokens = sorted(set(re.findall(r"[A-Za-z0-9_]+\.lesson(?:\.lesson)?", joined)))
        except Exception:
            tokens = []

        # Fallback: some WebGoat setups return HTML or JS instead of strict JSON.
        # Also catches the "Login Page" HTML if cookies were not applied.
        if not tokens:
            body = (r.text or "")
            if "<title>Login Page</title" in body or "Login Page" in body[:4000]:
                return []
            tokens = sorted(set(re.findall(r"[A-Za-z0-9_]+\.lesson(?:\.lesson)?", body)))

        if not tokens:
            return []

        # Build lesson entrypoints and related endpoints
        out = []
        lesson_names = set()

        for t in tokens:
            t = t.strip()
            if not t:
                continue

            # Normalize to include ".lesson.lesson" variant when we only got ".lesson"
            variants = {t}
            if t.endswith(".lesson") and not t.endswith(".lesson.lesson"):
                variants.add(t + ".lesson")  # -> ".lesson.lesson"

            for v in variants:
                out.append(f"{base_root}/{v}")

            # Keep a base lesson name for overview/info endpoints
            base_name = t.split(".lesson", 1)[0]
            if base_name:
                lesson_names.add(base_name)

        # Add overview/info endpoints (useful XHRs and navigation)
        for name in sorted(lesson_names):
            out.append(f"{base_root}/service/lessonoverview.mvc/{name}.lesson")
            out.append(f"{base_root}/service/lessoninfo.mvc/{name}.lesson.lesson")

        # Dedup + cap
        out = list(dict.fromkeys(out))
        cap = int(os.getenv("MAX_WEBGOAT_LESSON_URLS", "150"))
        return out[:cap]
    except Exception:
        return []


def is_http_url(url: str) -> bool:
    try:
        s = (urllib.parse.urlparse(url).scheme or '').lower()
        return s in ('http', 'https')
    except Exception:
        return False


# ---------------------------
# Heuristics / regex helpers
# ---------------------------

SQL_ERROR_RE = re.compile(
    r"("
    r"you have an error in your sql syntax|sql syntax.*mysql|warning: mysql|mysql_fetch|mysql_num_rows|"
    r"mysqli?_|postgresql|pg_query|pg_exec|psql:|sqlstate|"
    # SQLite: avoid matching the plain word 'sqlite' (it appears in docs/README); match real error tokens instead
    r"SQLITE_[A-Z_]+|sqlite\s*error|sqliteexception|sqlite3\.(operationalerror|integrityerror)|"
    r"near\s+\".*?\"\s*:\s*syntax error|unrecognized token:|no such table:|"
    r"microsoft odbc|odbc sql|sql server|ole db|unclosed quotation mark|"
    r"ora-\d+|oracle error|quoted string not properly terminated|"
    r"db2 sql error|jdbc exception|unterminated quoted string"
    r")",
    re.IGNORECASE,
)


# Avoid visiting endpoints that can kill the session during crawling/discovery
LOGOUT_RE = re.compile(r"(?:^|/)(?:logout|logoff|signout|sign-off|exit)(?:\b|/|$)", re.IGNORECASE)

def strip_fragment(u: str) -> str:
    try:
        p = urlparse(u)
        if not p.fragment:
            return u
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
    except Exception:
        return u

def same_origin(u: str, base: str) -> bool:
    try:
        pu, pb = urlparse(u), urlparse(base)
        return (pu.scheme, pu.netloc) == (pb.scheme, pb.netloc)
    except Exception:
        return False

def should_skip_url(u: str) -> bool:
    # skip obvious session killers + noisy endpoints
    if not u:
        return True
    if LOGOUT_RE.search(u):
        return True
    if "socket.io" in u:
        return True
    return False

def load_cookie_list(path: str) -> List[Dict[str, Any]]:
    """Load cookies.json produced by the crawler (list of cookie dicts)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    if isinstance(data, dict) and "cookies" in data:
        data = data["cookies"]
    if not isinstance(data, list):
        return []
    out: List[Dict[str, Any]] = []
    for c in data:
        if isinstance(c, dict) and "name" in c and "value" in c:
            out.append(c)
    return out

def extract_script_src(html: str, base_url: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html, flags=re.IGNORECASE):
        src = (m.group(1) or "").strip()
        if not src:
            continue
        u = urljoin(base_url, src)
        u = strip_fragment(u)
        out.append(u)
    return out

def extract_candidate_urls(text: str, base_url: str) -> List[str]:
    """
    Extract candidate URLs from HTML/JS/JSON text.
    - href/src/action attributes
    - quoted strings that look like paths (/WebGoat/..., /rest/..., /api/...)
    """
    cand: List[str] = []

    # attribute-style urls
    for m in re.finditer(r"(?:href|src|action)\s*=\s*['\"]([^'\"]+)['\"]", text, flags=re.IGNORECASE):
        v = (m.group(1) or "").strip()
        if not v or v.startswith("javascript:") or v.startswith("mailto:"):
            continue
        u = strip_fragment(urljoin(base_url, v))
        cand.append(u)

    # quoted absolute-ish paths in JS/JSON
    for m in re.finditer(r"['\"](\/(?:WebGoat|WebWolf|rest|api|service)\/[^'\"\s<>]+)['\"]", text, flags=re.IGNORECASE):
        u = strip_fragment(urljoin(base_url, m.group(1)))
        cand.append(u)

    # absolute urls
    for m in re.finditer(r"(?:(?:https?://)[^\s'\"<>]+)", text, flags=re.IGNORECASE):
        u = strip_fragment(m.group(0))
        cand.append(u)

    # de-dupe while preserving order
    seen: set[str] = set()
    out: List[str] = []
    for u in cand:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out

def mine_additional_endpoints(seed_urls: List[str], auth: AuthCtx, limit_pages: int = 35, include_js: bool = True) -> List[str]:
    """
    Lightweight endpoint mining:
    - GET a subset of pages, extract internal URLs from HTML/JS/JSON
    - optionally fetch referenced JS files and mine strings in them
    """
    found: List[str] = []
    seen: set[str] = set(strip_fragment(u) for u in seed_urls)
    js_seen: set[str] = set()

    base = auth.base
    for u in list(seed_urls)[:limit_pages]:
        u = strip_fragment(u)
        if should_skip_url(u) or is_static(u):
            continue
        r = safe_request(u, auth, method="GET")
        if not r:
            continue
        ctype = (r.headers.get("Content-Type") or "").lower()
        body = (r.text or "")
        if len(body) > 450_000:
            body = body[:450_000]

        for nu in extract_candidate_urls(body, u):
            nu = strip_fragment(nu)
            if nu in seen:
                continue
            if not same_origin(nu, base):
                continue
            if should_skip_url(nu):
                continue
            seen.add(nu)
            found.append(nu)

        if include_js and "html" in ctype:
            for jsu in extract_script_src(body, u)[:10]:
                jsu = strip_fragment(jsu)
                if jsu in js_seen:
                    continue
                if not same_origin(jsu, base):
                    continue
                js_seen.add(jsu)
                rjs = safe_request(jsu, auth, method="GET")
                if not rjs:
                    continue
                jst = rjs.text or ""
                if len(jst) > 650_000:
                    jst = jst[:650_000]
                for nu in extract_candidate_urls(jst, jsu):
                    nu = strip_fragment(nu)
                    if nu in seen:
                        continue
                    if not same_origin(nu, base):
                        continue
                    if should_skip_url(nu):
                        continue
                    seen.add(nu)
                    found.append(nu)

    return found

def selenium_discover_dom_forms(
    target_base: str,
    urls: List[str],
    cookies_path: str,
    chromedriver_path: str,
    max_pages: int = 25,
    page_wait_s: float = 2.0,
) -> List[Dict[str, Any]]:
    """
    DOM-based form discovery (helps when forms are rendered by JS).
    Uses cookies.json to avoid logging in again.
    """
    if webdriver is None or ChromeOptions is None or ChromeService is None:
        return []

    cookies = load_cookie_list(cookies_path)

    opts = ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    service = ChromeService(executable_path=chromedriver_path)
    driver = webdriver.Chrome(service=service, options=opts)

    discovered: List[Dict[str, Any]] = []
    seen: set[tuple] = set()
    try:
        driver.set_page_load_timeout(25)
        # must open base first to set cookie scope
        driver.get(target_base)

        host = urlparse(target_base).hostname or ""
        for c in cookies:
            dom = str(c.get("domain") or host)
            if host and dom and dom.lstrip(".") != host and not dom.endswith("." + host):
                continue
            ck: Dict[str, Any] = {"name": c["name"], "value": c.get("value", ""), "path": c.get("path", "/")}
            if "expiry" in c:
                try:
                    ck["expiry"] = int(c["expiry"])
                except Exception:
                    pass
            for k in ("secure", "httpOnly"):
                if k in c:
                    ck[k] = bool(c[k])
            if c.get("sameSite") in ("Lax", "Strict", "None"):
                ck["sameSite"] = c["sameSite"]
            try:
                driver.add_cookie(ck)
            except Exception:
                pass

        for u in urls:
            if len(discovered) >= max_pages * 4:
                break
            u = strip_fragment(u)
            if should_skip_url(u):
                continue
            if not same_origin(u, target_base):
                continue
            try:
                driver.get(u)
                time.sleep(page_wait_s)
                html = driver.page_source or ""
            except Exception:
                continue

            for f in extract_forms_from_html(html, u):
                key = (
                    f.get("page_url"),
                    f.get("action"),
                    f.get("method"),
                    tuple(sorted((f.get("inputs") or [])[:20])),
                )
                if key in seen:
                    continue
                seen.add(key)
                discovered.append(f)

    finally:
        try:
            driver.quit()
        except Exception:
            pass

    return discovered

def scan_discovered_forms(forms: List[Dict[str, Any]], auth: AuthCtx) -> List[Dict[str, Any]]:
    """
    Active checks against Selenium-discovered (DOM) forms only.

    This is intentionally conservative and self-contained so it won't crash due to
    missing outer-scope variables.
      - Reflected XSS: marker reflection in response
      - SQLi: error signature and simple true/false delta
    """
    findings: List[Dict[str, Any]] = []
    if not forms:
        return findings

    base = normalize_base(str(auth.get("base", ""))).rstrip("/")
    max_forms = 60

    for f in forms[:max_forms]:
        action = (f.get("action") or "").strip()
        if not action:
            continue

        page_url = f.get("page_url") or base
        action_url = strip_fragment(urljoin(page_url, action))

        if not same_origin(action_url, base) or is_static(action_url) or should_skip_url(action_url):
            continue

        method = str(f.get("method") or "GET").upper()
        inputs = [x for x in (f.get("inputs") or []) if x and len(str(x)) <= 64]
        if not inputs:
            continue

        # baseline values
        base_data = {str(k): "test" for k in inputs}

        def do_req(payload_data: Dict[str, str]) -> Optional[requests.Response]:
            if method == "GET":
                return safe_request(action_url, auth, method="GET", params=payload_data)
            return safe_request(action_url, auth, method=method, data=payload_data)

        base_resp = do_req(dict(base_data))
        base_text = (base_resp.text if base_resp is not None else "") or ""

        # --- Reflected XSS marker probe
        marker = f"XSS{int(time.time() * 1000)}"
        xss_payload = f'"><svg/onload=alert("{marker}")>'
        for k in inputs[:8]:
            d = dict(base_data)
            d[str(k)] = xss_payload
            r = do_req(d)
            if r and marker in ((r.text or "")[:250000]):
                findings.append({
                    "type": "XSS (Reflected)",
                    "severity": "High",
                    "confidence": "Confirmed",
                    "url": action_url,
                    "detail": f"Marker reflected back when injecting into form field '{k}'.",
                    "evidence": {
                        "status": r.status_code,
                        "marker": marker,
                        "field": str(k),
                        "snippet": body_snippet(r.text or "", marker),
                    },
                })
                break

        # --- SQLi: error signature + boolean delta (best-effort)
        true_pl = "' OR '1'='1"
        false_pl = "' AND '1'='2"
        err_pl = "' OR 1=1-- -"

        for k in inputs[:8]:
            # error-based
            d_err = dict(base_data)
            d_err[str(k)] = err_pl
            r_err = do_req(d_err)
            if r_err:
                t_err = (r_err.text or "")[:250000]
                if SQL_ERROR_RE.search(t_err.lower()):
                    findings.append({
                        "type": "SQL Injection (Error-based)",
                        "severity": "High",
                        "confidence": "Confirmed",
                        "url": action_url,
                        "detail": f"SQL error signature detected when injecting into form field '{k}'.",
                        "evidence": {
                            "status": r_err.status_code,
                            "field": str(k),
                            "snippet": t_err[:500],
                        },
                    })
                    break

            # boolean-ish delta
            dt = dict(base_data); df = dict(base_data)
            dt[str(k)] = true_pl
            df[str(k)] = false_pl
            rt = do_req(dt); rf = do_req(df)
            if not rt or not rf:
                continue

            tt = (rt.text or "")[:250000]
            tf = (rf.text or "")[:250000]

            sim_tf = similarity_ratio(tt, tf)
            sim_tb = similarity_ratio(tt, base_text)
            sim_fb = similarity_ratio(tf, base_text)

            if sim_tf < 0.70 and (sim_tb < 0.85 or sim_fb < 0.85):
                findings.append({
                    "type": "SQL Injection (Boolean-based)",
                    "severity": "High",
                    "confidence": "Medium",
                    "url": action_url,
                    "detail": f"Noticeable response delta between true/false payloads on field '{k}'.",
                    "evidence": {
                        "status_true": rt.status_code,
                        "status_false": rf.status_code,
                        "sim_true_false": round(sim_tf, 3),
                        "len_true": len(tt),
                        "len_false": len(tf),
                    },
                })
                break

    return findings
def parse_endpoints(path: str):
    """Parse crawler output.

    Supports:
      1) JSON blob: {"urls":[...],"forms":[...],"xhrs":[...]}
      2) line-based formats like:
         URL: http://...
         Form: http://... (Method: POST)
         XHR: http://...
      3) raw line list of URLs
    """
    if not os.path.exists(path):
        return {"urls": [], "forms": [], "xhrs": []}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read().strip()

    # JSON format (preferred)
    try:
        j = json.loads(data)
        return {
            "urls": j.get("urls", []) or [],
            "forms": j.get("forms", []) or [],
            "xhrs": j.get("xhrs", []) or [],
        }
    except Exception:
        pass

    urls, forms, xhrs = [], [], []

    for raw in data.splitlines():
        line = (raw or "").strip()
        if not line:
            continue

        # crawler_generic_v2 format
        if line.startswith("URL:"):
            u = line.split("URL:", 1)[1].strip()
            if u:
                urls.append(u)
            continue

        if line.startswith("XHR:"):
            u = line.split("XHR:", 1)[1].strip()
            if u:
                xhrs.append(u)
            continue

        if line.startswith("Form:"):
            rest = line.split("Form:", 1)[1].strip()
            # Example: "http://x/y (Method: POST)"
            method = "POST"
            action = rest
            if "(Method:" in rest:
                action = rest.split("(Method:", 1)[0].strip()
                mpart = rest.split("(Method:", 1)[1]
                method = mpart.split(")", 1)[0].strip().upper() or "POST"
            if action:
                forms.append({"action": action, "method": method})
            continue

        # raw URL line
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    # de-dup while preserving order
    def dedup(seq):
        seen=set()
        out=[]
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {"urls": dedup(urls), "forms": forms, "xhrs": dedup(xhrs)}
def load_cookies_to_session(sess: requests.Session, cookies_file: str, base_url: str):
    if not os.path.exists(cookies_file):
        return
    try:
        cookies = json.load(open(cookies_file, "r", encoding="utf-8"))
    except Exception:
        return
    # cookies can be list of dicts (selenium) or dict name->value
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or "localhost"
    if isinstance(cookies, dict):
        # simple name -> value dict (no domain/path metadata)
        for k, v in cookies.items():
            # omit domain so Requests attaches it to the current host automatically
            sess.cookies.set(k, v)
    elif isinstance(cookies, list):
        for c in cookies:
            try:
                name = c.get("name")
                value = c.get("value")
                # Selenium cookies may have a domain that doesn't match the scan host
                # (e.g., you logged in via 'localhost' but scan base_url is '127.0.0.1').
                raw_dom = (c.get("domain") or "").lstrip(".")
                path = c.get("path") or "/"
                if name is not None:
                    # If domain matches the current host, keep it. Otherwise, omit domain
                    # so the cookie is still sent to this host.
                    if raw_dom and (raw_dom == host or host.endswith(raw_dom) or raw_dom.endswith(host)):
                        sess.cookies.set(name, value, domain=raw_dom, path=path)
                    else:
                        sess.cookies.set(name, value, path=path)
            except Exception:
                continue

def safe_get(sess: requests.Session, url: str, timeout=10):
    try:
        return sess.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def safe_request(
    url: str,
    auth: AuthCtx,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
):
    """Best-effort HTTP request using an authenticated session (AuthCtx dict).

    Accepts either:
      - AuthCtx dict: {"session": requests.Session(), "base": "...", "verify_ssl": bool}
      - requests.Session (legacy): treated as the session with default verify setting
    """
    try:
        # Backward compatible: sometimes callers pass a raw requests.Session()
        if isinstance(auth, requests.Session):
            sess = auth
            verify_ssl = VERIFY_SSL
        elif isinstance(auth, dict):
            sess = auth.get("session")
            verify_ssl = auth.get("verify_ssl", VERIFY_SSL)
        else:
            return None

        if sess is None:
            return None
        base = auth.get("base") or ""
        if base and (not same_origin(url, base)):
            return None

        hdrs = dict(DEFAULT_HEADERS)
        if headers:
            hdrs.update(headers)

        return sess.request(
            method.upper(),
            url,
            params=params,
            data=data,
            json=json_data,
            headers=hdrs,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
    except Exception:
        return None
def body_snippet(text: str, marker: str, window=120):
    if not text:
        return ""
    i = text.find(marker)
    if i < 0:
        return ""
    start = max(0, i - window)
    end = min(len(text), i + len(marker) + window)
    return text[start:end].replace("\n", " ").replace("\r", " ")

def limited_headers(h: dict):
    # keep a small, useful subset
    keep = {}
    for k in ["Content-Type","Set-Cookie","Server","Location","Content-Security-Policy","Strict-Transport-Security",
              "X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","Access-Control-Allow-Origin",
              "Access-Control-Allow-Credentials"]:
        if k in h:
            keep[k] = h.get(k)
    return keep


def webgoat_requests_login(sess: requests.Session, base_url: str) -> bool:
    """Best-effort WebGoat login (lab only). Uses WEBGOAT_USER/WEBGOAT_PASS.
    Returns True if session appears logged in.
    """
    try:
        base_url = normalize_base(base_url)
        origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        root = origin + "/WebGoat"
        login_url = root + "/login"

        # Are we already logged in?
        r0 = sess.get(root, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=VERIFY_SSL)
        if r0 is not None and ("/login" not in (getattr(r0, "url", "") or "").lower()) and ("sign in" not in (r0.text or "").lower()):
            return True

        # Prime cookies
        r1 = sess.get(login_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=VERIFY_SSL)
        html = (r1.text or "") if r1 is not None else ""

        # Extract CSRF token if present (Spring often uses _csrf)
        csrf_name = None
        csrf_value = None
        m = re.search(r'name=["\'](_csrf|csrf)["\']\s+value=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            csrf_name, csrf_value = m.group(1), m.group(2)

        data = {"username": WEBGOAT_USER, "password": WEBGOAT_PASS}
        if csrf_name and csrf_value:
            data[csrf_name] = csrf_value

        r2 = sess.post(login_url, data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=VERIFY_SSL)
        # Check again
        r3 = sess.get(root, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=VERIFY_SSL)
        if r3 is not None and ("/login" not in (getattr(r3, "url", "") or "").lower()) and ("sign in" not in (r3.text or "").lower()):
            return True
    except Exception:
        return False
    return False

def _split_fragment(fragment: str) -> Tuple[str, Dict[str, str]]:
    """
    Split URL fragment like "/search?q=1&x=2" into (path, params).
    """
    if not fragment:
        return "", {}
    if "?" not in fragment:
        return fragment, {}
    frag_path, frag_q = fragment.split("?", 1)
    qd = parse_qs(frag_q, keep_blank_values=True)
    params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in qd.items()}
    return frag_path, params


def _build_url_with_fragment_params(url: str, new_params: Dict[str, str]) -> str:
    p = urlparse(url)
    frag_path, frag_params = _split_fragment(p.fragment or "")
    frag_params.update(new_params)
    frag_q = urlencode(frag_params, doseq=True)
    new_frag = frag_path
    if frag_q:
        new_frag = f"{frag_path}?{frag_q}"
    return p._replace(fragment=new_frag).geturl()


def _looks_numeric(s: str) -> bool:
    try:
        if s is None:
            return False
        s = str(s).strip()
        return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", s))
    except Exception:
        return False


def measure_request_time(url: str, auth: "AuthCtx", method: str = "GET", params: Optional[Dict[str, str]] = None,
                         data: Optional[Dict[str, str]] = None) -> Tuple[float, Optional[requests.Response]]:
    t0 = time.perf_counter()
    resp = safe_request(url, auth, method=method, params=params, data=data)
    t1 = time.perf_counter()
    return (t1 - t0), resp


def try_get_webdriver() -> Optional[Any]:
    """Try to initialize a headless Selenium webdriver (Chrome preferred)."""
    if not ENABLE_SELENIUM_XSS:
        return None
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options as ChromeOptions
    except Exception:
        return None

    # Chrome
    try:
        opts = ChromeOptions()
        opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--window-size=1200,800")
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(20)
        return driver
    except Exception:
        return None


def selenium_xss_exec_check(url: str, marker: str, auth: Optional["AuthCtx"] = None) -> bool:
    """
    Load a URL in a headless browser and check if our payload executed by
    looking for a DOM attribute we set via onerror/onload handler.

    If `auth` is provided, we attempt to copy cookies from the requests session
    into the browser (helps authenticated SPAs).
    """
    driver = try_get_webdriver()
    if driver is None:
        return False
    try:
        # Best-effort cookie transfer
        if auth and isinstance(auth, dict):
            sess = auth.get("session")
            base = (auth.get("base") or "").rstrip("/")
            if sess is not None and base:
                try:
                    driver.get(base + "/")
                    for c in sess.cookies:
                        ck = {
                            "name": c.name,
                            "value": c.value,
                            "path": c.path or "/",
                            "secure": bool(c.secure),
                        }
                        # domain must match current domain; Selenium is picky
                        if c.domain and c.domain.startswith("."):
                            ck["domain"] = c.domain.lstrip(".")
                        elif c.domain:
                            ck["domain"] = c.domain
                        try:
                            driver.add_cookie(ck)
                        except Exception:
                            pass
                except Exception:
                    pass

        driver.get(url)
        # Give SPA time to render
        time.sleep(1.8)
        val = driver.execute_script("return document.documentElement.getAttribute('data-xss')")
        return str(val) == marker
    except Exception:
        return False
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def make_xss_exec_payload(marker: str) -> str:
    # No alert() — just set a marker in DOM when executed.
    return f'"><img src=x onerror="document.documentElement.setAttribute(\'data-xss\',\'{marker}\')">'



def is_unescaped_xss_reflection(body: str, payload: str, marker: str) -> bool:
    """Return True when the injected XSS payload appears *unescaped* in the immediate response.

    We avoid naive checks like 'no &lt; anywhere' because many pages contain encoded examples.
    """
    if not body:
        return False

    # Best signal: the raw payload substring is present
    if payload in body:
        return True

    # If the fully-escaped payload is present, treat as encoded (not exploitable via reflection alone)
    escaped = html.escape(payload, quote=True)
    if escaped in body:
        return False

    # Fallback: marker + our specific sink keywords (unlikely to appear naturally)
    if marker and marker in body:
        if "data-xss" in body and ("setattribute" in body.lower() or "document.documentelement" in body.lower()):
            return True
        if "<script" in body.lower() and marker in body:
            return True
        if "<img" in body.lower() and "onerror" in body.lower() and marker in body:
            return True
        if "<svg" in body.lower() and ("onload" in body.lower() or "onbegin" in body.lower()) and marker in body:
            return True

    return False

def time_sqli_payloads(is_numeric: bool, sleep_s: int) -> List[Tuple[str, str]]:
    """
    Returns a small set of time-based payloads (db_hint, payload).
    Keep short to avoid long scans.
    """
    s = max(1, int(sleep_s))
    if is_numeric:
        return [
            ("MySQL", f"1 AND SLEEP({s})"),
            ("PostgreSQL", f"1;SELECT pg_sleep({s})--"),
            ("MSSQL", f"1;WAITFOR DELAY '0:0:{s}'--"),
        ]
    return [
        ("MySQL", f"' OR SLEEP({s})-- -"),
        ("PostgreSQL", f"';SELECT pg_sleep({s})--"),
        ("MSSQL", f"';WAITFOR DELAY '0:0:{s}'--"),
    ]



def proof_from_response(r: requests.Response):
    if not r:
        return {}
    req = getattr(r, "request", None)
    return {
        "request": {
            "method": getattr(req, "method", None),
            "url": getattr(req, "url", None),
            "headers": dict(getattr(req, "headers", {}) or {}),
        },
        "response": {
            "status": r.status_code,
            "final_url": r.url,
            "history": [h.status_code for h in (r.history or [])],
            "headers": limited_headers(r.headers),
            "len": len(r.text or ""),
        }
    }

def finding(vuln_type, severity, confidence, url, detail, evidence=None, proof=None):
    return {
        "type": vuln_type,
        "severity": severity,      # Info|Low|Medium|High
        "confidence": confidence,  # Info|Medium|Confirmed
        "url": url,
        "detail": detail,
        "evidence": evidence or {},
        "proof": proof or {}
    }

# -----------------------------
# Detection helpers
# -----------------------------
TOKEN_HINTS = ["csrf", "xsrf", "_csrf", "token", "authenticity"]
LOGIN_PATH_HINTS = ["/login", "/signin", "/register", "/signup", "/auth"]
SENSITIVE_KEYWORDS = ["token", "email", "role", "admin", "password", "credit", "address", "basket", "order", "invoice"]
PROTECTED_PATH_PATTERNS = [
    r"/admin\b", r"/whoami\b", r"/me\b", r"/account\b", r"/profile\b", r"/users?\b", r"/orders?\b", r"/addresses?\b",
    r"/basket\b", r"/cart\b"
]

def looks_like_login_page(url: str, html: str = "") -> bool:
    u = (url or "").lower()
    if any(h in u for h in LOGIN_PATH_HINTS):
        return True
    if html:
        t = html.lower()
        if ("name=\"password\"" in t or "type=\"password\"" in t) and ("login" in t or "sign in" in t):
            return True
    return False

def parse_forms_for_tokens(html: str):
    if not html:
        return []
    tokens = []
    # hidden inputs
    for m in re.finditer(r'<input[^>]+type=["\']?hidden["\']?[^>]*>', html, re.I):
        tag = m.group(0)
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        if not nm:
            continue
        name = nm.group(1).lower()
        if any(h in name for h in TOKEN_HINTS):
            tokens.append(nm.group(1))
    # meta tags (common in some frameworks)
    for m in re.finditer(r'<meta[^>]+name=["\']csrf-token["\'][^>]*>', html, re.I):
        tokens.append("meta:csrf-token")
    return tokens

def extract_post_forms(html: str):
    forms = []
    if not html:
        return forms
    for fm in re.finditer(r"<form\b[^>]*>", html, re.I):
        tag = fm.group(0)
        method_m = re.search(r"method=['\"]([^'\"]+)['\"]", tag, re.I)
        method = (method_m.group(1).strip().lower() if method_m else "get")
        if method != "post":
            continue
        action_m = re.search(r"action=['\"]([^'\"]*)['\"]", tag, re.I)
        action = (action_m.group(1).strip() if action_m else "")
        window = html[fm.end(): fm.end()+4000]
        inputs = []
        has_password = False
        for inp in re.finditer(r"<input[^>]*>", window, re.I):
            itag = inp.group(0)
            t = re.search(r"type=['\"]([^'\"]+)['\"]", itag, re.I)
            if t and t.group(1).lower() == "password":
                has_password = True
            nm = re.search(r'name=["\']([^"\']+)["\']', itag, re.I)
            if nm:
                inputs.append(nm.group(1))
        forms.append({"action": action, "inputs": sorted(set(inputs))[:30], "has_password": has_password})
    return forms[:10]

def cookie_samesite_hint(r: requests.Response) -> str:
    try:
        sc = r.headers.get("Set-Cookie", "") or ""
        m = re.search(r"(?i)\bSameSite\s*=\s*([A-Za-z]+)", sc)
        return m.group(1) if m else ""
    except Exception:
        return ""

def in_script_context(html: str, marker: str) -> bool:
    if not html or marker not in html:
        return False
    i = html.find(marker)
    # crude: find nearest <script ...> before and </script> after
    before = html.rfind("<script", 0, i)
    after = html.find("</script", i)
    return before != -1 and after != -1 and before < i < after

def in_attribute_context(html: str, marker: str) -> bool:
    if not html or marker not in html:
        return False
    # check if marker is within quotes on an attribute in the same tag
    # grab a local tag window
    i = html.find(marker)
    tag_start = html.rfind("<", 0, i)
    tag_end = html.find(">", i)
    if tag_start == -1 or tag_end == -1 or tag_end - tag_start > 2000:
        return False
    tag = html[tag_start:tag_end+1]
    return marker in tag and ("=" in tag)

def scan_security_misconfig(url: str, sess: requests.Session):
    findings = []
    if is_static(url):
        return findings
    r = safe_get(sess, url)
    if not r:
        return findings
    proof = proof_from_response(r)

    headers = {k.lower(): v for k, v in (r.headers.items() or [])}
    missing = []
    # Basic header checks
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")
    # framing protection: either XFO or CSP frame-ancestors
    has_xfo = "x-frame-options" in headers
    has_frame_anc = "content-security-policy" in headers and "frame-ancestors" in headers.get("content-security-policy","")
    if not (has_xfo or has_frame_anc):
        missing.append("X-Frame-Options / CSP frame-ancestors")
    # HSTS only meaningful on https
    if url.lower().startswith("https://") and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")

    # Cookie flags on Set-Cookie (best-effort)
    set_cookie = r.headers.get("Set-Cookie","") or ""
    cookie_issues = []
    if set_cookie:
        # if any cookie lacks HttpOnly / SameSite / Secure on https
        if "httponly" not in set_cookie.lower():
            cookie_issues.append("HttpOnly missing on at least one Set-Cookie")
        if url.lower().startswith("https://") and "secure" not in set_cookie.lower():
            cookie_issues.append("Secure missing on at least one Set-Cookie (HTTPS)")
        if "samesite" not in set_cookie.lower():
            cookie_issues.append("SameSite not set on at least one Set-Cookie")

    if missing or cookie_issues:
        evidence = {"missing_headers": missing, "cookie_issues": cookie_issues}
        findings.append(finding(
            "Security Misconfiguration (Headers/Cookies)",
            "Low" if len(missing) <= 2 and not cookie_issues else "Medium",
            "Confirmed",
            url,
            "Missing recommended security headers and/or cookie attributes were observed in the response.",
            evidence=evidence,
            proof=proof
        ))
    return findings

def scan_exceptional_conditions(url: str, sess: requests.Session):
    findings = []
    if is_static(url):
        return findings
    r = safe_get(sess, url)
    if not r:
        return findings
    txt = r.text or ""
    # confirmed signals
    patterns = [
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"org\.springframework\.",
        r"java\.lang\.",
        r"Stack trace",
        r"at\s+[a-zA-Z0-9_$.]+\(",
        r"SQL syntax.*MySQL",
        r"sqlite3\..*Error",
    ]
    hit = any(re.search(p, txt, re.I) for p in patterns)
    if r.status_code >= 500 or hit:
        snippet = (txt[:400].replace("\n"," ").replace("\r"," ") if txt else "")
        findings.append(finding(
            "Mishandling of Exceptional Conditions",
            "Medium" if r.status_code < 500 else "High",
            "Confirmed",
            url,
            "Server returned an error and/or leaked debug/stack-trace style details in the response body.",
            evidence={"status": r.status_code, "snippet": snippet},
            proof=proof_from_response(r)
        ))
    return findings

# def scan_xss_reflection(url: str, auth: "AuthCtx") -> List[Dict[str, Any]]:  # disabled (heuristic removed)
    """
    XSS *heuristic* (intentionally high false-positive rate).

    Why: many apps reflect user-controlled input (query params / SPA routes).
    For this project/demo, we flag endpoints that *look* like they could accept
    user input that might be rendered back to the page.

    This scan does NOT try to exploit anything; it only uses string/pattern signals.
    """
    if is_static(url):
        return []

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    signals: List[str] = []

    # WebGoat (lesson pages) include explicit indicators in the path.
    if "CrossSiteScripting" in parsed.path or "xss" in parsed.path.lower():
        signals.append("Path contains XSS-related keyword (lesson/route name).")

    # Client-side routes (e.g., Juice Shop '#/search') are good XSS leads.
    if "#/" in url or "/#/" in url:
        signals.append("Single-page-app route detected (fragment '#/...'). Input is often rendered client-side.")

    # Any query parameters are potential reflection points.
    if qs:
        signals.append(f"URL has {len(qs)} query parameter(s) which may be reflected into HTML.")

        xssish_names = {
            "q", "query", "search", "s", "term",
            "msg", "message", "comment", "name", "title", "desc",
            "redirect", "return", "next", "url"
        }
        hit = [k for k in qs.keys() if k.lower() in xssish_names]
        if hit:
            signals.append(f"Parameter name(s) commonly associated with reflected output: {', '.join(hit[:8])}.")

    # Light touch: look for obvious HTML/JS sinks already present in the response body (no injection).
    try:
        r = safe_request(url, auth, method="GET")
        if r is not None and r.status_code and "text" in r.headers.get("Content-Type", ""):
            body_l = (r.text or "").lower()
            if "<script" in body_l or "onerror=" in body_l or "onload=" in body_l:
                signals.append("Response body contains script/event-handler patterns (could indicate DOM injection points).")
            if "innerhtml" in body_l or "document.write" in body_l:
                signals.append("Response mentions common DOM sink (innerHTML/document.write).")
    except Exception:
        # don't fail the whole scan for a heuristic
        pass

    if not signals:
        return []

    return [{
        "type": "Potential XSS (Heuristic)",
        "severity": "Low",
        "confidence": "Suspected",
        "url": url,
        "detail": "Heuristic XSS lead: this endpoint appears to accept or render user-controlled input (high false-positive rate).",
        "evidence": {
            "why": "One or more XSS indicators were detected (no exploitation attempted).",
            "signals": signals,
        },
    }]

# def scan_sqli_error_based(url: str, auth: "AuthCtx") -> List[Dict[str, Any]]:  # disabled (heuristic removed)
    """
    SQLi *heuristic* (intentionally high false-positive rate).

    Flags endpoints that look like they might build SQL queries from user input
    (search endpoints, id parameters, etc.) or that already show SQL-error-like text.
    No payload injection is performed.
    """
    if is_static(url):
        return []

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    signals: List[str] = []

    # WebGoat lesson names.
    if "SqlInjection" in parsed.path or "sqli" in parsed.path.lower() or "sql" in parsed.path.lower():
        signals.append("Path contains SQLi-related keyword (lesson/route name).")

    # Common SQLi-looking query parameters
    if qs:
        sqli_names = {
            "id", "user", "userid", "username",
            "q", "query", "search", "term",
            "product", "productid", "category",
            "order", "sort", "filter"
        }
        hit = [k for k in qs.keys() if k.lower() in sqli_names]
        if hit:
            signals.append(f"Query parameter(s) often used in database lookups: {', '.join(hit[:10])}.")
        else:
            signals.append("URL has query parameters (user-controlled input) that may reach database queries.")

    # REST-ish search endpoints often map to DB queries.
    p_l = parsed.path.lower()
    if any(tok in p_l for tok in ["/search", "/products", "/items", "/orders", "/users", "/api/", "/rest/"]):
        signals.append("Endpoint path looks like a data/query API (often backed by a database).")

    # Optional: passive signature check for SQL errors in the response (no injection).
    sql_error_markers = [
        "sql syntax", "syntax error", "sqlite", "mysql", "mariadb",
        "postgresql", "pg::", "ora-", "odbc", "jdbc", "sqlstate",
        "unterminated", "unclosed quotation mark",
    ]
    try:
        r = safe_request(url, auth, method="GET")
        if r is not None and r.text:
            body_l = r.text.lower()
            hits = [m for m in sql_error_markers if m in body_l]
            if hits:
                signals.append(f"Response contains SQL error-like text: {', '.join(sorted(set(hits))[:5])}.")
    except Exception:
        pass

    if not signals:
        return []

    return [{
        "type": "Potential SQL Injection (Heuristic)",
        "severity": "Low",
        "confidence": "Suspected",
        "url": url,
        "detail": "Heuristic SQLi lead: endpoint looks like it may use user input in database queries (high false-positive rate).",
        "evidence": {
            "why": "One or more SQLi indicators were detected (no exploitation attempted).",
            "signals": signals,
        },
    }]


def scan_query_params_active(url: str, auth: "AuthCtx") -> List[Dict[str, Any]]:
    """
    Active checks against query parameters (server-side) + fragment parameters (SPA):
      - XSS:
          * reflection marker in response body (server-side)
          * optional Selenium execution check (client-side / SPA)
      - SQLi:
          * error signature
          * boolean-ish delta
          * time-based delay (blind SQLi)
    """
    findings: List[Dict[str, Any]] = []
    if is_static(url) or should_skip_url(url):
        return findings

    base = normalize_base(auth.get("base", "")).rstrip("/")
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)

    # Collect server-side params (normal query)
    params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in qs.items()}
    if params:
        # --- Baseline timing (server-side)
        base_params = dict(params)
        base_t1, _ = measure_request_time(strip_fragment(url), auth, method="GET", params=base_params)
        base_t2, _ = measure_request_time(strip_fragment(url), auth, method="GET", params=base_params)
        baseline = sorted([base_t1, base_t2])[0]  # use min to reduce jitter

        # XSS exec marker + payload
        marker = f"XSS{int(time.time() * 1000)}"
        exec_payload = make_xss_exec_payload(marker)

        for k in list(params.keys())[:MAX_PARAMS_PER_URL]:
            # --- Reflected XSS (server-side reflection)
            p_inj = dict(params)
            p_inj[k] = exec_payload
            r = safe_request(strip_fragment(url), auth, method="GET", params=p_inj)
            if r is not None:
                body = r.text or ""
                if is_unescaped_xss_reflection(body, exec_payload, marker):
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "Medium",
                        "confidence": "Medium",
                        "url": strip_fragment(r.url if hasattr(r, "url") else url),
                        "param": k,
                        "payload": exec_payload,
                        "evidence": {"marker": marker, "snippet": body_snippet(body, marker)},
                        "recommendation": "Output-encode user input; use templating auto-escaping; enforce CSP; avoid dangerous DOM sinks.",
                    })

            # --- XSS (Executed) using Selenium (helps SPAs / hash routes)
            # Only try if content appears HTML-ish or URL has fragment routes.
            if "#" in url or (r is not None and "text/html" in (r.headers.get("Content-Type", "").lower())):
                # Build a URL that includes our injected param (server-side query)
                inj_url = urlunparse(p._replace(query=urlencode(p_inj, doseq=True)))
                if selenium_xss_exec_check(inj_url, marker, auth):
                    findings.append({
                        "type": "XSS (Executed)",
                        "severity": "High",
                        "confidence": "High",
                        "url": inj_url,
                        "param": k,
                        "payload": exec_payload,
                        "evidence": {"marker": marker, "why": "Payload executed in a browser and set data-xss marker."},
                        "recommendation": "Fix the injection point; sanitize + encode; add CSP; review client-side rendering and DOM sinks.",
                    })

            # --- SQLi: error-based + boolean delta
            true_pl = "' OR '1'='1"
            false_pl = "' AND '1'='2"
            pt = dict(params); pf = dict(params)
            pt[k] = true_pl; pf[k] = false_pl
            rt = safe_request(strip_fragment(url), auth, method="GET", params=pt)
            rf = safe_request(strip_fragment(url), auth, method="GET", params=pf)

            if rt is not None:
                t = (rt.text or "")
                if SQL_ERROR_RE.search(t):
                    findings.append({
                        "type": "SQL Injection (Error-based)",
                        "severity": "High",
                        "confidence": "High",
                        "url": strip_fragment(rt.url if hasattr(rt, "url") else url),
                        "param": k,
                        "payload": param_true_pl,
                        "evidence": {"snippet": body_snippet(t, "sql")},
                        "recommendation": "Use parameterized queries; validate/normalize input; apply least-privilege DB accounts; add WAF rules.",
                    })

            # boolean-ish delta
            if rt is not None and rf is not None:
                tt, tf = (rt.text or ""), (rf.text or "")
                sim = similarity_ratio(tt, tf)
                rows_true = tt.lower().count("<tr")
                rows_false = tf.lower().count("<tr")
                if sim < 0.70 and (rt.status_code != rf.status_code or abs(len(tt) - len(tf)) > 200):
                    findings.append({
                        "type": "SQL Injection (Boolean-based)",
                        "severity": "High",
                        "confidence": "Medium",
                        "url": strip_fragment(url),
                        "param": k,
                        "payload": f"{param_true_pl} / {param_false_pl}",
                        "evidence": {"sim": sim, "len_true": len(tt), "len_false": len(tf), "rows_true": rows_true, "rows_false": rows_false, "codes": f"{rt.status_code}/{rf.status_code}"},
                        "recommendation": "Use parameterized queries; avoid string concatenation; centralize input validation; monitor DB errors and anomalies.",
                    })

            # --- SQLi: time-based delay (blind)
            is_num = _looks_numeric(params.get(k, ""))
            for db_hint, payload in time_sqli_payloads(is_num, SQLI_SLEEP)[:3]:
                p_delay = dict(params)
                p_delay[k] = payload
                dt, _ = measure_request_time(strip_fragment(url), auth, method="GET", params=p_delay)
                if dt - baseline >= SQLI_TIME_THRESHOLD:
                    findings.append({
                        "type": "SQL Injection (Time-based)",
                        "severity": "High",
                        "confidence": "High",
                        "url": strip_fragment(url),
                        "param": k,
                        "payload": payload,
                        "evidence": {"baseline_s": round(baseline, 3), "delay_s": round(dt, 3), "db_hint": db_hint},
                        "recommendation": "Use parameterized queries; disable stacked queries where possible; implement query timeouts; validate input types.",
                    })
                    break

    # ----- SPA fragment params (client-side)
    if p.fragment:
        frag_path, frag_params = _split_fragment(p.fragment)
        # If this is Juice Shop search route with no params, seed a q= parameter for DOM XSS probing
        if not frag_params and str(frag_path).rstrip('/').endswith('search'):
            frag_params = {'q': ''}
        if frag_params:
            marker = f"XSS{int(time.time() * 1000)}"
            exec_payload = make_xss_exec_payload(marker)
            for k in list(frag_params.keys())[:MAX_PARAMS_PER_URL]:
                fp = dict(frag_params)
                fp[k] = exec_payload
                test_url = _build_url_with_fragment_params(url, fp)
                if selenium_xss_exec_check(test_url, marker, auth):
                    findings.append({
                        "type": "XSS (Executed - SPA Fragment)",
                        "severity": "High",
                        "confidence": "High",
                        "url": test_url,
                        "param": k,
                        "payload": exec_payload,
                        "evidence": {"marker": marker, "why": "Payload executed in SPA route and set data-xss marker."},
                        "recommendation": "Sanitize client-side rendering; avoid inserting raw HTML; use trusted templating; apply CSP and DOM sanitizers.",
                    })

    return findings

def _json_item_count(resp_text: str) -> Optional[int]:
    """Try to parse JSON and estimate 'item count' for list-like payloads."""
    try:
        obj = json.loads(resp_text)
    except Exception:
        return None

    if isinstance(obj, list):
        return len(obj)

    if isinstance(obj, dict):
        # Common patterns: { data: [...] }, { items: [...] }, { products: [...] }, etc.
        for k in ("data", "items", "products", "results"):
            v = obj.get(k)
            if isinstance(v, list):
                return len(v)
        # Fallback: first list value
        for v in obj.values():
            if isinstance(v, list):
                return len(v)

    return None


def scan_sqli_boolean_based(url: str, auth: "AuthCtx") -> List[Dict[str, Any]]:
    """
    Disabled active boolean-based SQLi probing.

    For safety and simplicity (and because you requested *false-positive* style
    # findings), we only run the heuristic SQLi classifier in scan_sqli_error_based().  # disabled (heuristic removed)
    """
    return []


def _find_token_in_json(obj: Any) -> Optional[str]:
    """Best-effort recursive token finder in JSON responses."""
    try:
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in ("token", "authtoken", "access_token", "accesstoken", "jwt", "bearer", "authentication"):
                    if isinstance(v, str) and len(v) > 10:
                        return v
                    if isinstance(v, dict):
                        # common: {"authentication": {"token": "..."}}
                        t = _find_token_in_json(v)
                        if t:
                            return t
                t = _find_token_in_json(v)
                if t:
                    return t
        elif isinstance(obj, list):
            for it in obj:
                t = _find_token_in_json(it)
                if t:
                    return t
    except Exception:
        return None
    return None


def scan_login_sqli_bypass(auth: "AuthCtx") -> List[Dict[str, Any]]:
    """Targeted SQLi/auth-bypass check for common JSON login endpoints (e.g., Juice Shop /rest/user/login)."""
    findings: List[Dict[str, Any]] = []
    base = normalize_base(auth.get("base", ""))
    if not base:
        return findings

    # Common Juice Shop login endpoint
    login_url = urljoin(base, "/rest/user/login")
    if not same_origin(login_url, base):
        return findings

    # Baseline: invalid credentials should NOT return a token
    base_email = f"nonexistent_{rand_token(8)}@example.com"
    base_pass = rand_token(10)
    r0 = safe_request(login_url, auth, method="POST", json_data={"email": base_email, "password": base_pass})
    if r0 is None:
        return findings
    if r0.status_code == 404:
        return findings  # endpoint not present

    base_text = r0.text or ""
    base_has_error = bool(SQL_ERROR_RE.search(base_text))
    base_token = None
    try:
        base_json = r0.json()
        base_token = _find_token_in_json(base_json)
    except Exception:
        base_token = None

    # Payloads: small set, focused on bypass. (Use only on lab targets you control.)
    payloads = [
        ("' OR 1=1--", "x"),
        ("' OR 1=1-- -", "x"),
        ('" OR 1=1--', "x"),
        ("' OR '1'='1'--", "x"),
    ]

    # If this really is Juice Shop, also try classic comment truncation for known users
    juiceshop_specific = [
        ("admin@juice-sh.op'--", "x"),
        ("bender@juice-sh.op'--", "x"),
    ]

    # Detect Juice Shop to enable the extra two payloads (by page marker)
    try:
        home = safe_request(base, auth, method="GET")
        if home is not None and ("juice shop" in (home.text or "").lower()):
            payloads.extend(juiceshop_specific)
    except Exception:
        pass

    for em_pl, pw_pl in payloads:
        if _stop_event.is_set():
            break

        r = safe_request(login_url, auth, method="POST", json_data={"email": em_pl, "password": pw_pl})
        if r is None:
            continue

        text = r.text or ""
        status = r.status_code
        token = None
        resp_json = None
        try:
            resp_json = r.json()
            token = _find_token_in_json(resp_json)
        except Exception:
            resp_json = None
            token = None

        # Confirmed bypass: token returned where baseline did not return token
        if token and not base_token and status in (200, 201):
            # Try to extract a user/email/role hint
            email_hint = None
            role_hint = None
            try:
                # common shapes: {"user": {"email": ...}} or flattened
                if isinstance(resp_json, dict):
                    uo = resp_json.get("user") or resp_json.get("data") or resp_json.get("profile")
                    if isinstance(uo, dict):
                        email_hint = uo.get("email") or uo.get("username")
                        role_hint = uo.get("role") or uo.get("isAdmin")
                    if not email_hint:
                        # search for first email-like value
                        for k, v in resp_json.items():
                            if isinstance(v, str) and "@" in v:
                                email_hint = v
                                break
            except Exception:
                pass

            findings.append({
                "type": "SQL Injection (Auth bypass)",
                "severity": "High",
                "owasp": "A03:2021-Injection",
                "url": login_url,
                "param": "email",
                "payload": em_pl,
                "evidence": {
                    "status": status,
                    "token_present": True,
                    "user_hint": email_hint,
                    "role_hint": role_hint,
                    "note": "Login endpoint returned an auth token for an invalid baseline account.",
                },
            })
            break

        # Error-based: DB error appears after payload and was not present in baseline
        if (SQL_ERROR_RE.search(text) and not base_has_error) or (status >= 500 and not base_has_error):
            findings.append({
                "type": "SQL Injection (Error-based)",
                "severity": "High",
                "owasp": "A03:2021-Injection",
                "url": login_url,
                "param": "email",
                "payload": em_pl,
                "evidence": {
                    "status": status,
                    "snippet": sanitize_snippet(text),
                },
            })
            break

    return findings




def extract_forms_from_html(html: str, base_url: str) -> List[Dict[str, Any]]:
    """Very small HTML form extractor (best-effort)."""
    forms: List[Dict[str, Any]] = []
    try:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html, "html.parser")
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            method = (f.get("method") or "get").lower()
            full_action = urllib.parse.urljoin(base_url, action)

            inputs: List[Dict[str, Any]] = []
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = (inp.get("type") or "text").lower()
                value = inp.get("value") or ""
                inputs.append({"name": name, "type": itype, "value": value})

            if inputs:
                forms.append({"action": full_action, "method": method, "inputs": inputs})
    except Exception:
        return forms
    return forms


def scan_forms_active(url: str, auth: "AuthCtx") -> List[Dict[str, Any]]:
    """Active checks against HTML forms: reflected XSS marker + SQLi (error/boolean/time-based)."""
    findings: List[Dict[str, Any]] = []
    if is_static(url) or should_skip_url(url):
        return findings

    r = safe_request(url, auth, method="GET")
    if r is None:
        return findings
    ctype = (r.headers.get("Content-Type") or "").lower()
    if "html" not in ctype:
        return findings

    html = r.text or ""
    forms = extract_forms_from_html(html, url)
    if not forms:
        return findings

    for form in forms[:12]:
        action = form.get("action") or url
        # Only test forms that submit to the same origin
        if not same_origin(action, auth.get("base", "")):
            continue
        if is_static(action) or should_skip_url(action):
            continue
        method = (form.get("method") or "GET").upper()
        inputs = form.get("inputs") or []

        # Baseline (use benign values)
        base_data: Dict[str, str] = {}
        for inp in inputs:
            name = (inp.get("name") or "").strip()
            if not name:
                continue
            base_data[name] = (inp.get("value") or "test")

        # XSS exec payload
        marker = f"XSS{int(time.time()*1000)}"
        exec_payload = make_xss_exec_payload(marker)

        # SQLi payloads (string + numeric variants)
        str_true_pl = "' OR '1'='1"
        str_false_pl = "' AND '1'='2"
        num_true_pl = "1 OR 1=1"
        num_false_pl = "1 AND 1=2"

        # Build payload variations for each parameter
        for inp in inputs[:20]:
            name = (inp.get("name") or "").strip()
            if not name:
                continue

            # ---- baseline timing for this form submit
            def submit(data: Dict[str, str]) -> Tuple[float, Optional[requests.Response]]:
                if method == "GET":
                    return measure_request_time(action, auth, method="GET", params=data)
                return measure_request_time(action, auth, method=method, data=data)

            base_t, base_resp = submit(dict(base_data))
            baseline = base_t

            # ---- XSS reflected
            xss_data = dict(base_data)
            xss_data[name] = exec_payload
            _, rx = submit(xss_data)
            if rx is not None and "text/html" in (rx.headers.get("Content-Type","").lower()):
                body = rx.text or ""
                if is_unescaped_xss_reflection(body, exec_payload, marker):
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "Medium",
                        "confidence": "Medium",
                        "url": strip_fragment(rx.url if hasattr(rx, "url") else action),
                        "param": name,
                        "payload": exec_payload,
                        "evidence": {"marker": marker, "snippet": body_snippet(body, marker)},
                        "recommendation": "Output-encode user input; use auto-escaping templates; avoid raw HTML insertion; enforce CSP.",
                    })

                # ---- XSS executed (browser)
                if selenium_xss_exec_check(strip_fragment(rx.url if hasattr(rx,"url") else action), marker, auth):
                    findings.append({
                        "type": "XSS (Executed)",
                        "severity": "High",
                        "confidence": "High",
                        "url": strip_fragment(rx.url if hasattr(rx,"url") else action),
                        "param": name,
                        "payload": exec_payload,
                        "evidence": {"marker": marker, "why": "Payload executed in a browser and set data-xss marker."},
                        "recommendation": "Sanitize/encode output; fix injection point; add CSP; review DOM sinks and template rendering.",
                    })

            # Decide per-parameter payload family
            itype = (inp.get("type") or "").lower()
            is_num_param = itype in {"number", "range", "tel"} or _looks_numeric(base_data.get(name, ""))
            param_true_pl = num_true_pl if is_num_param else str_true_pl
            param_false_pl = num_false_pl if is_num_param else str_false_pl

            # ---- SQLi error-based
            sqli_data = dict(base_data)
            sqli_data[name] = param_true_pl
            _, rs = submit(sqli_data)
            if rs is not None:
                body = rs.text or ""
                if SQL_ERROR_RE.search(body):
                    findings.append({
                        "type": "SQL Injection (Error-based)",
                        "severity": "High",
                        "confidence": "High",
                        "url": strip_fragment(rs.url if hasattr(rs,"url") else action),
                        "param": name,
                        "payload": param_true_pl,
                        "evidence": {"snippet": body_snippet(body, "sql")},
                        "recommendation": "Use parameterized queries; validate input; suppress detailed DB errors; enforce least privilege on DB accounts.",
                    })

            # ---- SQLi boolean-based delta
            dt = dict(base_data); df = dict(base_data)
            dt[name] = param_true_pl; df[name] = param_false_pl
            _, rt = submit(dt)
            _, rf = submit(df)
            if rt is not None and rf is not None:
                tt, tf = (rt.text or ""), (rf.text or "")
                sim = similarity_ratio(tt, tf)
                rows_true = tt.lower().count("<tr")
                rows_false = tf.lower().count("<tr")
                if sim < 0.70 and (rt.status_code != rf.status_code or abs(len(tt) - len(tf)) > 200):
                    findings.append({
                        "type": "SQL Injection (Boolean-based)",
                        "severity": "High",
                        "confidence": "Medium",
                        "url": strip_fragment(action),
                        "param": name,
                        "payload": f"{param_true_pl} / {param_false_pl}",
                        "evidence": {"sim": sim, "len_true": len(tt), "len_false": len(tf), "rows_true": rows_true, "rows_false": rows_false, "codes": f"{rt.status_code}/{rf.status_code}"},
                        "recommendation": "Use parameterized queries; avoid dynamic SQL string concatenation; validate types; add monitoring.",
                    })

            # ---- SQLi time-based delay
            is_num = _looks_numeric(base_data.get(name, ""))
            for db_hint, payload in time_sqli_payloads(is_num, SQLI_SLEEP)[:3]:
                d = dict(base_data)
                d[name] = payload
                dt_s, _ = submit(d)
                if dt_s - baseline >= SQLI_TIME_THRESHOLD:
                    findings.append({
                        "type": "SQL Injection (Time-based)",
                        "severity": "High",
                        "confidence": "High",
                        "url": strip_fragment(action),
                        "param": name,
                        "payload": payload,
                        "evidence": {"baseline_s": round(baseline, 3), "delay_s": round(dt_s, 3), "db_hint": db_hint},
                        "recommendation": "Use parameterized queries; enforce query timeouts; block stacked queries; validate input types.",
                    })
                    break

    return findings

def scan_broken_access_control(url: str, auth_sess: requests.Session, anon_sess: requests.Session):
    findings = []
    if is_static(url) or not looks_sensitive_path(url):
        return findings

    ra = safe_get(auth_sess, url)
    rn = safe_get(anon_sess, url)
    if not ra or not rn:
        return findings

    # Only consider "anonymous can access" scenarios
    if rn.status_code != 200:
        return findings

    # Reduce noise: if both are 200 and near-identical AND doesn't look sensitive, treat as public
    ba = ra.text or ""
    bn = rn.text or ""
    sim = similarity_ratio(ba, bn)
    has_sensitive = any(k in (bn.lower()) for k in SENSITIVE_KEYWORDS)

    # Confidence rules:
    # - Confirmed: matches a strong protected pattern (admin/whoami/me/profile/account/users) AND anon is 200
    # - Medium: anon is 200 on sensitive-looking endpoint and response has sensitive keywords
    # - Info: otherwise (still suspicious but noisy)
    u = url.lower()
    strong = any(re.search(p, u) for p in PROTECTED_PATH_PATTERNS)
    confidence = "Info"
    severity = "Medium"

    if strong and ("/admin" in u or "/whoami" in u or "/me" in u or "/account" in u or "/profile" in u):
        confidence = "Confirmed"
        severity = "High"
    elif has_sensitive or "/admin" in u:
        confidence = "Medium"
        severity = "High" if "/admin" in u else "Medium"

    if sim > 0.98 and not has_sensitive and "/admin" not in u:
        return findings

    findings.append(finding(
        "Broken Access Control (Anonymous Access)",
        severity,
        confidence,
        url,
        "Anonymous session received HTTP 200 on a sensitive-looking endpoint. Confirm whether this endpoint should require authentication/authorization.",
        evidence={
            "anon_status": rn.status_code,
            "auth_status": ra.status_code,
            "similarity": round(sim, 3),
            "anon_len": len(bn),
            "auth_len": len(ba),
            "anon_snippet": (bn[:260].replace("\n", " ").replace("\r"," ") if bn else "")
        },
        proof={
            "auth": proof_from_response(ra),
            "anon": proof_from_response(rn)
        }
    ))
    return findings

# -----------------------------
# Main worker
# -----------------------------
def run_crawl_and_scan(base_url: str):
    global _results_cache
    _status["running"] = True
    _status["stage"] = "crawling"
    # Clear last results for a fresh run
    _set_last_results({})
    _status["message"] = "Starting..."
    _status["warnings"] = []
    _status["findings_count"] = 0
    _status["log"] = ""
    _results_cache = None

    _stop_event.clear()

    base_url = normalize_base(base_url)
    target_key = normalize_target_key(base_url)
    append_log(f"[*] Target: {base_url}")
    _status["target"] = base_url


    total_start = time.perf_counter()
    _status["crawl_seconds"] = None
    _status["scan_seconds"] = None
    _status["total_seconds"] = None
    # Lab-only host check
    try:
        netloc = urllib.parse.urlparse(base_url).netloc
        if not host_allowed(netloc):
            _status["stage"] = "error"
            _status["message"] = f"Blocked target netloc '{netloc}'. This tool is restricted to local/lab hosts by default."
            _status["running"] = False
            return
    except Exception:
        pass

    # 1) run crawler
    # Clean previous crawl artifacts to avoid stale results
    endpoints_path = os.path.abspath(ENDPOINTS_FILE)
    cookies_path = os.path.abspath(COOKIES_FILE)
    before_mtime = {}
    for fp in (endpoints_path, cookies_path):
        try:
            before_mtime[fp] = os.path.getmtime(fp)
        except Exception:
            before_mtime[fp] = 0.0
    for fp in (endpoints_path, cookies_path):
        try:
            if os.path.exists(fp):
                os.remove(fp)
        except Exception:
            pass
    append_log("[*] Running crawler...")
    _status["message"] = "Running crawler..."


    crawl_start = time.perf_counter()
    _status["crawl_started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    env = os.environ.copy()
    env["TARGET_URL"] = base_url
    env["MAX_PAGES"] = str(MAX_PAGES)
    env["ENDPOINTS_FILE"] = ENDPOINTS_FILE
    env["ENDPOINTS_OUT"] = ENDPOINTS_FILE
    env["COOKIES_FILE"] = COOKIES_FILE
    env["COOKIES_OUT"] = COOKIES_FILE
    env["MANUAL_LOGIN"] = "1" if MANUAL_LOGIN else "0"
    env["LOGIN_WAIT_SECONDS"] = str(LOGIN_WAIT_SECONDS)
    env["MAX_PAGES"] = str(MAX_PAGES)

    try:
        p = subprocess.Popen([sys.executable, CRAWLER_SCRIPT, base_url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
        while True:
            if _stop_event.is_set():
                try:
                    p.terminate()
                except Exception:
                    pass
                _status["stage"] = "error"
                _status["message"] = "Stopped by user."
                _status["running"] = False
                return
            line = p.stdout.readline()
            if not line:
                break
            append_log(line.rstrip())
        rc = p.wait(timeout=10)
        append_log(f"[*] Crawler finished (exit {rc})")
        crawl_end = time.perf_counter()
        crawl_seconds = round(crawl_end - crawl_start, 2)
        _status["crawl_seconds"] = crawl_seconds
        append_log(f"[+] Crawl time: {crawl_seconds}s")
        # If crawler failed AND did not produce fresh output, stop early
        endpoints_ok = os.path.exists(endpoints_path) and os.path.getsize(endpoints_path) > 0
        cookies_ok = os.path.exists(cookies_path) and os.path.getsize(cookies_path) > 0
        if rc != 0 and not endpoints_ok:
            _status["stage"] = "error"
            _status["message"] = "Crawler failed to run (no endpoints produced). Fix ChromeDriver/offline setup, then retry."
            _status["running"] = False
            return
        if rc != 0:
            _status["warnings"].append("Crawler exited non-zero; crawl coverage may be incomplete (continuing with any saved endpoints).")
    except Exception as e:
        _status["stage"] = "error"
        _status["message"] = f"Crawler error: {e}"
        _status["running"] = False
        return

    # 2) load endpoints and cookies
    data = parse_endpoints(ENDPOINTS_FILE)
    urls = list(dict.fromkeys(data.get("urls", [])))  # preserve order unique
    xhrs = list(dict.fromkeys(data.get("xhrs", [])))
    forms = data.get("forms", []) or []

    # merge urls + xhrs (xhrs are valuable for SPA apps)
    all_urls = list(dict.fromkeys(urls + xhrs))

    # Filter out non-http(s) and obvious static assets from the scan set
    all_urls = [u for u in all_urls if is_http_url(u) and not is_static(u)]

    # Keep scanning strictly within target origin (prevents false positives on external links)
    all_urls = [u for u in all_urls if same_origin(u, base_url)]

    append_log(f"[*] Loaded {len(urls)} URLs, {len(forms)} forms, {len(xhrs)} XHRs.")



    # Publish initial KPIs so the UI refresh button can show crawl counts immediately
    try:
        _set_last_results({
            "target": base_url,
        "target_key": target_key,
        "kpis": {"urls": len(urls), "forms": len(forms), "xhrs": len(xhrs)},
            "target_key": target_key,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "timings": {"crawl_seconds": _status.get("crawl_seconds"), "scan_seconds": _status.get("scan_seconds"), "total_seconds": _status.get("total_seconds")},
            "findings": [],
            "kpis": {"urls": len(urls), "forms": len(forms), "xhrs": len(xhrs)},
        })
    except Exception:
        pass
    _status["stage"] = "scanning"
    _status["message"] = "Scanning..."


    scan_start = time.perf_counter()
    _status["scan_started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    auth_sess = requests.Session()
    anon_sess = requests.Session()
    auth_sess.headers.update({"User-Agent": "LabScanner/1.0"})
    anon_sess.headers.update({"User-Agent": "LabScanner/1.0"})

    load_cookies_to_session(auth_sess, COOKIES_FILE, base_url)
    append_log("[*] Loaded cookies from crawler into session.")

    # Auth context for scanners that use safe_request()
    auth_ctx: AuthCtx = {"session": auth_sess, "base": base_url, "verify_ssl": VERIFY_SSL}
    # Optional: auto-login to WebGoat via requests (if enabled)
    if WEBGOAT_AUTOLOGIN and "/WebGoat" in base_url:
        if webgoat_requests_login(auth_sess, base_url):
            append_log("[*] WebGoat auto-login successful (requests).")
        else:
            append_log("[!] WebGoat auto-login failed (requests). You may need MANUAL_LOGIN=1 or correct WEBGOAT_USER/WEBGOAT_PASS.")

    anon_ctx: AuthCtx = {"session": anon_sess, "base": base_url, "verify_ssl": VERIFY_SSL}

    # Juice Shop SPA route seeds (so DOM XSS in #/search is testable even if the crawler dropped fragments)
    try:
        home = safe_request(base_url, anon_ctx, method='GET')
        if home is not None and 'juice shop' in ((home.text or '').lower()):
            spa_search = base_url.rstrip('/') + '/#/search'
            spa_search_q = base_url.rstrip('/') + '/#/search?q=test'
            all_urls = list(dict.fromkeys(all_urls + [spa_search, spa_search_q]))
            append_log('[*] Detected Juice Shop; added SPA seeds: #/search')
    except Exception:
        pass



    # WebGoat lesson expansion (helps discover lesson entrypoints without manual clicking)
    extra_lessons = []
    if "/WebGoat" in base_url:
        extra_lessons = expand_webgoat_lessons(auth_sess, base_url, xhrs)
        if extra_lessons:
            append_log(f"[*] WebGoat lesson expansion added {len(extra_lessons)} lesson URLs.")
            all_urls = list(dict.fromkeys(all_urls + extra_lessons))
        else:
            append_log("[!] WebGoat lesson expansion returned 0 URLs (check you're logged in / lessonmenu reachable).")


    findings = []
    scanned = 0

    last_push = time.time()
    last_len = 0


    # Targeted login SQLi/auth-bypass check (high signal on Juice Shop-like apps)
    try:
        findings += scan_login_sqli_bypass(anon_ctx)
    except Exception:
        pass

    # Scan up to MAX_URLS (deterministic)
    for u in all_urls[:MAX_URLS]:
        if not is_http_url(u):
            continue
        # Avoid killing authenticated session mid-scan
        if is_logoutish(u) or should_skip_url(u):
            continue
        # Skip obvious static assets (keeps scanning focused)
        try:
            pu = urllib.parse.urlparse(u)
            if (pu.path or '').lower().endswith(tuple(STATIC_EXT)):
                continue
        except Exception:
            pass
        if _stop_event.is_set():
            _status["stage"] = "error"
            _status["message"] = "Stopped by user."
            _status["running"] = False
            return

        scanned += 1
        _status["message"] = f"Scanning ({scanned}/{min(len(all_urls), MAX_URLS)})..."
        append_log(f"[*] Scanning: {u}")

        # High-confidence checks
        findings += scan_security_misconfig(u, auth_sess)
        findings += scan_exceptional_conditions(u, auth_sess)

        # Access control (needs both sessions)
        findings += scan_broken_access_control(u, auth_sess, anon_sess)
        findings += scan_query_params_active(u, auth_ctx)
        findings += scan_sqli_boolean_based(u, auth_ctx)

        # Active form checks (best-effort)
        findings += scan_forms_active(u, auth_ctx)


        # Push partial results periodically so the Refresh button can show progress
        try:
            if len(findings) != last_len or scanned % 10 == 0 or (time.time() - last_push) > 2.0:
                last_len = len(findings)
                last_push = time.time()
                _status["findings_count"] = last_len
                _set_last_results({
                    "target": base_url,
                    "target_key": target_key,
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "findings": findings,
                    "kpis": {"urls": len(urls), "forms": len(forms), "xhrs": len(xhrs)},
                })
        except Exception:
            pass

    scan_end = time.perf_counter()
    scan_seconds = round(scan_end - scan_start, 2)
    _status["scan_seconds"] = scan_seconds
    total_seconds = round(scan_end - total_start, 2)
    _status["total_seconds"] = total_seconds
    append_log(f"[+] Scan time: {scan_seconds}s")
    append_log(f"[+] Total time: {total_seconds}s")

    results = {
        "target": base_url,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "timings": {"crawl_seconds": _status.get("crawl_seconds"), "scan_seconds": _status.get("scan_seconds"), "total_seconds": _status.get("total_seconds")},
        "manual_login": MANUAL_LOGIN,
        "max_urls": MAX_URLS,
        "counts": {"urls": len(urls), "forms": len(forms), "xhrs": len(xhrs)},
        "findings": findings,
        "notes": {
            "confidence_levels": {
                "Confirmed": "Strong external evidence (direct header/body proof or strong differential signal).",
                "Medium": "Suspicious and supported by signals, but may still require validation.",
            }
        }
    }

    # Store results in memory so the UI does not rely on the JSON file
    _set_last_results(results)

    try:
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        append_log(f"[*] Results saved to {RESULTS_FILE}")
    except Exception as e:
        _status["warnings"].append(f"Failed to write results file: {e}")

    _status["findings_count"] = len(findings)
    _status["stage"] = "done"
    _status["message"] = f"Done. Crawl {_status.get('crawl_seconds')}s | Scan {_status.get('scan_seconds')}s | Total {_status.get('total_seconds')}s"
    _status["running"] = False

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("home.html", manual_login=MANUAL_LOGIN, max_urls=MAX_URLS, max_pages=MAX_PAGES, allowed_netlocs=ALLOWED_NETLOCS)


@app.route("/index")
def scan_page():
    # Scan UI page
    return render_template("index.html", manual_login=MANUAL_LOGIN, max_urls=MAX_URLS, max_pages=MAX_PAGES, allowed_netlocs=ALLOWED_NETLOCS)

@app.route("/scan")
def scan_page_alias():
    # Backward-compatible alias (older links)
    return scan_page()

@app.route("/report")
def report_page():
    # Report dashboard page (charts)
    return render_template("report.html", manual_login=MANUAL_LOGIN, max_urls=MAX_URLS, max_pages=MAX_PAGES, allowed_netlocs=ALLOWED_NETLOCS)

@app.route("/api/start", methods=["POST"])
def api_start():
    if _status["running"]:
        return jsonify({"ok": False, "error": "Already running"}), 409
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"ok": False, "error": "Missing target"}), 400

    # Clear any previous results so the UI doesn't show stale findings
    try:
        _set_last_results({
            "target": normalize_base(target),
            "target_key": normalize_target_key(target),
            "findings": [],
            "kpis": {"urls": 0, "forms": 0, "xhrs": 0},
        })
    except Exception:
        _set_last_results({
            "target": target,
            "target_key": normalize_target_key(target),
            "findings": [],
            "kpis": {"urls": 0, "forms": 0, "xhrs": 0},
        })

    _status["stage"] = "starting"
    _status["message"] = "Starting scan..."
    _status["target"] = target
    _status["log"] = ""
    _status["findings_count"] = 0

    # Kick worker thread
    t = threading.Thread(target=run_crawl_and_scan, args=(target,), daemon=True)
    t.start()
    return jsonify({"ok": True})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    # Backward-compatible alias for older UI builds
    return api_start()

@app.route("/api/status")
def api_status():
    return jsonify(_status)

@app.route("/api/results")
def api_results():
    """
    Return the latest results from memory.

    If the client supplies ?target=..., only return results that match that target's base/origin.
    This prevents stale findings from a previous scan showing up when the user hasn't started a new scan yet.
    """
    req_target = (request.args.get("target") or "").strip()
    mem = _get_last_results()

    if mem and isinstance(mem, dict):
        if req_target:
            try:
                mem_key = str(mem.get("target_key") or normalize_target_key(str(mem.get("target", ""))))
                req_key = normalize_target_key(req_target)
                if mem_key != req_key:

                    return jsonify({
                        "ok": False,
                        "findings": [],
                        "kpis": {"urls": 0, "forms": 0, "xhrs": 0},
                        "error": "No results for this target"
                    })
            except Exception:
                return jsonify({
                    "ok": False,
                    "findings": [],
                    "kpis": {"urls": 0, "forms": 0, "xhrs": 0},
                    "error": "Invalid target"
                })

        mem.setdefault("findings", [])
        mem.setdefault("kpis", {"urls": 0, "forms": 0, "xhrs": 0})
        mem["ok"] = True
        return jsonify(mem)

    return jsonify({
        "ok": False,
        "findings": [],
        "kpis": {"urls": 0, "forms": 0, "xhrs": 0},
        "error": "No results yet"
    })
# -----------------------------
# PDF report export
# -----------------------------
def _pdf_wrap_text(txt: str, width: int = 110) -> List[str]:
    if txt is None:
        return []
    s = str(txt).replace("\r", "")
    lines: List[str] = []
    for raw in s.split("\n"):
        raw = raw.strip()
        if not raw:
            lines.append("")
            continue
        while len(raw) > width:
            lines.append(raw[:width])
            raw = raw[width:]
        lines.append(raw)
    return lines


def _pdf_escape(s: str) -> str:
    """Escape text for PDF literal strings (minimal)."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    out = []
    for ch in s:
        o = ord(ch)
        if 32 <= o <= 126:
            out.append(ch)
        elif ch in ("\n", "\r", "\t"):
            out.append(" ")
        else:
            out.append("?")
    return "".join(out)

def _build_minimal_pdf_from_lines(pages):
    """
    Dependency-free PDF generator (Helvetica Type1).
    pages: list[list[str]]
    """
    import datetime
    W, H = 612, 792  # letter
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]  # xref 0 object

    def write_obj(obj_num, body_bytes: bytes):
        offsets.append(len(out))
        out.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        out.extend(body_bytes)
        if not body_bytes.endswith(b"\n"):
            out.extend(b"\n")
        out.extend(b"endobj\n")

    font_obj = 4
    next_obj = 5

    # Font object
    write_obj(font_obj, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_obj_nums = []
    page_content_obj_nums = []

    for page_lines in pages:
        # Content stream
        x = 50
        y_start = 760
        leading = 12

        safe_lines = [_pdf_escape(ln) for ln in page_lines]
        ops = []
        ops.append("BT")
        ops.append("/F1 10 Tf")
        ops.append(f"{leading} TL")
        ops.append(f"{x} {y_start} Td")
        for i, ln in enumerate(safe_lines):
            if i == 0:
                ops.append(f"({ln}) Tj")
            else:
                ops.append("T*")
                ops.append(f"({ln}) Tj")
        ops.append("ET")
        stream = ("\n".join(ops) + "\n").encode("latin-1", "replace")
        content_obj = next_obj
        next_obj += 1
        content_body = b"<< /Length %d >>\nstream\n%s\nendstream\n" % (len(stream), stream)
        write_obj(content_obj, content_body)

        # Page object
        page_obj = next_obj
        next_obj += 1
        page_body = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
            f"/Contents {content_obj} 0 R >>"
        ).encode("ascii")
        write_obj(page_obj, page_body)

        page_obj_nums.append(page_obj)
        page_content_obj_nums.append(content_obj)

    # Pages object (2)
    kids = " ".join([f"{n} 0 R" for n in page_obj_nums]).encode("ascii")
    pages_body = b"<< /Type /Pages /Kids [ " + kids + b" ] /Count " + str(len(page_obj_nums)).encode("ascii") + b" >>"
    # We'll write catalog (1) and pages (2) after building kids,
    # but object numbers must exist. We'll insert them at the end and adjust xref accordingly by writing now.

    # Catalog object (1)
    # NOTE: we must write obj 1 and 2 in order for stable xref entries
    # However we already wrote obj 4+. That's okay in PDFs.
    write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    write_obj(2, pages_body)

    # Info object (3)
    now = datetime.datetime.now().strftime("D:%Y%m%d%H%M%S")
    info_body = f"<< /Producer (CrawlerScanner) /CreationDate ({now}) >>".encode("ascii")
    write_obj(3, info_body)

    # Build xref
    xref_start = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    # offsets list includes obj 0 then obj 4.. then obj 1,2,3 in the order written.
    # BUT xref requires entries by object number. We'll rebuild mapping.
    # We stored offsets in write order; we need obj->offset.
    # Let's reconstruct: we know we wrote objects in this exact sequence:
    # 4, then for each page: content, page, then 1,2,3.
    obj_numbers = []
    obj_numbers.append(4)
    for i in range(len(pages)):
        obj_numbers.append(5 + i*2)      # content
        obj_numbers.append(6 + i*2)      # page
    # then 1,2,3
    obj_numbers.extend([1,2,3])

    obj_to_off = {n: off for n, off in zip(obj_numbers, offsets[1:])}

    max_obj = max(obj_to_off.keys()) if obj_to_off else 0
    # Rewrite xref properly: we will rebuild from scratch and overwrite what we wrote (simpler: rebuild whole PDF).
    # Instead, generate xref/trailer freshly from obj_to_off and append a second xref section (allowed).
    # We'll do a clean xref section for 0..max_obj.
    out = out[:xref_start]
    out.extend(f"xref\n0 {max_obj+1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for n in range(1, max_obj+1):
        off = obj_to_off.get(n, 0)
        if off == 0:
            out.extend(b"0000000000 00000 n \n")
        else:
            out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    trailer = f"<< /Size {max_obj+1} /Root 1 0 R /Info 3 0 R >>".encode("ascii")
    out.extend(b"trailer\n")
    out.extend(trailer + b"\n")
    out.extend(b"startxref\n")
    out.extend(f"{xref_start}\n".encode("ascii"))
    out.extend(b"%%EOF\n")
    return bytes(out)

def build_pdf_report(results: Dict[str, Any]) -> bytes:
    """
    Generate a PDF report.

    - If reportlab is installed, use it (richer layout).
    - Otherwise, fall back to a minimal built-in PDF generator (no extra deps).
    """
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        buff = BytesIO()
        c = canvas.Canvas(buff, pagesize=letter)
        w, h = letter

        def new_page():
            nonlocal y
            c.showPage()
            y = h - 50
            c.setFont("Helvetica", 10)

        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, h - 40, "CrawlerScanner Report")
        c.setFont("Helvetica", 10)

        target = (results or {}).get("target") or "-"
        gen = (results or {}).get("generated_at") or "-"
        y = h - 70
        c.drawString(40, y, f"Target: {target}")
        y -= 14
        c.drawString(40, y, f"Generated: {gen}")
        y -= 18

        findings = (results or {}).get("findings") or []
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        counts = {s: 0 for s in sev_order}
        for f in findings:
            s = str((f or {}).get("severity") or "Info").title()
            if s not in counts:
                s = "Info"
            counts[s] += 1

        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Summary")
        y -= 14
        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Total findings: {len(findings)}")
        y -= 14
        c.drawString(40, y, "By severity: " + ", ".join([f"{s}={counts[s]}" for s in sev_order]))
        y -= 20

        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Findings")
        y -= 14
        c.setFont("Helvetica", 9)

        if not findings:
            c.drawString(40, y, "No findings.")
            c.save()
            return buff.getvalue()

        for i, f in enumerate(findings, start=1):
            f = f or {}
            if y < 90:
                new_page()

            sev = str(f.get("severity") or "Info")
            typ = str(f.get("type") or "Finding")
            url = str(f.get("url") or "-")
            param = f.get("parameter") or f.get("param") or ""
            owasp = str(f.get("owasp") or "-")

            c.setFont("Helvetica-Bold", 10)
            c.drawString(40, y, f"{i}. {typ}  [{sev}]")
            y -= 12
            c.setFont("Helvetica", 9)
            for line in _pdf_wrap_text(f"URL: {url}", 120):
                if y < 70: new_page()
                c.drawString(45, y, line)
                y -= 11
            if param:
                for line in _pdf_wrap_text(f"Parameter: {param}", 120):
                    if y < 70: new_page()
                    c.drawString(45, y, line)
                    y -= 11
            c.drawString(45, y, f"OWASP: {owasp}")
            y -= 11

            ev = f.get("evidence")
            if isinstance(ev, (dict, list)):
                try:
                    ev_txt = json.dumps(ev, indent=2)
                except Exception:
                    ev_txt = str(ev)
            else:
                ev_txt = "" if ev is None else str(ev)

            ev_txt = ev_txt[:1500]
            if ev_txt:
                c.setFont("Helvetica-Oblique", 9)
                c.drawString(45, y, "Evidence:")
                y -= 11
                c.setFont("Helvetica", 8)
                for line in _pdf_wrap_text(ev_txt, 120):
                    if y < 70: new_page()
                    c.drawString(55, y, line)
                    y -= 10
                y -= 6

            y -= 8

        c.save()
        return buff.getvalue()
    except Exception:
        # Fallback: minimal PDF, no external dependencies
        lines = []
        target = (results or {}).get("target") or "-"
        gen = (results or {}).get("generated_at") or "-"
        lines.append("CrawlerScanner Report")
        lines.append(f"Target: {target}")
        lines.append(f"Generated: {gen}")
        lines.append("")
        findings = (results or {}).get("findings") or []
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        counts = {s: 0 for s in sev_order}
        for f in findings:
            s = str((f or {}).get("severity") or "Info").title()
            if s not in counts:
                s = "Info"
            counts[s] += 1
        lines.append("Summary")
        lines.append(f"Total findings: {len(findings)}")
        lines.append("By severity: " + ", ".join([f"{s}={counts[s]}" for s in sev_order]))
        lines.append("")
        lines.append("Findings")
        lines.append("")

        if not findings:
            lines.append("No findings.")
        else:
            for i, f in enumerate(findings, start=1):
                f = f or {}
                sev = str(f.get("severity") or "Info")
                typ = str(f.get("type") or "Finding")
                url = str(f.get("url") or "-")
                param = f.get("parameter") or f.get("param") or ""
                owasp = str(f.get("owasp") or "-")
                lines.append(f"{i}. {typ} [{sev}]")
                lines.extend(_pdf_wrap_text(f"URL: {url}", 95))
                if param:
                    lines.extend(_pdf_wrap_text(f"Parameter: {param}", 95))
                lines.append(f"OWASP: {owasp}")
                ev = f.get("evidence")
                if isinstance(ev, (dict, list)):
                    try:
                        ev_txt = json.dumps(ev, indent=2)
                    except Exception:
                        ev_txt = str(ev)
                else:
                    ev_txt = "" if ev is None else str(ev)
                ev_txt = ev_txt[:1200]
                if ev_txt:
                    lines.append("Evidence:")
                    lines.extend(["  " + ln for ln in _pdf_wrap_text(ev_txt, 95)])
                lines.append("")

        # paginate
        per_page = 55
        pages = [lines[i:i+per_page] for i in range(0, len(lines), per_page)]
        return _build_minimal_pdf_from_lines(pages)

@app.route("/download/pdf")
def download_pdf():
    """
    Download the latest scan report as PDF (manual button only).

    This endpoint uses the in-memory last results cache (no dependency on scan_results.json).
    Optional: ?target=... to ensure the PDF matches the current target.
    """
    req_target = (request.args.get("target") or "").strip()
    results = _get_last_results()
    if not results or not isinstance(results, dict) or results.get("findings") is None:
        return "No results to export", 404

    if req_target:
        try:
            if normalize_base(str(results.get("target", ""))) != normalize_base(req_target):
                return "No results for this target", 404
        except Exception:
            return "Invalid target", 400

    pdf_bytes = build_pdf_report(results)
    from io import BytesIO
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="scan_report.pdf",
    )

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CrawlerScanner</title>
  <style>
    :root{--bg:#0b0f16;--card:#111827;--card2:#0f172a;--muted:#9ca3af;--text:#e5e7eb;--b:#1f2937;--accent:#60a5fa;--ok:#34d399;--warn:#fbbf24;--bad:#fb7185;}
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:linear-gradient(180deg,#0b0f16,#070a0f 70%);color:var(--text);}
    .wrap{max-width:980px;margin:22px auto;padding:0 14px;}
    .title{font-size:22px;font-weight:700;margin:0 0 6px;}
    .sub{color:var(--muted);margin:0 0 16px;font-size:13px;}
    .card{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--b);border-radius:14px;padding:14px 16px;margin:14px 0;box-shadow:0 10px 30px rgba(0,0,0,.25);}
    .hero{position:relative;}
    .spider{position:absolute;top:12px;right:14px;width:44px;height:44px;opacity:.9;}

    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
    input{flex:1;min-width:320px;background:#0b1220;border:1px solid #243043;color:var(--text);padding:10px 12px;border-radius:10px;outline:none;}
    select{background:#0b1220;border:1px solid #243043;color:var(--text);padding:10px 12px;border-radius:10px;outline:none;}

    button{background:#0b1220;border:1px solid #243043;color:var(--text);padding:10px 12px;border-radius:10px;cursor:pointer}
    button:hover{border-color:#35507a}
    button:disabled{opacity:.5;cursor:not-allowed}
    .pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #243043;background:#0b1220;border-radius:999px;padding:6px 10px;color:var(--muted);font-size:12px;}
    .kpi{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
    .kpi .pill b{color:var(--text)}
    .hr{height:1px;background:#162033;margin:10px 0}
    .finding{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:10px 0;border-top:1px solid #162033}
    .finding:first-child{border-top:none}
    .fleft{min-width:0}
    .ftype{font-weight:700}
    .fmeta{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-all}
    .sev{font-size:12px;padding:4px 8px;border-radius:999px;border:1px solid #243043;background:#0b1220;white-space:nowrap}
    .sev.high{border-color:rgba(251,113,133,.55);color:var(--bad)}
    .sev.med{border-color:rgba(251,191,36,.55);color:var(--warn)}
    .sev.low{border-color:rgba(96,165,250,.55);color:var(--accent)}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #243043;border-radius:10px;padding:10px;margin:8px 0 0;color:#d1d5db;font-size:12px;max-height:260px;overflow:auto}
    /* modal */
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:18px;}
    .modal .box{max-width:820px;width:100%;background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--b);border-radius:16px;box-shadow:0 18px 60px rgba(0,0,0,.45);padding:14px 16px;}
    .modal .top{display:flex;justify-content:space-between;align-items:center;gap:10px;}
    .modal .top h3{margin:0;font-size:16px}
    .x{background:transparent;border:1px solid #243043;border-radius:10px;padding:6px 10px;cursor:pointer}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card hero">
      <img class="spider" alt="spider" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAA3klEQVR42u2ZSxKEIAwFuf+lcetCLTEfnkl3FQs3Q16PGNAxAAAAAAAAAADymV1D343W4ctLmAujbvgzV9eKEjyKyhTgLtHjFs0QELaUrGt1GoZMV7EWGhF+y4P064TeArZ3kNUCvARItc6VAFYBkvuGKTQQ0FmC5B5/BISUPjO0/Od3Sihx5C0XPkNCyZcfhGft/1xG600QAm4Kigzb9plAF+genlbIQehH+wBPMW/mkQzvIeHLfFLhvV+Ly0iI/joUMf/W8CsSMupwFWD9LZVaTHt/tbMIAAAAAMADB0+4n4vUVd3AAAAAAElFTkSuQmCC"/>
      <div class="title">CrawlerScanner</div>
      <div class="sub">Crawl target (Selenium) → collect endpoints/cookies → run lightweight checks (SQLi / XSS / basic security headers / access-control heuristics).</div>
    </div>

    <div class="card">
      <div class="row">
        <input id="target" placeholder="http://127.0.0.1:8080/WebGoat/" />
        <button type="button" id="btnStart" onclick="startScan()">Start scan</button>
        <button type="button" id="btnRefresh" onclick="manualRefresh()">Refresh results</button>
        <button type="button" id="btnPdf" onclick="downloadPdf()" disabled>Download PDF</button>
        <select id="sevFilter" onchange="applyFilter()" title="Filter by severity">
          <option value="all" selected>All severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
      </div>
      <div class="kpi" id="kpi"></div>
      <div class="hr"></div>
      <div class="pill" id="status">Status: idle</div>
      <pre id="log" style="display:none"></pre>
    </div>

    <div class="card">
      <div style="font-weight:700;margin-bottom:8px">Findings</div>
      <div id="summary" style="color:var(--muted);font-size:13px;margin-bottom:10px">No findings yet.</div>
      <div id="findings"></div>
    </div>
  </div>

  <div class="modal" id="modal" onclick="backdropClose(event)">
    <div class="box" onclick="event.stopPropagation()">
      <div class="top">
        <h3 id="mTitle">Details</h3>
        <button type="button" class="x" onclick="closeModal()">Close</button>
      </div>
      <div id="mBody"></div>
    </div>
  </div>

<script>
let POLL = null;
let CURRENT_FILTER = 'all';
let LAST_DATA = null;
let HAS_STARTED = false;
let ACTIVE_TARGET = '';

function setBusy(b){
  document.getElementById('btnStart').disabled = b;
}

function clearView(){
  // Reset filter + clear findings area
  CURRENT_FILTER = 'all';
  const sel = document.getElementById('sevFilter');
  if(sel) sel.value = 'all';
  render({findings: [], kpis: {urls: 0, forms: 0, xhrs: 0}});
  const logEl = document.getElementById('log');
  if(logEl){
    logEl.style.display = 'none';
    logEl.textContent = '';
  }
}

function init(){
  HAS_STARTED = false;
  ACTIVE_TARGET = '';
  LAST_DATA = null;
  clearView();

  // Update status pill (without pulling stale results)
  fetch('/api/status').then(r=>r.json()).then(s=>{
    if(!s) return;
    let extra='';
    if(typeof s.crawl_seconds === 'number') extra += ` | crawl ${s.crawl_seconds}s`;
    if(typeof s.scan_seconds === 'number') extra += ` | scan ${s.scan_seconds}s`;
    if(typeof s.total_seconds === 'number') extra += ` | total ${s.total_seconds}s`;
    document.getElementById('status').textContent = `Status: ${s.stage} — ${s.message}${extra}`;
  }).catch(()=>null);
}


function downloadPdf(){
  const tgt = (ACTIVE_TARGET || document.getElementById('target').value.trim());
  const url = '/download/pdf' + (tgt ? ('?target=' + encodeURIComponent(tgt)) : '');
  window.location = url;
}


function applyFilter(){
  const sel = document.getElementById('sevFilter');
  CURRENT_FILTER = sel ? sel.value : 'all';
  if(LAST_DATA) render(LAST_DATA);
}

function renderEvidence(ev){
  if(ev === null || ev === undefined) return "";
  if(typeof ev === "string") return ev;
  try { return JSON.stringify(ev, null, 2); } catch(e) { return String(ev); }
}

function fmtKpi(label, value){
  return `<span class="pill"><span>${label}:</span> <b>${value}</b></span>`;
}

function sevClass(s){
  s = (s||'').toLowerCase();
  if(s.includes('high')) return 'high';
  if(s.includes('medium')) return 'med';
  return 'low';
}

function showModal(f){
  document.getElementById('mTitle').textContent = `${f.type} (${f.severity||'info'})`;
  const body = `
    <div class="fmeta"><b>OWASP:</b> ${f.owasp||'-'}</div>
    <div class="fmeta"><b>URL:</b> ${f.url||'-'}</div>
    ${f.parameter ? `<div class="fmeta"><b>Parameter:</b> ${f.parameter}</div>` : ``}
    ${f.evidence ? `<div class="fmeta"><b>Evidence:</b></div><pre class="mono small" style="white-space:pre-wrap;margin:6px 0 0 0;">${renderEvidence(f.evidence)}</pre>` : ``}
    ${f.request ? `<div class="fmeta" style="margin-top:8px"><b>Request:</b></div><pre>${f.request}</pre>` : ``}
    ${f.response_snippet ? `<div class="fmeta" style="margin-top:8px"><b>Response snippet:</b></div><pre>${f.response_snippet}</pre>` : ``}
  `;
  document.getElementById('mBody').innerHTML = body;
  document.getElementById('modal').style.display = 'flex';
}

function closeModal(){ document.getElementById('modal').style.display = 'none'; }
function backdropClose(e){ if(e.target.id === 'modal') closeModal(); }

function render(data){
  LAST_DATA = data;
  const fAll = data.findings || [];
  const f = (CURRENT_FILTER === 'all') ? fAll : fAll.filter(x => String((x.severity||'Info')) === CURRENT_FILTER);
  const k = data.kpis || {};
  const kpi = document.getElementById('kpi');
  kpi.innerHTML = [
    fmtKpi('URLs', k.urls ?? '?'),
    fmtKpi('Forms', k.forms ?? '?'),
    fmtKpi('XHRs', k.xhrs ?? '?'),
    fmtKpi('Findings', (data.findings||[]).length),
    fmtKpi('Shown', (CURRENT_FILTER==='all') ? fAll.length : f.length),
  ].join(' ');
  const btnPdf = document.getElementById('btnPdf');
  if(btnPdf){ btnPdf.disabled = !(fAll && fAll.length); }
  const sel = document.getElementById('sevFilter');
  if(sel){ sel.value = CURRENT_FILTER; }

  const list = document.getElementById('findings');
  const sum = document.getElementById('summary');
    if(!f.length){
    sum.textContent = (fAll.length ? `No findings for filter: ${CURRENT_FILTER}` : 'No findings yet.');
    list.innerHTML = '';
    return;
  }
  sum.textContent = `Showing ${f.length} of ${fAll.length} finding(s) (filter: ${CURRENT_FILTER}). Click "Details" for proof/evidence.`;
  list.innerHTML = f.map((x,i)=>`
    <div class="finding">
      <div class="fleft">
        <div class="ftype">${x.type}</div>
        <div class="fmeta">${x.url || ''}</div>
      </div>
      <div class="row" style="gap:8px;flex-wrap:nowrap">
        <span class="sev ${sevClass(x.severity)}">${x.severity || 'info'}</span>
        <button type="button" class="btnDetails" data-idx="${i}">Details</button>
      </div>
    </div>
  `).join('');
  window.__FALL = fAll;
  window.__F = f;
  // Bind details buttons without using inline onclick (CSP-friendly)
  document.querySelectorAll('.btnDetails').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.getAttribute('data-idx') || '0');
      const item = (window.__F || [])[idx];
      if (item) showModal(item);
    });
  });
}

async function manualRefresh(){
  const t = document.getElementById('target').value.trim();
  if(t){
    HAS_STARTED = true;
    ACTIVE_TARGET = t;
  }
  await refresh();
}

async function refresh(){
  const s = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if(s){
    let extra='';
    if(typeof s.crawl_seconds === 'number') extra += ` | crawl ${s.crawl_seconds}s`;
    if(typeof s.scan_seconds === 'number') extra += ` | scan ${s.scan_seconds}s`;
    if(typeof s.total_seconds === 'number') extra += ` | total ${s.total_seconds}s`;
    document.getElementById('status').textContent = `Status: ${s.stage} — ${s.message}${extra}`;
    const logEl = document.getElementById('log');
    if(s.log && s.log.trim()){
      logEl.style.display = 'block';
      logEl.textContent = s.log;
    } else {
      logEl.style.display = 'none';
      logEl.textContent = '';
    }
  }

  // Don't display stale results until the user starts a scan in this page session
  if(!HAS_STARTED){
    clearView();
    return;
  }

  const tgt = (ACTIVE_TARGET || document.getElementById('target').value.trim());
  const r = await fetch('/api/results?target=' + encodeURIComponent(tgt)).then(r=>r.json()).catch(()=>null);
  if(r && r.ok){
    render(r);
  } else {
    clearView();
  }
}

async function pollOnce(){
  const s = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if(!s) return;
  let extra='';
    if(typeof s.crawl_seconds === 'number') extra += ` | crawl ${s.crawl_seconds}s`;
    if(typeof s.scan_seconds === 'number') extra += ` | scan ${s.scan_seconds}s`;
    if(typeof s.total_seconds === 'number') extra += ` | total ${s.total_seconds}s`;
    document.getElementById('status').textContent = `Status: ${s.stage} — ${s.message}${extra}`;
  const logEl = document.getElementById('log');
  if(s.log && s.log.trim()){
    logEl.style.display = 'block';
    logEl.textContent = s.log;
  } else {
    logEl.style.display = 'none';
    logEl.textContent = '';
  }

  if(s.stage === 'done' || s.stage === 'error'){
    if(POLL){ clearInterval(POLL); POLL = null; }
    setBusy(false);
    await refresh();
  }
}

async function startScan(){
  const target = document.getElementById('target').value.trim();
  if(!target){ alert('Please enter a target URL.'); return; }

  HAS_STARTED = true;
  ACTIVE_TARGET = target;
  clearView();

  setBusy(true);
  document.getElementById('status').textContent = 'Status: starting...';
  document.getElementById('log').style.display = 'none';
  document.getElementById('log').textContent = '';

  const res = await fetch('/api/start', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target})
  }).then(r=>r.json()).catch(()=>({ok:false, error:'Request failed'}));

  if(!res.ok){
    setBusy(false);
    document.getElementById('status').textContent = `Status: error — ${res.error || 'Failed to start'}`;
    return;
  }

  // Start polling status until done/error
  if(POLL) clearInterval(POLL);
  POLL = setInterval(pollOnce, 1000);
  await pollOnce();
}

window.addEventListener('load', init);
</script>
</body>
</html>"""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)


def extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    return extract_forms_from_html(html, base_url)