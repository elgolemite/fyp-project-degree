#!/usr/bin/env python3
"""
crawler_generic_v3_offline.py

Drop-in replacement for crawler_generic_v3.py that works in *offline / restricted-DNS* environments.

Key change:
- Does NOT require webdriver_manager to download ChromeDriver from googlechromelabs.github.io.
- Uses a locally available chromedriver if provided via:
    - environment variable CHROMEDRIVER_PATH (full path to chromedriver.exe)
    - or chromedriver available on PATH
If neither exists, it will try Selenium Manager (may still download; can fail offline).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urldefrag

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By


DEFAULT_MAX_PAGES = int(os.getenv("MAX_PAGES", "250"))
DEFAULT_SLEEP = float(os.getenv("CRAWL_SLEEP", "0.25"))

ENDPOINTS_OUT = os.getenv("ENDPOINTS_OUT", "endpoints.txt")
COOKIES_OUT = os.getenv("COOKIES_OUT", "cookies.json")

SKIP_SCHEMES = {"mailto", "data", "javascript", "tel"}

# URLs that *end the authenticated session* or otherwise ruin coverage
# Skip endpoints that would kill your session mid-crawl.
# Matches anywhere in the path, e.g. /WebGoat/logout or /rest/user/logout
SKIP_PATH_RE = re.compile(r"(?:^|/)(?:logout|logoff|signout)(?:\b|/|$)", re.IGNORECASE)
SKIP_QUERY_RE = re.compile(r"(?:^|&)(?:logout|logoff|signout)(?:=|&|$)", re.IGNORECASE)

def _should_skip_url(u: str) -> bool:
    try:
        p = urlparse(u)
    except Exception:
        return False
    path = p.path or ""
    q = p.query or ""
    if SKIP_PATH_RE.search(path):
        return True
    if SKIP_QUERY_RE.search(q):
        return True
    return False

SKIP_EXT_RE = re.compile(r".*\.(?:png|jpg|jpeg|gif|svg|ico|css|js|woff2?|ttf|eot|map)$", re.IGNORECASE)


def _norm_url(u: str) -> Optional[str]:
    u = (u or "").strip()
    if not u:
        return None
    # Drop fragments (but keep SPA "#/route" – treat as significant only if it starts with "#/")
    if "#/" not in u:
        u, _ = urldefrag(u)

    p = urlparse(u)
    if p.scheme and p.scheme.lower() in SKIP_SCHEMES:
        return None
    if p.scheme and p.scheme.lower() not in {"http", "https"}:
        return None

    # Skip obvious static assets
    if SKIP_EXT_RE.match(p.path or ""):
        return None

    return u


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _build_driver() -> webdriver.Chrome:
    opts = Options()
    if os.getenv("HEADLESS", "0").strip().lower() in ("1", "true", "yes", "y"):
        opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1200,900")

    chromedriver_path = os.getenv("CHROMEDRIVER_PATH", "").strip()

    # 1) Explicit path
    if chromedriver_path:
        return webdriver.Chrome(service=Service(chromedriver_path), options=opts)

    # 2) PATH or Selenium Manager
    try:
        return webdriver.Chrome(options=opts)
    except WebDriverException as e:
        # 3) Optional webdriver_manager fallback (needs internet)
        if os.getenv("ALLOW_WEBDRIVER_MANAGER", "0").strip().lower() in ("1", "true", "yes", "y"):
            try:
                from webdriver_manager.chrome import ChromeDriverManager  # type: ignore
                return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
            except Exception:
                raise e
        raise e


def _extract_links(driver: webdriver.Chrome, base: str) -> List[str]:
    out: List[str] = []
    for a in driver.find_elements(By.TAG_NAME, "a"):
        href = a.get_attribute("href") or ""
        u = _norm_url(href)
        if not u:
            continue
        if _should_skip_url(u):
            continue
        if _same_origin(base, u):
            out.append(u)
    return out


def _extract_forms(driver: webdriver.Chrome, base: str) -> List[Dict[str, Any]]:
    forms_out: List[Dict[str, Any]] = []
    for f in driver.find_elements(By.TAG_NAME, "form"):
        action = f.get_attribute("action") or base
        method = (f.get_attribute("method") or "GET").upper()
        action = urljoin(base, action)
        action = _norm_url(action) or ""
        if not action or not _same_origin(base, action):
            continue

        inputs = f.find_elements(By.CSS_SELECTOR, "input,textarea,select")
        fields: List[Dict[str, str]] = []
        for inp in inputs:
            name = (inp.get_attribute("name") or "").strip()
            itype = (inp.get_attribute("type") or "").strip().lower()
            if not name:
                continue
            fields.append({"name": name, "type": itype})
        forms_out.append({"action": action, "method": method, "fields": fields})
    return forms_out


def _capture_xhr_urls(driver: webdriver.Chrome, base: str) -> List[str]:
    out: List[str] = []
    try:
        entries = driver.execute_script("return performance.getEntriesByType('resource').map(e=>e.name);")
        if isinstance(entries, list):
            for u in entries:
                if isinstance(u, str):
                    u = _norm_url(u)
                    if u and _same_origin(base, u):
                        out.append(u)
    except Exception:
        pass
    return out



def _is_login_page(driver) -> bool:
    try:
        u = (driver.current_url or "").lower()
        if "/login" in u or "signin" in u:
            return True
        # Heuristic: presence of username+password fields
        has_user = bool(driver.find_elements(By.CSS_SELECTOR, "input[name='username'],input#username,input[name='email'],input[type='email']"))
        has_pass = bool(driver.find_elements(By.CSS_SELECTOR, "input[name='password'],input#password,input[type='password']"))
        return has_user and has_pass
    except Exception:
        return False

def _attempt_autologin(driver, username: str, password: str) -> bool:
    """Best-effort auto login for lab apps (incl. WebGoat).
    Controlled by env AUTO_LOGIN=1 and LOGIN_USER/LOGIN_PASS.
    """
    try:
        # Find fields
        user_el = None
        for sel in ["input[name='username']", "input#username", "input[name='email']", "input[type='email']"]:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            if els:
                user_el = els[0]
                break
        pass_el = None
        for sel in ["input[name='password']", "input#password", "input[type='password']"]:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            if els:
                pass_el = els[0]
                break
        if not user_el or not pass_el:
            return False

        try:
            user_el.clear()
        except Exception:
            pass
        user_el.send_keys(username)

        try:
            pass_el.clear()
        except Exception:
            pass
        pass_el.send_keys(password)

        # Submit
        btn = None
        for sel in ["button[type='submit']", "input[type='submit']", "button[name='login']", "button"]:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            if els:
                btn = els[0]
                break
        if btn:
            btn.click()
        else:
            try:
                pass_el.submit()
            except Exception:
                return False

        time.sleep(2)
        return not _is_login_page(driver)
    except Exception:
        return False

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python crawler_generic_v3_offline.py <target_url>")
        return 2

    target = sys.argv[1].strip()
    if not target:
        return 2

    target = _norm_url(target) or target
    print(f"[*] Opening target: {target}")

    max_pages = int(os.getenv("MAX_PAGES", str(DEFAULT_MAX_PAGES)))
    manual_login = os.getenv("MANUAL_LOGIN", "0").strip().lower() in ("1", "true", "yes", "y")
    login_wait = int(os.getenv("LOGIN_WAIT_SECONDS", "90"))
    auto_login = os.getenv("AUTO_LOGIN", "0").strip().lower() in ("1","true","yes","y")
    login_user = os.getenv("LOGIN_USER", "guest")
    login_pass = os.getenv("LOGIN_PASS", "guest")

    driver = _build_driver()

    seen: Set[str] = set()
    q: deque[str] = deque()

    endpoints: List[str] = []
    xhrs: List[str] = []
    forms_all: List[Dict[str, Any]] = []

    try:
        driver.get(target)

        # Optional: auto-login (lab only)
        if (not manual_login) and auto_login and _is_login_page(driver):
            print("[*] AUTO_LOGIN=1 -> attempting automatic login...")
            if _attempt_autologin(driver, login_user, login_pass):
                print("[*] AUTO_LOGIN succeeded.")
            else:
                print("[!] AUTO_LOGIN failed (you may need MANUAL_LOGIN=1 or different LOGIN_USER/LOGIN_PASS).")

        if manual_login:
            print(f"[*] MANUAL_LOGIN=1 -> you have {login_wait}s to log in in the browser window...")
            time.sleep(max(5, login_wait))
            try:
                cur = driver.current_url
                cur = _norm_url(cur) or cur
                if cur and _same_origin(target, cur):
                    q.append(cur)
            except Exception:
                q.append(target)
        else:
            try:
                cur = driver.current_url
                cur = _norm_url(cur) or cur
                if cur and _same_origin(target, cur):
                    q.append(cur)
                else:
                    q.append(target)
            except Exception:
                q.append(target)

        while q and len(seen) < max_pages:
            u = q.popleft()
            if not u or u in seen:
                continue
            # Avoid visiting endpoints that would end the session (logout/logoff/signout)
            if _should_skip_url(u):
                print(f"[*] Skipping (session-killer): {u}")
                continue
            seen.add(u)

            print(f"[*] Visiting ({len(seen)}/{max_pages}): {u}")
            try:
                driver.get(u)
                time.sleep(DEFAULT_SLEEP)
            except Exception:
                continue

            endpoints.append(u)

            try:
                forms_all.extend(_extract_forms(driver, target))
            except Exception:
                pass

            try:
                xhrs.extend(_capture_xhr_urls(driver, target))
            except Exception:
                pass

            for link in _extract_links(driver, target):
                if link not in seen:
                    q.append(link)

        endpoints_u = sorted(set(endpoints))
        xhrs_u = sorted(set(xhrs))

        with open(ENDPOINTS_OUT, "w", encoding="utf-8") as f:
            for u in endpoints_u:
                f.write(f"URL: {u}\n")
            for x in xhrs_u:
                f.write(f"XHR: {x}\n")
            for form in forms_all:
                f.write(f"Form: {form.get('action','')} (Method: {form.get('method','GET')})\n")
                for fld in form.get("fields", []):
                    f.write(f"  - {fld.get('name','')} ({fld.get('type','')})\n")

        cookies = driver.get_cookies()
        with open(COOKIES_OUT, "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=2)

        print("[+] Crawling finished.")
        print(f"[+] Endpoints saved to {ENDPOINTS_OUT}")
        print(f"[+] Cookies saved to {COOKIES_OUT}")
        return 0

    finally:
        try:
            driver.quit()
            print("[*] Browser closed.")
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())