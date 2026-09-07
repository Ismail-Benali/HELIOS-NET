"""HELIOS-NET :: tools/hn_publish.py
Zero-dependency Hacker News submission helper (Python stdlib only).

The PUBLIC HN API (https://github.com/HackerNews/API) is READ-ONLY:
it is a Firebase dump of internal data structures and exposes no write
endpoint.  Automated publishing therefore targets the website's own HTML
flow:

    1. POST https://news.ycombinator.com/login   (acct, pw)  -> session cookie
    2. GET  https://news.ycombinator.com/submit  (authed)    -> hidden CSRF fields
    3. POST https://news.ycombinator.com/r       (fnid + title, url|text) -> new item
       (modern HN posts submissions to /r, a redirect wrapper around
        the classic /submit endpoint; /submit answers with a blank form)

Credentials are read ONLY from environment variables (never from files):

    set  HN_USERNAME=h3lk3       & set HN_PASSWORD=..."
    python tools/hn_publish.py --title "..." --url "https://..." [--text "..."]
    python tools/hn_publish.py --title "..." --text "..." [--show]
    python tools/hn_publish.py --dry-run --title "..." --url "..."   (no network)

Exit codes: 0 published, 1 error, 2 auth failed, 3 dry-run.
"""

from __future__ import annotations

import argparse
import html.parser
import http.cookiejar
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
BASE = "https://news.ycombinator.com"
LOGIN_URL = BASE + "/login"
SUBMIT_URL = BASE + "/submit"

MAX_TEXT = 4000


class FormCrawler(html.parser.HTMLParser):
    """Collects hidden + text inputs belonging to the first matching form."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self.forms: list[dict[str, str]] = []
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._in_form = True
            self.forms.append({})
        elif tag == "input" and self._in_form:
            name = a.get("name")
            if name:
                self.forms[-1][name] = a.get("value", "")


def _open(method: str, url: str, opener: urllib.request.OpenerDirector,
          data: dict[str, str] | None = None) -> urllib.response.addinfourl:
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    return opener.open(req, timeout=45)


def fetch_token_fields(opener: urllib.request.OpenerDirector) -> dict[str, str]:
    """GET /submit while authenticated; return every hidden form field."""
    resp = _open("GET", SUBMIT_URL, opener)
    html = resp.read().decode("utf-8", "replace")
    if re.search(r"<form[^>]*action=[\"\']?login", html) and "username:" in html:
        raise PermissionError("session expired: /submit requires an authenticated user cookie")
    crawler = FormCrawler()
    crawler.feed(html)
    return dict(crawler.forms[0]) if crawler.forms else {}


def submit(title: str, url: str | None, text: str | None,
           cookie_header: str | None = None, raw_session: bool = False) -> tuple[int, str]:
    """Login (unless HN_COOKIE provided) and post the submission.

    Returns (exit_code, result_url_or_reason).
    """
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    if raw_session:
        opener.addheaders = [("Cookie", cookie_header or os.environ.get("HN_COOKIE", ""))]
    else:
        user = os.environ.get("HN_USERNAME")
        pw = os.environ.get("HN_PASSWORD")
        if not user or not pw:
            print("[hn_publish] set HN_USERNAME and HN_PASSWORD (env) first", file=sys.stderr)
            return 1, "missing credentials"
        try:
            resp = _open("POST", LOGIN_URL, opener, {"acct": user, "pw": pw})
        except urllib.error.HTTPError as exc:
            return 1, f"login HTTP {exc.code}"
        body = resp.read().decode("utf-8", "replace")
        if "Bad login" in body:
            return 2, "Bad login: username or password rejected (401)"

    tokens = fetch_token_fields(opener)

    payload: dict[str, str] = dict(tokens)
    payload["title"] = title
    if url:
        payload["url"] = url
    elif text:
        payload["text"] = text
    elif "text" in tokens:
        payload["text"] = text or ""
    if "fnop" in payload and not payload.get("fnop"):
        payload["fnop"] = "submit"

    try:
        resp = _open("POST", BASE + "/r", opener, payload)
    except urllib.error.HTTPError as exc:
        reason = exc.url if exc.url else f"submit HTTP {exc.code}"
        return 1, reason

    final = resp.geturl()
    body = resp.read().decode("utf-8", "replace")
    if "item?id=" in final or "item?id=" in body:
        m = re.search(r"item\?id=(\d+)", final + " " + body)
        return 0, f"published https://news.ycombinator.com/item?id={m.group(1) if m else '?'}"
    if "toonew" in final or "not able to submit" in body:
        return 2, "account too new / low karma: HN blocks the submission (fnop=toonew)"
    if "showlim" in final:
        return 2, "Show HN temporarily restricted for this account (/showlim)"
    if "Unknown or expired link" in body:
        return 1, "CSRF token expired; retry immediately after re-fetching /submit"
    return 1, final or "unexpected response"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hn_publish",
                                description="Automatic Hacker News submission (login + /submit).")
    p.add_argument("--title", required=True, help="Submission title")
    p.add_argument("--url", help="Link URL (omit for Ask/Show text post)")
    p.add_argument("--text", help="Body text (max %d chars)" % MAX_TEXT)
    p.add_argument("--show", action="store_true", help="Prefix 'Show HN: ' to title if absent")
    p.add_argument("--raw-session", action="store_true",
                   help="Use HN_COOKIE session directly instead of logging in")
    p.add_argument("--dry-run", action="store_true", help="Validate arguments, do not touch network")
    args = p.parse_args(argv)

    title = args.title
    if args.show and not title.lower().startswith("show hn"):
        title = "Show HN: " + title
    if args.text and len(args.text) > MAX_TEXT:
        print(f"[hn_publish] text too long ({len(args.text)} > {MAX_TEXT})", file=sys.stderr)
        return 1
    if not args.url and not args.text:
        print("[hn_publish] provide --url or --text", file=sys.stderr)
        return 1
    if not args.raw_session and not (os.environ.get("HN_USERNAME") and os.environ.get("HN_PASSWORD")):
        if not args.dry_run:
            print("[hn_publish] set HN_USERNAME/HN_PASSWORD or use --raw-session", file=sys.stderr)
            return 1

    if args.dry_run:
        print(f"[dry-run] title={title!r} url={args.url!r} text={'yes' if args.text else 'no'}")
        print("[dry-run] flow: POST /login -> GET /submit (tokens) -> POST /submit")
        return 3

    code, msg = submit(title, args.url, args.text, raw_session=args.raw_session)
    print(f"[hn_publish] {msg}")
    return code


if __name__ == "__main__":
    time.sleep(0)  # placeholder to keep predictable ordering
    sys.exit(main())