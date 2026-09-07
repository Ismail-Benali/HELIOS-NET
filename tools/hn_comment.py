"""HELIOS-NET :: tools/hn_comment.py
Zero-dependency Hacker News comment helper (Python stdlib only).

Reputation building: HN blocks new / low-karma accounts from submitting
(fnop=toonew) but allows commenting; gaining karma via one curated comment
per run is the sanctioned path to lifting that restriction.

Flow (mirrors the site's own HTML form, no write API exists):

    1. POST https://news.ycombinator.com/login   (acct, pw)  -> session cookie
    2. GET  https://news.ycombinator.com/item?id=<n> (authed, inside the thread)
       -> hidden CSRF fields: parent=<id> + hmac=<one-time token>
    3. POST https://news.ycombinator.com/comment (parent + hmac + text)
       -> new reply under that item

Credentials are read ONLY from environment variables (never from files):

    set  HN_USERNAME=h3l0s_t3k       & set HN_PASSWORD=..."
    python tools/hn_comment.py --item <id> --text "..." [--dry-run]

Companion: python tools/hn_comment.py --newest [--limit N]  (read-only listing)

Exit codes: 0 posted, 1 error, 2 auth/eligibility failed, 3 dry-run.
"""

from __future__ import annotations

import argparse
import html as html_mod
import html.parser
import http.cookiejar
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
BASE = "https://news.ycombinator.com"
LOGIN_URL = BASE + "/login"
ITEM_URL = BASE + "/item?id="
COMMENT_URL = BASE + "/comment"
NEWEST_URL = BASE + "/newest"

MAX_TEXT = 4000


class FormCrawler(html.parser.HTMLParser):
    """Collects hidden inputs belonging to the first matching form by name."""

    def __init__(self, form_action: str) -> None:
        super().__init__(convert_charrefs=True)
        self.target = form_action
        self.fields: dict[str, str] = {}
        self.captured = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            action = (a.get("action") or "").lower()
            self.captured = (self.target in action)
        elif tag == "input" and self.captured:
            name = a.get("name")
            if name:
                self.fields[name] = a.get("value", "")


def _open(method, url, opener, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    return opener.open(req, timeout=45)


def fetch_tokens(opener, item_id: str) -> dict[str, str]:
    """GET the thread while authenticated; return parent + hmac from the reply form."""
    resp = _open("GET", ITEM_URL + item_id, opener)
    html = resp.read().decode("utf-8", "replace")
    if re.search(r"<form[^>]*action=[\"\']?login", html) and "username:" in html:
        raise PermissionError("session expired: /item page requires an authenticated user cookie")
    crawler = FormCrawler(form_action="comment")
    crawler.feed(html)
    return dict(crawler.fields)


def comment(item_id: str, text: str, cookie_header: str | None = None,
            raw_session: bool = False) -> tuple[int, str]:
    """Login (unless HN_COOKIE provided) and post one reply under item_id."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    if raw_session:
        opener.addheaders = [("Cookie", cookie_header or os.environ.get("HN_COOKIE", ""))]
    else:
        user = os.environ.get("HN_USERNAME")
        pw = os.environ.get("HN_PASSWORD")
        if not user or not pw:
            print("[hn_comment] set HN_USERNAME and HN_PASSWORD (env) first", file=sys.stderr)
            return 1, "missing credentials"
        try:
            resp = _open("POST", LOGIN_URL, opener, {"acct": user, "pw": pw})
        except urllib.error.HTTPError as exc:
            return 1, f"login HTTP {exc.code}"
        body = resp.read().decode("utf-8", "replace")
        if "Bad login" in body:
            return 2, "Bad login: username or password rejected (401)"

    tokens = fetch_tokens(opener, item_id)
    if not tokens.get("hmac"):
        return 1, "no reply form found for item " + item_id

    payload = {"parent": item_id, "hmac": tokens["hmac"], "text": text}

    try:
        resp = _open("POST", COMMENT_URL, opener, payload)
    except urllib.error.HTTPError as exc:
        return 1, f"comment HTTP {exc.code}"

    final = resp.geturl()
    body = resp.read().decode("utf-8", "replace")
    if "item?id=" in final or "item?id=" in body:
        m = re.search(r"item\?id=(\d+)", final + " " + body)
        return 0, f"posted comment https://news.ycombinator.com/item?id={m.group(1) if m else '?'}"
    if "Unknown or expired link" in body:
        return 1, "CSRF token expired; re-fetch the thread and retry"
    if "rate limited" in body.lower() or "try again later" in body.lower():
        return 2, "rate-limited by HN; wait and retry"
    return 1, final or "unexpected response"


def list_newest(limit: int) -> tuple[int, list[tuple[str, str]]]:
    """Read-only: parse the newest page and return (id, title) pairs."""
    resp = _open("GET", NEWEST_URL, urllib.request.build_opener())
    html = resp.read().decode("utf-8", "replace")
    items: list[tuple[str, str]] = []
    for m in re.finditer(r'<tr class="athing\s+[^"]*" id="(\d+)"', html):
        item_id = m.group(1)
        rest = html[m.end():m.end() + 800]
        tm = re.search(r'class="titleline"[^<]*<a[^>]*>([^<]+)</a>', rest)
        if tm:
            title = html_mod.unescape(tm.group(1))
            items.append((item_id, title))
        if len(items) >= limit:
            break
    return 0, items


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hn_comment",
                                description="Post one HN comment (login + /comment).")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--item", help="Item ID (or URL) to comment under")
    g.add_argument("--newest", action="store_true", help="List fresh items on /newest (read-only)")
    p.add_argument("--text", help="Comment body (max %d chars)" % MAX_TEXT)
    p.add_argument("--limit", type=int, default=10, help="With --newest: how many rows")
    p.add_argument("--dry-run", action="store_true", help="Validate only; no network writes")
    args = p.parse_args(argv)

    if args.newest:
        code, items = list_newest(args.limit)
        for iid, title in items:
            print(f"{iid:>10}  {title}")
        print(f"\n[hn_comment] {len(items)} newest items. Then: "
              f"python tools/hn_comment.py --item <id> --text \"...\"")
        return code

    item = args.item
    if "item?id=" in item:
        item = item.rsplit("item?id=", 1)[1].split("&", 1)[0]
    if not item.isdigit():
        print("[hn_comment] --item must be a numeric HN item id", file=sys.stderr)
        return 1
    if not args.text:
        print("[hn_comment] provide --text for the comment body", file=sys.stderr)
        return 1
    if len(args.text) > MAX_TEXT:
        print(f"[hn_comment] comment too long ({len(args.text)} > {MAX_TEXT})", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"[dry-run] parent={item} text={args.text[:60]!r}...")
        print("[dry-run] flow: POST /login -> GET /item?id= (tokens) -> POST /comment")
        return 3

    use_raw = bool(os.environ.get("HN_COOKIE"))
    if not use_raw and not (os.environ.get("HN_USERNAME") and os.environ.get("HN_PASSWORD")):
        print("[hn_comment] set HN_USERNAME/HN_PASSWORD or HN_COOKIE (env) first", file=sys.stderr)
        return 1

    code, msg = comment(item, args.text, raw_session=use_raw)
    print(f"[hn_comment] {msg}")
    return code


if __name__ == "__main__":
    sys.exit(main())