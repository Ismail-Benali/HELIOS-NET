# HELP — Auto-Publishing to Hacker News

**Goal:** publish HELIOS-NET announcements on Hacker News automatically,
with zero external Python dependencies.

---

## 1. Reality check: the official API is read-only

The [Hacker News API](https://github.com/HackerNews/API) is a **Firebase
firehose** — "a dump of our in-memory data structures". It allows **reading**
items, users, stories, comments, and polling for new items. **There is no
public write endpoint** (no official way to post via API key).

Verified against `HackerNews/API` README · `clientlibs.py` · `hackernews.py`:

| Endpoint | Method | Purpose |
|---|---|---|
| `https://hacker-news.firebaseio.com/v0/item/{id}` | GET | read an item |
| `https://hacker-news.firebaseio.com/v0/user/{id}` | GET | read a user |
| `https://hacker-news.firebaseio.com/v0/topstories` | GET | read top story ids |
| `.../maxitem.json` | GET | read max item id |
| `https://hn.algolia.com/api/v1/search` | GET | search posts |

No mutation. Therefore **publishing requires driving the website's own HTML
forms**.

---

## 2. How Hacker News actually accepts submissions (reverse-engineering)

Target: `https://news.ycombinator.com` (plain HTML site).

### 2.1 Login (no CSRF)
```
POST /login
  acct=<username>
  pw=<password>
```
The login form has **no hidden CSRF field** (verified: forms only contain
`acct`, `pw`, and an optional `creating` hidden flag on the signup form).
On success the server sets a session cookie (`user=...`).

### 2.2 Get the submit page (authenticated)
```
GET /submit
```
When **not** logged in, this page returns the login form again — proof that
submission requires a valid session cookie. Authenticated, it returns a form
containing one-time hidden CSRF tokens (fields such as `hpx`, `hpn`, `hmac`,
`fnid`, `fnop`) that must be echoed back on POST.

### 2.3 Submit
```
POST /r                                   # modern HN wrapper (NOT /submit)
  fnid=<one-time token from GET /submit>
  fnop=submit-page
  title=<title>
  url=<url>        # link post
  text=<text>      # Ask/Show text post (≤ 4000 chars)
```
Verified live: POSTing to `/submit` returns a blank re-rendered form;
POSTing to `/r` is the path that actually processes the submission.
A successful submit 302-redirects to `item?id=<N>` or renders the item.

---

## 3. Automation tool

`tools/hn_publish.py` — Python stdlib only (urllib + http.cookiejar).
It performs the 3-step flow above with a single command.

### Prerequisites
- Python 3.8+
- Credentials via environment variables **only** (never stored in files):

```powershell
$env:HN_USERNAME = "H3l!0s_T3k"
$env:HN_PASSWORD = "..."              # current password
```

### Usage

```powershell
# Link post (Show HN for our main repo)
python tools/hn_publish.py --title "Show HN: HELIOS-NET - Autonomous Red Teaming & ASM Orchestrator" `
    --url "https://github.com/Ismail-Benali/HELIOS-NET" --show

# Text/Ask post
python tools/hn_publish.py --title "Ask HN: ..." --text "body text"

# Dry run (no network, validates args)
python tools/hn_publish.py --dry-run --title "..."
```

### Exit codes
| Code | Meaning |
|---|---|
| 0 | published (prints `https://news.ycombinator.com/item?id=<N>`) |
| 1 | error (bad args / expired CSRF / network) |
| 2 | **auth/eligibility failed** — bad credentials, Show HN restricted, or `fnop=toonew` |
| 3 | dry-run |

---

## 4. Live findings (blockers) ⚠️

Tested end-to-end with the real account — the tooling reaches the exact
decision points; HN's own rules gate the final publish:

| Attempt | Result |
|---|---|
| Login `H3l0s_T3k` | ✅ session cookie issued |
| `POST /submit` (title/url) | ❌ blank form re-rendered (wrong endpoint) |
| `POST /r` title = `Show HN: ...` | ❌ `/showlim` — Show HNs temporarily restricted |
| `POST /r` plain title | ❌ `fnop=toonew` — *"Sorry, your account isn't able to submit this site."* |

The account is **23 hours old with karma 1**. Hacker News deliberately blocks
new / low-karma accounts from submitting. This is not a bug to engineer around;
HN requires the account to build karma and history first.

---

## 5. Notes & etiquette

- HN rate-limits logins/submissions; one post per run, keep sessions warm.
- New/low-karma accounts get a long "wait" throttle on submissions.
- `--show` prepends `Show HN: ` for project launches.
- Never commit credentials — they live only in your shell session.