# Trashmail

A small, self-hosted **catch-all mail sink** with a web UI. One container receives mail over SMTP
(you point an MX record at it), stores every message as an `.eml` file, indexes it in SQLite and
lets you browse, search, filter, forward, auto-process (rules) and block (blacklist) it.

It **never relays** mail: it only accepts messages for its own domains and stores them.

> **For Claude / contributors:** read this whole file first. It is the source of truth for what the
> project is, how it is laid out and which decisions were made on purpose. `CLAUDE.md` points here.

---------------------------------------------------------------------------------------------------

## Features

| Area | What it does |
|---|---|
| Receiving | aiosmtpd server, opportunistic STARTTLS, size limit, per-IP rate limit, only accepts configured domains |
| Storage | One `.eml` per message *per recipient* in `DATA_DIR/mail/YYYY/MM/<uuid>.eml`; metadata + FTS5 index in SQLite |
| Inbox | Unread rows stand out (bold, accent bar) from read ones (muted); click the star to flag in place. Filter by recipient, favorite and **tag**, full-text search, All / Unread / Flagged view with a **per-user default** (e.g. always start on Unread), bulk actions incl. bulk tagging, 24 h activity chart. |
| Tags | Free-form labels on messages. Add them by hand (message page, bulk bar) or automatically with the rule action **Add tag**; click a tag to filter. Case-insensitive, max 32 characters. |
| Message view | Sanitised HTML in a sandboxed iframe, **external resources blocked until you click "Load external resources"**, plain text, headers, attachments, download `.eml`, forward, flag, delete |
| Rules | Per recipient address or global. **Any number of conditions** (sender / recipient / subject / body / any / a specific header; contains, does not contain, equals, starts/ends with, regex), combined with *all* or *any*. **One or more actions** that run in order: **flag**, **mark as read**, **add tag**, **forward**, **delete**. Named, prioritised, editable, with a hit log. |
| Favorites | A named group of recipient addresses with notes. The favorite's page shows all its emails (search, unread/flagged, bulk actions) and all rules scoped to its addresses, with an inline rule editor. The inbox can be filtered by favorite. |
| Blacklist | Sender address, sender domain, recipient address, recipient domain. Rejected with `550` during the SMTP dialogue. Domains also match subdomains. |
| Auth checks | SPF, DKIM, DMARC results shown as badges; optional reject on SPF fail |
| Retention | Auto-delete after N days (flagged mail is kept) |
| Users | Login, per-user name/password/admin flag; admins add/edit/remove users |
| Config | Everything via env (+ `_FILE` variants), persisted to SQLite, editable in the UI |

---------------------------------------------------------------------------------------------------

## Quick start (production)

```bash
cp .env.example .env                           # then edit: LOCAL_DOMAINS, ADMIN_PASSWORD, FORWARD_*, ...
cp docker-compose.example.yml docker-compose.yml
docker compose up -d --build
```

All configuration lives in `.env` (git-ignored; documented in `.env.example`), which compose passes to
the container with `env_file`. For secrets you can instead mount a directory (see the commented
volume in the compose file) and use the `*_FILE` variants, e.g. `ADMIN_PASSWORD_FILE=/run/secrets/admin_password`.
Remember: runtime settings in `.env` only *seed* the database on first start (see Configuration).

1. Create an `MX` record for your domain pointing at a host name whose `A`/`AAAA` points at the server.
2. Make sure TCP port **25** of the server reaches the container (compose maps `SMTP_PUBLISH_PORT` (default 25) → 2525).
3. Put a TLS-terminating reverse proxy in front of web port **8080** and set `COOKIE_SECURE=true`.
4. Log in with `ADMIN_USERNAME` / the admin password. If `ADMIN_PASSWORD` is not set, a random one is
   generated and **printed once in the container log**.

Notes on port 25: many cloud providers block inbound/outbound 25 by default. Inbound is what you need.

**Check the real client IP.** The per-IP rate and connection limits and SPF checks need the sender's real
address. Send a test mail from another machine and look at *Client IP* in the message details. On Linux with
Docker's default networking it is preserved; Docker Desktop/OrbStack and some IPv6 setups show the NAT
gateway (e.g. `192.168.x.1`), in which case the per-IP limits apply to everyone together (use host
networking or fix the IPv6 proxying).

---------------------------------------------------------------------------------------------------

## Releasing (GitHub Container Registry)

`.github/workflows/release.yml` runs when you push a version tag of the form `v*.*.*`:

```bash
git tag v1.0.0 && git push origin v1.0.0     # or publish a GitHub release, which creates the tag
```

1. Runs the test-suite (`pytest`). The image is only published if it passes.
2. Builds a multi-arch image (`linux/amd64`, `linux/arm64`) and pushes it to `ghcr.io/<owner>/<repo>`
   with exactly two tags: the git tag (`v1.0.0`) and `latest`. There are no commit-hash or branch tags.

No secrets need to be configured: it logs in with the workflow's own `GITHUB_TOKEN`
(*Settings → Actions → General → Workflow permissions* must allow read/write for packages, or leave the
default since the workflow requests `packages: write` itself). After the first release, set the package
visibility in the GitHub *Packages* settings if you want it public. Use it in compose via
`image: ghcr.io/<owner>/<repo>:v1.0.0` (see `docker-compose.example.yml`).

### What can end up in the image

Only application code. This is enforced twice:

* `.dockerignore` is an **allowlist** (`**` then `!pyproject.toml`, `!app/**/*.py`, templates, static).
  `.env`, `docker-compose.yml`, `secrets/`, `data/`, tests, docs, `.git` and caches never enter the
  build context. **If you add a new kind of file to the app (e.g. fonts in a subfolder), add it there.**
* The Dockerfile copies only `pyproject.toml` (dependency list) and `app/`, and bakes in no credentials:
  all configuration arrives at runtime via env / `*_FILE` / the `/data` volume. The session
  `SECRET_KEY` is generated at first start inside `/data`, never in the image.

`.gitignore` additionally excludes `.env`, `.env.*` (except `.env.example`), `docker-compose.yml`,
`secrets/`, `*.pem`, `*.key`, `*.db` and `data/*`.

---------------------------------------------------------------------------------------------------

## Development (devcontainer)

Open the folder in VS Code → *Reopen in Container*. The dev container:

* is Python 3.13 with `swaks` + `sqlite3` installed,
* runs `pip install -e '.[dev]'` on creation,
* pre-sets env: `DATA_DIR=<workspace>/data`, `SMTP_LISTEN_PORT=2525`, `WEB_PORT=8080`,
  `LOCAL_DOMAINS=localhost,example.test`, admin user `admin` / `admin`.

```bash
python -m app.main            # web on :8080, SMTP on :2525
pytest                        # full test-suite (≈ 2 s)
ruff check .

# send a test mail
swaks --server localhost:2525 --from alice@sender.test --to bob@example.test \
      --header "Subject: Hello" --body "It works"
```

Open http://localhost:8080, log in as `admin` / `admin`.

If you change the dev env vars in `devcontainer.json` *after* the first start, remember that settings
are persisted in `data/trashmail.db` (see **Configuration** below) — delete `data/trashmail.db` or use
the *Reset* buttons in Settings.

---------------------------------------------------------------------------------------------------

## Configuration

### The rule: env seeds → DB wins

Every variable can be given as `NAME` **or** `NAME_FILE` (path to a file whose content is the value,
e.g. a Docker secret). `NAME_FILE` takes precedence over `NAME`.

*Runtime settings* (table below) are copied from the environment into SQLite **on first start, only if
the DB has no value for them yet**. After that the database value always wins and can be changed in
**Settings**. Changing the env var later therefore has no effect unless you press *Reset* in Settings
(deletes the DB value → env/default applies again).

### Bootstrap variables (env only, read at start)

| Variable | Default | Meaning |
|---|---|---|
| `DATA_DIR` | `/data` | Holds `trashmail.db`, `mail/`, and the generated `secret_key` |
| `SMTP_LISTEN_HOST` / `SMTP_LISTEN_PORT` | `0.0.0.0` / `25` (image: `2525`) | SMTP listener |
| `WEB_HOST` / `WEB_PORT` | `0.0.0.0` / `8080` | Web UI |
| `SECRET_KEY` | generated + stored in `DATA_DIR/secret_key` | Signs session cookies |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_NAME` | `admin` / *random, logged* / `Administrator` | Created only if there are no users yet |
| `COOKIE_SECURE` | `false` | Set `true` when the UI is served over HTTPS |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | – | Enables STARTTLS on the SMTP port (PEM files) |

(`TLS_CERT_PATH` is intentionally not called `TLS_CERT_FILE`, to avoid clashing with the `_FILE` suffix.)

### Runtime settings (env seeds, UI edits, UI wins)

| Variable | Default | Meaning |
|---|---|---|
| `LOCAL_DOMAINS` | *empty = accept all* | Comma list of domains to accept; `*.example.com` = subdomains. Others get `550` at `RCPT TO` |
| `SPF_REJECT` | `false` | Reject with `550` when SPF = fail |
| `MAX_MESSAGE_SIZE` | `26214400` | Bytes. Larger gets `552`. Raising it needs a restart |
| `MAX_RECIPIENTS` | `10` | Recipients per message; further `RCPT TO` get `452`. Each recipient stores its own copy |
| `RATE_LIMIT_PER_IP` | `30` | Messages per IP per minute (`450` beyond) |
| `MAX_CONNECTIONS` / `MAX_CONNECTIONS_PER_IP` | `50` / `5` | Concurrent connections; further ones get `421` and are closed |
| `COMMAND_LIMIT` | `50` | Uses of any one SMTP command per session; the session is dropped beyond. Needs a restart |
| `RETENTION_DAYS` | `30` | Delete unflagged mail older than N days |
| `MAX_STORAGE_MB` | `5120` | Storage cap. At the cap new mail is refused with `452` until space is freed |
| `FORWARD_SMTP_HOST` / `_PORT` | – / `587` | Outbound SMTP account used for forwarding |
| `FORWARD_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` or `none` |
| `FORWARD_SMTP_USER` / `FORWARD_SMTP_PASSWORD` | – | Credentials (password is write-only in the UI) |
| `FORWARD_FROM` | SMTP user | From address of forwarded mail |
| `FORWARD_LIMIT_PER_HOUR` | `60` | Forwards triggered by *rules* per hour. Beyond it the mail is stored but not forwarded (logged as failed hit) |

`0` disables a limit. Defaults are chosen for an internet-facing MX; the storage figure is the sum of stored
message sizes (not free disk space), so size your volume above `MAX_STORAGE_MB` plus the database.

### Two-factor authentication (TOTP)

Optional, per user: *Account → Two-factor authentication*. Scan the QR code with any authenticator app
(Google Authenticator, 1Password, Aegis, …), confirm with a code, and save the 8 one-time recovery codes
that are shown once. At sign-in the password is followed by a code (or a recovery code).

* Standard RFC 6238 (SHA-1, 6 digits, 30 s, ±1 step drift). A code can be used only once.
* The second step is only reachable with a 5-minute signed "password accepted" cookie; 5 wrong codes lock
  that account's second step for 15 minutes, and failures count towards the per-IP login throttle.
* Admins can *Reset 2FA* for a user on the Users page (lost phone and recovery codes). Disabling needs the
  user's password.
* The TOTP secret is stored in the SQLite database in clear text (it must be readable to verify codes);
  protect `/data` accordingly. Recovery codes are stored only as SHA-256 hashes.

---------------------------------------------------------------------------------------------------

## How it works

```
 Internet ──SMTP:25──► aiosmtpd Handler (app/smtp_server.py)
                          MAIL FROM → sender blacklist, per-IP rate limit
                          RCPT TO   → LOCAL_DOMAINS, recipient blacklist
                          DATA      → size, SPF/DKIM/DMARC, then per recipient:
                                       rules.matching_rules → store (unless delete) → forward/flag
                                                  │
                                 mailstore.store ─┼─► DATA_DIR/mail/YYYY/MM/<uuid>.eml
                                                  └─► SQLite: messages + messages_fts
 Browser ──HTTP:8080──► FastAPI (app/web/*) ── Jinja2 templates ── mailstore / rules / auth
```

* **One process**: `app/main.py` runs uvicorn; the SMTP controller (own thread) and the hourly
  retention task are started in the FastAPI lifespan (`app/web/app.py`).
* **SQLite**: a short-lived connection per call (WAL) in `app/db.py`; there is no ORM. Schema is
  `CREATE TABLE IF NOT EXISTS` in `db.SCHEMA`. That never alters an existing table, so **when you add a
  column, also append it to `db.MIGRATIONS`** (applied by `db.init()` on every start). Data migrations live next to it: `_migrate_rules_v2` moved the old
  one-condition-one-action rules into `rule_conditions` / `rule_actions` (it is a no-op on new databases).
* **Per-recipient copies**: a mail to 3 local recipients is stored 3 times, so each copy can be
  flagged/deleted/ruled independently. Simple on purpose.
* **Forwarding** sends a *new* message from the configured SMTP account with the original attached as
  `original.eml` (keeps your own SPF/DKIM valid). Forwarded mail carries `X-Trashmail-Forwarded: 1`;
  rules never forward such mail again (loop protection).
* **Rule semantics**: a rule belongs to one recipient address (or all) and has 0..n conditions joined by
  AND (`match_mode=all`) or OR (`any`); no conditions = matches every message in scope. All enabled matching
  rules apply, ordered by `priority`, and each runs all of its actions in order. Actions combine across rules:
  `delete` wins (the mail is never stored, but forward actions still run and every action is logged),
  `flag` / `mark_read` set the stored message's state and `tag` actions attach their tags to it. `equals` on sender/recipient also matches a bare
  address inside `Name <addr>`. Tables: `rules`, `rule_conditions`, `rule_actions`, `rule_hits`.
* **HTML mail safety**: `nh3` sanitises HTML; it is served from `/messages/{id}/body` inside an
  `<iframe sandbox>` with a strict CSP (`default-src 'none'; img-src data:`). `cid:` images are inlined
  as data URIs. The *Load external resources* button just reloads the iframe with `?external=1`, which
  relaxes only `img-src`/`style-src`/`font-src`/`media-src`. Scripts never run.
* **Security basics**: argon2 password hashes, signed `HttpOnly`/`SameSite=Lax` session cookie, optional
  TOTP second factor, CSRF token on every POST (`verify_csrf`; the login steps have none because there is
  no session yet), login throttling per IP (in memory), admin-only pages guarded by the `admin_user`
  dependency, secrets never rendered back into forms.
* **Abuse protection** (`app/smtp_server.py`): connection limits are enforced in `LimitedSMTP.connection_made`
  (a subclass wired in through `LimitedController.factory`), the per-session command limit is aiosmtpd's
  `command_call_limit`, recipient/storage/rate limits are checked in the `handle_*` hooks, the hourly
  forward cap in `deliver()`. Storage use is `SUM(messages.size)`, cached for 5 s (`mailstore.storage_used`).

## Project layout

```
app/
  config.py          env + *_FILE resolution, Boot (env only) vs SETTINGS (env seeds, DB wins)
  db.py              schema + tiny sqlite helpers (query / one / execute / tx)
  auth.py            users, argon2, session signing, bootstrap admin
  smtp_server.py     aiosmtpd handler + deliver() pipeline (rules → store → forward)
  mailstore.py       .eml write, indexing, search, listing, HTML sanitising, retention
  rules.py           rules (conditions/actions CRUD + matching), blacklist, local-domain policy
                     (tags live in mailstore.py: message_tags table, add_tags/tags_for/all_tags)
  favorites.py       favorites (named address groups with notes) + their counts
  forwarder.py       outbound SMTP (aiosmtplib) using effective settings
  security_checks.py SPF / DKIM / DMARC
  main.py            uvicorn entry point
  web/
    app.py           create_app(): wiring, lifespan, error + security headers
    deps.py          templates, filters, session/current_user/admin_user/verify_csrf, render(), back()
    routes_auth.py   /login /logout /account
    routes_mail.py   / (inbox) /messages/*
    routes_favorites.py /favorites, /favorites/{id}
    ruleui.py        rule-editor form parsing/context shared by rules + favorite pages
    routes_admin.py  /rules /blacklist /users /settings
    templates/       Jinja2 pages (server-rendered, almost no JS)
    icons.py         inline SVG icon set (`icon()` template global)
    static/theme.css design tokens (colours, radii, shadows, dark mode)  ← re-skin here
    static/app.css   layout + components
    static/app.js    dialogs, confirms, bulk selection, toasts
tests/               pytest: config, rules/blacklist, mailstore, smtp (real server), web (TestClient)
.devcontainer/       dev environment
Dockerfile           production image (non-root, listens on 2525/8080)
.github/workflows/   release.yml: test + build + push image to ghcr.io on v* tags
```

## UI design

A conventional "admin app" shell: fixed left sidebar (brand, Mail / Automation / Administration navigation,
unread counter, user chip), content column with a page header, and card-based pages. Neutral grey
palette with one green brand colour, 10 px radii, thin borders, small shadows, system/Inter font stack,
automatic dark mode.

* **Tokens**: all colours, radii, shadows and fonts are CSS variables in `app/web/static/theme.css`
  (light + dark). Re-skin there first.
* **Components**: `app/web/static/app.css` (buttons, inputs, switches, badges, avatars, cards, tables,
  dialogs, toasts, popover menus, settings rows). Avatars get a stable colour from the sender address
  (`hue` filter in `app/web/deps.py`).
* **Icons**: inline SVG (Lucide-style) via the `icon('name', size)` template global, defined in
  `app/web/icons.py`. Add new paths there.
* **JS**: only `app/web/static/app.js` (dialogs, confirm prompts, bulk selection, toasts, settings save
  bar). No build step, no framework. Destructive buttons use `data-confirm="..."`; dialogs use
  `data-open="id"` / `data-close`.
* **Pages**: inbox (stats, 24 h chart, search, filters incl. favorite and tag, per-user default view, clickable stars, bulk actions), message (sandboxed
  body, auth badges, details, attachments, forward, Block/Rule menus), favorites (cards) and a favorite
  page (emails + notes + rules side by side), rules (sentence-style cards + a dialog editor with dynamic
  condition/action rows, `static/app.js`),
  blacklist, users (table + dialogs), settings (grouped rows with source badges and a sticky save bar).
* UI language is English (strings live in the templates; there is no i18n layer yet).

## Testing

`pytest` (see Development). The SMTP tests start a real aiosmtpd server on a free local port and talk to
it with `smtplib`; web tests use FastAPI's `TestClient` with `create_app(start_smtp=False)`.
Each test gets a fresh temporary `DATA_DIR` (`tests/conftest.py`).

## Known limitations / ideas

* No IMAP/POP3, no outbound relaying, no per-user mailboxes: all users see all mail (rules are shared).
* Rate limiting and login throttling are in-memory (reset on restart, per process).
* DMARC check is a simplified alignment check (relaxed, approximated organisational domain).
* Migrations are a simple list of added columns (`db.MIGRATIONS`); there is no framework. No i18n.
* Ideas not built yet: disposable aliases with expiry, push notification/webhook on new mail,
  API tokens + JSON API, ClamAV scanning, `.eml` import, WebAuthn/passkeys, SRS / DKIM-signed forwarding.
