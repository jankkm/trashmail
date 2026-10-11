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
| Inbox | List, filter by recipient, full-text search (subject/sender/recipient/body), unread/flagged filters, bulk actions, 24 h activity chart |
| Message view | Sanitised HTML in a sandboxed iframe, **external resources blocked until you click "Load external resources"**, plain text, headers, attachments, download `.eml`, forward, flag, delete |
| Rules | Global or per recipient address. Match sender / recipient / subject / body / any / specific header with contains, equals, startswith, endswith, regex. Actions: **forward**, **delete**, **flag**. Hit log. |
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

---------------------------------------------------------------------------------------------------

## Releasing (GitHub Container Registry)

`.github/workflows/release.yml` runs when you push a tag that starts with `v`:

```bash
git tag v1.0.0 && git push origin v1.0.0     # or publish a GitHub release, which creates the tag
```

1. Runs the test-suite (`pytest`). The image is only published if it passes.
2. Builds a multi-arch image (`linux/amd64`, `linux/arm64`) and pushes it to
   `ghcr.io/<owner>/<repo>` with the tags `1.0.0`, `1.0`, `1` (major tag skipped for `v0.x`) and `latest`.
3. Adds a build-provenance attestation.

No secrets need to be configured: it logs in with the workflow's own `GITHUB_TOKEN`
(*Settings → Actions → General → Workflow permissions* must allow read/write for packages, or leave the
default since the workflow requests `packages: write` itself). After the first release, set the package
visibility in the GitHub *Packages* settings if you want it public. Use it in compose via
`image: ghcr.io/<owner>/<repo>:1.0.0` (see `docker-compose.example.yml`).

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
| `MAX_MESSAGE_SIZE` | `26214400` | Bytes. Raising it needs a restart (SMTP-level limit is fixed at start) |
| `RATE_LIMIT_PER_IP` | `30` | Messages per IP per minute (`450` beyond). `0` = off |
| `SPF_REJECT` | `false` | Reject with `550` when SPF = fail |
| `RETENTION_DAYS` | `0` | Delete unflagged mail older than N days. `0` = forever |
| `FORWARD_SMTP_HOST` / `_PORT` | – / `587` | Outbound SMTP account used for forwarding |
| `FORWARD_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` or `none` |
| `FORWARD_SMTP_USER` / `FORWARD_SMTP_PASSWORD` | – | Credentials (password is write-only in the UI) |
| `FORWARD_FROM` | SMTP user | From address of forwarded mail |

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
  `CREATE TABLE IF NOT EXISTS` in `db.SCHEMA` — **if you change a table, add a migration step in
  `db.init()`** (none exist yet).
* **Per-recipient copies**: a mail to 3 local recipients is stored 3 times, so each copy can be
  flagged/deleted/ruled independently. Simple on purpose.
* **Forwarding** sends a *new* message from the configured SMTP account with the original attached as
  `original.eml` (keeps your own SPF/DKIM valid). Forwarded mail carries `X-Trashmail-Forwarded: 1`;
  rules never forward such mail again (loop protection).
* **Rule semantics**: all enabled matching rules apply, ordered by `priority`. `delete` wins over
  `flag` (mail is not stored at all, but forward rules still run and every hit is logged). `equals`
  on sender/recipient also matches a bare address inside `Name <addr>`.
* **HTML mail safety**: `nh3` sanitises HTML; it is served from `/messages/{id}/body` inside an
  `<iframe sandbox>` with a strict CSP (`default-src 'none'; img-src data:`). `cid:` images are inlined
  as data URIs. The *Load external resources* button just reloads the iframe with `?external=1`, which
  relaxes only `img-src`/`style-src`/`font-src`/`media-src`. Scripts never run.
* **Security basics**: argon2 password hashes, signed `HttpOnly`/`SameSite=Lax` session cookie, CSRF
  token on every POST (`verify_csrf`), login throttling per IP (in memory), admin-only pages guarded by
  the `admin_user` dependency, secrets never rendered back into forms.

## Project layout

```
app/
  config.py          env + *_FILE resolution, Boot (env only) vs SETTINGS (env seeds, DB wins)
  db.py              schema + tiny sqlite helpers (query / one / execute / tx)
  auth.py            users, argon2, session signing, bootstrap admin
  smtp_server.py     aiosmtpd handler + deliver() pipeline (rules → store → forward)
  mailstore.py       .eml write, indexing, search, listing, HTML sanitising, retention
  rules.py           rule matching, validation, blacklist + local-domain policy
  forwarder.py       outbound SMTP (aiosmtplib) using effective settings
  security_checks.py SPF / DKIM / DMARC
  main.py            uvicorn entry point
  web/
    app.py           create_app(): wiring, lifespan, error + security headers
    deps.py          templates, filters, session/current_user/admin_user/verify_csrf, render(), back()
    routes_auth.py   /login /logout /account
    routes_mail.py   / (inbox) /messages/*
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
* **Pages**: inbox (stats, 24 h chart, search, filters, bulk actions), message (sandboxed body, auth
  badges, details, attachments, forward, Block/Rule menus), rules (sentence-style list + dialog),
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
* No DB migrations framework yet (see above). No i18n.
* Ideas not built yet: disposable aliases with expiry, push notification/webhook on new mail,
  API tokens + JSON API, ClamAV scanning, `.eml` import, TOTP 2FA, SRS / DKIM-signed forwarding.
