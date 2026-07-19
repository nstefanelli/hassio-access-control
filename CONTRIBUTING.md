# Contributing

Bug reports, focused fixes, tests, documentation, and feature proposals are
welcome. For larger behavior changes, open an issue first so the physical-
access and migration implications can be agreed before implementation.

## Before opening anything public

- Security vulnerabilities belong in [GitHub Private Vulnerability
  Reporting](SECURITY.md), not an issue or pull request.
- Remove API keys, HA/UniFi tokens, passwords, PINs, cookies, database files,
  household identities, console addresses, and unredacted logs.
- Search existing issues and the [changelog](access_control/CHANGELOG.md).

Quick links:

- [Report a bug](https://github.com/nstefanelli/hassio-access-control/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/nstefanelli/hassio-access-control/issues/new?template=feature_request.yml)
- [Development guide](docs/DEVELOPMENT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Local setup

Use Python 3.12:

```bash
cd access_control/rootfs/opt
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r access_control/requirements-dev.txt
.venv/bin/pytest access_control/tests -q
```

Most tests use fake HA/UniFi clients. Changes to the app manifest, Ingress,
Supervisor APIs, restart behavior, authentication, or real upstream payload
parsing also need a smoke test on a disposable Home Assistant/UniFi environment
when available.

The complete [development guide](docs/DEVELOPMENT.md) covers focused tests,
security checks, the local image, direct-mode smoke testing, and repository
conventions.

## Frontend changes

The runtime UI is self-hosted. If a template adds/removes Tailwind classes or
the CSS input changes, commit the regenerated minified stylesheet:

```bash
cd access_control/frontend
npm ci
npm run build
```

Node.js 20+ is required for this build. Commit `package-lock.json` and the
generated `static/app.css`; never commit `node_modules/`. Keep browser URLs
relative/Ingress-aware and shared behavior in `static/app.js`.

## Container build

```bash
cd access_control
docker build \
  --build-arg BUILD_ARCH=amd64 \
  --build-arg BUILD_VERSION=dev \
  -t access-control:dev .
```

The build context is `access_control/`, so its local `.dockerignore` is the
effective ignore file. Keep test data, local databases, virtual environments,
caches, and frontend dependencies out of the image context.

## What CI checks

Every pull request and push to `main` runs:

- `yamllint`;
- `hadolint`;
- `shellcheck` and release-helper self-tests;
- Python 3.12 tests;
- Bandit at medium-or-higher severity/confidence;
- `pip-audit` for runtime and development requirements;
- native `amd64` and `aarch64` image builds when app/shared build inputs
  changed;
- an aggregation gate that requires every selected architecture to succeed.

Pull-request images are never pushed. Ordinary main builds use immutable
`sha-*` tags; only a main push with a manifest version change publishes the
version and `latest` tags. GitHub Release creation waits for successful main
push CI. See [Development → Release process](docs/DEVELOPMENT.md#release-process).

## Pull-request expectations

- Keep the change scoped and explain the failure mode or user outcome.
- Add regression tests, including concurrency/failure cases where relevant.
- Run the full suite before pushing.
- Update canonical documentation when configuration, operations, API, trust
  boundaries, or contributor workflow changes.
- Add user-visible changes under `## [Unreleased]` in
  `access_control/CHANGELOG.md`.
- Include before/after screenshots for visible UI changes.
- Call out database migrations, upgrade/rollback behavior, and physical-door
  safety effects explicitly.

Conventional Commit prefixes are encouraged but not required: `feat`, `fix`,
`docs`, `perf`, `refactor`, `test`, and `chore`.

## Review principles

- Lockdown, alarm uncertainty, corrupt schedules, and failed re-lock paths
  should resolve conservatively.
- A failed settings update must not destroy a working live client or split-
  console topology.
- State-changing web routes require authentication, CSRF, boundary validation,
  and the appropriate action rate limit.
- The shared SQLite connection remains autocommit-only. Concurrent
  multi-statement workflows must use an isolated, task-owned transaction and
  explicit process-level coordination where the operation is read-modify-write.
- Access-client changes must preserve persisted site-namespace verification
  before initial publication, candidate swaps, REST reauthentication, and
  WebSocket reconnect.
- Avoid persistent writes for short-lived caches or unchanged topology.
- Do not surface raw upstream response bodies or secrets in the UI/logs.
- Preserve HA Ingress `root_path` behavior in links, redirects, fetches, and
  cookies.

## Repository map

```text
access_control/
├── config.yaml                         # HA app manifest
├── Dockerfile
├── frontend/                           # pinned Tailwind inputs
├── rootfs/run.sh                       # bashio/container entry point
└── rootfs/opt/access_control/
    ├── main.py                         # lifecycle and background services
    ├── auth_engine.py                  # physical authorization decisions
    ├── database.py                     # schema and state
    ├── web_routes.py / api_routes.py   # dashboard and external API
    ├── templates/ / static/            # self-hosted UI
    └── tests/
docs/                                    # canonical documentation
.github/workflows/                       # CI and releases
```
