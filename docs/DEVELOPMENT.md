# Development

Access Control is a Python 3.12 FastAPI application with Jinja templates and a
small self-hosted frontend bundle. Most work can be tested without a real
Home Assistant or UniFi console; the test suite uses fakes around those
boundaries.

## Prerequisites

- Python 3.12
- Docker for image and direct-container smoke tests
- Node.js 20 or newer only when changing Tailwind classes/CSS inputs
- Git and a POSIX shell

## Python environment and tests

From the repository root:

```bash
cd access_control/rootfs/opt
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r access_control/requirements-dev.txt
.venv/bin/pytest access_control/tests -q
```

The development requirements include the pinned runtime requirements. Run a
focused module while iterating, then the full suite before handoff:

```bash
.venv/bin/pytest access_control/tests/test_auth_engine.py -q
.venv/bin/pytest access_control/tests -q
```

High-risk changes should include concurrency or failure-path regressions, not
only success cases. In particular, preserve coverage for:

- lockdown immediately before a physical command;
- alarm unknown/mixed/transitional states;
- incomplete and overnight schedules;
- concurrent rate-limit consumption;
- durable re-lock replacement, pause/resume, restart, and recovery;
- accepted HA lock responses whose observed state never becomes `locked`;
- remote-unlock persistence failure and critical-task shutdown draining;
- split-console client replacement and Access site-identity mismatch on initial
  login, REST reauthentication, and WebSocket reconnect;
- ingress identity, CSRF, body limits, cookies, and response headers;
- visitor timezone and DST gap/fold rejection;
- atomic topology sync, empty-upstream guards, and native-lock
  retirement/revival;
- hub pairing changes, shared-hub conflicts, HA unknown/read errors, and
  lockdown enforcement-pending behavior.

## Frontend assets

Runtime pages do not depend on Tailwind's Play CDN, HTMX CDN, Google Fonts, or
another internet-hosted UI asset. The compiled stylesheet and JavaScript are
served from `access_control/rootfs/opt/access_control/static/`.

When a template adds/removes Tailwind classes or
`access_control/frontend/src/app.css` changes, rebuild the committed CSS:

```bash
cd access_control/frontend
npm ci
npm run build
git diff -- ../rootfs/opt/access_control/static/app.css
```

`package-lock.json` pins Tailwind and its transitive dependencies. Do not commit
`node_modules/`. The container build uses the committed minified CSS; it does
not run Node or fetch frontend dependencies.

`static/app.js` contains the small amount of shared browser behavior, including
background polling and CSRF form injection. Keep URLs relative so they work
under both HA's per-session Ingress prefix and direct local testing.

## Run locally without Supervisor

Build the image from the app directory:

```bash
cd access_control
docker build \
  --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.21 \
  --build-arg BUILD_ARCH=amd64 \
  --build-arg BUILD_VERSION=dev \
  -t access-control:dev .
```

Run with an isolated data directory and Supervisor proxy disabled:

```bash
mkdir -p /tmp/access-control-data
printf '%s\n' '{"log_level":"debug","use_supervisor_api":false}' \
  > /tmp/access-control-options.json

docker run --rm -p 8080:8080 \
  -v /tmp/access-control-data:/data \
  -v /tmp/access-control-options.json:/data/options.json:ro \
  access-control:dev
```

Open <http://localhost:8080/setup>. Use disposable fake/test systems; setup
performs real network logins with submitted credentials.

The direct mode is a development/advanced path. Its session cookie is `Secure`,
so plain HTTP does not model a production browser session perfectly. For an
Ingress identity smoke test, send a syntactically valid prefix and HA admin
headers:

```bash
curl -i \
  -H 'X-Ingress-Path: /api/hassio_ingress/testtoken' \
  -H 'X-Remote-User-Id: test-user-id' \
  -H 'X-Remote-User-Name: Test Admin' \
  -H 'X-Remote-User-Is-Admin: true' \
  http://localhost:8080/
```

This checks application routing only. It does not reproduce Supervisor's
network peer, token lifecycle, or full browser SSO flow; perform a final smoke
test on a disposable HA installation for manifest, Ingress, auth, restart, or
Supervisor API changes.

## Static/security checks

The CI-equivalent Python security checks can be run from the repository root:

```bash
python3.12 -m pip install bandit pip-audit
bandit -r access_control/rootfs/opt/access_control \
  -x access_control/rootfs/opt/access_control/tests \
  --severity-level medium --confidence-level medium
pip-audit -r access_control/rootfs/opt/access_control/requirements.txt --strict
pip-audit -r access_control/rootfs/opt/access_control/requirements-dev.txt --strict
```

Run available repository linters before pushing:

```bash
yamllint .
shellcheck -e SC1008 -s bash \
  access_control/rootfs/run.sh .github/scripts/release-utils.sh
docker run --rm -i hadolint/hadolint < access_control/Dockerfile
bash .github/scripts/release-utils.sh self-test
```

CI is the authority for pinned linter/action versions.

## CI pipeline

Pull requests and pushes to `main` run:

1. YAML, Dockerfile, and shell linting, including release-helper self-tests.
2. A reproducible pinned frontend rebuild, failing if committed CSS has drifted.
3. The Python test suite on 3.12.
4. Bandit, failing on medium-or-higher severity and confidence.
5. `pip-audit` for both runtime and development lock files.
6. Native `amd64` and `aarch64` image builds when app/shared build inputs
   changed.
7. An aggregation job that fails if any required architecture failed.

Pull-request images are built but not pushed. Main-branch builds push either an
immutable `sha-<40 hex>` snapshot tag or, for a verified manifest version
change, the version and `latest` tags. The app-local `.dockerignore` excludes
virtual environments, caches, tests, development dependencies, local databases,
and Node modules from the build context.

## Release process

Releases are version-driven and CI-gated.

1. Add user-visible changes under `## [Unreleased]` while developing.
2. For release, change `access_control/config.yaml` to a new semantic version.
3. Rename/copy the prepared notes into an exact literal section:
   `## [X.Y.Z] - YYYY-MM-DD`. Leave `Unreleased` in place for future work.
4. Merge/push the version change to `main`.
5. CI tests and builds both architectures. Only a main push whose manifest
   version changed may publish `X.Y.Z` and `latest`; ordinary main and manual
   builds publish immutable `sha-*` tags.
6. After the successful main push CI run, the Release workflow verifies the
   exact commit, extracts only the exact changelog section, creates the
   annotated `vX.Y.Z` tag, and publishes the GitHub Release.

The release workflow does not run ahead of CI. If tag creation succeeded but
GitHub Release creation failed, manually dispatch Release with the exact tagged
40-character `head_sha`; it repairs the missing release without moving the
tag. Manual release targets must already have a successful `main` push CI run.
A tag pointing at a different commit is treated as an error, not rewritten.

Never reuse a released version. CI refuses to mutate a version image tag once
the corresponding Git tag exists.

## Change discipline

- Keep URL generation Ingress-safe; avoid root-absolute browser URLs unless a
  helper deliberately adds `root_path`.
- Every state-changing dashboard route requires login, CSRF, and the relevant
  action rate limit. Setup is the narrowly guarded exception.
- Validate entity domains, scope enums, relationship ownership, and numeric
  ranges at the HTTP boundary.
- Do not log upstream response bodies or raw credentials to user-facing pages.
- Preserve atomic database ownership. The shared `aiosqlite` connection is
  autocommit-only for ordinary statements; multi-statement logical workflows
  must use a task-owned isolated connection/transaction (and a process lock for
  read-modify-write coordination where needed).
- A door-safety failure should retain/retry the safer durable state and surface
  an observable error.
- Update [configuration](CONFIGURATION.md), [operations](OPERATIONS.md), the
  [API contract](API.md), and the changelog when behavior changes.

## Documentation checks

Before merging documentation changes:

```bash
git diff --check
rg -n '1\.1\.x|America/New_York|Tailwind CDN|HTMX CDN|cp .*/access_control\.db' \
  README.md SECURITY.md CONTRIBUTING.md access_control docs
```

Review relative Markdown links from the file containing them. Dated audit and
spec documents must carry a historical-status banner so a reader does not use
them as the current operating guide.
