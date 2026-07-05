# Contributing

Thanks for the interest. This is a hobby project, so the bar for
"contributing" is intentionally low — bug reports, feature ideas, and
PRs are all welcome.

## Quick links

- [Report a bug](https://github.com/nstefanelli/hassio-access-control/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/nstefanelli/hassio-access-control/issues/new?template=feature_request.yml)
- [Report a security issue](SECURITY.md) (private channel — don't open a public issue)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Development setup

The app is a FastAPI + HTMX dashboard packaged as a Home Assistant app.
You can develop and test it entirely on your laptop — no real UniFi or
HA install needed for most changes.

### Run the test suite

```bash
cd access_control/rootfs/opt
python -m venv .venv
.venv/bin/pip install -r access_control/requirements-dev.txt
.venv/bin/pytest access_control/tests -q
```

The suite takes ~1 second and covers the auth engine, circuit breaker,
ingress middleware, re-lock manager, and core route flows.

### Build the container image locally

```bash
cd access_control
docker build \
  --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.21 \
  --build-arg BUILD_ARCH=amd64 \
  --build-arg BUILD_VERSION=dev \
  -t access-control:dev .
```

### Run the container

```bash
mkdir -p /tmp/ac-data
echo '{"log_level":"info","use_supervisor_api":false}' > /tmp/ac-opts.json
docker run --rm -p 8080:8080 \
  -v /tmp/ac-data:/data \
  -v /tmp/ac-opts.json:/data/options.json:ro \
  access-control:dev
```

Then open <http://localhost:8080/setup> in your browser.

To simulate the HA Ingress + SSO path, pass the headers manually with
`curl`:

```bash
curl -H 'X-Ingress-Path: /api/hassio_ingress/dummytoken' \
     -H 'X-Remote-User-Id: u1' \
     -H 'X-Remote-User-Name: Test' \
     -H 'X-Remote-User-Is-Admin: true' \
     http://localhost:8080/
```

## What CI checks

Every push to `main` and every PR triggers:

- `yamllint` — YAML files (configs, workflows, GitHub forms)
- `hadolint` — Dockerfile linting
- `shellcheck` — `run.sh` and other bash
- `pytest` — full test suite
- Multi-arch build (`amd64`, `aarch64`) using the
  [home-assistant/builder][builder] action; PRs build with `--test`, main
  builds publish to `ghcr.io`

All checks must pass before a PR can merge.

### First publish: make the GHCR package public (one-time, manual)

A newly-created GHCR package is **private by default**. Home Assistant's
Supervisor pulls the image anonymously (it has no GHCR credentials), so an
install fails with `pull access denied` / `403` until the package is made
public — with no in-HA hint that this is the cause. After the first CI push
of each architecture, the maintainer must flip visibility:

`https://github.com/users/<owner>/packages/container/<image-name>/settings`
→ **Change visibility** → **Public**.

This is one-time per package per arch — `hassio-access-control-amd64` and
`hassio-access-control-aarch64` are **separate packages**, so both need it.
There is no non-PAT API path on the free tier, so it isn't automated.

## Style notes

- **Python**: roughly PEP 8. No formatter is enforced yet; new code
  should look like neighboring code.
- **Templates**: HTML + Jinja2. Use **relative URLs** so they resolve
  against `<base href>` under both ingress and direct-port access. The
  README's "Anti-pattern" callout in `templates/base.html` explains why.
- **Tests**: prefer `unittest.IsolatedAsyncioTestCase` for async tests
  (matches the existing pattern; works out of the box with `pytest`).

## Commit / PR conventions

Conventional Commits are encouraged but not required:

- `feat: ...` — new feature
- `fix: ...` — bug fix
- `docs: ...` — documentation only
- `refactor: ...` — internal restructuring with no behavior change
- `test: ...` — test changes only
- `chore: ...` — build, CI, dependencies

For PRs:

- Link the issue you're addressing if there is one (`Fixes #N`).
- Update `access_control/CHANGELOG.md` under an `## [Unreleased]` heading
  if the change is user-visible.
- Add tests for new behavior. Run `pytest` before pushing.
- If you change anything in `access_control/config.yaml`'s `version`,
  also update `CHANGELOG.md` with the corresponding release section.

## Repo layout

```text
.
├── access_control/            # the app
│   ├── config.yaml            # app manifest
│   ├── Dockerfile             # multi-arch image
│   ├── build.yaml             # base images per arch
│   ├── apparmor.txt           # security profile
│   ├── README.md / DOCS.md / CHANGELOG.md
│   └── rootfs/
│       ├── run.sh             # bashio entrypoint
│       └── opt/access_control/  # FastAPI app + tests
├── .github/workflows/ci.yaml  # lint + build + publish
├── docs/specs/                # design notes
├── docs/screenshots/          # README screenshots
└── README.md                  # main README
```

[builder]: https://github.com/home-assistant/builder
