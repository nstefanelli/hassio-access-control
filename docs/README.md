# Access Control documentation

This directory is the canonical documentation set for Access Control.
Start with the page that matches what you are trying to do:

| Guide | Audience | Contents |
|---|---|---|
| [Configuration](CONFIGURATION.md) | Operators | Installation, first run, credentials, locks, groups, schedules, visitors, and environment overrides |
| [Operations](OPERATIONS.md) | Operators | Health checks, logs, updates, safe backup and restore, recovery, and troubleshooting |
| [REST API](API.md) | Integrators | Authentication, scopes, endpoint contracts, examples, and errors |
| [Architecture](ARCHITECTURE.md) | Operators and developers | Components, data flow, authorization flow, persistence, and resilience |
| [Security model](SECURITY-MODEL.md) | Operators and reviewers | Assets, trust boundaries, credential handling, accepted risks, and hardening |
| [Development](DEVELOPMENT.md) | Contributors | Local setup, tests, CSS build, container build, CI, and releases |
| [Security policy](../SECURITY.md) | Reporters | Supported versions and private vulnerability reporting |
| [Changelog](../access_control/CHANGELOG.md) | Everyone | User-visible changes by release |

The repository [README](../README.md) is the project landing page. The
Home Assistant app store renders
[`access_control/README.md`](../access_control/README.md), while Supervisor's
Documentation tab renders
[`access_control/DOCS.md`](../access_control/DOCS.md). Those shorter pages
link back to this canonical set.

## Source-of-truth order

When two pages disagree, use this order:

1. The checked-out implementation and `access_control/config.yaml`.
2. The current guides listed above.
3. The latest changelog entry.
4. Dated audits and design notes.

Files under `docs/specs/` and documents with a date in their filename are
historical records. They explain why a past change was made; they are not a
current operating contract.
