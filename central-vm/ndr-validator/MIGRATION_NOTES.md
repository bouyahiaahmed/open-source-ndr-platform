# Migration notes from the old validator

I chose a clean rebuild instead of patching the old validator because the old version had too many brittle moving parts: many knobs, server-rendered pages, and checks that could easily become false critical errors.

This new validator keeps the same goal but changes the design:

- One standalone Docker Compose file.
- One FastAPI backend.
- One polished single-page UI.
- SQLite history and metric baselines.
- Direct OpenSearch queries for pipeline integrity.
- Prometheus counter-delta logic for Vector and Data Prepper silent errors.
- Optional Docker socket checks for stopped/missing containers.
- Clear evidence and remediation for every check.

The validator is intentionally resilient: if one component is down, the whole scan still completes and shows the remaining evidence instead of crashing.
