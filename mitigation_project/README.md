# Web Cache Poisoning & Deception — Mitigation

This repo contains the **mitigated** version of the vulnerable Flask +
nginx lab used for the attack side of this project. It fixes both attack
classes at two independent layers (proxy and application) — see
`mitigation_report.md` for the full writeup.

## Structure

```
.
├── app/
│   ├── Dockerfile
│   └── app.py          # fixed Flask app
├── nginx/
│   └── nginx.conf       # fixed nginx config
├── docker-compose.yml
├── validate_fix.sh      # re-runs the original attacks, confirms they fail
└── mitigation_report.md # full write-up: root cause, fixes, validation
```

## Run it

```bash
docker compose up -d --build
./validate_fix.sh
```

The mitigated stack listens on `http://localhost:8080` (chosen to avoid
colliding with the vulnerable lab if you run both repos side by side).

## What changed vs. the vulnerable version

| Fix | nginx | Flask |
|---|---|---|
| Cache Poisoning | `X-Forwarded-Host` forwarded as `$host` instead of the client header | app no longer reads `X-Forwarded-Host` from the request at all |
| Cache Deception | `/account/profile.css` caching block removed; `/account*` forced to `proxy_cache off` + `Cache-Control: private, no-store` | `/account/<path:anything>` catch-all route removed entirely |

See `mitigation_report.md` for the detailed rationale, Sigma-rule
implications, and residual risk notes.
