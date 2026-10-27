# Phase 4 — Mitigation and Hardening

## 1. Overview

Both attacks exploited the same root cause: the cache layer (nginx) trusted
inputs it should not have trusted — a client-supplied header in the
poisoning case, and an ambiguous URL path in the deception case — while the
application layer blindly reflected that same untrusted input back into
responses. The fixes below close each gap independently, at both the proxy
and the application level, so that a failure in one layer does not reopen
the vulnerability.

| Attack | Root cause | Where it's fixed |
|---|---|---|
| Cache Poisoning (X-Forwarded-Host) | Unkeyed, attacker-controlled header reflected into cached HTML | nginx (stop forwarding client header) + Flask (stop reading it) |
| Web Cache Deception | URL path confusion lets `/account/x.css` resolve to private data, which the cache then stores as if it were a static asset | nginx (no caching under `/account`) + Flask (remove the path-confusion route) |

## 2. Fix 1 — X-Forwarded-Host Cache Poisoning

**nginx (`nginx.conf`)**
- Changed `proxy_set_header X-Forwarded-Host $http_x_forwarded_host;` to
  `proxy_set_header X-Forwarded-Host $host;` in every location block.
  `$host` is derived by nginx from its own server config / the request's
  real `Host` header context, not from a client-injectable variable — the
  client can no longer put arbitrary text into this header.

**Flask (`app.py`)**
- Removed `request.headers.get('X-Forwarded-Host', request.host)` from
  `home()` and `static_page()`. Both now use a fixed `CANONICAL_HOST`
  value read from server-side configuration (environment variable), so
  there is nothing left for an attacker's header to influence even if a
  future proxy misconfiguration forwarded it again.
- This is defense in depth: fixing only nginx would already stop the
  attack, but fixing the app too means the vulnerability can't be
  reintroduced by a single config change on either side alone.

**Validation:**
```bash
curl -H "X-Forwarded-Host: attacker.evil.com" http://localhost:8081/
# Expect: links point to the real canonical host, not attacker.evil.com
```

## 3. Fix 2 — Web Cache Deception

**nginx (`nginx.conf`)**
- Removed the `location = /account/profile.css` block that explicitly
  cached a sensitive response and ignored `Cache-Control`, `Expires`,
  `Vary`, and `Set-Cookie` — this block existed purely to make the
  deception demo work and is the most direct fix: delete it.
- The regex location `location ~ ^/(login|account|logout)` now applies to
  *every* path under `/account/...` (nginx regex locations match on
  prefix, so `/account/x.css`, `/account/photo.jpg`, etc. all fall into
  this block) and sets `proxy_cache off;` plus
  `Cache-Control: private, no-store` unconditionally. There is no
  location block anywhere in the config that caches anything under
  `/account`.

**Flask (`app.py`)**
- Removed the `@app.route('/account/<path:anything>')` catch-all route
  entirely. That route was the actual source of the "URL interpretation
  mismatch" — it's what made `/account/nonexistent.css` resolve to the
  real account page in the first place. Without it, any such path returns
  a normal Flask 404, so there's no sensitive body for a cache to
  mistakenly store as a static asset even under a misconfigured proxy.
- Added an `after_request` hook that sets `Cache-Control: private,
  no-store` on every response under `/account`, `/login`, and `/logout`
  as a second layer of protection independent of the nginx config.

**Validation:**
```bash
curl -i http://localhost:8080/account/x.css
# Expect: 404 Not Found, and no X-Cache-Status: HIT on a repeat request
```

## 4. Why both layers matter

A single-layer fix is fragile in a real deployment: proxies get
reconfigured, new routes get added by other developers, and WAF/CDN rules
in front of nginx can reintroduce unkeyed headers. Fixing the application
to never trust `X-Forwarded-Host` and never expose a path-confusable route
means the app is safe even if the proxy config regresses, and fixing the
proxy means the app is protected even before a code deploy ships.

## 5. Detection rules (carried over from Phase 3, still valid)

The Sigma rules your team already wrote for Phase 3 continue to serve as
compensating controls post-fix — they now function as **regression
alerts**: if either rule fires in production logs after these mitigations
are deployed, it means the fix was bypassed or reverted and should trigger
an incident review rather than being expected traffic.

- `Web Cache Deception Attempt` — flags `/account/*.{css,js,jpg,png,gif}`
  requests. Post-fix, these should only ever return 404 and never a HIT.
- `Unkeyed Header Injection Attempt` — flags `X-Forwarded-Host` headers
  containing `evil`/`attacker` strings. Post-fix, this header is no
  longer forwarded to the app at all, so any log line matching this rule
  indicates either an attack attempt against the old config or a
  misconfigured proxy in front of nginx.

## 6. Residual risk / what's out of scope

- `app.secret_key` and session cookie flags were hardened
  (`HttpOnly`, `SameSite=Lax`, `Secure`) as general good practice, but
  session management itself was not part of the two attack classes this
  project targets and would need its own review (e.g., secret rotation,
  session fixation) for a production system.
- These fixes assume nginx is the only cache in the request path. A real
  deployment with a CDN in front of nginx would need the same
  `Cache-Control: private, no-store` policy enforced at the CDN layer too,
  since a CDN cache would not consult nginx's cache-key logic at all.

## 7. Re-running the attacks against the fixed stack

To demonstrate the fix in the final report, re-run your friend's exact
attack steps from Phase 2 against the mitigated containers and capture the
output showing failure:

1. Cache poisoning attempt → response no longer contains the attacker's
   host anywhere in the HTML.
2. Cache deception attempt (`/account/photo.jpg`,
   `/account/profile.css`) → `404` on first request; `X-Cache-Status`
   never reaches `HIT` for an unauthenticated attacker.
3. Static-page JS injection → script `src` always points to the fixed
   canonical host, never to a header-controlled one.

Pair each "before" screenshot (already in the attack catalogue PDF) with
an "after" screenshot from the mitigated stack for the final report —
that side-by-side is usually the strongest piece of evidence in these
write-ups.
