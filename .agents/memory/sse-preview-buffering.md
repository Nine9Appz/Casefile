---
name: SSE buffering in the workspace preview
description: Why streamed (SSE/fetch) responses appear all-at-once in the Replit workspace preview, and the pattern to get incremental UI anyway.
---

In the Casefile project, the agent reasoning trace appeared all at once at the end instead of step-by-step. Proven cause: an SSE response (`POST /api/cases/:id/investigate`, `text/event-stream`) is buffered until the stream closes by a layer **between the platform proxy and the browser's fetch reader** — the workspace preview/iframe environment.

What was ruled out (all proven correct/streaming):
- Server: the agent is a clean async generator (`yield` per event); the route does `res.write` per event with `flushHeaders` + `X-Accel-Buffering: no` + `Cache-Control: no-cache, no-transform`.
- Platform proxy: `curl` to the dev domain streamed events ~1s apart for **GET and POST**, **even with `Accept-Encoding: gzip, br`** (response had no `content-encoding`, HTTP/2). So compression/proxy buffering is NOT the cause.
- Client read loop: the hook uses `response.body.getReader()` and parses frames incrementally (no full-body buffering).
- Browser proof: console timestamps showed every event (`started`→`done`) arriving in a ~13ms burst at close, despite ~30s server runtime.

**Why:** `curl` (no `Accept-Encoding` by default, and not the browser) bypasses whatever buffers the browser path; the buffering only manifests for the in-preview browser fetch and is outside app control.

**How to apply:** Don't depend on SSE/streamed-fetch arrival timing for incremental UI in the preview. If the data is also persisted incrementally (here, analysis steps are written to Postgres seconds apart during the run), drive the incremental UI by **polling that persisted state** (e.g. a `setInterval` invalidating the relevant react-query keys while the job runs), and keep the SSE only for ephemeral live feed. Clear the interval on completion, error, manual stop, and unmount. This may be preview/dev-only (production likely has no such buffering layer), but polling the DB is robust in both.
