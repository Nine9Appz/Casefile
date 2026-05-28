# Threat Model

## Project Overview

Casefile is a forensic case-management and incident-response application. A React/Vite frontend in `artifacts/case-room` lets operators create cases, upload evidence, launch an autonomous investigation loop, and review structured reasoning, execution logs, and incident reports. An Express 5 API in `artifacts/api-server` persists case data in PostgreSQL via Drizzle and calls an OpenAI-backed agent in `lib/sift-agent`, which can invoke local forensic tools from `lib/sift-tools` and a restricted outbound fetch tool for MCP / threat-intel enrichment.

For production scoping, the public web UI and `/api` server are in scope. `artifacts/mockup-sandbox` is a dev-only surface unless a production path is shown to serve it. The app is not currently deployed, so deployment visibility is unknown; scans should assume a normal public deployment rather than a private/password-gated one.

## Assets

- **Case data and uploaded evidence** — case titles/descriptions, uploaded logs, memory strings, network captures, MCP URLs, and disk images. This is the core customer data set and may contain credentials, secrets, internal hostnames, and other sensitive forensic material.
- **Incident reports and analysis steps** — the agent’s conclusions, intermediate findings, and training-oriented reasoning records. Exposure or tampering would mislead operators and can leak sensitive evidence-derived content.
- **Execution logs / chain-of-custody records** — tool inputs, output hashes, verified hashes, and error records. These are security-sensitive because they document what evidence was read and may echo sensitive derived data.
- **Availability and spend budget** — investigation runs consume database, CPU, memory, and OpenAI-backed model calls. Abuse of public analysis endpoints can create direct financial cost and service degradation.
- **Application secrets and integrations** — database credentials, Replit-managed OpenAI integration credentials, and any future external service secrets used by server-side tools.

## Trust Boundaries

- **Browser to API server** — every case-management, artifact, report, and investigation action crosses this boundary. The browser is untrusted; the server must authenticate callers, authorize object access, validate payloads, and rate-limit expensive actions.
- **API server to PostgreSQL** — the API has broad access to evidence, reports, and logs. Any missing access control or unsafe query path at the API layer exposes the full forensic dataset.
- **API server / agent loop to OpenAI integration** — server-side prompts and evidence-derived content leave the application boundary to an external model provider. Sensitive evidence should only cross this boundary when a legitimate user initiated analysis.
- **Agent tools to external URLs** — `mcpFetcher` is the only intended network-capable tool and must enforce SSRF protections, protocol limits, and response caps because the model can decide when to call it.
- **Production vs dev-only artifacts** — `artifacts/mockup-sandbox` exists in the repo but is not assumed to ship to production. Findings from that area should be ignored unless production reachability is demonstrated.

## Scan Anchors

- **Production entry points**: `artifacts/api-server/src/index.ts`, `artifacts/api-server/src/app.ts`, `artifacts/api-server/src/routes/*`, `artifacts/case-room/src/main.tsx`.
- **Highest-risk areas**: unauthenticated API route tree in `artifacts/api-server/src/routes/*`; agent loop and tool invocation in `lib/sift-agent/src/*`; outbound fetch logic in `lib/sift-tools/src/mcp.ts`; evidence reads in `lib/db/src/integrity.ts`.
- **Public surfaces**: case CRUD, artifact read/upload, logs, reports, chain-of-custody, and investigation start/stream endpoints under `/api`.
- **Authenticated/admin surfaces**: none currently visible in server code.
- **Usually dev-only**: `artifacts/mockup-sandbox/**` unless a production path serves it.

## Threat Categories

### Spoofing

The project currently exposes case-management and investigation functionality at the public API boundary, so the primary spoofing risk is that an unauthenticated caller can act as a legitimate analyst. The system must require a valid server-side identity for every endpoint that reads or mutates case data or triggers model-backed analysis, and object access must be bound to that identity rather than to client-supplied IDs alone.

### Tampering

Evidence integrity inside the database is treated seriously via triggers and read-time hash verification, but that guarantee only matters if untrusted callers cannot invoke mutation endpoints freely. The system must ensure that only authorized users can create cases, upload artifacts, delete cases, and start investigations, and it must prevent client-controlled requests from rewriting or destroying another user’s case history.

### Information Disclosure

Uploaded evidence, execution logs, reports, and chain-of-custody records are likely to contain sensitive incident-response material. The system must ensure these resources are not readable by the public internet, that direct artifact-fetch endpoints are scoped to authorized users, and that model/tool outputs do not leak evidence to unauthorized callers or logs.

### Denial of Service

Investigation requests can trigger repeated LLM calls and local analysis over large evidence blobs, while upload endpoints accept sizable payloads. The system must apply authentication, quotas, and rate limits to expensive or storage-heavy endpoints so an attacker cannot exhaust tokens, database space, or server resources through repeated case creation, artifact upload, or investigation runs.

### Elevation of Privilege

There is no separate admin surface today, so elevation risk centers on broken object-level authorization and unsafe tool boundaries. The system must enforce per-case authorization on every read/write path, keep external fetch capability constrained against SSRF, and ensure the model cannot turn user-supplied evidence into arbitrary server-side capability beyond the narrowly defined tool set.
