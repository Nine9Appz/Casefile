# Protocol SIFT — Analyst Training Loop

## Overview

Protocol SIFT is a fully autonomous incident response agent that processes forensic case data
(logs, network captures, memory strings, MCP endpoints) and explains its reasoning at every
step. Designed to train junior analysts by making the senior-analyst decision-making process
transparent — what tool was chosen, why, what was expected, what was actually found, and how
the investigation pivots when findings don't add up.

License: MIT.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **AI engine**: OpenAI gpt-5.4 via Replit AI Integrations proxy
  (no API key required; client at `lib/integrations-openai-ai-server`)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

## Build Progress

- [x] Step 1 — MIT license + OpenAI AI integration setup
- [ ] Step 2 — Database schema (cases, artifacts, analysis steps, exec logs, reports)
- [ ] Step 3 — OpenAPI spec + codegen
- [ ] Step 4 — Forensic tool suite (log parser, IOC extractor, timeline, network, entropy, MCP)
- [ ] Step 5 — Evidence integrity enforcement (architectural read-only boundary)
- [ ] Step 6 — Autonomous agent reasoning loop (streaming SSE)
- [ ] Step 7 — React frontend case room interface
- [ ] Step 8 — Streaming polish + bundled sample dataset

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
