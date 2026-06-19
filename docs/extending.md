# Extending Casefile

This guide is for a practitioner who wants to *build on* Casefile: add a new
forensic tool the agent can call, add a new kind of evidence it can ingest, or
attach a real DFIR workstation. It documents the exact files and the order to
touch them.

For the runtime architecture and trust model, see
[`architecture.md`](architecture.md). For deployment and configuration, see the
[README](../README.md).

## The tool pipeline

A forensic capability flows through three packages:

```
lib/sift-tools     ToolDescriptor (pure function + zod in/out schemas)
      |              registered in TOOL_REGISTRY
      v
lib/sift-mcp       auto-served over MCP — server.ts iterates TOOL_REGISTRY
      |              and calls server.registerTool for every entry
      v
lib/sift-agent     tool-adapter.ts exposes a model-facing tool that maps to
                     the underlying sift-tool and dispatches the call
```

The important consequence: once a tool is in `TOOL_REGISTRY`, the MCP server
exposes it automatically. You do **not** hand-register anything in
`lib/sift-mcp`. The deliberate wiring is (1) the registry entry and (2) the
agent-facing tool in `sift-agent` — plus, for a tool that reads an artifact's
bytes, (3) declaring it in two content-consuming allowlists (see the caveat in
step 3).

## Add a native forensic tool

Worked example: a tool the agent runs against an artifact's content. Use the
existing entropy scanner ([`lib/sift-tools/src/entropy.ts`](../lib/sift-tools/src/entropy.ts))
as the template.

### 1. Implement the tool — `lib/sift-tools/src/<yourTool>.ts`

Export a `ToolDescriptor` (see
[`lib/sift-tools/src/types.ts`](../lib/sift-tools/src/types.ts)): a `name`, a
`description`, zod `inputSchema` / `outputSchema`, and a pure `run` function.
Keep it pure — no I/O, no network. (`mcpFetcher` is the only tool that touches
the network, and it is locked down server-side.)

```ts
import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const YaraScanInput = z.object({
  content: z.string().min(1),
  ruleset: z.enum(["default", "packers"]).default("default"),
});

export const YaraScanOutput = z.object({
  matches: z.array(z.object({ rule: z.string(), offset: z.number().int() })),
});

export const yaraScan: ToolDescriptor<typeof YaraScanInput, typeof YaraScanOutput> = {
  name: "yaraScan",
  description: "Scan artifact content against a bundled YARA ruleset.",
  inputSchema: YaraScanInput,
  outputSchema: YaraScanOutput,
  run: ({ content, ruleset }) => {
    // pure analysis of `content`
    return { matches: [] };
  },
};
```

For a tool that reads evidence bytes, name the input field `content` (a string).
The agent never passes raw bytes around — it passes an `artifact_id`, and the
api-server loads + hash-verifies the artifact and feeds its content in (see
dispatch step 4 below).

### 2. Register it — `lib/sift-tools/src/index.ts`

Import the descriptor, export it, and add it to `TOOL_REGISTRY`. The registry
key is the canonical `ToolName` used everywhere downstream.

```ts
import { yaraScan } from "./yara.js";
export * from "./yara.js";

export const TOOL_REGISTRY = {
  // ...existing entries...
  yaraScan,
} as const;
```

`ToolName` is `keyof typeof TOOL_REGISTRY`, so this entry is now a valid tool
name across the codebase, and `listTools()` advertises its schema.

### 3. MCP exposure — nothing to do

[`lib/sift-mcp/src/server.ts`](../lib/sift-mcp/src/server.ts) iterates
`TOOL_REGISTRY` and registers every entry as a typed MCP tool. The in-process
client and the stdio entrypoint both pick it up with no further changes.

One caveat for **content-consuming tools** — tools that read an artifact's
bytes (the `content` field pattern). A content tool must be named in two
allowlists or it will fail at runtime:

- `CONTENT_CONSUMING_TOOL_NAMES` in
  [`lib/sift-mcp/src/evidence.ts`](../lib/sift-mcp/src/evidence.ts) — enables the
  inline/reference evidence contract (re-verifying a pre-staged file's SHA-256
  in remote mode). `server.ts` derives its `CONTENT_CONSUMING` set from this
  list, so this is the single place to edit on the MCP side.
- `CONTENT_CONSUMING_TOOLS` in
  [`lib/sift-agent/src/tool-runner.ts`](../lib/sift-agent/src/tool-runner.ts) —
  `runToolOnArtifact` (the function behind `dispatchArtifactTool` in step 4)
  throws `Tool '<name>' does not consume artifact content; use runTool()
  instead` unless the tool is in this set.

Structured-input tools (which take already-extracted data, not raw evidence)
appear in neither list.

### 4. Expose it to the agent — `lib/sift-agent/src/tool-adapter.ts`

This is where you decide what the model can call and how the call is dispatched.
Four edits in this one file:

1. Add the model-facing name to the `AgentToolName` union.
2. Add a zod args schema for the model's arguments. If the tool just takes an
   artifact id, reuse the existing `ArtifactRefArgs` ( `{ artifact_id }` ).
3. Add an entry to the `TOOLS` array: `name`, a model-facing `description`
   (this is the prompt the model sees — be precise about when to use it and
   what it returns), the `schema`, and `underlyingTool` set to the
   `TOOL_REGISTRY` key from step 2.
4. Add a `case` for it in `dispatchToolCall`. Pick the dispatcher that matches
   the tool's input:

| Tool input | Dispatcher | What it does |
| --- | --- | --- |
| An artifact id (`ArtifactRefArgs`) | `dispatchArtifactTool(def.underlyingTool!, args.artifact_id, ctx)` | Loads + **hash-verifies** the artifact, runs the tool on its content, writes an `execution_logs` row, returns `execution_log_id` + `verified_hash`. |
| Already-extracted structured data | `dispatchStructuredTool(def.underlyingTool!, args, ctx)` | Runs the tool on the supplied arguments, writes an `execution_logs` row. No artifact hashing (no artifact is read). |

```ts
// 1. union
type AgentToolName = /* ... */ | "yara_scan";

// 3. TOOLS array
{
  name: "yara_scan",
  description:
    "Scan an artifact's content against the bundled YARA ruleset. Returns rule matches with offsets.",
  schema: ArtifactRefArgs,
  underlyingTool: "yaraScan",
},

// 4. dispatch — add yara_scan to the artifact-tool case group
case "yara_scan": {
  const args = parsed.data as z.infer<typeof ArtifactRefArgs>;
  return dispatchArtifactTool(def.underlyingTool!, args.artifact_id, ctx);
}
```

Use `dispatchArtifactTool` whenever the tool acts on stored evidence — it is
what produces the chain-of-custody guarantee (the returned `verified_hash` is
the SHA-256 the tool actually ran on, recorded in `execution_logs`). It calls
`runToolOnArtifact`, so the tool must be in the two content-consuming allowlists
from step 3 or the call throws. Reserve `dispatchStructuredTool` for tools that
operate on data the agent already pulled from a prior tool result (like
`build_timeline` and `analyze_network`), where there is no artifact to
re-verify.

### 5. Verify

```sh
pnpm run typecheck   # the ToolName / AgentToolName unions catch missed wiring
pnpm run build
```

Then start the API server, load a case, and run an investigation — the new tool
appears in the model's callable set and, when used, in the Chain of Custody tab.

## Add a new kind of evidence

Artifact kinds are a Postgres enum,
[`artifactKindEnum`](../lib/db/src/schema/case-artifacts.ts) (`log_file`,
`network_capture`, `memory_strings`, `text`, `mcp_endpoint`, `disk_image`).

1. Add your value to `artifactKindEnum` in
   `lib/db/src/schema/case-artifacts.ts`.
2. Apply the schema change: `pnpm --filter @workspace/db run push`.
3. If a tool should only run against the new kind, say so in that tool's
   model-facing `description` in `tool-adapter.ts` (as `analyze_disk_image` and
   `analyze_pcap` do — "Only valid against artifacts of kind ...").

Note: artifact content and hash are immutable once written — database triggers
([`lib/db/src/triggers.sql`](../lib/db/src/triggers.sql)) reject any UPDATE to
`content`/`kind`/`sha256_hash` and block direct deletes. Adding an enum value is
a schema change and is unaffected; this only constrains row mutation.

## Attach a real DFIR workstation (remote tools)

You do not need to write any Casefile code to add tools that live on a real SANS
SIFT Workstation (or any MCP server speaking the same contract). The agent
discovers remote tools over `tools/list` and exposes only the ones you name in
`SIFT_REMOTE_TOOL_ALLOWLIST` (deny-by-default). See
[Remote SIFT Workstation over MCP](../README.md#remote-sift-workstation-over-mcp)
in the README and the reference server at
[`lib/sift-mcp/reference/sift-workstation-server.mjs`](../lib/sift-mcp/reference/sift-workstation-server.mjs).

Add a native tool (this guide) when the capability is pure analysis that should
ship with Casefile; add a remote tool (allowlist) when it must run real DFIR
binaries on a trusted VM you control.
