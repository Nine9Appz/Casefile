#!/usr/bin/env node
/**
 * Reference SIFT Workstation MCP server (USER-OWNED, ADAPT BEFORE USE).
 *
 * This is a self-contained example of the server you run *on your own* SIFT
 * Workstation VM so Casefile can drive real DFIR command-line tools over the
 * network via MCP. It implements the same MCP Streamable-HTTP contract the
 * agent's remote client speaks (`POST /mcp`), so once it is running and
 * reachable you only need to point the agent at it:
 *
 *     # on the SIFT Workstation VM
 *     npm install @modelcontextprotocol/sdk zod
 *     SIFT_MCP_TOKEN=<a-long-random-secret> node sift-workstation-server.mjs
 *
 *     # on the Casefile agent (api-server) side
 *     SIFT_MCP_URL=https://<your-vm-host>:8790/mcp
 *     SIFT_MCP_TOKEN=<the-same-secret>
 *
 * The agent discovers whatever tools this server advertises over `tools/list`
 * and exposes any it does not already have a built-in wrapper for to the model
 * (generic remote dispatch). The tools below are deliberately small, real
 * examples — replace/extend them with the actual Workstation capabilities you
 * want to expose (volatility3, sleuthkit, plaso, yara, ...).
 *
 * TRUST BOUNDARY (read this):
 *  - For built-in Casefile tools, evidence integrity (SHA-256 verification) is
 *    enforced agent-side before the tool runs, because the agent is the
 *    custodian of that content. The tools here operate on evidence that lives
 *    on THIS machine, so the agent cannot hash-verify it — that responsibility
 *    is yours. Keep the VM and its evidence store trusted, and prefer
 *    read-only handling of acquired images.
 *  - This server exposes only the specific, schema-validated tools you register
 *    below. Do NOT add a generic "run any shell command" tool: that would hand
 *    an LLM arbitrary code execution on your Workstation.
 *  - Always set SIFT_MCP_TOKEN (shared secret) and put the endpoint behind TLS
 *    / a private network. Without a token the server refuses to start.
 *
 * This file is plain Node ESM (.mjs) with no Casefile dependencies so you can
 * copy it onto a stock SIFT Workstation and run it directly.
 */
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const execFileAsync = promisify(execFile);

const PORT = Number(process.env.PORT ?? process.env.SIFT_MCP_PORT ?? 8790);
const TOKEN = process.env.SIFT_MCP_TOKEN?.trim() || null;
/**
 * Root directory under which acquired evidence (disk/memory images, pcaps) is
 * pre-staged on this Workstation. The agent never transfers the bytes; it sends
 * a reference { path, sha256 } and this server resolves the file *here* and
 * re-verifies the hash before any tool touches it. Set this to your evidence
 * locker, e.g. /cases/evidence.
 */
const EVIDENCE_ROOT = process.env.SIFT_MCP_EVIDENCE_ROOT?.trim() || null;

if (!TOKEN) {
  console.error(
    "Refusing to start: set SIFT_MCP_TOKEN to a long random secret so only " +
      "your Casefile agent can reach this Workstation.",
  );
  process.exit(1);
}

/**
 * Evidence-passing contract (shared with the agent): resolve a pre-staged file
 * under EVIDENCE_ROOT and re-verify its SHA-256 (over the raw bytes, i.e.
 * sha256sum-compatible) before returning its absolute path to a DFIR tool. Fails
 * closed: throws if the root is unset, the path escapes the root, the file is
 * missing, or the hash does not match — so a tool never runs on unverified or
 * tampered evidence.
 */
const evidenceRefSchema = z.object({
  path: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-fA-F]{64}$/),
  encoding: z.enum(["base64", "text"]).optional(),
  sizeBytes: z.number().int().nonnegative().optional(),
});

async function resolveVerifiedEvidencePath(ref) {
  const parsed = evidenceRefSchema.safeParse(ref);
  if (!parsed.success) {
    throw new Error(`invalid evidenceRef: ${parsed.error.message}`);
  }
  if (!EVIDENCE_ROOT) {
    throw new Error(
      "this Workstation has no SIFT_MCP_EVIDENCE_ROOT configured; cannot resolve evidence references",
    );
  }
  const root = resolve(EVIDENCE_ROOT);
  const full = resolve(root, parsed.data.path);
  if (full !== root && !full.startsWith(root + sep)) {
    throw new Error(`evidence path '${parsed.data.path}' escapes the evidence root`);
  }
  let bytes;
  try {
    bytes = await readFile(full);
  } catch {
    throw new Error(`pre-staged evidence not found at '${parsed.data.path}'`);
  }
  const computed = createHash("sha256").update(bytes).digest("hex");
  if (computed.toLowerCase() !== parsed.data.sha256.toLowerCase()) {
    throw new Error(
      `sha256 mismatch for '${parsed.data.path}': expected ${parsed.data.sha256}, recomputed ${computed}`,
    );
  }
  return full;
}

const evidenceRefInput = z
  .object({
    path: z.string().min(1).describe("Path of the pre-staged evidence, relative to SIFT_MCP_EVIDENCE_ROOT."),
    sha256: z.string().regex(/^[0-9a-fA-F]{64}$/).describe("Expected SHA-256 (hex) of the raw evidence bytes."),
    encoding: z.enum(["base64", "text"]).optional(),
    sizeBytes: z.number().int().nonnegative().optional(),
  })
  .describe(
    "Reference to pre-staged evidence; the server resolves it under " +
      "SIFT_MCP_EVIDENCE_ROOT and re-verifies the sha256 before the tool runs.",
  );

/**
 * Run a DFIR CLI and return its stdout as text. Arguments are always passed as
 * an argv array (never a shell string) so the model's inputs cannot inject
 * extra shell commands. Adjust the allowlisted binaries/paths for your VM.
 */
async function runCli(bin, args, { timeoutMs = 120_000 } = {}) {
  try {
    const { stdout } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return {
      ok: false,
      error: e?.stderr?.toString?.() || e?.message || String(e),
    };
  }
}

function textResult(payload) {
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
  };
}

function errorResult(message) {
  return { content: [{ type: "text", text: String(message) }], isError: true };
}

function buildServer() {
  const server = new McpServer({
    name: "sift-workstation",
    version: "0.1.0",
  });

  // Example 1: Volatility 3 process listing on a memory image. Demonstrates a
  // genuine Workstation capability Casefile has no built-in wrapper for, so it
  // is discovered and exposed to the agent as a remote tool.
  server.registerTool(
    "volatility_pslist",
    {
      description:
        "List processes from a memory image using Volatility 3 " +
        "(windows.pslist). The memory image is passed by reference and the " +
        "server verifies its SHA-256 before running. Returns the raw output.",
      inputSchema: {
        evidenceRef: evidenceRefInput,
      },
    },
    async (args) => {
      let imagePath;
      try {
        imagePath = await resolveVerifiedEvidencePath(args?.evidenceRef);
      } catch (e) {
        return errorResult(e?.message || String(e));
      }
      const res = await runCli("vol", ["-f", imagePath, "windows.pslist"]);
      if (!res.ok) return errorResult(res.error);
      return textResult({ tool: "windows.pslist", output: res.stdout });
    },
  );

  // Example 2: Sleuth Kit filesystem listing on a disk image.
  server.registerTool(
    "tsk_fls",
    {
      description:
        "List files/directories in a disk image using The Sleuth Kit (fls). " +
        "The disk image is passed by reference and the server verifies its " +
        "SHA-256 before running. Useful for surfacing deleted entries.",
      inputSchema: {
        evidenceRef: evidenceRefInput,
        offset: z
          .number()
          .int()
          .optional()
          .describe("Partition byte offset (sectors * 512), if applicable."),
      },
    },
    async (args) => {
      let imagePath;
      try {
        imagePath = await resolveVerifiedEvidencePath(args?.evidenceRef);
      } catch (e) {
        return errorResult(e?.message || String(e));
      }
      const argv = ["-r"];
      if (typeof args?.offset === "number") {
        argv.push("-o", String(args.offset));
      }
      argv.push(imagePath);
      const res = await runCli("fls", argv);
      if (!res.ok) return errorResult(res.error);
      return textResult({ tool: "fls", output: res.stdout });
    },
  );

  // Example 3: YARA scan of a file against a rules file. The scan target is
  // evidence (verified by reference); the rules file is a Workstation-local
  // path you control, not evidence.
  server.registerTool(
    "yara_scan",
    {
      description:
        "Scan a pre-staged evidence file with a YARA rules file and return " +
        "matches. The target is verified by SHA-256 before scanning.",
      inputSchema: {
        rulesPath: z.string().describe("Path to a .yar/.yara rules file."),
        evidenceRef: evidenceRefInput,
      },
    },
    async (args) => {
      const rulesPath = String(args?.rulesPath ?? "");
      if (!rulesPath) return errorResult("rulesPath is required");
      let targetPath;
      try {
        targetPath = await resolveVerifiedEvidencePath(args?.evidenceRef);
      } catch (e) {
        return errorResult(e?.message || String(e));
      }
      const res = await runCli("yara", ["-r", rulesPath, targetPath]);
      if (!res.ok) return errorResult(res.error);
      return textResult({ tool: "yara", matches: res.stdout });
    },
  );

  return server;
}

const httpServer = createServer(async (req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", server: "sift-workstation" }));
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }

  const auth = req.headers.authorization;
  if (auth !== `Bearer ${TOKEN}`) {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "unauthorized" }));
    return;
  }

  let body;
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
  } catch {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid_json" }));
    return;
  }

  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (e) {
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "internal_error",
          message: e instanceof Error ? e.message : String(e),
        }),
      );
    }
  }
});

httpServer.listen(PORT, () => {
  console.log(
    `SIFT Workstation MCP server listening on :${PORT} — POST /mcp (bearer auth required)`,
  );
});
