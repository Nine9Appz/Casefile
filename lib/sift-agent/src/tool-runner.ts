import {
  db,
  executionLogsTable,
  loadVerifiedArtifact,
  ArtifactIntegrityError,
  type VerifiedArtifact,
} from "@workspace/db";
import {
  callSiftTool,
  getActiveMcpEndpoint,
  isRemoteMcp,
  shouldReferenceEvidence,
} from "@workspace/sift-mcp";
import { type ToolName } from "@workspace/sift-tools";

const CONTENT_CONSUMING_TOOLS = new Set<ToolName>([
  "logParser",
  "iocExtractor",
  "entropyScanner",
  "diskImageAnalyzer",
  "pcapAnalyzer",
]);

export interface RunToolOnArtifactArgs {
  caseId: string;
  artifactId: string;
  toolName: ToolName;
  extraInput?: Record<string, unknown>;
  analysisStepId?: string;
}

export interface RunToolArgs {
  caseId: string;
  toolName: ToolName;
  input: Record<string, unknown>;
  analysisStepId?: string;
}

export interface ToolRunResult {
  ok: boolean;
  toolName: ToolName;
  artifactId: string | null;
  verifiedHash: string | null;
  output: unknown;
  error: string | null;
  startedAt: Date;
  endedAt: Date;
  executionLogId: string;
}

/**
 * Run a content-consuming tool against a stored artifact. The artifact is
 * loaded via `loadVerifiedArtifact` (which checks SHA-256), the verified
 * content is injected into the tool input as `content`, the tool is invoked
 * through the Zod-validated registry, and the result is recorded in
 * `execution_logs` for the chain of custody.
 *
 * The agent never gets to type artifact content directly; it can only point
 * at an artifact by id. This is the architectural boundary that prevents
 * fabricated evidence from ever reaching a tool.
 */
export async function runToolOnArtifact(
  args: RunToolOnArtifactArgs,
): Promise<ToolRunResult> {
  const { caseId, artifactId, toolName, extraInput, analysisStepId } = args;
  if (!CONTENT_CONSUMING_TOOLS.has(toolName)) {
    throw new Error(
      `Tool '${toolName}' does not consume artifact content; use runTool() instead`,
    );
  }
  const startedAt = new Date();
  let verified: VerifiedArtifact | null = null;
  let output: unknown = null;
  let errorMessage: string | null = null;
  let ok = false;
  let useReference = false;
  try {
    verified = await loadVerifiedArtifact(artifactId);
    if (verified.artifact.caseId !== caseId) {
      throw new Error(
        `Artifact ${artifactId} does not belong to case ${caseId} (belongs to ${verified.artifact.caseId})`,
      );
    }
    // Evidence-passing contract: small text/JSON evidence travels inline; large
    // *binary* evidence (disk/memory images, pcaps) is sent by reference so a
    // multi-GB image is not base64-inlined over the wire. Reference mode only
    // applies when a remote server is configured — the in-process server has no
    // pre-staged evidence root and operates on the inline bytes. Either way the
    // verified SHA-256 travels with the call so the server can re-verify before
    // it processes the bytes.
    useReference =
      isRemoteMcp() &&
      shouldReferenceEvidence({
        contentEncoding: verified.artifact.contentEncoding,
        sizeBytes: verified.artifact.sizeBytes,
      });
    let input: Record<string, unknown>;
    if (useReference) {
      if (!verified.artifact.filename) {
        throw new Error(
          `Cannot reference large binary artifact ${artifactId} for remote ` +
            `execution: it has no filename for the Workstation to resolve`,
        );
      }
      input = {
        ...(extraInput ?? {}),
        evidenceRef: {
          path: verified.artifact.filename,
          sha256: verified.verifiedHash,
          encoding: "base64",
          sizeBytes: verified.artifact.sizeBytes,
        },
      };
    } else {
      const content =
        verified.artifact.contentEncoding === "base64"
          ? verified.bytes.toString("base64")
          : verified.artifact.content;
      input = {
        ...(extraInput ?? {}),
        content,
        sha256: verified.verifiedHash,
      };
    }
    const result = await callSiftTool(toolName, input);
    if (result.ok) {
      ok = true;
      output = result.data;
    } else {
      errorMessage = result.error;
    }
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
    // Persist a log row before re-throwing so spoliation is auditable, then
    // surface the integrity violation as a fatal halt — the agent must NOT
    // be allowed to "recover" from tampered evidence.
    if (err instanceof ArtifactIntegrityError) {
      const endedAt = new Date();
      await db.insert(executionLogsTable).values({
        caseId,
        analysisStepId: analysisStepId ?? null,
        artifactId,
        toolName,
        input: {
          artifactId,
          sha256: null,
          mcpEndpoint: getActiveMcpEndpoint(),
          extraInput: extraInput ?? {},
        },
        output: {
          error: errorMessage,
          spoliation: true,
          storedHash: err.storedHash,
          computedHash: err.computedHash,
        },
        startedAt,
        endedAt,
        error: errorMessage,
      });
      throw err;
    }
  }
  const endedAt = new Date();

  const loggedInput = {
    artifactId,
    sha256: verified?.verifiedHash ?? null,
    mcpEndpoint: getActiveMcpEndpoint(),
    evidenceMode: useReference ? "reference" : "inline",
    extraInput: extraInput ?? {},
  };
  const [logRow] = await db
    .insert(executionLogsTable)
    .values({
      caseId,
      analysisStepId: analysisStepId ?? null,
      artifactId,
      toolName,
      input: loggedInput,
      output: ok ? (output as object) : { error: errorMessage },
      startedAt,
      endedAt,
      error: errorMessage,
    })
    .returning({ id: executionLogsTable.id });

  return {
    ok,
    toolName,
    artifactId,
    verifiedHash: verified?.verifiedHash ?? null,
    output,
    error: errorMessage,
    startedAt,
    endedAt,
    executionLogId: logRow.id,
  };
}

/**
 * Run a structured tool (timelineBuilder, networkAnalyzer, mcpFetcher) that
 * does not consume artifact content directly. Still writes an execution_logs
 * row so every tool invocation is auditable.
 */
export async function runTool(args: RunToolArgs): Promise<ToolRunResult> {
  const { caseId, toolName, input, analysisStepId } = args;
  if (CONTENT_CONSUMING_TOOLS.has(toolName)) {
    throw new Error(
      `Tool '${toolName}' must be run via runToolOnArtifact() so the content is verified`,
    );
  }
  const startedAt = new Date();
  let output: unknown = null;
  let errorMessage: string | null = null;
  let ok = false;
  try {
    const result = await callSiftTool(toolName, input);
    if (result.ok) {
      ok = true;
      output = result.data;
    } else {
      errorMessage = result.error;
    }
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
  }
  const endedAt = new Date();

  const [logRow] = await db
    .insert(executionLogsTable)
    .values({
      caseId,
      analysisStepId: analysisStepId ?? null,
      artifactId: null,
      toolName,
      input: { ...input, mcpEndpoint: getActiveMcpEndpoint() },
      output: ok ? (output as object) : { error: errorMessage },
      startedAt,
      endedAt,
      error: errorMessage,
    })
    .returning({ id: executionLogsTable.id });

  return {
    ok,
    toolName,
    artifactId: null,
    verifiedHash: null,
    output,
    error: errorMessage,
    startedAt,
    endedAt,
    executionLogId: logRow.id,
  };
}

export interface RunRemoteToolArgs {
  caseId: string;
  toolName: string;
  input: Record<string, unknown>;
  analysisStepId?: string;
}

export interface RemoteToolRunResult {
  ok: boolean;
  toolName: string;
  output: unknown;
  error: string | null;
  startedAt: Date;
  endedAt: Date;
  executionLogId: string;
  mcpEndpoint: string;
}

/**
 * Run a tool that the active MCP server advertised but the agent has no static
 * wrapper for — i.e. a capability unique to a remote SIFT Workstation (e.g.
 * volatility, sleuthkit, yara). These tools operate on evidence the Workstation
 * holds locally; the agent passes through the model-supplied arguments and
 * records the call (with the endpoint) for the chain of custody.
 *
 * Unlike `runToolOnArtifact`, no Casefile-stored content is injected here — the
 * agent is not the custodian of the Workstation's local evidence — so this path
 * does not perform agent-side hash verification. That guarantee shifts to the
 * Workstation, and the boundary is documented in the architecture notes.
 */
export async function runRemoteTool(
  args: RunRemoteToolArgs,
): Promise<RemoteToolRunResult> {
  const { caseId, toolName, input, analysisStepId } = args;
  const mcpEndpoint = getActiveMcpEndpoint();
  const startedAt = new Date();
  let output: unknown = null;
  let errorMessage: string | null = null;
  let ok = false;
  try {
    const result = await callSiftTool(toolName, input);
    if (result.ok) {
      ok = true;
      output = result.data;
    } else {
      errorMessage = result.error;
    }
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
  }
  const endedAt = new Date();

  const [logRow] = await db
    .insert(executionLogsTable)
    .values({
      caseId,
      analysisStepId: analysisStepId ?? null,
      artifactId: null,
      toolName,
      input: { ...input, mcpEndpoint, remote: true },
      output: ok ? (output as object) : { error: errorMessage },
      startedAt,
      endedAt,
      error: errorMessage,
    })
    .returning({ id: executionLogsTable.id });

  return {
    ok,
    toolName,
    output,
    error: errorMessage,
    startedAt,
    endedAt,
    executionLogId: logRow.id,
    mcpEndpoint,
  };
}
