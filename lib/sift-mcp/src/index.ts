export {
  buildSiftMcpServer,
  SIFT_MCP_SERVER_NAME,
  SIFT_MCP_SERVER_VERSION,
} from "./server.js";
export {
  callSiftTool,
  listSiftTools,
  isRemoteMcp,
  getActiveMcpEndpoint,
  type DiscoveredTool,
} from "./client.js";
export {
  EVIDENCE_CONTRACT_VERSION,
  EVIDENCE_INLINE_MAX_BYTES,
  CONTENT_CONSUMING_TOOL_NAMES,
  evidenceRefSchema,
  shouldReferenceEvidence,
  resolveAndVerifyEvidence,
  EvidenceVerificationError,
  type EvidenceRef,
  type EvidenceVerificationCode,
} from "./evidence.js";
