import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const LogParserInput = z.object({
  content: z.string().min(1),
  format: z.enum(["ssh", "syslog", "generic", "auto"]).default("auto"),
});
export type LogParserInput = z.infer<typeof LogParserInput>;

export const LogEvent = z.object({
  timestamp: z.string().nullable(),
  source: z.string().nullable(),
  action: z.string().nullable(),
  user: z.string().nullable(),
  ip: z.string().nullable(),
  raw: z.string(),
});
export type LogEvent = z.infer<typeof LogEvent>;

export const LogParserOutput = z.object({
  format: z.enum(["ssh", "syslog", "generic"]),
  eventCount: z.number().int().nonnegative(),
  events: z.array(LogEvent),
});
export type LogParserOutput = z.infer<typeof LogParserOutput>;

const SSH_RE =
  /^(?<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:(?<host>\S+)\s+)?sshd(?:\[\d+\])?:\s*(?<msg>.*)$/;
const SSH_ACCEPT_RE =
  /^(?<action>Accepted|Failed)\s+(?<method>\S+)\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<ip>\S+)\s+port\s+\d+/;
const SSH_DISCONNECT_RE = /Disconnected from (?:user \S+ )?(?<ip>\S+)/;
const SYSLOG_RE =
  /^(?<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<proc>[^:\[\]]+)(?:\[\d+\])?:\s*(?<msg>.*)$/;
const ISO_TS_RE = /^(?<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?<msg>.*)$/;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function detectFormat(content: string): "ssh" | "syslog" | "generic" {
  const head = content.split("\n").slice(0, 20).join("\n");
  if (/sshd(?:\[\d+\])?:/.test(head)) return "ssh";
  if (SYSLOG_RE.test(head.split("\n")[0] ?? "")) return "syslog";
  return "generic";
}

function parseSshLine(line: string): LogEvent | null {
  const m = SSH_RE.exec(line);
  if (!m?.groups) return null;
  const { ts, host, msg } = m.groups;
  let action: string | null = null;
  let user: string | null = null;
  let ip: string | null = null;
  const accept = SSH_ACCEPT_RE.exec(msg);
  if (accept?.groups) {
    action = accept.groups.action.toLowerCase() === "accepted" ? "auth_success" : "auth_failure";
    user = accept.groups.user;
    ip = accept.groups.ip;
  } else {
    const disc = SSH_DISCONNECT_RE.exec(msg);
    if (disc?.groups) {
      action = "disconnect";
      ip = disc.groups.ip;
    } else {
      action = "ssh_event";
      const ipMatch = IP_RE.exec(msg);
      if (ipMatch) ip = ipMatch[0];
    }
  }
  return { timestamp: ts, source: host ?? "sshd", action, user, ip, raw: line };
}

function parseSyslogLine(line: string): LogEvent | null {
  const m = SYSLOG_RE.exec(line);
  if (!m?.groups) return null;
  const { ts, host, proc, msg } = m.groups;
  const ipMatch = IP_RE.exec(msg);
  return {
    timestamp: ts,
    source: `${host}/${proc}`,
    action: proc,
    user: null,
    ip: ipMatch ? ipMatch[0] : null,
    raw: line,
  };
}

function parseGenericLine(line: string): LogEvent | null {
  const iso = ISO_TS_RE.exec(line);
  const ipMatch = IP_RE.exec(line);
  if (!iso?.groups && !ipMatch) return null;
  return {
    timestamp: iso?.groups?.ts ?? null,
    source: null,
    action: null,
    user: null,
    ip: ipMatch ? ipMatch[0] : null,
    raw: line,
  };
}

function parse(content: string, format: "ssh" | "syslog" | "generic"): LogEvent[] {
  const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events: LogEvent[] = [];
  for (const line of lines) {
    const parser =
      format === "ssh" ? parseSshLine : format === "syslog" ? parseSyslogLine : parseGenericLine;
    const ev = parser(line) ?? parseGenericLine(line);
    if (ev) events.push(ev);
  }
  return events;
}

export const logParser: ToolDescriptor<typeof LogParserInput, typeof LogParserOutput> = {
  name: "logParser",
  description:
    "Parses raw log text into structured events. Supports SSH/sshd auth logs, generic syslog, and a fallback that extracts timestamps and IPs from arbitrary lines. Set format to 'auto' (default) to let the tool detect the format.",
  inputSchema: LogParserInput,
  outputSchema: LogParserOutput,
  run: ({ content, format }) => {
    const fmt = format === "auto" ? detectFormat(content) : format;
    const events = parse(content, fmt);
    return { format: fmt, eventCount: events.length, events };
  },
};
