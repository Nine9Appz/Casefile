import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const NetworkInput = z.object({
  connections: z
    .array(
      z.object({
        ip: z.string(),
        port: z.number().int().min(0).max(65535).optional(),
      }),
    )
    .min(1),
});
export type NetworkInput = z.infer<typeof NetworkInput>;

export const IpFrequency = z.object({
  ip: z.string(),
  count: z.number().int().positive(),
  classification: z.enum(["private", "loopback", "linklocal", "cgnat", "public", "invalid"]),
});

export const SuspiciousPort = z.object({
  port: z.number().int(),
  reason: z.string(),
  ips: z.array(z.string()),
});

export const NetworkOutput = z.object({
  totalConnections: z.number().int(),
  uniqueIps: z.number().int(),
  internal: z.array(IpFrequency),
  external: z.array(IpFrequency),
  invalid: z.array(IpFrequency),
  repeatOffenders: z.array(IpFrequency),
  suspiciousPorts: z.array(SuspiciousPort),
});
export type NetworkOutput = z.infer<typeof NetworkOutput>;

const COMMON_PORTS: Record<number, string> = {
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  445: "smb",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  5900: "vnc",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
  9200: "elasticsearch",
  27017: "mongodb",
};

const SUSPICIOUS_PORTS: Record<number, string> = {
  23: "telnet (cleartext credentials)",
  445: "SMB (lateral movement / EternalBlue family)",
  3389: "RDP (common brute-force target)",
  4444: "Metasploit default handler",
  5900: "VNC (often exposed without auth)",
  6667: "IRC (legacy C2 channel)",
  31337: "elite/back-orifice (legacy backdoor port)",
};

function classify(ip: string): z.infer<typeof IpFrequency>["classification"] {
  const parts = ip.split(".");
  if (parts.length !== 4) return "invalid";
  const nums = parts.map(Number);
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return "invalid";
  const [a, b] = nums;
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "linklocal";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  return "public";
}

export const network: ToolDescriptor<typeof NetworkInput, typeof NetworkOutput> = {
  name: "networkAnalyzer",
  description:
    "Classifies a list of IP/port pairs as internal (RFC1918, loopback, link-local, CGNAT) vs external public IPs, counts per-IP frequency to surface repeat offenders, and flags well-known suspicious ports (telnet, SMB, RDP, common C2 ports). Operates entirely offline — no GeoIP or reputation lookups.",
  inputSchema: NetworkInput,
  outputSchema: NetworkOutput,
  run: ({ connections }) => {
    const counts = new Map<string, { count: number; classification: ReturnType<typeof classify> }>();
    const portMap = new Map<number, Set<string>>();
    for (const c of connections) {
      const cls = classify(c.ip);
      const entry = counts.get(c.ip);
      if (entry) entry.count++;
      else counts.set(c.ip, { count: 1, classification: cls });
      if (c.port !== undefined) {
        const set = portMap.get(c.port) ?? new Set<string>();
        set.add(c.ip);
        portMap.set(c.port, set);
      }
    }
    const all: z.infer<typeof IpFrequency>[] = Array.from(counts, ([ip, v]) => ({
      ip,
      count: v.count,
      classification: v.classification,
    })).sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip));

    const internal = all.filter((r) =>
      ["private", "loopback", "linklocal", "cgnat"].includes(r.classification),
    );
    const external = all.filter((r) => r.classification === "public");
    const invalid = all.filter((r) => r.classification === "invalid");
    const repeatOffenders = external.filter((r) => r.count >= 5);

    const suspiciousPorts: z.infer<typeof SuspiciousPort>[] = [];
    for (const [port, ips] of portMap.entries()) {
      const reason = SUSPICIOUS_PORTS[port];
      if (reason) {
        suspiciousPorts.push({ port, reason, ips: Array.from(ips).sort() });
      } else if (port > 49151 && ips.size >= 3) {
        suspiciousPorts.push({
          port,
          reason: "high ephemeral port reused across multiple IPs (possible scan or callback)",
          ips: Array.from(ips).sort(),
        });
      }
    }
    suspiciousPorts.sort((a, b) => a.port - b.port);

    return {
      totalConnections: connections.length,
      uniqueIps: counts.size,
      internal,
      external,
      invalid,
      repeatOffenders,
      suspiciousPorts,
    };
  },
};

export const COMMON_PORT_NAMES = COMMON_PORTS;
