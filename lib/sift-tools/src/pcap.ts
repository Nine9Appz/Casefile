import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

/**
 * Pure-Node packet-capture analyzer. Parses classic libpcap (.pcap / .cap)
 * and pcapng (.pcapng) files straight from bytes — it never shells out to
 * tshark/tcpdump or mounts anything. It walks the capture, decodes the
 * link/IP/transport headers of each packet, and rolls the result up into
 * conversation, talker, protocol, and DNS summaries plus harvested IP/domain
 * indicators.
 *
 * The aggregates are capped so the output stays small regardless of how big
 * the capture is; `maxPackets` bounds how many packets are decoded.
 */

const DEFAULT_MAX_PACKETS = 50000;
const MAX_CONNECTIONS = 100;
const MAX_TALKERS = 50;
const MAX_DNS = 100;
const MAX_ENDPOINTS = 200;
const MAX_INDICATORS = 200;

export const PcapInput = z.object({
  content: z.string().min(1),
  maxPackets: z.number().int().min(1).max(500000).default(DEFAULT_MAX_PACKETS),
});
export type PcapInput = z.infer<typeof PcapInput>;

const Connection = z.object({
  srcIp: z.string(),
  srcPort: z.number().int().nullable(),
  dstIp: z.string(),
  dstPort: z.number().int().nullable(),
  protocol: z.string(),
  packets: z.number().int().positive(),
});

const Talker = z.object({
  ip: z.string(),
  packets: z.number().int().positive(),
});

const Endpoint = z.object({
  ip: z.string(),
  port: z.number().int().optional(),
});

export const PcapOutput = z.object({
  detectedFormat: z.enum(["pcap", "pcapng", "unknown"]),
  byteOrder: z.enum(["big", "little", "unknown"]),
  linkTypes: z.array(z.string()),
  packetsParsed: z.number().int().nonnegative(),
  truncated: z.boolean(),
  timeRange: z.object({
    start: z.string().nullable(),
    end: z.string().nullable(),
  }),
  protocolCounts: z.object({
    tcp: z.number().int().nonnegative(),
    udp: z.number().int().nonnegative(),
    icmp: z.number().int().nonnegative(),
    other: z.number().int().nonnegative(),
  }),
  topConnections: z.array(Connection),
  topTalkers: z.array(Talker),
  endpoints: z.array(Endpoint),
  dnsQueries: z.array(z.string()),
  embeddedIndicators: z.object({
    ipv4: z.array(z.string()),
    domains: z.array(z.string()),
  }),
  observations: z.array(z.string()),
});
export type PcapOutput = z.infer<typeof PcapOutput>;

const LINKTYPE_NAMES: Record<number, string> = {
  0: "NULL/Loopback",
  1: "Ethernet",
  12: "Raw IP",
  14: "Raw IP",
  101: "Raw IP",
  113: "Linux SLL",
  127: "802.11 Radiotap",
  276: "Linux SLL2",
};

interface DecodedPacket {
  tsMs: number | null;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: "tcp" | "udp" | "icmp" | "other";
  dnsName: string | null;
}

function ipv4(buf: Buffer, o: number): string {
  return `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}`;
}

function ipv6(buf: Buffer, o: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(buf.readUInt16BE(o + i).toString(16));
  }
  // Collapse the longest run of zero groups into "::".
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen > 1) {
    const head = groups.slice(0, bestStart).join(":");
    const tail = groups.slice(bestStart + bestLen).join(":");
    return `${head}::${tail}`;
  }
  return groups.join(":");
}

// Returns the offset within `pkt` where the IP header begins, or null when the
// frame is not IP (ARP, unsupported link layer, truncated, ...).
function linkLayerToIp(pkt: Buffer, linkType: number): number | null {
  switch (linkType) {
    case 1: {
      // Ethernet II
      if (pkt.length < 14) return null;
      let etherType = pkt.readUInt16BE(12);
      let off = 14;
      // Walk VLAN (802.1Q / 802.1ad) tags.
      while (etherType === 0x8100 || etherType === 0x88a8) {
        if (pkt.length < off + 4) return null;
        etherType = pkt.readUInt16BE(off + 2);
        off += 4;
      }
      if (etherType === 0x0800 || etherType === 0x86dd) return off;
      return null;
    }
    case 0:
      // BSD loopback: 4-byte address family in host order.
      return pkt.length >= 4 ? 4 : null;
    case 113:
      // Linux "cooked" SLL.
      return pkt.length >= 16 ? 16 : null;
    case 276:
      // Linux SLL2.
      return pkt.length >= 20 ? 20 : null;
    case 12:
    case 14:
    case 101:
      // Raw IP (no link layer).
      return 0;
    default:
      return null;
  }
}

function decodeDnsName(buf: Buffer, l4Start: number): string | null {
  // UDP header is 8 bytes; DNS header is 12 bytes; questions follow.
  const dns = l4Start + 8;
  if (buf.length < dns + 12) return null;
  const qdcount = buf.readUInt16BE(dns + 4);
  if (qdcount < 1) return null;
  let p = dns + 12;
  const labels: string[] = [];
  let guard = 0;
  while (p < buf.length && guard++ < 64) {
    const len = buf[p];
    if (len === 0) break;
    // Compression pointer — uncommon in a question, just stop here.
    if ((len & 0xc0) === 0xc0) break;
    p++;
    if (p + len > buf.length) return null;
    labels.push(buf.toString("ascii", p, p + len));
    p += len;
  }
  if (labels.length === 0) return null;
  const name = labels.join(".");
  return /^[a-zA-Z0-9._-]+$/.test(name) ? name.toLowerCase() : null;
}

function decodePacket(pkt: Buffer, linkType: number, tsMs: number | null): DecodedPacket | null {
  const ipOff = linkLayerToIp(pkt, linkType);
  if (ipOff === null || pkt.length < ipOff + 1) return null;
  const version = pkt[ipOff] >> 4;

  let srcIp: string;
  let dstIp: string;
  let proto: number;
  let l4: number;

  if (version === 4) {
    if (pkt.length < ipOff + 20) return null;
    const ihl = (pkt[ipOff] & 0x0f) * 4;
    if (ihl < 20) return null;
    proto = pkt[ipOff + 9];
    srcIp = ipv4(pkt, ipOff + 12);
    dstIp = ipv4(pkt, ipOff + 16);
    l4 = ipOff + ihl;
  } else if (version === 6) {
    if (pkt.length < ipOff + 40) return null;
    proto = pkt[ipOff + 6];
    srcIp = ipv6(pkt, ipOff + 8);
    dstIp = ipv6(pkt, ipOff + 24);
    l4 = ipOff + 40;
  } else {
    return null;
  }

  let protocol: DecodedPacket["protocol"] = "other";
  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let dnsName: string | null = null;

  if (proto === 6 || proto === 17) {
    protocol = proto === 6 ? "tcp" : "udp";
    if (pkt.length >= l4 + 4) {
      srcPort = pkt.readUInt16BE(l4);
      dstPort = pkt.readUInt16BE(l4 + 2);
      if (proto === 17 && (srcPort === 53 || dstPort === 53)) {
        dnsName = decodeDnsName(pkt, l4);
      }
    }
  } else if (proto === 1 || proto === 58) {
    protocol = "icmp";
  }

  return { tsMs, srcIp, dstIp, srcPort, dstPort, protocol, dnsName };
}

interface ParseResult {
  format: PcapOutput["detectedFormat"];
  byteOrder: PcapOutput["byteOrder"];
  linkTypes: Set<number>;
  packets: DecodedPacket[];
  truncated: boolean;
}

function parseClassicPcap(buf: Buffer, maxPackets: number): ParseResult {
  const head = buf.readUInt32BE(0);
  let little: boolean;
  let nano: boolean;
  if (head === 0xa1b2c3d4) {
    little = false;
    nano = false;
  } else if (head === 0xd4c3b2a1) {
    little = true;
    nano = false;
  } else if (head === 0xa1b23c4d) {
    little = false;
    nano = true;
  } else {
    little = true;
    nano = true;
  }
  const u32 = (o: number) => (little ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const linkType = u32(20);
  const linkTypes = new Set<number>([linkType]);
  const packets: DecodedPacket[] = [];
  let truncated = false;

  let off = 24;
  while (off + 16 <= buf.length) {
    const tsSec = u32(off);
    const tsFrac = u32(off + 4);
    const inclLen = u32(off + 8);
    off += 16;
    if (inclLen === 0 || off + inclLen > buf.length) break;
    if (packets.length >= maxPackets) {
      truncated = true;
      break;
    }
    const pkt = buf.subarray(off, off + inclLen);
    off += inclLen;
    const tsMs = tsSec * 1000 + (nano ? tsFrac / 1e6 : tsFrac / 1e3);
    const decoded = decodePacket(pkt, linkType, Number.isFinite(tsMs) ? tsMs : null);
    if (decoded) packets.push(decoded);
  }

  return {
    format: "pcap",
    byteOrder: little ? "little" : "big",
    linkTypes,
    packets,
    truncated,
  };
}

function parsePcapng(buf: Buffer, maxPackets: number): ParseResult {
  // Endianness comes from the Section Header Block's byte-order magic.
  const little = buf.readUInt32LE(8) === 0x1a2b3c4d;
  const u16 = (o: number) => (little ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o: number) => (little ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  const interfaceLinkTypes: number[] = [];
  const linkTypes = new Set<number>();
  const packets: DecodedPacket[] = [];
  let truncated = false;

  let off = 0;
  while (off + 12 <= buf.length) {
    const blockType = u32(off);
    const blockLen = u32(off + 4);
    if (blockLen < 12 || off + blockLen > buf.length) break;

    if (blockType === 0x00000001) {
      // Interface Description Block: linktype at body start.
      const lt = u16(off + 8);
      interfaceLinkTypes.push(lt);
      linkTypes.add(lt);
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block (min 32 bytes: header through original_len + trailer).
      if (blockLen < 32) {
        off += blockLen;
        continue;
      }
      if (packets.length >= maxPackets) {
        truncated = true;
        break;
      }
      const ifaceId = u32(off + 8);
      const tsHigh = u32(off + 12);
      const tsLow = u32(off + 16);
      const capLen = u32(off + 20);
      const dataStart = off + 28;
      if (dataStart + capLen <= off + blockLen && dataStart + capLen <= buf.length) {
        const lt = interfaceLinkTypes[ifaceId] ?? interfaceLinkTypes[0] ?? 1;
        const usec = tsHigh * 4294967296 + tsLow;
        const tsMs = usec / 1000;
        const pkt = buf.subarray(dataStart, dataStart + capLen);
        const decoded = decodePacket(pkt, lt, Number.isFinite(tsMs) && tsMs > 0 ? tsMs : null);
        if (decoded) packets.push(decoded);
      }
    } else if (blockType === 0x00000003) {
      // Simple Packet Block (no timestamp, uses interface 0; min 16 bytes).
      if (blockLen < 16) {
        off += blockLen;
        continue;
      }
      if (packets.length >= maxPackets) {
        truncated = true;
        break;
      }
      const origLen = u32(off + 8);
      const dataStart = off + 12;
      const capLen = Math.min(origLen, blockLen - 16);
      if (capLen > 0 && dataStart + capLen <= buf.length) {
        const lt = interfaceLinkTypes[0] ?? 1;
        const pkt = buf.subarray(dataStart, dataStart + capLen);
        const decoded = decodePacket(pkt, lt, null);
        if (decoded) packets.push(decoded);
      }
    }

    off += blockLen;
  }

  return {
    format: "pcapng",
    byteOrder: little ? "little" : "big",
    linkTypes,
    packets,
    truncated,
  };
}

function detectAndParse(buf: Buffer, maxPackets: number): ParseResult {
  if (buf.length >= 24) {
    const head = buf.readUInt32BE(0);
    if (
      head === 0xa1b2c3d4 ||
      head === 0xd4c3b2a1 ||
      head === 0xa1b23c4d ||
      head === 0x4d3cb2a1
    ) {
      return parseClassicPcap(buf, maxPackets);
    }
    // pcapng Section Header Block magic 0x0A0D0D0A (byte-order independent).
    if (buf.readUInt32BE(0) === 0x0a0d0d0a) {
      return parsePcapng(buf, maxPackets);
    }
  }
  return {
    format: "unknown",
    byteOrder: "unknown",
    linkTypes: new Set<number>(),
    packets: [],
    truncated: false,
  };
}

function isPublicIpv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  const [a, b] = p;
  if (a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 0 || a >= 224) return false;
  return true;
}

export const pcap: ToolDescriptor<typeof PcapInput, typeof PcapOutput> = {
  name: "pcapAnalyzer",
  description:
    "Parse a packet capture (.pcap / .cap / .pcapng) straight from bytes. Detects the capture format and link types, decodes Ethernet/VLAN/Linux-SLL/raw-IP frames down to IPv4/IPv6 + TCP/UDP/ICMP, and returns conversation (5-tuple) summaries, top talkers, destination endpoints ready to feed analyze_network, DNS query names, the capture time range, protocol counts, and harvested IP/domain indicators. Pure-Node: never shells out to tcpdump/tshark.",
  inputSchema: PcapInput,
  outputSchema: PcapOutput,
  run: ({ content, maxPackets }) => {
    const buf = Buffer.from(content, "base64");
    if (buf.length === 0) {
      return {
        detectedFormat: "unknown" as const,
        byteOrder: "unknown" as const,
        linkTypes: [],
        packetsParsed: 0,
        truncated: false,
        timeRange: { start: null, end: null },
        protocolCounts: { tcp: 0, udp: 0, icmp: 0, other: 0 },
        topConnections: [],
        topTalkers: [],
        endpoints: [],
        dnsQueries: [],
        embeddedIndicators: { ipv4: [], domains: [] },
        observations: ["Empty payload — capture decoded to 0 bytes."],
      };
    }

    const result = detectAndParse(buf, maxPackets);

    if (result.format === "unknown") {
      return {
        detectedFormat: "unknown" as const,
        byteOrder: "unknown" as const,
        linkTypes: [],
        packetsParsed: 0,
        truncated: false,
        timeRange: { start: null, end: null },
        protocolCounts: { tcp: 0, udp: 0, icmp: 0, other: 0 },
        topConnections: [],
        topTalkers: [],
        endpoints: [],
        dnsQueries: [],
        embeddedIndicators: { ipv4: [], domains: [] },
        observations: [
          `Not a recognized capture: ${buf.length} bytes, no pcap/pcapng magic. Expected .pcap, .cap, or .pcapng.`,
        ],
      };
    }

    const protocolCounts = { tcp: 0, udp: 0, icmp: 0, other: 0 };
    const connCounts = new Map<string, { conn: Omit<z.infer<typeof Connection>, "packets">; packets: number }>();
    const talkerCounts = new Map<string, number>();
    const endpointKeys = new Set<string>();
    const endpoints: z.infer<typeof Endpoint>[] = [];
    const dnsSet = new Set<string>();
    const ipv4Set = new Set<string>();
    let minTs: number | null = null;
    let maxTs: number | null = null;

    for (const p of result.packets) {
      protocolCounts[p.protocol]++;
      const key = `${p.srcIp}|${p.srcPort ?? ""}|${p.dstIp}|${p.dstPort ?? ""}|${p.protocol}`;
      const existing = connCounts.get(key);
      if (existing) existing.packets++;
      else
        connCounts.set(key, {
          conn: {
            srcIp: p.srcIp,
            srcPort: p.srcPort,
            dstIp: p.dstIp,
            dstPort: p.dstPort,
            protocol: p.protocol,
          },
          packets: 1,
        });

      talkerCounts.set(p.srcIp, (talkerCounts.get(p.srcIp) ?? 0) + 1);
      talkerCounts.set(p.dstIp, (talkerCounts.get(p.dstIp) ?? 0) + 1);

      if (p.dstPort !== null) {
        const epKey = `${p.dstIp}|${p.dstPort}`;
        if (!endpointKeys.has(epKey) && endpoints.length < MAX_ENDPOINTS) {
          endpointKeys.add(epKey);
          endpoints.push({ ip: p.dstIp, port: p.dstPort });
        }
      }

      if (p.dnsName) dnsSet.add(p.dnsName);
      if (p.srcIp.includes(".")) ipv4Set.add(p.srcIp);
      if (p.dstIp.includes(".")) ipv4Set.add(p.dstIp);

      if (p.tsMs !== null) {
        if (minTs === null || p.tsMs < minTs) minTs = p.tsMs;
        if (maxTs === null || p.tsMs > maxTs) maxTs = p.tsMs;
      }
    }

    const topConnections = Array.from(connCounts.values())
      .sort((a, b) => b.packets - a.packets)
      .slice(0, MAX_CONNECTIONS)
      .map((c) => ({ ...c.conn, packets: c.packets }));

    const topTalkers = Array.from(talkerCounts.entries())
      .map(([ip, packets]) => ({ ip, packets }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, MAX_TALKERS);

    const dnsQueries = Array.from(dnsSet).sort().slice(0, MAX_DNS);
    const domainSet = new Set(dnsQueries);
    const publicIpv4 = Array.from(ipv4Set)
      .filter(isPublicIpv4)
      .sort()
      .slice(0, MAX_INDICATORS);

    const linkTypeNames = Array.from(result.linkTypes).map(
      (lt) => LINKTYPE_NAMES[lt] ?? `LinkType ${lt}`,
    );

    const toIso = (ms: number | null) =>
      ms === null ? null : new Date(ms).toISOString();

    const observations: string[] = [];
    observations.push(
      `${result.format} capture (${result.byteOrder}-endian), ${buf.length} bytes; decoded ${result.packets.length} IP packet${
        result.packets.length === 1 ? "" : "s"
      }${result.truncated ? ` (truncated at maxPackets=${maxPackets})` : ""}.`,
    );
    if (linkTypeNames.length) {
      observations.push(`Link types: ${linkTypeNames.join(", ")}.`);
    }
    observations.push(
      `Protocols: ${protocolCounts.tcp} TCP, ${protocolCounts.udp} UDP, ${protocolCounts.icmp} ICMP, ${protocolCounts.other} other.`,
    );
    if (minTs !== null && maxTs !== null) {
      const span = ((maxTs - minTs) / 1000).toFixed(1);
      observations.push(`Capture spans ${span}s (${toIso(minTs)} → ${toIso(maxTs)}).`);
    }
    if (dnsQueries.length) {
      observations.push(
        `${dnsQueries.length} unique DNS quer${dnsQueries.length === 1 ? "y" : "ies"} observed — review for tunneling/exfil if subdomains are long or high-entropy.`,
      );
    }
    if (endpoints.length) {
      observations.push(
        `${endpoints.length} unique destination endpoint${endpoints.length === 1 ? "" : "s"} captured — pass 'endpoints' to analyze_network to classify and flag suspicious ports.`,
      );
    }
    if (publicIpv4.length || domainSet.size) {
      observations.push(
        `Harvested ${publicIpv4.length} public IPv4 and ${domainSet.size} domain indicator${domainSet.size === 1 ? "" : "s"} — enrich high-value ones with fetch_url.`,
      );
    }
    if (result.packets.length === 0) {
      observations.push(
        "No IP packets decoded — the capture may use an unsupported link layer or contain only non-IP frames (ARP, STP, etc.).",
      );
    }

    return {
      detectedFormat: result.format,
      byteOrder: result.byteOrder,
      linkTypes: linkTypeNames,
      packetsParsed: result.packets.length,
      truncated: result.truncated,
      timeRange: { start: toIso(minTs), end: toIso(maxTs) },
      protocolCounts,
      topConnections,
      topTalkers,
      endpoints,
      dnsQueries,
      embeddedIndicators: {
        ipv4: publicIpv4,
        domains: Array.from(domainSet).sort(),
      },
      observations,
    };
  },
};
