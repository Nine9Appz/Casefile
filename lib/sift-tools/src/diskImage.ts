import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const DiskImageInput = z.object({
  /** Base64-encoded raw bytes of the disk image. */
  content: z.string().min(1),
  /** Minimum length of an ASCII string to surface. */
  minStringLength: z.number().int().min(4).max(64).default(8),
  /** Maximum number of unique strings to return. */
  maxStrings: z.number().int().min(1).max(2000).default(300),
});
export type DiskImageInput = z.infer<typeof DiskImageInput>;

export const DiskImageOutput = z.object({
  byteLength: z.number().int(),
  detectedFormat: z.enum([
    "raw_dd",
    "iso9660",
    "fat",
    "ntfs",
    "ext",
    "ewf_e01",
    "vmdk",
    "vhd",
    "qcow2",
    "unknown",
  ]),
  detectedFilesystems: z.array(z.string()),
  partitionScheme: z.enum(["mbr", "gpt", "none"]),
  partitions: z.array(
    z.object({
      index: z.number().int(),
      type: z.string(),
      bootable: z.boolean(),
      startLba: z.number().int().nonnegative(),
      sizeLba: z.number().int().nonnegative(),
    }),
  ),
  /** Suspicious indicators surfaced from printable strings — IPs, domains, URLs. */
  embeddedIndicators: z.object({
    ipv4: z.array(z.string()),
    domains: z.array(z.string()),
    urls: z.array(z.string()),
  }),
  /** Top printable strings (longest first), trimmed and de-duplicated. */
  notableStrings: z.array(z.string()),
  /** Free-form analyst notes generated from the structural scan. */
  observations: z.array(z.string()),
});
export type DiskImageOutput = z.infer<typeof DiskImageOutput>;

const MBR_PART_TYPE: Record<number, string> = {
  0x00: "empty",
  0x01: "fat12",
  0x04: "fat16_small",
  0x05: "extended_chs",
  0x06: "fat16",
  0x07: "ntfs_or_exfat",
  0x0b: "fat32_chs",
  0x0c: "fat32_lba",
  0x0e: "fat16_lba",
  0x0f: "extended_lba",
  0x82: "linux_swap_or_solaris",
  0x83: "linux",
  0x8e: "linux_lvm",
  0xa5: "freebsd",
  0xa6: "openbsd",
  0xa8: "macos_ufs",
  0xa9: "netbsd",
  0xaf: "hfs_plus",
  0xee: "gpt_protective",
  0xef: "efi_system",
  0xfd: "linux_raid",
};

function detectFormat(buf: Buffer): DiskImageOutput["detectedFormat"] {
  if (buf.length < 8) return "unknown";
  // EWF (E01): "EVF\x09\x0D\x0A\xFF\x00"
  if (
    buf[0] === 0x45 && buf[1] === 0x56 && buf[2] === 0x46 &&
    buf[3] === 0x09 && buf[4] === 0x0d && buf[5] === 0x0a &&
    buf[6] === 0xff && buf[7] === 0x00
  ) {
    return "ewf_e01";
  }
  // VMDK: "KDMV" (sparse) or text "# Disk DescriptorFile"
  if (buf[0] === 0x4b && buf[1] === 0x44 && buf[2] === 0x4d && buf[3] === 0x56) {
    return "vmdk";
  }
  // QCOW2: "QFI\xfb"
  if (buf[0] === 0x51 && buf[1] === 0x46 && buf[2] === 0x49 && buf[3] === 0xfb) {
    return "qcow2";
  }
  // VHD footer "conectix" or VHDX "vhdxfile"
  if (buf.length >= 8 && buf.subarray(0, 8).toString("ascii") === "conectix") {
    return "vhd";
  }
  // ISO9660: at offset 0x8001 = "CD001"
  if (
    buf.length >= 0x8006 &&
    buf.subarray(0x8001, 0x8006).toString("ascii") === "CD001"
  ) {
    return "iso9660";
  }
  // NTFS boot sector OEM ID at offset 3 = "NTFS    "
  if (buf.length >= 11 && buf.subarray(3, 11).toString("ascii") === "NTFS    ") {
    return "ntfs";
  }
  // FAT boot sector OEM ID at offset 3 starts with "MSDOS" / "MSWIN" / "mkfs.fat"
  if (buf.length >= 11) {
    const oem = buf.subarray(3, 11).toString("ascii");
    if (/^(MSDOS|MSWIN|mkfs\.fa|FAT)/.test(oem)) return "fat";
  }
  // ext2/3/4 superblock magic 0xEF53 at offset 1024+56 (little-endian)
  if (buf.length >= 1024 + 58) {
    const magic = buf.readUInt16LE(1024 + 56);
    if (magic === 0xef53) return "ext";
  }
  // MBR signature at offset 510 means raw dd of a disk
  if (buf.length >= 512 && buf[510] === 0x55 && buf[511] === 0xaa) {
    return "raw_dd";
  }
  return "unknown";
}

function detectFilesystems(buf: Buffer): string[] {
  const fs = new Set<string>();
  if (buf.length >= 11 && buf.subarray(3, 11).toString("ascii") === "NTFS    ") {
    fs.add("ntfs");
  }
  if (buf.length >= 11) {
    const oem = buf.subarray(3, 11).toString("ascii");
    if (/^(MSDOS|MSWIN|mkfs\.fa|FAT)/.test(oem)) fs.add("fat");
  }
  if (
    buf.length >= 1024 + 58 &&
    buf.readUInt16LE(1024 + 56) === 0xef53
  ) {
    fs.add("ext");
  }
  if (
    buf.length >= 0x8006 &&
    buf.subarray(0x8001, 0x8006).toString("ascii") === "CD001"
  ) {
    fs.add("iso9660");
  }
  return [...fs];
}

interface RawPartition {
  index: number;
  type: string;
  bootable: boolean;
  startLba: number;
  sizeLba: number;
}

function parseMbr(buf: Buffer): RawPartition[] {
  const out: RawPartition[] = [];
  if (buf.length < 512 || buf[510] !== 0x55 || buf[511] !== 0xaa) return out;
  for (let i = 0; i < 4; i++) {
    const off = 446 + i * 16;
    const bootable = buf[off] === 0x80;
    const typeByte = buf[off + 4];
    const startLba = buf.readUInt32LE(off + 8);
    const sizeLba = buf.readUInt32LE(off + 12);
    if (typeByte === 0 && sizeLba === 0) continue;
    out.push({
      index: i,
      type: MBR_PART_TYPE[typeByte] ?? `0x${typeByte.toString(16).padStart(2, "0")}`,
      bootable,
      startLba,
      sizeLba,
    });
  }
  return out;
}

function parseGpt(buf: Buffer): { scheme: "gpt" | null; partitions: RawPartition[] } {
  // GPT header at LBA 1 (offset 512 for 512-byte sectors) starts with "EFI PART".
  if (buf.length < 512 + 92) return { scheme: null, partitions: [] };
  const sigBuf = buf.subarray(512, 512 + 8);
  if (sigBuf.toString("ascii") !== "EFI PART") {
    return { scheme: null, partitions: [] };
  }
  const partEntryLba = Number(buf.readBigUInt64LE(512 + 72));
  const numEntries = buf.readUInt32LE(512 + 80);
  const entrySize = buf.readUInt32LE(512 + 84);
  const tableOffset = partEntryLba * 512;
  if (
    entrySize < 128 ||
    entrySize > 512 ||
    numEntries === 0 ||
    numEntries > 512 ||
    tableOffset + numEntries * entrySize > buf.length
  ) {
    return { scheme: "gpt", partitions: [] };
  }
  const partitions: RawPartition[] = [];
  for (let i = 0; i < numEntries; i++) {
    const off = tableOffset + i * entrySize;
    const guidLo = buf.readBigUInt64LE(off);
    const guidHi = buf.readBigUInt64LE(off + 8);
    if (guidLo === 0n && guidHi === 0n) continue;
    const firstLba = Number(buf.readBigUInt64LE(off + 32));
    const lastLba = Number(buf.readBigUInt64LE(off + 40));
    partitions.push({
      index: i,
      type: gptTypeGuid(buf, off),
      bootable: false,
      startLba: firstLba,
      sizeLba: Math.max(0, lastLba - firstLba + 1),
    });
  }
  return { scheme: "gpt", partitions };
}

function gptTypeGuid(buf: Buffer, off: number): string {
  // GUID stored mixed-endian: 4-2-2 little endian, then 2-6 big endian.
  const d1 = buf.readUInt32LE(off).toString(16).padStart(8, "0");
  const d2 = buf.readUInt16LE(off + 4).toString(16).padStart(4, "0");
  const d3 = buf.readUInt16LE(off + 6).toString(16).padStart(4, "0");
  const d4 = buf.subarray(off + 8, off + 10).toString("hex");
  const d5 = buf.subarray(off + 10, off + 16).toString("hex");
  return `${d1}-${d2}-${d3}-${d4}-${d5}`;
}

function extractAsciiStrings(buf: Buffer, minLen: number, max: number): string[] {
  const out = new Set<string>();
  let run: number[] = [];
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      run.push(b);
    } else {
      if (run.length >= minLen) {
        out.add(Buffer.from(run).toString("ascii"));
        if (out.size >= max) break;
      }
      run = [];
    }
  }
  if (run.length >= minLen) out.add(Buffer.from(run).toString("ascii"));
  // Sort by length desc, then alpha; truncate.
  return [...out].sort((a, b) => b.length - a.length || a.localeCompare(b)).slice(0, max);
}

const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b/g;
const URL_RE = /https?:\/\/[^\s"'<>]{4,256}/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|us|uk|de|ru|cn|info|biz|dev|app|xyz|onion|local)\b/gi;

function dedupe(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function harvestIndicators(strings: string[]): DiskImageOutput["embeddedIndicators"] {
  const joined = strings.join("\n");
  const ips = joined.match(IPV4_RE) ?? [];
  const urls = joined.match(URL_RE) ?? [];
  const domains = (joined.match(DOMAIN_RE) ?? []).map((d) => d.toLowerCase());
  return {
    ipv4: dedupe(ips),
    urls: dedupe(urls),
    domains: dedupe(domains),
  };
}

export const diskImage: ToolDescriptor<typeof DiskImageInput, typeof DiskImageOutput> = {
  name: "diskImageAnalyzer",
  description:
    "Parse a raw disk image (.img / .dd / .raw or container header). Detects filesystem signatures (NTFS, FAT, ext, ISO9660), the partition scheme (MBR or GPT) and enumerates partitions with type and LBA range, extracts printable ASCII strings, and harvests embedded indicators (IPv4 addresses, domains, URLs) from those strings. Pure-Node: does not mount the image or shell out to any external tool.",
  inputSchema: DiskImageInput,
  outputSchema: DiskImageOutput,
  run: ({ content, minStringLength, maxStrings }) => {
    const buf = Buffer.from(content, "base64");
    if (buf.length === 0) {
      return {
        byteLength: 0,
        detectedFormat: "unknown" as const,
        detectedFilesystems: [],
        partitionScheme: "none" as const,
        partitions: [],
        embeddedIndicators: { ipv4: [], domains: [], urls: [] },
        notableStrings: [],
        observations: ["Empty payload — image decoded to 0 bytes."],
      };
    }

    const format = detectFormat(buf);
    const filesystems = detectFilesystems(buf);
    const gpt = parseGpt(buf);
    const mbr = gpt.scheme === "gpt" ? [] : parseMbr(buf);
    const partitions = gpt.scheme === "gpt" ? gpt.partitions : mbr;
    const scheme: DiskImageOutput["partitionScheme"] =
      gpt.scheme === "gpt"
        ? "gpt"
        : mbr.length > 0
          ? "mbr"
          : "none";

    const strings = extractAsciiStrings(buf, minStringLength, maxStrings);
    const indicators = harvestIndicators(strings);

    const observations: string[] = [];
    observations.push(`Image is ${buf.length} bytes; detected as ${format}.`);
    if (scheme !== "none") {
      observations.push(
        `${scheme.toUpperCase()} partition table with ${partitions.length} entr${
          partitions.length === 1 ? "y" : "ies"
        }.`,
      );
    } else {
      observations.push("No partition table detected (likely a single-filesystem image).");
    }
    if (filesystems.length > 0) {
      observations.push(`Filesystem signatures: ${filesystems.join(", ")}.`);
    }
    if (indicators.ipv4.length || indicators.domains.length || indicators.urls.length) {
      observations.push(
        `Embedded indicators found: ${indicators.ipv4.length} IPv4, ${indicators.domains.length} domains, ${indicators.urls.length} URLs. Run extract_iocs or fetch_url on the high-confidence ones.`,
      );
    } else {
      observations.push("No high-confidence IP/domain/URL indicators in extracted strings.");
    }

    return {
      byteLength: buf.length,
      detectedFormat: format,
      detectedFilesystems: filesystems,
      partitionScheme: scheme,
      partitions,
      embeddedIndicators: indicators,
      notableStrings: strings,
      observations,
    };
  },
};
