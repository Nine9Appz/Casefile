import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const IocExtractorInput = z.object({
  content: z.string().min(1),
});
export type IocExtractorInput = z.infer<typeof IocExtractorInput>;

export const IocExtractorOutput = z.object({
  ips: z.array(z.string()),
  domains: z.array(z.string()),
  // Subset of `domains` that mixes ASCII Latin with non-ASCII letters in the
  // same label — a strong homoglyph / IDN-spoofing signal. Surfaced separately
  // so reviewers see lookalike domains without scanning the full domain list.
  suspiciousDomains: z.array(z.string()),
  urls: z.array(z.string()),
  emails: z.array(z.string()),
  md5: z.array(z.string()),
  sha1: z.array(z.string()),
  sha256: z.array(z.string()),
  cves: z.array(z.string()),
  filePaths: z.array(z.string()),
  totalCount: z.number().int().nonnegative(),
});
export type IocExtractorOutput = z.infer<typeof IocExtractorOutput>;

const RE = {
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
  url: /\bhttps?:\/\/[^\s<>"']+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  // Unicode-aware so we capture IDN / homoglyph domains (e.g. corp-fіnance.com
  // with a Cyrillic 'і') as a single token rather than truncating at the
  // non-ASCII letter. `\b` is ASCII-only so we use Unicode-aware lookarounds.
  domain:
    /(?<![\p{L}\p{N}.-])(?:(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?)\.)+(?:com|net|org|io|ru|cn|uk|de|fr|jp|in|br|info|biz|gov|edu|mil|local|onion|xyz|top|club|site|app|dev|cloud|tech|co)(?![\p{L}\p{N}-])/giu,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  windowsPath: /\b[A-Za-z]:\\(?:[^\s\\<>"|?*]+\\)*[^\s\\<>"|?*]+/g,
  unixPath: /(?:^|\s)(\/(?:bin|etc|home|opt|root|sbin|srv|tmp|usr|var)\/[^\s"'<>]+)/g,
};

function uniqSorted(arr: Iterable<string>): string[] {
  return Array.from(new Set(arr)).sort();
}

function dedupAll<T extends Record<string, RegExp>>(
  content: string,
  patterns: T,
): Record<keyof T, string[]> {
  const out = {} as Record<keyof T, string[]>;
  for (const k of Object.keys(patterns) as Array<keyof T>) {
    const matches = content.match(patterns[k]) ?? [];
    out[k] = uniqSorted(matches.map((m) => m.trim()));
  }
  return out;
}

export const iocExtractor: ToolDescriptor<typeof IocExtractorInput, typeof IocExtractorOutput> = {
  name: "iocExtractor",
  description:
    "Sweeps any text blob and extracts indicators of compromise: IPv4 addresses, domains, URLs, emails, MD5/SHA1/SHA256 hashes, CVE identifiers, and Windows/Unix file paths. Returns deduplicated, sorted lists per category.",
  inputSchema: IocExtractorInput,
  outputSchema: IocExtractorOutput,
  run: ({ content }) => {
    const raw = dedupAll(content, RE);
    const urls = raw.url;
    const ips = raw.ip;
    const emails = raw.email;
    const urlHosts = new Set<string>();
    for (const u of urls) {
      try {
        urlHosts.add(new URL(u).hostname.toLowerCase());
      } catch {
        // ignore malformed
      }
    }
    const emailDomains = new Set(emails.map((e) => e.split("@")[1]?.toLowerCase() ?? ""));
    const domains = uniqSorted(
      raw.domain
        .map((d) => d.toLowerCase())
        .filter((d) => !urlHosts.has(d) && !emailDomains.has(d) && !ips.includes(d)),
    );
    const filePaths = uniqSorted([...raw.windowsPath, ...raw.unixPath.map((p) => p.trim())]);
    // Flag labels that mix ASCII Latin letters with non-ASCII letters
    // (a homoglyph / IDN-spoofing signature). Restricted to letters
    // (\p{L}) so labels that legitimately mix ASCII letters with
    // non-ASCII digits/punctuation are not over-flagged.
    const isMixedScript = (d: string) => {
      for (const label of d.split(".")) {
        const hasAsciiLetter = /[a-z]/i.test(label);
        // Match a character that is non-ASCII AND a Unicode letter.
        // (Lookahead asserts non-ASCII at the position, then \p{L} matches.)
        const hasNonAsciiLetter = /(?=[^\x00-\x7f])\p{L}/u.test(label);
        if (hasAsciiLetter && hasNonAsciiLetter) return true;
      }
      return false;
    };
    // Include domains that live inside captured emails — homoglyph attacks
    // most often arrive as a spoofed sender address, and our dedup pass
    // strips email domains out of the plain `domains` list.
    const emailDomainList = Array.from(emailDomains).filter((d) => d.length > 0);
    const suspiciousDomains = uniqSorted(
      [...domains, ...emailDomainList].filter(isMixedScript),
    );
    const result = {
      ips,
      domains,
      suspiciousDomains,
      urls,
      emails,
      md5: raw.md5.filter((h) => !raw.sha1.includes(h) && !raw.sha256.includes(h)),
      sha1: raw.sha1.filter((h) => !raw.sha256.includes(h)),
      sha256: raw.sha256,
      cves: raw.cve.map((c) => c.toUpperCase()),
      filePaths,
      totalCount: 0,
    };
    result.totalCount =
      result.ips.length +
      result.domains.length +
      result.urls.length +
      result.emails.length +
      result.md5.length +
      result.sha1.length +
      result.sha256.length +
      result.cves.length +
      result.filePaths.length;
    return result;
  },
};
