import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const TimelineEventInput = z.object({
  timestamp: z.string(),
  label: z.string(),
  source: z.string().optional(),
});

export const TimelineInput = z.object({
  events: z.array(TimelineEventInput).min(1),
  burstWindowSeconds: z.number().int().positive().default(60),
  burstMinEvents: z.number().int().min(2).default(5),
  gapThresholdSeconds: z.number().int().positive().default(3600),
});
export type TimelineInput = z.infer<typeof TimelineInput>;

export const SortedEvent = z.object({
  timestamp: z.string(),
  epochMs: z.number(),
  label: z.string(),
  source: z.string().nullable(),
});

export const Burst = z.object({
  startTimestamp: z.string(),
  endTimestamp: z.string(),
  durationSeconds: z.number(),
  eventCount: z.number().int(),
});

export const Gap = z.object({
  beforeTimestamp: z.string(),
  afterTimestamp: z.string(),
  gapSeconds: z.number(),
});

export const TimelineOutput = z.object({
  totalEvents: z.number().int(),
  parsedEvents: z.number().int(),
  unparsedEvents: z.number().int(),
  firstTimestamp: z.string().nullable(),
  lastTimestamp: z.string().nullable(),
  spanSeconds: z.number().nullable(),
  sorted: z.array(SortedEvent),
  bursts: z.array(Burst),
  gaps: z.array(Gap),
});
export type TimelineOutput = z.infer<typeof TimelineOutput>;

const SYSLOG_TS_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/;
const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

function parseTimestamp(ts: string, referenceYear: number): number | null {
  const direct = Date.parse(ts);
  if (!Number.isNaN(direct)) return direct;
  const m = SYSLOG_TS_RE.exec(ts.trim());
  if (m) {
    const [, mon, d, h, mi, s] = m;
    const monthIdx = MONTHS[mon];
    if (monthIdx === undefined) return null;
    return Date.UTC(referenceYear, monthIdx, Number(d), Number(h), Number(mi), Number(s));
  }
  return null;
}

export const timeline: ToolDescriptor<typeof TimelineInput, typeof TimelineOutput> = {
  name: "timelineBuilder",
  description:
    "Sorts events chronologically and detects bursts (≥N events within a sliding window) and gaps (≥T seconds with no activity). Accepts ISO 8601 or syslog-style timestamps; syslog timestamps without a year are assumed to be in the current UTC year.",
  inputSchema: TimelineInput,
  outputSchema: TimelineOutput,
  run: ({ events, burstWindowSeconds, burstMinEvents, gapThresholdSeconds }) => {
    const referenceYear = new Date().getUTCFullYear();
    const parsed: { timestamp: string; epochMs: number; label: string; source: string | null }[] = [];
    let unparsed = 0;
    for (const ev of events) {
      const epoch = parseTimestamp(ev.timestamp, referenceYear);
      if (epoch === null) {
        unparsed++;
        continue;
      }
      parsed.push({
        timestamp: ev.timestamp,
        epochMs: epoch,
        label: ev.label,
        source: ev.source ?? null,
      });
    }
    parsed.sort((a, b) => a.epochMs - b.epochMs);

    const bursts: z.infer<typeof Burst>[] = [];
    const windowMs = burstWindowSeconds * 1000;
    let i = 0;
    while (i < parsed.length) {
      let j = i;
      while (j < parsed.length && parsed[j].epochMs - parsed[i].epochMs <= windowMs) {
        j++;
      }
      const count = j - i;
      if (count >= burstMinEvents) {
        bursts.push({
          startTimestamp: parsed[i].timestamp,
          endTimestamp: parsed[j - 1].timestamp,
          durationSeconds: (parsed[j - 1].epochMs - parsed[i].epochMs) / 1000,
          eventCount: count,
        });
        i = j;
      } else {
        i++;
      }
    }

    const gaps: z.infer<typeof Gap>[] = [];
    const gapMs = gapThresholdSeconds * 1000;
    for (let k = 1; k < parsed.length; k++) {
      const delta = parsed[k].epochMs - parsed[k - 1].epochMs;
      if (delta >= gapMs) {
        gaps.push({
          beforeTimestamp: parsed[k - 1].timestamp,
          afterTimestamp: parsed[k].timestamp,
          gapSeconds: delta / 1000,
        });
      }
    }

    const first = parsed[0]?.timestamp ?? null;
    const last = parsed[parsed.length - 1]?.timestamp ?? null;
    const spanSeconds =
      parsed.length >= 2
        ? (parsed[parsed.length - 1].epochMs - parsed[0].epochMs) / 1000
        : null;

    return {
      totalEvents: events.length,
      parsedEvents: parsed.length,
      unparsedEvents: unparsed,
      firstTimestamp: first,
      lastTimestamp: last,
      spanSeconds,
      sorted: parsed,
      bursts,
      gaps,
    };
  },
};
