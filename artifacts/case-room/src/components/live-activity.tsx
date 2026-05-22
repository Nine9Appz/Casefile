import { useState } from "react";
import type { AgentEvent } from "@/hooks/use-investigation-stream";
import { Activity, ChevronDown, Lock, AlertTriangle } from "lucide-react";

interface LiveActivityCardProps {
  events: AgentEvent[];
  iteration: number | null;
}

/**
 * Renders the in-flight events that have streamed in since the last
 * persisted analysis_step — i.e. what the agent is currently doing
 * but has not yet committed to the case file via record_finding.
 */
export function LiveActivityCard({ events, iteration }: LiveActivityCardProps) {
  const [expandedThinking, setExpandedThinking] = useState<Record<number, boolean>>({});

  if (events.length === 0) return null;

  const toggle = (i: number) => setExpandedThinking((p) => ({ ...p, [i]: !p[i] }));

  return (
    <div
      data-testid="live-activity-card"
      className="rounded border border-amber-400/50 bg-amber-400/[0.04] overflow-hidden"
    >
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-amber-400/30 bg-amber-400/[0.06]">
        <div className="flex items-center gap-2">
          <Activity size={11} className="text-amber-300 animate-pulse" />
          <span className="font-mono text-[10px] uppercase tracking-widest text-amber-300">
            Live · in flight{iteration !== null ? ` · iteration ${iteration}` : ""}
          </span>
        </div>
        <span className="font-mono text-[10px] text-muted-foreground">
          {events.length} event{events.length === 1 ? "" : "s"}
        </span>
      </div>

      <div className="px-3 py-2 space-y-2 font-mono text-xs">
        {events.map((ev, i) => {
          if (ev.type === "thinking") {
            const lines = ev.text.split("\n");
            const isLong = lines.length > 3 || ev.text.length > 220;
            const isExpanded = expandedThinking[i] ?? false;
            const preview = isLong
              ? lines.slice(0, 2).join("\n").slice(0, 220) + "…"
              : ev.text;
            return (
              <div key={i} className="pl-3 border-l-2 border-amber-400/30">
                <button
                  type="button"
                  onClick={() => isLong && toggle(i)}
                  disabled={!isLong}
                  className={`flex items-start gap-1 text-left w-full ${
                    isLong ? "hover:text-foreground cursor-pointer" : "cursor-default"
                  } text-muted-foreground`}
                  data-testid={`live-thinking-toggle-${i}`}
                >
                  {isLong && (
                    <ChevronDown
                      size={10}
                      className={`mt-0.5 shrink-0 transition-transform ${
                        isExpanded ? "" : "-rotate-90"
                      }`}
                    />
                  )}
                  <span className="italic whitespace-pre-wrap flex-1">
                    {isExpanded || !isLong ? ev.text : preview}
                  </span>
                </button>
                {isLong && (
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground/60 mt-1 ml-3">
                    {isExpanded
                      ? "click to collapse"
                      : `thinking · ${lines.length} lines · click to expand`}
                  </div>
                )}
              </div>
            );
          }
          if (ev.type === "tool_call") {
            return (
              <div key={i} className="text-primary">
                <span className="font-bold">&gt; EXEC: {ev.name}</span>
                <div className="bg-primary/5 p-2 rounded mt-1 border border-primary/20 text-primary/80 overflow-x-auto whitespace-pre-wrap text-[11px]">
                  {JSON.stringify(ev.args, null, 2)}
                </div>
              </div>
            );
          }
          if (ev.type === "tool_result") {
            return (
              <div key={i} className={ev.ok ? "text-emerald-300" : "text-destructive"}>
                <span className="opacity-70">
                  &lt; RESULT ({ev.name}) {ev.ok ? "OK" : "FAIL"}:
                </span>
                <div className="bg-black/40 p-2 rounded mt-1 border border-border overflow-x-auto whitespace-pre-wrap text-[11px] opacity-90">
                  {ev.summary}
                </div>
                {ev.verifiedHash && (
                  <div className="text-[10px] text-muted-foreground mt-1 flex items-center">
                    <Lock size={10} className="mr-1" /> sha256:{" "}
                    {ev.verifiedHash.substring(0, 16)}…
                  </div>
                )}
              </div>
            );
          }
          if (ev.type === "error") {
            return (
              <div
                key={i}
                className="text-destructive p-2 border border-destructive/30 bg-destructive/10 rounded flex items-start gap-2"
              >
                <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                <span>
                  {ev.message}
                  {ev.fatal ? " (fatal)" : ""}
                </span>
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );
}
