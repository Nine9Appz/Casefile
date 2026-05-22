import { useState } from "react";
import type { ExecutionLog } from "@workspace/api-client-react";
import { format } from "date-fns";
import { ChevronRight, CheckCircle2, XCircle, Hash, Clock, Cpu } from "lucide-react";

interface ExecLogPanelProps {
  logs: ExecutionLog[];
}

export function ExecLogPanel({ logs }: ExecLogPanelProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (logs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-muted-foreground opacity-50 mt-20">
        <Cpu size={32} className="mb-2" />
        <p className="font-mono text-xs uppercase tracking-widest">No tool executions yet</p>
      </div>
    );
  }

  const totalTokens = logs.reduce(
    (s, l) => s + (l.tokensPrompt ?? 0) + (l.tokensCompletion ?? 0),
    0,
  );
  const okCount = logs.filter((l) => !l.error).length;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <Stat value={logs.length} label="Calls" />
        <Stat value={okCount} label="OK" />
        <Stat value={totalTokens} label="Tokens" />
      </div>

      <div className="space-y-1.5">
        {logs.map((log) => {
          const isOpen = expanded[log.id] ?? false;
          const started = new Date(log.startedAt);
          const ended = new Date(log.endedAt);
          const durMs = ended.getTime() - started.getTime();
          const tokens = (log.tokensPrompt ?? 0) + (log.tokensCompletion ?? 0);

          return (
            <div
              key={log.id}
              data-testid={`exec-log-${log.id}`}
              className={`rounded border ${
                log.error ? "border-destructive/40" : "border-border"
              } bg-card/40 overflow-hidden`}
            >
              <button
                type="button"
                onClick={() => setExpanded((p) => ({ ...p, [log.id]: !p[log.id] }))}
                className="w-full px-2 py-1.5 flex items-center gap-2 text-left hover:bg-card/80 transition-colors"
              >
                <ChevronRight
                  size={11}
                  className={`shrink-0 transition-transform text-muted-foreground ${
                    isOpen ? "rotate-90" : ""
                  }`}
                />
                {log.error ? (
                  <XCircle size={11} className="shrink-0 text-destructive" />
                ) : (
                  <CheckCircle2 size={11} className="shrink-0 text-emerald-400" />
                )}
                <span className="font-mono text-[11px] text-foreground truncate flex-1">
                  {log.toolName}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground shrink-0 flex items-center gap-2">
                  <span className="flex items-center gap-0.5">
                    <Clock size={9} />
                    {durMs}ms
                  </span>
                  {tokens > 0 && (
                    <span className="flex items-center gap-0.5">
                      <Hash size={9} />
                      {tokens}
                    </span>
                  )}
                </span>
              </button>

              {isOpen && (
                <div className="border-t border-border/60 px-2 py-2 space-y-1.5 font-mono text-[10px]">
                  <DetailRow label="Started" value={format(started, "HH:mm:ss.SSS")} />
                  <DetailRow label="Ended" value={format(ended, "HH:mm:ss.SSS")} />
                  <DetailRow
                    label="Tokens"
                    value={`${log.tokensPrompt ?? 0} prompt · ${log.tokensCompletion ?? 0} completion`}
                  />
                  {log.artifactId && (
                    <DetailRow label="Artifact" value={log.artifactId.split("-")[0]} />
                  )}
                  {log.analysisStepId && (
                    <DetailRow
                      label="Step"
                      value={log.analysisStepId.split("-")[0]}
                    />
                  )}
                  {log.error && (
                    <div className="mt-1 p-1.5 rounded bg-destructive/10 border border-destructive/30 text-destructive whitespace-pre-wrap">
                      {log.error}
                    </div>
                  )}
                  <details className="mt-1">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground uppercase tracking-widest text-[9px]">
                      Input
                    </summary>
                    <pre className="mt-1 p-1.5 rounded bg-black/40 border border-border overflow-x-auto text-[10px]">
                      {safeStringify(log.input)}
                    </pre>
                  </details>
                  <details>
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground uppercase tracking-widest text-[9px]">
                      Output
                    </summary>
                    <pre className="mt-1 p-1.5 rounded bg-black/40 border border-border overflow-x-auto text-[10px] max-h-48 overflow-y-auto">
                      {safeStringify(log.output)}
                    </pre>
                  </details>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div className="bg-card border border-border p-2 rounded text-center">
      <div className="text-lg font-mono text-primary">{value}</div>
      <div className="text-[10px] font-mono text-muted-foreground uppercase">{label}</div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[70px_1fr] gap-2">
      <span className="text-muted-foreground uppercase tracking-widest">{label}</span>
      <span className="text-foreground truncate">{value}</span>
    </div>
  );
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}
