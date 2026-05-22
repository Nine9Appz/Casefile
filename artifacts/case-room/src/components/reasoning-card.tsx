import type { AnalysisStep } from "@workspace/api-client-react";
import { metaFor } from "@/lib/phase-meta";
import { Info, Wrench, Target, Eye, ArrowRight, Sparkles } from "lucide-react";

interface ReasoningCardProps {
  step: AnalysisStep;
  trainingMode: boolean;
}

export function ReasoningCard({ step, trainingMode }: ReasoningCardProps) {
  const meta = metaFor(step.phase);

  return (
    <div
      data-testid={`reasoning-card-${step.stepNumber}`}
      className={`rounded border ${meta.border} ${meta.bg} overflow-hidden`}
    >
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/60 bg-card/30">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-widest border ${meta.badge}`}
          >
            {meta.shortLabel}
          </span>
          <span className="font-mono text-[10px] text-muted-foreground uppercase tracking-widest shrink-0">
            Step {step.stepNumber}
          </span>
          {step.toolUsed && (
            <span className="font-mono text-[10px] text-foreground/70 truncate flex items-center gap-1 min-w-0">
              <Wrench size={9} className="shrink-0" />
              <span className="truncate">{step.toolUsed}</span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 font-mono text-[10px] text-muted-foreground shrink-0">
          {step.tokensUsed > 0 && <span>{step.tokensUsed} tok</span>}
          {step.durationMs > 0 && <span>{step.durationMs}ms</span>}
        </div>
      </div>

      <div className="px-3 py-2 space-y-2 text-xs">
        <Field
          icon={<Info size={10} />}
          label="RATIONALE"
          accent={meta.accent}
          value={step.rationale}
        />
        <Field
          icon={<Target size={10} />}
          label="EXPECTED"
          accent={meta.accent}
          value={step.expected}
        />
        <Field
          icon={<Eye size={10} />}
          label="FOUND"
          accent={meta.accent}
          value={step.found}
          emphasis
        />
        <Field
          icon={<ArrowRight size={10} />}
          label="NEXT"
          accent={meta.accent}
          value={step.nextStep}
        />
      </div>

      {trainingMode && (
        <div
          data-testid={`training-annotation-${step.stepNumber}`}
          className="border-t border-border/60 bg-background/40 px-3 py-2 flex gap-2 text-[11px] leading-relaxed text-muted-foreground"
        >
          <Sparkles size={11} className="text-primary mt-0.5 shrink-0" />
          <span>{meta.annotation}</span>
        </div>
      )}
    </div>
  );
}

interface FieldProps {
  icon: React.ReactNode;
  label: string;
  accent: string;
  value: string;
  emphasis?: boolean;
}

function Field({ icon, label, accent, value, emphasis }: FieldProps) {
  return (
    <div className="grid grid-cols-[80px_1fr] gap-2 items-start">
      <div
        className={`flex items-center gap-1 ${accent} font-mono text-[10px] uppercase tracking-widest pt-0.5`}
      >
        {icon}
        <span>{label}</span>
      </div>
      <div
        className={`font-mono text-foreground/90 whitespace-pre-wrap leading-relaxed ${
          emphasis ? "text-foreground" : ""
        }`}
      >
        {value}
      </div>
    </div>
  );
}
