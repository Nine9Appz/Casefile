import type { AnalysisPhase } from "@workspace/api-client-react";

export interface PhaseMeta {
  label: string;
  shortLabel: string;
  accent: string;
  border: string;
  bg: string;
  badge: string;
  annotation: string;
}

export const PHASE_META: Record<AnalysisPhase, PhaseMeta> = {
  triage: {
    label: "Triage",
    shortLabel: "TRIAGE",
    accent: "text-cyan-300",
    border: "border-cyan-400/30",
    bg: "bg-cyan-400/[0.03]",
    badge: "bg-cyan-400/10 text-cyan-300 border-cyan-400/30",
    annotation:
      "Triage steps establish ground truth. The agent surveys what evidence is present before picking a thread to pull on. Notice it lists artifacts and runs cheap, broad scans first.",
  },
  deep_analysis: {
    label: "Deep Analysis",
    shortLabel: "DEEP",
    accent: "text-emerald-300",
    border: "border-emerald-400/30",
    bg: "bg-emerald-400/[0.03]",
    badge: "bg-emerald-400/10 text-emerald-300 border-emerald-400/30",
    annotation:
      "Deep-analysis steps drill into a specific lead. The agent should cite concrete values (IPs, hashes, timestamps) from prior tool results in its 'found' field — that is how it grounds inference in evidence rather than guessing.",
  },
  synthesis: {
    label: "Synthesis",
    shortLabel: "SYNTH",
    accent: "text-violet-300",
    border: "border-violet-400/30",
    bg: "bg-violet-400/[0.03]",
    badge: "bg-violet-400/10 text-violet-300 border-violet-400/30",
    annotation:
      "Synthesis steps stitch separate findings into a single narrative. This is where 'failed logins' + 'successful login' + 'lateral movement' become 'a credential brute-force that succeeded'.",
  },
  self_correction: {
    label: "Self-Correction",
    shortLabel: "REVISE",
    accent: "text-amber-300",
    border: "border-amber-400/60",
    bg: "bg-amber-400/[0.06]",
    badge: "bg-amber-400/15 text-amber-300 border-amber-400/50",
    annotation:
      "Self-correction is the agent contradicting an earlier hypothesis based on new evidence. A good investigation has at least one of these — a clean linear story usually means the agent missed something.",
  },
};

export function metaFor(phase: AnalysisPhase): PhaseMeta {
  return PHASE_META[phase] ?? PHASE_META.triage;
}
