import {
  index,
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { casesTable } from "./cases";

export const analysisPhaseEnum = pgEnum("analysis_phase", [
  "triage",
  "deep_analysis",
  "synthesis",
  "self_correction",
]);

export const analysisStepsTable = pgTable(
  "analysis_steps",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    caseId: uuid("case_id")
      .notNull()
      .references(() => casesTable.id, { onDelete: "cascade" }),
    stepNumber: integer("step_number").notNull(),
    phase: analysisPhaseEnum("phase").notNull(),
    toolUsed: text("tool_used"),
    rationale: text("rationale").notNull(),
    expected: text("expected").notNull(),
    found: text("found").notNull(),
    nextStep: text("next_step").notNull(),
    tokensUsed: integer("tokens_used").notNull().default(0),
    durationMs: integer("duration_ms").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("uniq_step_per_case").on(table.caseId, table.stepNumber),
    index("idx_steps_case").on(table.caseId),
  ],
);

export const insertAnalysisStepSchema = createInsertSchema(
  analysisStepsTable,
).omit({
  id: true,
  createdAt: true,
});

export type InsertAnalysisStep = z.infer<typeof insertAnalysisStepSchema>;
export type AnalysisStep = typeof analysisStepsTable.$inferSelect;
