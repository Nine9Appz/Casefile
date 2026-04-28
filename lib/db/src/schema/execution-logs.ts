import {
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { analysisStepsTable } from "./analysis-steps";
import { caseArtifactsTable } from "./case-artifacts";
import { casesTable } from "./cases";

export const executionLogsTable = pgTable(
  "execution_logs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    caseId: uuid("case_id")
      .notNull()
      .references(() => casesTable.id, { onDelete: "cascade" }),
    analysisStepId: uuid("analysis_step_id").references(
      () => analysisStepsTable.id,
      { onDelete: "set null" },
    ),
    artifactId: uuid("artifact_id").references(() => caseArtifactsTable.id, {
      onDelete: "set null",
    }),
    toolName: text("tool_name").notNull(),
    input: jsonb("input").notNull(),
    output: jsonb("output").notNull(),
    tokensPrompt: integer("tokens_prompt").notNull().default(0),
    tokensCompletion: integer("tokens_completion").notNull().default(0),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    endedAt: timestamp("ended_at", { withTimezone: true }).notNull(),
    error: text("error"),
  },
  (table) => [
    index("idx_exec_case").on(table.caseId),
    index("idx_exec_step").on(table.analysisStepId),
  ],
);

export const insertExecutionLogSchema = createInsertSchema(
  executionLogsTable,
).omit({
  id: true,
});

export type InsertExecutionLog = z.infer<typeof insertExecutionLogSchema>;
export type ExecutionLog = typeof executionLogsTable.$inferSelect;
