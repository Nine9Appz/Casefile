import {
  jsonb,
  numeric,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { casesTable } from "./cases";

export const incidentSeverityEnum = pgEnum("incident_severity", [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);

export const incidentReportsTable = pgTable("incident_reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  caseId: uuid("case_id")
    .notNull()
    .unique()
    .references(() => casesTable.id, { onDelete: "cascade" }),
  summary: text("summary").notNull(),
  severity: incidentSeverityEnum("severity").notNull().default("informational"),
  iocs: jsonb("iocs").notNull(),
  ttps: jsonb("ttps").notNull(),
  timeline: jsonb("timeline").notNull(),
  confidenceScore: numeric("confidence_score", { precision: 3, scale: 2 }),
  recommendations: jsonb("recommendations").notNull(),
  generatedAt: timestamp("generated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const insertIncidentReportSchema = createInsertSchema(
  incidentReportsTable,
).omit({
  id: true,
  generatedAt: true,
});

export type InsertIncidentReport = z.infer<typeof insertIncidentReportSchema>;
export type IncidentReport = typeof incidentReportsTable.$inferSelect;
