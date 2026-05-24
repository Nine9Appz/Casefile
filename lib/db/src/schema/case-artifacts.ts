import {
  index,
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { casesTable } from "./cases";

export const artifactKindEnum = pgEnum("artifact_kind", [
  "log_file",
  "network_capture",
  "memory_strings",
  "text",
  "mcp_endpoint",
  "disk_image",
]);

export const contentEncodingEnum = pgEnum("content_encoding", [
  "text",
  "base64",
]);

export const caseArtifactsTable = pgTable(
  "case_artifacts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    caseId: uuid("case_id")
      .notNull()
      .references(() => casesTable.id, { onDelete: "cascade" }),
    kind: artifactKindEnum("kind").notNull(),
    filename: text("filename"),
    content: text("content").notNull(),
    contentEncoding: contentEncodingEnum("content_encoding")
      .notNull()
      .default("text"),
    sha256Hash: varchar("sha256_hash", { length: 64 }).notNull(),
    sizeBytes: integer("size_bytes").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [index("idx_artifacts_case").on(table.caseId)],
);

export const insertCaseArtifactSchema = createInsertSchema(
  caseArtifactsTable,
).omit({
  id: true,
  sha256Hash: true,
  sizeBytes: true,
  createdAt: true,
});

export type InsertCaseArtifact = z.infer<typeof insertCaseArtifactSchema>;
export type CaseArtifact = typeof caseArtifactsTable.$inferSelect;
