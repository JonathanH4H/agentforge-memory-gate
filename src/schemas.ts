import { z } from "zod";

export const SOURCE_CLASSES = [
  "email",
  "calendar",
  "tool_result",
  "user",
  "web",
  "unknown",
] as const;

export const POLICY_MODES = ["enforce", "silent", "declared"] as const;
export const ACTIONS = ["allow", "redact", "quarantine", "block"] as const;

export const SourceClassSchema = z.enum(SOURCE_CLASSES);
export const PolicyModeSchema = z.enum(POLICY_MODES);
export const ActionSchema = z.enum(ACTIONS);

export const ContentHashSchema = z
  .string()
  .regex(/^sha256:[a-fA-F0-9]{64}$/, "content_hash must be sha256:<hex>");

export const PolicySchema = z.object({
  mode: PolicyModeSchema,
  max_action: ActionSchema,
});

export const ScanRequestSchema = z.object({
  text: z.string(),
  source_class: SourceClassSchema,
  content_hash: ContentHashSchema,
  policy: PolicySchema,
  nonce: z.string().min(1),
  agent_id: z.string().min(1),
});

export const DetectorHitSchema = z.object({
  id: z.string(),
  hit: z.boolean(),
  span: z.tuple([z.number().int(), z.number().int()]),
});

export const GapDisclosureSchema = z.object({
  gap_type: z.literal("detector_coverage"),
  scope: z.literal("heuristic_v0; not formal MINJA proof"),
  signed_by: z.literal("memory-gate"),
});

export const MeterSchema = z.object({
  meter_ref: z.string().regex(/^mtr_/),
  sku: z.literal("memory_scan"),
  billable: z.boolean(),
  usdc: z.number().nullable(),
  price_pending: z.boolean(),
  outcome: ActionSchema,
  unit: z.literal("memory_scan"),
});

export const ScanResultSchema = z
  .object({
    scan_id: z.string().regex(/^scn_/),
    content_hash: ContentHashSchema,
    action: ActionSchema,
    score: z.number().min(0).max(1),
    detectors: z.array(DetectorHitSchema),
    redacted_text: z.string().nullable(),
    gap_disclosure: GapDisclosureSchema,
    fpr_note: z.string(),
    meter: MeterSchema,
  })
  .superRefine((value, ctx) => {
    if (value.action === "redact") {
      if (typeof value.redacted_text !== "string") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "redacted_text is required when action=redact",
          path: ["redacted_text"],
        });
      }
    } else if (value.redacted_text !== null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "redacted_text must be null unless action=redact",
        path: ["redacted_text"],
      });
    }
  });

export type SourceClass = z.infer<typeof SourceClassSchema>;
export type PolicyMode = z.infer<typeof PolicyModeSchema>;
export type Action = z.infer<typeof ActionSchema>;
export type Policy = z.infer<typeof PolicySchema>;
export type ScanRequest = z.infer<typeof ScanRequestSchema>;
export type DetectorHit = z.infer<typeof DetectorHitSchema>;
export type GapDisclosure = z.infer<typeof GapDisclosureSchema>;
export type Meter = z.infer<typeof MeterSchema>;
export type ScanResult = z.infer<typeof ScanResultSchema>;

export const GAP_DISCLOSURE: GapDisclosure = {
  gap_type: "detector_coverage",
  scope: "heuristic_v0; not formal MINJA proof",
  signed_by: "memory-gate",
};

/** Conservative overnight estimate; not a published academic rate. See README. */
export const FPR_NOTE = "benign_corpus_fpr≈0.02";

export const LIST_PRICE_USDC = 0.002;
export const METER_SKU = "memory_scan" as const;
