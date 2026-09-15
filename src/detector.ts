import type { Action, DetectorHit } from "./schemas.js";

export type DetectorId =
  | "asi06.injection"
  | "asi06.override"
  | "asi06.exfil"
  | "asi06.ignore_previous";

type Pattern = {
  id: DetectorId;
  weight: number;
  re: RegExp;
};

/**
 * ASI06-pattern heuristics only (injection / override / exfil-ish / ignore-previous).
 * Not a MINJA formal proof. Spans are UTF-16 code-unit offsets into the original text.
 */
const PATTERNS: Pattern[] = [
  {
    id: "asi06.ignore_previous",
    weight: 0.62,
    re: /ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|guidance|policies|policy)/gi,
  },
  {
    id: "asi06.ignore_previous",
    weight: 0.6,
    re: /disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s*(instructions?|prompts?|rules?|guidance)?/gi,
  },
  {
    id: "asi06.ignore_previous",
    weight: 0.58,
    re: /forget\s+(all\s+|your\s+)?(previous\s+)?(instructions?|rules?|guidelines|safety)/gi,
  },
  {
    id: "asi06.override",
    weight: 0.72,
    re: /override\s+(the\s+|your\s+)?(system|safety|policy|instructions?)/gi,
  },
  {
    id: "asi06.override",
    weight: 0.74,
    re: /new\s+system\s+prompt/gi,
  },
  {
    id: "asi06.override",
    weight: 0.7,
    re: /you\s+are\s+now\s+(dan|jailbroken|unrestricted|without\s+restrictions)/gi,
  },
  {
    id: "asi06.override",
    weight: 0.68,
    re: /developer\s+mode\s+(enabled|on|activated)/gi,
  },
  {
    id: "asi06.override",
    weight: 0.66,
    re: /\bjailbreak\b/gi,
  },
  {
    id: "asi06.exfil",
    weight: 0.92,
    re: /\bexfiltrat(?:e|ion|ing)\b/gi,
  },
  {
    id: "asi06.exfil",
    weight: 0.9,
    re: /(dump|export|print)\s+(your\s+|the\s+|full\s+)*(memory|system\s+prompt|hidden\s+instructions?|secrets?|credentials)/gi,
  },
  {
    id: "asi06.exfil",
    weight: 0.88,
    re: /send\s+(all\s+)?(secrets?|api\s+keys?|credentials|memory)\s+to/gi,
  },
  {
    id: "asi06.exfil",
    weight: 0.86,
    re: /reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions?)/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.68,
    re: /ignore\s+(the\s+)?(system|user)\s+(prompt|instructions?)/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.66,
    re: /hidden\s+(instruction|prompt)s?/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.7,
    re: /<\|im_start\|>\s*system/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.64,
    re: /\[INST\]/g,
  },
  {
    id: "asi06.injection",
    weight: 0.63,
    re: /beginning\s+of\s+(a\s+)?new\s+(instruction|prompt)/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.4,
    re: /do\s+not\s+(tell|mention|reveal)\s+(the\s+user|anyone|the\s+human)/gi,
  },
  {
    id: "asi06.injection",
    weight: 0.42,
    re: /when\s+(this|the)\s+(memory|note|document)\s+is\s+retrieved/gi,
  },
];

export type Span = [number, number];

export type Detection = {
  score: number;
  recommended: Action;
  detectors: DetectorHit[];
  redactSpans: Span[];
};

function collectMatches(text: string, re: RegExp): Span[] {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const clone = new RegExp(re.source, flags);
  const spans: Span[] = [];
  let match: RegExpExecArray | null;
  while ((match = clone.exec(text)) !== null) {
    if (match[0].length === 0) {
      clone.lastIndex += 1;
      continue;
    }
    spans.push([match.index, match.index + match[0].length]);
    if (clone.lastIndex === match.index) clone.lastIndex += 1;
  }
  return spans;
}

function mergeSpans(spans: Span[]): Span[] {
  if (spans.length === 0) return [];
  const sorted = [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out: Span[] = [sorted[0]!];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i]!;
    const last = out[out.length - 1]!;
    if (cur[0] <= last[1]) {
      last[1] = Math.max(last[1], cur[1]);
    } else {
      out.push([...cur] as Span);
    }
  }
  return out;
}

function actionFromScore(score: number): Action {
  if (score >= 0.85) return "block";
  if (score >= 0.55) return "quarantine";
  if (score >= 0.3) return "redact";
  return "allow";
}

export function detect(text: string): Detection {
  const byId = new Map<
    DetectorId,
    { weight: number; span: Span; all: Span[] }
  >();

  for (const pattern of PATTERNS) {
    const spans = collectMatches(text, pattern.re);
    if (spans.length === 0) continue;
    const existing = byId.get(pattern.id);
    if (!existing || pattern.weight > existing.weight) {
      byId.set(pattern.id, {
        weight: pattern.weight,
        span: spans[0]!,
        all: existing ? mergeSpans([...existing.all, ...spans]) : spans,
      });
    } else {
      existing.all = mergeSpans([...existing.all, ...spans]);
    }
  }

  const detectors: DetectorHit[] = [];
  const weights: number[] = [];
  const redactSpans: Span[] = [];

  for (const [id, rec] of byId) {
    detectors.push({ id, hit: true, span: rec.span });
    weights.push(rec.weight);
    redactSpans.push(...rec.all);
  }

  detectors.sort((a, b) => a.span[0] - b.span[0] || a.id.localeCompare(b.id));

  const score =
    weights.length === 0
      ? 0
      : Math.min(
          1,
          1 - weights.reduce((product, w) => product * (1 - w), 1),
        );

  return {
    score: Number(score.toFixed(4)),
    recommended: actionFromScore(score),
    detectors,
    redactSpans: mergeSpans(redactSpans),
  };
}

export function redactText(text: string, spans: Span[]): string {
  if (spans.length === 0) return text;
  const merged = mergeSpans(spans);
  let out = "";
  let cursor = 0;
  for (const [start, end] of merged) {
    out += text.slice(cursor, start);
    out += "[REDACTED]";
    cursor = end;
  }
  out += text.slice(cursor);
  return out;
}
