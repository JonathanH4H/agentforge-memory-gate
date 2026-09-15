import { describe, expect, it } from "vitest";
import { detect } from "../src/detector.js";
import { BENIGN_FIXTURES } from "../src/fixtures/benign.js";
import { MALICIOUS_FIXTURES } from "../src/fixtures/malicious.js";
import { FPR_NOTE } from "../src/schemas.js";

describe("detector v0 fixtures", () => {
  it("flags malicious ASI06-pattern fixtures", () => {
    for (const fixture of MALICIOUS_FIXTURES) {
      const result = detect(fixture.text);
      const ids = result.detectors.filter((d) => d.hit).map((d) => d.id);
      for (const id of fixture.expectIds) {
        expect(ids, fixture.text).toContain(id);
      }
      expect(result.recommended, fixture.text).not.toBe("allow");
      expect(result.score).toBeGreaterThan(0);
      for (const det of result.detectors) {
        expect(det.span[1]).toBeGreaterThan(det.span[0]);
        expect(fixture.text.slice(det.span[0], det.span[1]).length).toBeGreaterThan(0);
      }
    }
  });

  it("keeps benign corpus FPR at or under the published overnight note", () => {
    const flagged = BENIGN_FIXTURES.filter((text) => detect(text).recommended !== "allow");
    const fpr = flagged.length / BENIGN_FIXTURES.length;
    expect(BENIGN_FIXTURES.length).toBeGreaterThanOrEqual(40);
    expect(fpr).toBeLessThanOrEqual(0.05);
    expect(FPR_NOTE).toBe("benign_corpus_fpr≈0.02");
  });

  it("allow-path text does not trip heuristics", () => {
    const text = "Team standup at 10am. Ship the README and add curl examples.";
    const result = detect(text);
    expect(result.recommended).toBe("allow");
    expect(result.detectors).toEqual([]);
    expect(result.score).toBe(0);
  });
});
