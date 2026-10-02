export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type Category = 'secret' | 'pii' | 'keyword' | 'custom';

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * One detected piece of sensitive content.
 *
 * Findings carry offsets into the original text but, by default, NOT the raw
 * matched text, so that logging a finding never leaks the secret itself.
 * Use `text.slice(start, end)` if you really need it, or set
 * `includeMatch: true` on the scanner.
 */
export interface Finding {
  /** Stable rule id, e.g. `secret.github-pat`, `pii.cn-id-card`. */
  ruleId: string;
  /** Id of the detector that produced it, e.g. `secrets`. */
  detector: string;
  category: Category;
  severity: Severity;
  /** 0..1 — how sure the detector is. Validated matches (checksums, known prefixes) score high. */
  confidence: number;
  /** Start offset (UTF-16 code units, inclusive) in the original text. */
  start: number;
  /** End offset (exclusive). */
  end: number;
  /** Human readable description of the rule. */
  description?: string;
  /** Masked preview safe to log, e.g. `ghp_…Q2xY`. */
  preview: string;
  /** Raw matched text. Only present when the scanner has `includeMatch: true`. */
  match?: string;
  /** Optional free-form tag (e.g. keyword list label). */
  tag?: string;
}

/** A finding as produced by a detector, before the scanner fills in derived fields. */
export type RawFinding = Omit<Finding, 'detector' | 'preview' | 'match'> & {
  preview?: string;
};

export interface DetectContext {
  /** Lower-cased copy of the text, computed once and shared by detectors. */
  readonly lowerText: string;
}

export interface SyncDetector {
  id: string;
  async?: false;
  detect(text: string, ctx: DetectContext): RawFinding[];
}

export interface AsyncDetector {
  id: string;
  async: true;
  detect(text: string, ctx: DetectContext): Promise<RawFinding[]>;
}

export type Detector = SyncDetector | AsyncDetector;
