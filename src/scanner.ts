import { pii } from './detectors/pii';
import { secrets } from './detectors/secrets';
import { SEVERITY_RANK, type DetectContext, type Detector, type Finding, type RawFinding, type Severity, type SyncDetector } from './types';
import { maskPreview } from './utils';

export interface ScannerOptions {
  /** Detectors to run. Default: `[secrets(), pii()]`. */
  detectors?: Detector[];
  /** Drop findings below this severity. Default `low` (keep all). */
  minSeverity?: Severity;
  /** Drop findings below this confidence. Default 0. */
  minConfidence?: number;
  /** Matched text equal to a string, or matching a regex, is never reported. */
  allowlist?: (string | RegExp)[];
  /** Rule ids (e.g. `pii.email`) to drop. Prefix match with a trailing `*` (`pii.*`). */
  disableRules?: string[];
  /**
   * Resolve overlapping findings, keeping the strongest one
   * (severity → confidence → longer span). Default true.
   */
  dedupe?: boolean;
  /** Attach the raw matched text to findings. Default false — avoid logging secrets. */
  includeMatch?: boolean;
}

export type Masker = (finding: Finding, original: string) => string;

export interface RedactOptions {
  /** Replacement for each finding. Default `[REDACTED:<ruleId>]`. */
  mask?: Masker;
}

export interface RedactResult {
  text: string;
  findings: Finding[];
}

export interface Scanner {
  /** Run all detectors (sync and async). */
  scan(text: string): Promise<Finding[]>;
  /** Run only synchronous detectors — use for latency-critical paths (e.g. before sending). */
  scanSync(text: string): Finding[];
  /** Scan, then replace every finding. */
  redact(text: string, options?: RedactOptions): Promise<RedactResult>;
  redactSync(text: string, options?: RedactOptions): RedactResult;
  /** True if any finding at or above `minSeverity` (default: the scanner's own). Sync detectors only. */
  hasSensitiveSync(text: string, minSeverity?: Severity): boolean;
}

/** Built-in maskers. */
export const masks = {
  /** `[REDACTED:secret.github-token]` */
  label: ((f) => `[REDACTED:${f.ruleId}]`) as Masker,
  /** `[REDACTED]` */
  plain: (() => '[REDACTED]') as Masker,
  /** Replace every character with `ch`, preserving length. */
  char:
    (ch = '*'): Masker =>
    (_f, original) =>
      ch.repeat([...original].length),
  /** Keep the first `head` and last `tail` characters: `ghp_****…****Q2xY`. */
  partial:
    (head = 4, tail = 4, ch = '*'): Masker =>
    (_f, original) => {
      const chars = [...original];
      if (chars.length <= head + tail) return ch.repeat(chars.length);
      return chars.slice(0, head).join('') + ch.repeat(chars.length - head - tail) + chars.slice(chars.length - tail).join('');
    },
};

function priority(f: Finding): [number, number, number] {
  return [SEVERITY_RANK[f.severity], f.confidence, f.end - f.start];
}

function stronger(a: Finding, b: Finding): boolean {
  const pa = priority(a);
  const pb = priority(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i]! !== pb[i]!) return pa[i]! > pb[i]!;
  }
  return false;
}

/** Keep the strongest finding among overlapping ones (greedy by priority). */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const sorted = [...findings].sort((a, b) => (stronger(a, b) ? -1 : stronger(b, a) ? 1 : a.start - b.start));
  const kept: Finding[] = [];
  for (const f of sorted) {
    if (kept.some((k) => f.start < k.end && k.start < f.end)) continue;
    kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start || b.end - a.end);
}

export function applyRedaction(text: string, findings: Finding[], mask: Masker = masks.label): string {
  // Merge overlaps first so replacements never interleave.
  const spans = dedupeFindings(findings);
  let out = '';
  let cursor = 0;
  for (const f of spans) {
    if (f.start < cursor) continue;
    out += text.slice(cursor, f.start) + mask(f, text.slice(f.start, f.end));
    cursor = f.end;
  }
  return out + text.slice(cursor);
}

export function createScanner(options: ScannerOptions = {}): Scanner {
  const detectors = options.detectors ?? [secrets(), pii()];
  const syncDetectors = detectors.filter((d): d is SyncDetector => !d.async);
  const minRank = SEVERITY_RANK[options.minSeverity ?? 'low'];
  const minConfidence = options.minConfidence ?? 0;
  const allowStrings = new Set((options.allowlist ?? []).filter((a): a is string => typeof a === 'string'));
  const allowRegexes = (options.allowlist ?? []).filter((a): a is RegExp => a instanceof RegExp);
  const disabled = options.disableRules ?? [];
  const dedupe = options.dedupe ?? true;
  const includeMatch = options.includeMatch ?? false;

  const isDisabled = (ruleId: string) =>
    disabled.some((d) => (d.endsWith('*') ? ruleId.startsWith(d.slice(0, -1)) : ruleId === d));

  function finalize(text: string, raw: Array<{ detector: string; findings: RawFinding[] }>, rank = minRank): Finding[] {
    const out: Finding[] = [];
    for (const { detector, findings } of raw) {
      for (const r of findings) {
        if (r.start < 0 || r.end > text.length || r.end <= r.start) continue;
        if (SEVERITY_RANK[r.severity] < rank || r.confidence < minConfidence) continue;
        if (isDisabled(r.ruleId)) continue;
        const match = text.slice(r.start, r.end);
        if (allowStrings.has(match) || allowRegexes.some((re) => re.test(match))) continue;
        const f: Finding = { ...r, detector, preview: r.preview ?? maskPreview(match) };
        if (includeMatch) f.match = match;
        out.push(f);
      }
    }
    return dedupe ? dedupeFindings(out) : out.sort((a, b) => a.start - b.start);
  }

  const ctxFor = (text: string): DetectContext => ({ lowerText: text.toLowerCase() });

  function runSync(text: string) {
    const ctx = ctxFor(text);
    return syncDetectors.map((d) => ({ detector: d.id, findings: d.detect(text, ctx) }));
  }

  const scanner: Scanner = {
    scanSync(text) {
      return finalize(text, runSync(text));
    },
    async scan(text) {
      const ctx = ctxFor(text);
      const raw = await Promise.all(
        detectors.map(async (d) => ({ detector: d.id, findings: await d.detect(text, ctx) })),
      );
      return finalize(text, raw);
    },
    redactSync(text, opts) {
      const findings = scanner.scanSync(text);
      return { text: applyRedaction(text, findings, opts?.mask), findings };
    },
    async redact(text, opts) {
      const findings = await scanner.scan(text);
      return { text: applyRedaction(text, findings, opts?.mask), findings };
    },
    hasSensitiveSync(text, minSeverity) {
      const rank = minSeverity ? SEVERITY_RANK[minSeverity] : minRank;
      return finalize(text, runSync(text), rank).length > 0;
    },
  };
  return scanner;
}
