import type { Category, RawFinding, Severity, SyncDetector } from '../types';
import { toGlobal } from '../utils';

export interface RegexRule {
  /** Rule id, used verbatim as `finding.ruleId`. */
  id: string;
  pattern: RegExp;
  category?: Category;
  severity?: Severity;
  confidence?: number;
  description?: string;
  /** Return false to drop a match. */
  validate?: (match: string, m: RegExpExecArray, text: string) => boolean;
}

/** Quick way to add domain-specific patterns (internal hostnames, employee ids, ticket formats…). */
export function regexDetector(id: string, rules: RegexRule[]): SyncDetector {
  const compiled = rules.map((r) => ({ ...r, pattern: toGlobal(r.pattern) }));
  return {
    id,
    detect(text) {
      const out: RawFinding[] = [];
      for (const r of compiled) {
        r.pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = r.pattern.exec(text)) !== null) {
          if (m[0].length === 0) {
            r.pattern.lastIndex++;
            continue;
          }
          if (r.validate && !r.validate(m[0], m, text)) continue;
          out.push({
            ruleId: r.id,
            category: r.category ?? 'custom',
            severity: r.severity ?? 'medium',
            confidence: r.confidence ?? 0.8,
            start: m.index,
            end: m.index + m[0].length,
            description: r.description,
          });
        }
      }
      return out;
    },
  };
}
