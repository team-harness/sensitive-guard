import { AhoCorasick } from '../aho-corasick';
import { normalize, type NormalizeOptions } from '../normalize';
import type { RawFinding, Severity, SyncDetector } from '../types';

export interface KeywordList {
  /** Label stored in `finding.tag`, e.g. `politics`, `abuse`, `internal-codename`. */
  label: string;
  words: string[];
  severity?: Severity;
}

export interface KeywordsOptions extends NormalizeOptions {
  /** Detector id; also used in rule ids (`keyword.<label>`). Default `keywords`. */
  id?: string;
  /** Either a flat word list or labelled lists with their own severity. */
  words?: string[];
  lists?: KeywordList[];
  /** Severity for `words`. Default `medium`. */
  severity?: Severity;
  /**
   * For words made only of ASCII letters/digits, require the match not to be
   * part of a larger ASCII word in the original text (so `ass` doesn't hit `class`).
   * Default true.
   */
  asciiWordBoundary?: boolean;
  /** Words that, if they cover a match, suppress it (e.g. `assassin` for `ass`). */
  exceptions?: string[];
}

const ASCII_WORD = /^[a-z0-9]+$/;
const ASCII_ALNUM = /[A-Za-z0-9]/;

/**
 * Keyword / blocklist detector: Aho–Corasick over normalised text.
 *
 * Bring your own lists — this package deliberately ships no word list,
 * since what counts as sensitive is product- and jurisdiction-specific.
 */
export function keywords(options: KeywordsOptions): SyncDetector {
  const id = options.id ?? 'keywords';
  const lists: KeywordList[] = [...(options.lists ?? [])];
  if (options.words?.length) lists.push({ label: id, words: options.words, severity: options.severity ?? 'medium' });

  const norm = (s: string) => normalize(s, options).text;

  const patterns: string[] = [];
  const meta: { label: string; severity: Severity; ascii: boolean }[] = [];
  const seen = new Set<string>();
  for (const list of lists) {
    for (const w of list.words) {
      const n = norm(w);
      if (!n) continue;
      const key = `${list.label}\u0000${n}`;
      if (seen.has(key)) continue;
      seen.add(key);
      patterns.push(n);
      meta.push({ label: list.label, severity: list.severity ?? options.severity ?? 'medium', ascii: ASCII_WORD.test(n) });
    }
  }
  const ac = new AhoCorasick(patterns);
  const exceptionAc = options.exceptions?.length ? new AhoCorasick(options.exceptions.map(norm).filter(Boolean)) : null;
  const wordBoundary = options.asciiWordBoundary ?? true;

  return {
    id,
    detect(text) {
      if (patterns.length === 0) return [];
      const n = normalize(text, options);
      const exceptionSpans = exceptionAc ? exceptionAc.search(n.text) : [];
      const out: RawFinding[] = [];
      for (const m of ac.search(n.text)) {
        if (exceptionSpans.some((e) => e.start <= m.start && e.end >= m.end)) continue;
        const info = meta[m.pattern]!;
        const start = n.starts[m.start]!;
        const end = n.ends[m.end - 1]!;
        if (wordBoundary && info.ascii) {
          if (ASCII_ALNUM.test(text[start - 1] ?? '') || ASCII_ALNUM.test(text[end] ?? '')) continue;
        }
        out.push({
          ruleId: `keyword.${info.label}`,
          category: 'keyword',
          severity: info.severity,
          confidence: 0.9,
          start,
          end,
          tag: info.label,
          description: `Matched keyword list "${info.label}"`,
        });
      }
      return out;
    },
  };
}
