/**
 * Text normalisation for keyword matching, with an offset map back to the
 * original string so findings can point at (and redact) the exact original span.
 *
 * Defaults handle the most common evasion tricks:
 *   - full-width / compatibility forms → NFKC  (ＡＢＣ１２３ → abc123)
 *   - case                                  (ABC → abc)
 *   - noise characters between letters      (敏 感 词, 敏*感*词, f.u.c.k, zero-width chars)
 *   - optional char map                     (traditional → simplified, homoglyphs)
 */

export interface NormalizeOptions {
  /** Apply Unicode NFKC per code point. Default true. */
  nfkc?: boolean;
  /** Lower-case. Default true. */
  lowercase?: boolean;
  /**
   * Characters dropped before matching, so `敏*感*词` matches `敏感词`.
   * Default: whitespace, zero-width chars, and common ASCII / CJK punctuation.
   * Pass `null` to keep everything.
   */
  ignore?: RegExp | null;
  /**
   * Single-character substitutions applied after NFKC/lower-casing,
   * e.g. a traditional→simplified table (`{ 敏: '敏', 詞: '词' }`) or
   * homoglyphs (`{ '0': 'o', '@': 'a' }`). Keys and values must be one code point.
   */
  charMap?: Record<string, string>;
}

export const DEFAULT_IGNORE = /[\s​-‏⁠﻿!-/:-@[-`{-~·•‧∙、，。！？；：…—～·「」『』（）《》【】〈〉“”‘’]/u;

export interface NormalizedText {
  /** Normalised text. */
  text: string;
  /** For each UTF-16 index in `text`, the start offset in the original. */
  starts: number[];
  /** For each UTF-16 index in `text`, the end offset (exclusive) in the original. */
  ends: number[];
}

export function normalize(input: string, options: NormalizeOptions = {}): NormalizedText {
  const nfkc = options.nfkc ?? true;
  const lower = options.lowercase ?? true;
  let ignore = options.ignore === undefined ? DEFAULT_IGNORE : options.ignore;
  if (ignore && (ignore.global || ignore.sticky)) ignore = new RegExp(ignore.source, ignore.flags.replace(/[gy]/g, ''));
  const charMap = options.charMap;

  let text = '';
  const starts: number[] = [];
  const ends: number[] = [];

  let i = 0;
  while (i < input.length) {
    const cp = input.codePointAt(i)!;
    const len = cp > 0xffff ? 2 : 1;
    let s = input.slice(i, i + len);
    if (nfkc) s = s.normalize('NFKC');
    if (lower) s = s.toLowerCase();
    for (const ch of s) {
      const mapped = charMap?.[ch] ?? ch;
      if (ignore && ignore.test(mapped)) continue;
      for (let k = 0; k < mapped.length; k++) {
        starts.push(i);
        ends.push(i + len);
      }
      text += mapped;
    }
    i += len;
  }
  return { text, starts, ends };
}
