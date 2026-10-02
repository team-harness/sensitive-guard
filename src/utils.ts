/**
 * Shannon entropy in bits per character — the same measure gitleaks and
 * trufflehog use to tell random-looking secrets from ordinary words.
 *
 *   "password"                          ≈ 2.75
 *   "hunter2hunter2"                    ≈ 2.81
 *   "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..." ≈ 4.5+
 */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const len = [...s].length;
  let h = 0;
  for (const n of freq.values()) {
    const p = n / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Number of character classes present: lower, upper, digit, other. */
export function charClassCount(s: string): number {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^A-Za-z0-9]/.test(s)) n++;
  return n;
}

/**
 * Mask a string so it is safe to show in logs: reveals at most ~1/4 of the
 * characters (≤ 4 at each end) and never the length of short values.
 *
 *   ghp_ + 36 chars → `ghp_…3zA5`,  S3cr3t-P4ss → `S…s`,  hunter2 → `********`
 */
export function maskPreview(s: string, maxKeep = 4): string {
  const chars = [...s];
  const keep = Math.min(maxKeep, Math.floor(chars.length / 8));
  if (keep === 0) return '********';
  return `${chars.slice(0, keep).join('')}…${chars.slice(-keep).join('')}`;
}

export function clamp01(n: number): number {
  return n < 0 ? 0 : n > 1 ? 1 : n;
}

/**
 * Heuristics for unquoted values that are code rather than literals:
 * `req.body.password`, `getToken()`, `Password` (a type), `string`.
 */
export function looksLikeCode(value: string, ctx: { text: string; end: number; quoted: boolean }): boolean {
  if (ctx.quoted) return false;
  if (ctx.text[ctx.end] === '(' || value.includes('(')) return true;
  const v = value.replace(/[)\]}!]+$/, ''); // `foo)`, `bar!` (TS non-null)
  // member access incl. optional chaining / indexing: a.b, a?.b, a[0].b, a!.b
  if (/^[A-Za-z_$][\w$]*(?:!?\??\.[A-Za-z_$][\w$]*|\[[^\]]*\])+$/.test(v)) return true;
  if (/^[A-Za-z_$]+$/.test(v)) return true; // bare identifier / type name, no digits
  return false;
}

/** `1.2.3`, `v18.20.0`, `^13.0.6`, `~5.9`, `>=9` */
export function looksLikeVersion(value: string): boolean {
  return /^(?:[\^~]|[<>]=?|=)?v?\d+(?:\.\d+)+(?:[-+][\w.]+)?$/.test(value);
}

export function looksLikePathOrUrl(value: string): boolean {
  return /^(?:\.{0,2}\/|~\/|[A-Za-z]:\\)/.test(value) || value.includes('://');
}

export function hasLetterAndDigit(value: string): boolean {
  return /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

/** Decode base64 / base64url to a binary string, or null if invalid. */
export function decodeBase64(s: string): string | null {
  try {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    return globalThis.atob(b);
  } catch {
    return null;
  }
}

/** Ensure a regex is global so `matchAll` / `exec` loops work. */
export function toGlobal(re: RegExp): RegExp {
  return re.flags.includes('g') ? re : new RegExp(re.source, `${re.flags}g`);
}
