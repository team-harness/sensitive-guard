import type { RawFinding, Severity, SyncDetector } from '../types';
import { clamp01, shannonEntropy } from '../utils';
import { BUILTIN_SECRET_RULES } from '../rules/secrets';

/**
 * Secret detection, modelled on gitleaks' algorithm:
 *
 *   1. keyword pre-filter   — a rule only runs if one of its (lower-case) keywords
 *                             occurs in the text. Cheap, skips most rules on most messages.
 *   2. regex + secret group — the regex locates the candidate; a capture group
 *                             isolates the actual secret (e.g. only the password
 *                             inside a connection string).
 *   3. entropy threshold    — Shannon entropy of the secret must reach the rule's
 *                             minimum, which filters out words and placeholders.
 *   4. allowlists/stopwords — placeholders (`${TOKEN}`, `<your-key>`, `xxxx`),
 *                             documented example keys, rule-level allowlists.
 *   5. rule validator       — optional structural check (JWT header decodes,
 *                             Basic auth contains `user:pass`, value isn't code…).
 */

export interface SecretMatchContext {
  /** Full original text. */
  text: string;
  /** Offsets of the secret within `text`. */
  start: number;
  end: number;
  /** The regex match. */
  match: RegExpExecArray;
  /** True if the secret was wrapped in quotes in the source (`"…"`, `'…'`, `` `…` ``). */
  quoted: boolean;
}

export type ValidateResult = boolean | { severity?: Severity; confidence?: number };

export interface SecretRule {
  /** Rule id without the `secret.` prefix, e.g. `github-token`. */
  id: string;
  description: string;
  /** Pattern. Flags are preserved; `g` and `d` are added automatically. */
  regex: RegExp;
  /** Capture group holding the secret. Defaults to 0 (whole match). */
  secretGroup?: number;
  /** Lower-case keywords; the rule is skipped unless one occurs in the text. Omit to always run. */
  keywords?: string[];
  /** Minimum Shannon entropy (bits/char) of the secret. */
  entropy?: number;
  severity?: Severity;
  /** Base confidence, default 0.9. */
  confidence?: number;
  /** Secrets matching any of these are ignored. */
  allowlist?: RegExp[];
  /** Skip the global placeholder / stopword check (e.g. for private-key blocks). */
  skipPlaceholderCheck?: boolean;
  /** Trailing characters stripped from the secret (and its span) before checks, e.g. `/[.)\]}:]+$/`. */
  trimEnd?: RegExp;
  /** Extra structural check. Return false to drop, or override severity/confidence. */
  validate?: (secret: string, ctx: SecretMatchContext) => ValidateResult;
}

export interface SecretsOptions {
  /** Replace the built-in rule set entirely. */
  rules?: SecretRule[];
  /** Additional rules appended to the built-in (or replaced) set. */
  extraRules?: SecretRule[];
  /** Rule ids (without `secret.` prefix) to disable. */
  disable?: string[];
  /**
   * Ignore secrets that look like documentation examples
   * (`AKIAIOSFODNN7EXAMPLE`, `…EXAMPLEKEY`, `sample`, `dummy`, `fake`). Default true.
   */
  ignoreExamples?: boolean;
  /** Extra values / patterns to never report. */
  allowlist?: (string | RegExp)[];
}

// ---------------------------------------------------------------------------
// Placeholder / stopword handling (applies to every rule unless skipped)
// ---------------------------------------------------------------------------

const PLACEHOLDER_EXACT =
  /^(?:[x*.•#_\-=]+|0+|1+|12345\d*|abc(?:123|def)?|qwerty|changeme|change[_-]?me|change[_-]?it|notasecret|placeholder|dummy|redacted|masked|hidden|secret|secrets|password|passwd|token|apikey|api[_-]?key|test|testing|none|null|nil|undefined|true|false|string|str|number|int|integer|boolean|bool|any|object|required|optional|todo|tbd|empty|\.\.\.|…)$/i;

const PLACEHOLDER_SHAPES: RegExp[] = [
  /^\$\{[^}]*\}$/, // ${TOKEN}
  /^\$\{?[A-Z_][A-Z0-9_]*\}?$/, // $TOKEN
  /^%[A-Za-z_][A-Za-z0-9_]*%$/, // %TOKEN%
  /^\{\{.*\}\}$/, // {{ token }}
  /^<[^>]*>$/, // <your-token>
  /^\[[^\]]*\]$/, // [REDACTED]
  /^\$\(.*\)$/, // $(cat token)
  /^(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|env)[.[(]/i,
  /(?:^|[^a-z])your[_-]/i, // your_api_key, sk-your-key-here
  /(?:xxxx|\*\*\*\*|••••)/i,
];

const EXAMPLE_MARKERS = /(?:example|sample|dummy|placeholder|fake|redacted)/i;

function isPlaceholder(secret: string): boolean {
  if (PLACEHOLDER_EXACT.test(secret)) return true;
  return PLACEHOLDER_SHAPES.some((re) => re.test(secret));
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

interface CompiledRule {
  rule: SecretRule;
  re: RegExp;
}

function compile(rule: SecretRule): CompiledRule {
  const flags = new Set(rule.regex.flags.split(''));
  flags.add('g');
  flags.add('d'); // hasIndices → exact offsets for capture groups
  return { rule, re: new RegExp(rule.regex.source, [...flags].join('')) };
}

const QUOTES = new Set(['"', "'", '`']);

export function secrets(options: SecretsOptions = {}): SyncDetector {
  const disabled = new Set(options.disable ?? []);
  const ruleSet = [...(options.rules ?? BUILTIN_SECRET_RULES), ...(options.extraRules ?? [])].filter(
    (r) => !disabled.has(r.id),
  );
  const compiled = ruleSet.map(compile);
  const ignoreExamples = options.ignoreExamples ?? true;
  const allowStrings = new Set((options.allowlist ?? []).filter((a): a is string => typeof a === 'string'));
  const allowRegexes = (options.allowlist ?? []).filter((a): a is RegExp => a instanceof RegExp);

  return {
    id: 'secrets',
    detect(text, ctx) {
      const out: RawFinding[] = [];
      for (const { rule, re } of compiled) {
        if (rule.keywords && rule.keywords.length > 0 && !rule.keywords.some((k) => ctx.lowerText.includes(k))) {
          continue;
        }
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          const group = rule.secretGroup ?? 0;
          let secret = m[group];
          const span = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices?.[group];
          if (!secret || !span) continue;
          const start = span[0];
          let end = span[1];
          if (rule.trimEnd) {
            const trimmed = secret.replace(rule.trimEnd, '');
            end -= secret.length - trimmed.length;
            secret = trimmed;
            if (!secret) continue;
          }

          if (!rule.skipPlaceholderCheck && isPlaceholder(secret)) continue;
          if (ignoreExamples && EXAMPLE_MARKERS.test(secret)) continue;
          if (allowStrings.has(secret) || allowRegexes.some((r) => r.test(secret))) continue;
          if (rule.allowlist?.some((r) => r.test(secret))) continue;
          if (rule.entropy !== undefined && shannonEntropy(secret) < rule.entropy) continue;

          let severity: Severity = rule.severity ?? 'high';
          let confidence = rule.confidence ?? 0.9;
          if (rule.validate) {
            const quoted = start > 0 && QUOTES.has(text[start - 1] ?? '');
            const res = rule.validate(secret, { text, start, end, match: m, quoted });
            if (res === false) continue;
            if (typeof res === 'object') {
              severity = res.severity ?? severity;
              confidence = res.confidence ?? confidence;
            }
          }

          out.push({
            ruleId: `secret.${rule.id}`,
            category: 'secret',
            severity,
            confidence: clamp01(confidence),
            start,
            end,
            description: rule.description,
          });
        }
      }
      return out;
    },
  };
}

export { isPlaceholder };
