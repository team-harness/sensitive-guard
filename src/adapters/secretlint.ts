import type { AsyncDetector, RawFinding, Severity } from '../types';

/**
 * Adapter that runs secretlint (https://github.com/secretlint/secretlint) as an
 * async detector. Install the optional peers first:
 *
 *   npm i @secretlint/core @secretlint/secretlint-rule-preset-recommend
 *
 * secretlint is file-oriented and noticeably slower (~10–30 ms per message)
 * than the built-in `secrets()` detector, so use it as a second, deeper pass —
 * e.g. before persisting conversations — rather than on every keystroke.
 */

export interface SecretlintRuleConfig {
  id: string;
  // secretlint rule creator; typed loosely to avoid a hard type dependency
  rule: unknown;
  options?: Record<string, unknown>;
  allowMessageIds?: string[];
  disabled?: boolean;
}

export interface SecretlintDetectorOptions {
  /** Rule configs. Default: `@secretlint/secretlint-rule-preset-recommend`. */
  rules?: SecretlintRuleConfig[];
  /** Severity for all secretlint findings. Default `critical`. */
  severity?: Severity;
  /** Virtual file path passed to secretlint (some rules key off the file name). */
  filePath?: string;
}

interface LintMessage {
  ruleId: string;
  messageId: string;
  message: string;
  range: readonly [number, number];
}

type LintSource = (args: {
  source: { filePath: string; content: string; contentType: 'text' | 'binary' };
  options: { config: { rules: SecretlintRuleConfig[] }; maskSecrets?: boolean };
}) => Promise<{ messages: LintMessage[] }>;

export function secretlint(options: SecretlintDetectorOptions = {}): AsyncDetector {
  let ready: Promise<{ lintSource: LintSource; rules: SecretlintRuleConfig[] }> | null = null;

  const load = () =>
    (ready ??= (async () => {
      let core: { lintSource: LintSource };
      try {
        core = (await import('@secretlint/core')) as unknown as { lintSource: LintSource };
      } catch (err) {
        throw new Error(
          'sensitive-guard/secretlint: @secretlint/core is not installed. Run `npm i @secretlint/core @secretlint/secretlint-rule-preset-recommend`.',
          { cause: err },
        );
      }
      let rules = options.rules;
      if (!rules) {
        const preset = (await import('@secretlint/secretlint-rule-preset-recommend')) as unknown as { creator: unknown };
        rules = [{ id: '@secretlint/secretlint-rule-preset-recommend', rule: preset.creator }];
      }
      return { lintSource: core.lintSource, rules };
    })());

  return {
    id: 'secretlint',
    async: true,
    async detect(text) {
      const { lintSource, rules } = await load();
      const res = await lintSource({
        source: { filePath: options.filePath ?? '/sensitive-guard/message.txt', content: text, contentType: 'text' },
        options: { config: { rules }, maskSecrets: true },
      });
      return res.messages.map(
        (m): RawFinding => ({
          ruleId: `secretlint.${m.messageId}`,
          category: 'secret',
          severity: options.severity ?? 'critical',
          // Slightly below the built-in provider rules (0.9+): when both fire on the same
          // span, keep the built-in finding, which is usually tighter (e.g. password only).
          confidence: 0.85,
          start: m.range[0],
          end: trimEnd(text, m.range[0], m.range[1]),
          description: `${m.ruleId}: ${m.messageId}`,
        }),
      );
    },
  };
}

/**
 * secretlint patterns usually stop at whitespace, which Chinese prose doesn't have:
 * `postgres://u:p@db/app，token 在下面` would swallow `，token`. Cut the span at the
 * first whitespace / CJK / full-width character — none of these occur in credentials.
 */
const SPAN_STOP = /[\s　-〿㐀-䶿一-鿿豈-﫿＀-￯]/;

function trimEnd(text: string, start: number, end: number): number {
  for (let i = start + 1; i < end; i++) {
    if (SPAN_STOP.test(text[i]!)) return i;
  }
  return end;
}
