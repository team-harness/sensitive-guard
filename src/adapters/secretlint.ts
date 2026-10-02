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
          confidence: 0.9,
          start: m.range[0],
          end: m.range[1],
          description: `${m.ruleId}: ${m.messageId}`,
        }),
      );
    },
  };
}
