import type { RawFinding, Severity, SyncDetector } from '../types';

/**
 * PII detectors with validation, tuned for Chinese data plus a few universal types.
 *
 * Every pattern is followed by a structural check so that random digit runs
 * (order ids, snowflake ids, timestamps) do not become findings:
 *   - cn-id-card     : GB 11643 checksum + valid birth date
 *   - bank-card      : Luhn + known BIN prefix; confidence boosted by context words
 *   - cn-uscc        : GB 32100 统一社会信用代码 checksum
 *   - cn-mobile      : valid 1[3-9]x segment, optional +86
 *   - email, ipv4    : syntactic checks
 */

export type PiiType = 'cn-id-card' | 'cn-mobile' | 'bank-card' | 'cn-uscc' | 'email' | 'ipv4';

export interface PiiOptions {
  /** Which types to detect. Default: all except `ipv4`. */
  include?: PiiType[];
  /** Override severity per type. */
  severity?: Partial<Record<PiiType, Severity>>;
}

const DEFAULT_TYPES: PiiType[] = ['cn-id-card', 'cn-mobile', 'bank-card', 'cn-uscc', 'email'];

const DEFAULT_SEVERITY: Record<PiiType, Severity> = {
  'cn-id-card': 'high',
  'bank-card': 'high',
  'cn-mobile': 'medium',
  email: 'low',
  'cn-uscc': 'low',
  ipv4: 'low',
};

const DESCRIPTIONS: Record<PiiType, string> = {
  'cn-id-card': 'Chinese resident ID card number (居民身份证号)',
  'cn-mobile': 'Chinese mobile phone number (手机号)',
  'bank-card': 'Bank / payment card number (银行卡号)',
  'cn-uscc': 'Unified social credit code (统一社会信用代码)',
  email: 'Email address',
  ipv4: 'IPv4 address',
};

// ---------------------------------------------------------------------------
// Validators (exported for reuse and testing)
// ---------------------------------------------------------------------------

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const ID_CHECK = '10X98765432';

export function isValidCnIdCard(id: string): boolean {
  if (!/^\d{17}[\dXx]$/.test(id)) return false;
  const y = Number(id.slice(6, 10));
  const m = Number(id.slice(10, 12));
  const d = Number(id.slice(12, 14));
  const date = new Date(Date.UTC(y, m - 1, d));
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d) return false;
  if (y < 1900 || date.getTime() > Date.now()) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * (ID_WEIGHTS[i] as number);
  return ID_CHECK[sum % 11] === id[17]!.toUpperCase();
}

export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Major card networks: UnionPay 62/81, Visa 4, Mastercard 51-55/2221-2720, Amex 34/37, JCB 35, Discover 6011/65. */
function hasKnownBin(d: string): boolean {
  return /^(?:62|81|4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|35|6011|65)/.test(d);
}

const USCC_CHARS = '0123456789ABCDEFGHJKLMNPQRTUWXY';
const USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];

export function isValidUscc(code: string): boolean {
  if (!/^[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}$/.test(code)) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += USCC_CHARS.indexOf(code[i]!) * (USCC_WEIGHTS[i] as number);
  const check = (31 - (sum % 31)) % 31;
  return USCC_CHARS[check] === code[17];
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

const CARD_CONTEXT = /(?:卡号|银行卡|信用卡|借记卡|储蓄卡|card|visa|mastercard|unionpay|银联|账号|帐号)/i;

interface PiiPattern {
  type: PiiType;
  re: RegExp;
  check: (m: string, text: string, start: number) => false | { confidence: number; severity?: Severity };
}

const PATTERNS: PiiPattern[] = [
  {
    type: 'cn-id-card',
    re: /(?<![0-9A-Za-z])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9A-Za-z])/g,
    check: (m) => (isValidCnIdCard(m) ? { confidence: 0.95 } : false),
  },
  {
    type: 'bank-card',
    // 15–19 digits, optionally grouped by spaces or dashes
    re: /(?<![0-9])(?:\d[ -]?){14,18}\d(?![0-9])/g,
    check: (m, text, start) => {
      const d = m.replace(/[ -]/g, '');
      if (d.length < 15 || d.length > 19) return false;
      if (/^(\d)\1+$/.test(d)) return false;
      if (!hasKnownBin(d) || !luhn(d)) return false;
      // 18-digit strings that are valid ID cards are handled by the id-card pattern
      if (d.length === 18 && isValidCnIdCard(d)) return false;
      const window = text.slice(Math.max(0, start - 24), start);
      const grouped = /[ -]/.test(m);
      if (CARD_CONTEXT.test(window)) return { confidence: 0.9 };
      // Without context a bare digit run is often an order / snowflake id
      return grouped ? { confidence: 0.75 } : { confidence: 0.5, severity: 'medium' };
    },
  },
  {
    type: 'cn-mobile',
    re: /(?<![0-9])(?:(?:\+|00)?86[ -]?)?1[3-9]\d(?:[ -]?\d{4}){2}(?![0-9])/g,
    check: () => ({ confidence: 0.85 }),
  },
  {
    type: 'cn-uscc',
    re: /(?<![0-9A-Z])[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])/g,
    check: (m) => (isValidUscc(m) ? { confidence: 0.9 } : false),
  },
  {
    type: 'email',
    re: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![A-Za-z0-9-])/g,
    check: (m) => {
      const domain = m.split('@')[1]!.toLowerCase();
      if (/^(?:example\.(?:com|org|net)|test\.com|localhost)$/.test(domain)) return false;
      return { confidence: 0.95 };
    },
  },
  {
    type: 'ipv4',
    re: /(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])/g,
    check: (m) => {
      if (/^(?:0\.|127\.|255\.)/.test(m)) return false;
      return { confidence: 0.7 };
    },
  },
];

export function pii(options: PiiOptions = {}): SyncDetector {
  const include = new Set(options.include ?? DEFAULT_TYPES);
  const severity = { ...DEFAULT_SEVERITY, ...options.severity };
  const active = PATTERNS.filter((p) => include.has(p.type));

  return {
    id: 'pii',
    detect(text) {
      const out: RawFinding[] = [];
      for (const p of active) {
        p.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.re.exec(text)) !== null) {
          const res = p.check(m[0], text, m.index);
          if (!res) continue;
          out.push({
            ruleId: `pii.${p.type}`,
            category: 'pii',
            severity: res.severity ?? severity[p.type],
            confidence: res.confidence,
            start: m.index,
            end: m.index + m[0].length,
            description: DESCRIPTIONS[p.type],
          });
        }
      }
      return out;
    },
  };
}
