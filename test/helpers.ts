/**
 * Fake credential generators. Tokens are built at runtime from a seeded PRNG
 * so this repository never contains literal secrets (which would also trip
 * GitHub push protection).
 */

let seed = 0x9e3779b9;
export function rand(): number {
  // mulberry32
  seed = (seed + 0x6d2b79f5) | 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

export const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const UPPER_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const B64 = `${ALNUM}+/`;
export const B64URL = `${ALNUM}-_`;
export const HEX = '0123456789abcdef';
export const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export function randStr(n: number, alphabet = ALNUM): string {
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rand() * alphabet.length)];
  return s;
}

const p = (...parts: string[]) => parts.join('');

export const fake = {
  githubPat: () => p('gh', 'p_', randStr(36)),
  githubFineGrained: () => p('github', '_pat_', randStr(82, `${ALNUM}_`)),
  gitlabPat: () => p('gl', 'pat-', randStr(20)),
  awsKeyId: () => p('AK', 'IA', randStr(16, UPPER_B32)),
  awsSecret: () => randStr(40, B64),
  openaiProject: () => p('sk-', 'proj-', randStr(100, B64URL)),
  skKey: () => p('sk', '-', randStr(48)),
  anthropic: () => p('sk-', 'ant-', 'api03-', randStr(93, B64URL), 'AA'),
  googleApiKey: () => p('AI', 'za', randStr(35, B64URL)),
  stripeLive: () => p('sk', '_live_', randStr(32)),
  stripeTest: () => p('sk', '_test_', randStr(32)),
  npmToken: () => p('np', 'm_', randStr(36)),
  slackBot: () => p('xo', 'xb-', randStr(12, '0123456789'), '-', randStr(12, '0123456789'), '-', randStr(24)),
  aliyunId: () => p('LT', 'AI', randStr(20)),
  tencentId: () => p('AK', 'ID', randStr(32)),
  dingtalkUrl: () => p('https://oapi.dingtalk.com/robot/send?access', '_token=', randStr(64, HEX)),
  feishuUrl: () =>
    p(
      'https://open.feishu.cn/open-apis/bot/v2/hook/',
      randStr(8, HEX), '-', randStr(4, HEX), '-', randStr(4, HEX), '-', randStr(4, HEX), '-', randStr(12, HEX),
    ),
  jwt: () => {
    const b64url = (s: string) => Buffer.from(s).toString('base64url');
    return [b64url('{"alg":"HS256","typ":"JWT"}'), b64url(`{"sub":"${randStr(10)}","iat":1700000000}`), randStr(43, B64URL)].join('.');
  },
  privateKey: (lines = 6) =>
    [p('-----BEGIN RSA ', 'PRIVATE KEY-----'), ...Array.from({ length: lines }, () => randStr(64, B64)), p('-----END RSA ', 'PRIVATE KEY-----')].join(
      '\n',
    ),
  generic32: () => randStr(32),
};

// --- PII generators -------------------------------------------------------

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
export function cnId(prefix17: string): string {
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(prefix17[i]) * ID_WEIGHTS[i]!;
  return prefix17 + '10X98765432'[sum % 11];
}

export function luhnComplete(partial: string): string {
  for (let d = 0; d <= 9; d++) {
    const s = partial + d;
    let sum = 0;
    let dbl = false;
    for (let i = s.length - 1; i >= 0; i--) {
      let n = Number(s[i]);
      if (dbl) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      dbl = !dbl;
    }
    if (sum % 10 === 0) return s;
  }
  throw new Error('unreachable');
}

const USCC_CHARS = '0123456789ABCDEFGHJKLMNPQRTUWXY';
const USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];
export function uscc(prefix17: string): string {
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += USCC_CHARS.indexOf(prefix17[i]!) * USCC_WEIGHTS[i]!;
  return prefix17 + USCC_CHARS[(31 - (sum % 31)) % 31];
}
