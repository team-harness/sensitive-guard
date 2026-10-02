import type { SecretRule } from '../detectors/secrets';
import {
  charClassCount,
  decodeBase64,
  hasLetterAndDigit,
  looksLikeCode,
  looksLikePathOrUrl,
  looksLikeVersion,
  shannonEntropy,
} from '../utils';

/**
 * Built-in secret rules. Patterns are adapted from gitleaks
 * (https://github.com/gitleaks/gitleaks, MIT) and secretlint (MIT),
 * plus providers common in China (Aliyun, Tencent Cloud, Volcengine,
 * DingTalk / Feishu / WeCom webhooks, OpenAI-compatible `sk-` keys).
 *
 * Conventions:
 * - `(?<![A-Za-z0-9_])` / `(?![A-Za-z0-9_])` are used instead of `\b` because
 *   many tokens contain `-` or `_`.
 * - `keywords` are lower-case substrings used as a cheap pre-filter.
 */

const B = String.raw`(?<![A-Za-z0-9_\-])`; // left boundary
const E = String.raw`(?![A-Za-z0-9_\-])`; // right boundary

/** Host part (text right after `@`) is a documentation domain: example.com / .org / .net / .test / .invalid */
function isExampleHost(afterAt: string): boolean {
  const host = (/^[^\s/:?#'"]+/.exec(afterAt)?.[0] ?? '').toLowerCase();
  return /(?:^|\.)example\.(?:com|org|net)$|\.(?:example|test|invalid)$/.test(host);
}

function re(source: string, flags = ''): RegExp {
  return new RegExp(source, flags);
}

// --- generic assignment rules ---------------------------------------------

/** Operators accepted between a key and its value: `=`, `:`, `:=`, `=>`, full-width colon. */
const ASSIGN = String.raw`["'\x60]?\s{0,4}(?:=|:=|:|=>|：)\s{0,4}`;
/** Value characters: stops at whitespace, quotes, separators, CJK and full-width punctuation. */
const VALUE_CHARS = String.raw`[^\s"'\x60,;<>，。；、！？\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]`;

/** Sentence / code punctuation that trails an unquoted value: `abc123.`, `NonSharedBuffer):` */
const TRIM_END = /[.,:)\]}]+$/;

const genericApiKey: SecretRule = {
  id: 'generic-api-key',
  description: 'Generic API key / token / secret assignment',
  regex: re(
    String.raw`(?<![A-Za-z0-9])(?:[A-Za-z0-9_.\-]{0,25}?)(?:api[_.\-]?key|apikey|secret[_.\-]?key|client[_.\-]?secret|app[_.\-]?secret|access[_.\-]?key(?:[_.\-]?(?:id|secret))?|access[_.\-]?token|auth[_.\-]?token|refresh[_.\-]?token|private[_.\-]?key|secret|token|credentials?)(?![a-z])[A-Za-z0-9_.\-]{0,15}` +
      ASSIGN +
      String.raw`(["'\x60]?)(${VALUE_CHARS}{12,256})`,
    'i',
  ),
  secretGroup: 2,
  trimEnd: TRIM_END,
  keywords: ['key', 'secret', 'token', 'credential'],
  entropy: 3.5,
  severity: 'high',
  confidence: 0.65,
  validate(value, ctx) {
    if (looksLikeCode(value, ctx) || looksLikePathOrUrl(value) || looksLikeVersion(value)) return false;
    if (/^\d+$/.test(value)) return false;
    // Random keys of this length virtually always contain a digit; identifiers and
    // constants (refresh_token_expiry_seconds, "?NonExpressionParenEnd") don't.
    if (!hasLetterAndDigit(value)) return false;
    return true;
  },
};

const genericPassword: SecretRule = {
  id: 'generic-password',
  description: 'Password / credential assignment (incl. 密码 / 口令 / 密钥)',
  regex: re(
    String.raw`(?:(?<![A-Za-z0-9])[A-Za-z0-9_.\-]{0,20}?(?:password|passwd|passphrase|pwd)(?![a-z])[A-Za-z0-9_.\-]{0,10}|密码|口令|密钥|秘钥|令牌|授权码)` +
      String.raw`(["'\x60]?\s{0,4}(?:=|:=|:|=>|：)\s{0,4}|\s+(?:is|was)\s+|\s{0,2}(?:就)?(?:是|为)\s{0,2})` +
      String.raw`(["'\x60]?)(${VALUE_CHARS}{6,128})`,
    'i',
  ),
  secretGroup: 3,
  trimEnd: TRIM_END,
  keywords: ['pass', 'pwd', '密码', '口令', '密钥', '秘钥', '令牌', '授权码'],
  severity: 'high',
  confidence: 0.7,
  validate(value, ctx) {
    if (looksLikeCode(value, ctx) || looksLikePathOrUrl(value) || looksLikeVersion(value)) return false;
    const op = ctx.match[1] ?? '';
    const naturalLanguage = !/[=:：]/.test(op);
    const classes = charClassCount(value);
    if (naturalLanguage) {
      // "the password is incorrect" vs "the password is Hunter2!"
      if (classes < 2) return false;
      return { confidence: 0.6 };
    }
    if (classes < 2 && shannonEntropy(value) < 2.5) return false;
    return true;
  },
};

// --- specific provider rules ----------------------------------------------

export const BUILTIN_SECRET_RULES: SecretRule[] = [
  {
    id: 'private-key',
    description: 'Private key block (RSA / EC / DSA / OpenSSH / PGP / PKCS#8)',
    // Matches up to the END marker, or to end of text if the paste was truncated.
    regex: re(
      String.raw`-----BEGIN[ A-Z0-9_\-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END[ A-Z0-9_\-]{0,100}PRIVATE KEY(?: BLOCK)?-----|$)`,
    ),
    keywords: ['private key'],
    severity: 'critical',
    confidence: 0.95,
    skipPlaceholderCheck: true,
    validate(block) {
      const body = block
        .replace(/-----(?:BEGIN|END)[^-]*-----/g, '')
        .replace(/^[A-Za-z-]+:.*$/gm, '') // PEM headers like Proc-Type
        .replace(/\\n|\s/g, '');
      if (body.length < 40) return { severity: 'high', confidence: 0.6 };
      return true;
    },
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS access key ID',
    regex: re(String.raw`(?<![A-Z0-9])((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})(?![A-Z0-9])`),
    secretGroup: 1,
    keywords: ['akia', 'asia', 'abia', 'acca', 'a3t'],
    entropy: 3.0,
    severity: 'high',
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS secret access key',
    regex: re(
      String.raw`(?:aws|amazon)[\w.\-]{0,20}(?:secret|private)[\w.\-]{0,20}["']?\s{0,5}(?:=|:|=>)\s{0,5}["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])`,
      'i',
    ),
    secretGroup: 1,
    keywords: ['aws', 'amazon'],
    entropy: 4.0,
    severity: 'critical',
  },
  {
    id: 'github-token',
    description: 'GitHub token (PAT, OAuth, App, refresh, fine-grained PAT)',
    regex: re(`${B}(gh[pousr]_[0-9A-Za-z]{36,76}|github_pat_[0-9A-Za-z_]{82})${E}`),
    secretGroup: 1,
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'],
    entropy: 3.0,
    severity: 'critical',
    confidence: 0.98,
  },
  {
    id: 'gitlab-token',
    description: 'GitLab token (PAT, pipeline trigger, deploy, runner, feed)',
    regex: re(`${B}(gl(?:pat|ptt|dt|rt|soat|ft|cbt|imt)-[0-9A-Za-z_\\-]{20,})${E}`),
    secretGroup: 1,
    keywords: ['glpat-', 'glptt-', 'gldt-', 'glrt-', 'glsoat-', 'glft-', 'glcbt-', 'glimt-'],
    entropy: 3.0,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    regex: re(`${B}(xox[abposre]-[0-9A-Za-z\\-]{20,})${E}`),
    secretGroup: 1,
    keywords: ['xox'],
    entropy: 3.0,
    severity: 'critical',
  },
  {
    id: 'slack-webhook',
    description: 'Slack incoming webhook URL',
    regex: re(String.raw`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/+\-]{20,}`),
    keywords: ['hooks.slack.com'],
    severity: 'high',
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API key',
    regex: re(`${B}(sk-ant-(?:api|admin|oat|ort)\\d{2}-[A-Za-z0-9_\\-]{80,})${E}`),
    secretGroup: 1,
    keywords: ['sk-ant-'],
    severity: 'critical',
    confidence: 0.98,
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI API key (project / service account / admin / legacy)',
    regex: re(
      `${B}(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\\-]{20,}T3BlbkFJ[A-Za-z0-9_\\-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\\-]{40,})${E}`,
    ),
    secretGroup: 1,
    keywords: ['sk-'],
    entropy: 3.5,
    severity: 'critical',
    confidence: 0.97,
  },
  {
    id: 'sk-api-key',
    description: 'OpenAI-compatible `sk-` API key (DeepSeek, Moonshot/Kimi, DashScope/Qwen, SiliconFlow, legacy OpenAI, …)',
    regex: re(`${B}(sk-[A-Za-z0-9]{32,64})${E}`),
    secretGroup: 1,
    keywords: ['sk-'],
    entropy: 3.5,
    severity: 'critical',
    confidence: 0.85,
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    regex: re(`${B}(AIza[0-9A-Za-z_\\-]{35})${E}`),
    secretGroup: 1,
    keywords: ['aiza'],
    entropy: 3.0,
    severity: 'high',
  },
  {
    id: 'stripe-key',
    description: 'Stripe secret / restricted key',
    regex: re(`${B}((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99})${E}`),
    secretGroup: 1,
    keywords: ['sk_live', 'sk_test', 'rk_live', 'rk_test'],
    entropy: 3.0,
    severity: 'critical',
    validate: (s) => (s.includes('_test_') ? { severity: 'medium' } : true),
  },
  {
    id: 'npm-token',
    description: 'npm access token',
    regex: re(`${B}(npm_[A-Za-z0-9]{36})${E}`),
    secretGroup: 1,
    keywords: ['npm_'],
    entropy: 3.0,
    severity: 'critical',
  },
  {
    id: 'pypi-token',
    description: 'PyPI upload token',
    regex: re(`${B}(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\\-]{50,})${E}`),
    secretGroup: 1,
    keywords: ['pypi-ageichlwas5vcmc'],
    severity: 'critical',
  },
  {
    id: 'huggingface-token',
    description: 'Hugging Face access token',
    regex: re(`${B}(hf_[A-Za-z]{34})${E}`),
    secretGroup: 1,
    keywords: ['hf_'],
    entropy: 3.0,
    severity: 'high',
  },
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API key',
    regex: re(`${B}(SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43})${E}`),
    secretGroup: 1,
    keywords: ['sg.'],
    severity: 'high',
  },
  {
    id: 'shopify-token',
    description: 'Shopify access token',
    regex: re(`${B}(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})${E}`),
    secretGroup: 1,
    keywords: ['shpat_', 'shpca_', 'shppa_', 'shpss_'],
    severity: 'high',
  },
  {
    id: 'telegram-bot-token',
    description: 'Telegram bot token',
    regex: re(String.raw`(?<![0-9])(\d{8,10}:AA[0-9A-Za-z_\-]{33})(?![0-9A-Za-z_\-])`),
    secretGroup: 1,
    keywords: [':aa'],
    severity: 'high',
  },
  {
    id: 'discord-webhook',
    description: 'Discord webhook URL',
    regex: re(String.raw`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,}`),
    keywords: ['discord'],
    severity: 'high',
  },
  {
    id: 'azure-storage-key',
    description: 'Azure storage account key',
    regex: re(String.raw`AccountKey=([A-Za-z0-9+/]{86}==)`, 'i'),
    secretGroup: 1,
    keywords: ['accountkey='],
    severity: 'critical',
  },
  // --- China cloud / IM providers ---
  {
    id: 'alibaba-access-key-id',
    description: 'Alibaba Cloud (Aliyun) AccessKey ID',
    regex: re(String.raw`(?<![A-Za-z0-9])(LTAI[A-Za-z0-9]{12,20})(?![A-Za-z0-9])`),
    secretGroup: 1,
    keywords: ['ltai'],
    entropy: 3.0,
    severity: 'high',
  },
  {
    id: 'alibaba-access-key-secret',
    description: 'Alibaba Cloud (Aliyun) AccessKey Secret',
    regex: re(
      String.raw`(?:ali(?:baba|yun|cloud)?[\w.\-]{0,20}secret|access[_\-]?key[_\-]?secret)[\w.\-]{0,10}["']?\s{0,5}(?:=|:|=>)\s{0,5}["']?([A-Za-z0-9]{30})(?![A-Za-z0-9])`,
      'i',
    ),
    secretGroup: 1,
    keywords: ['ali', 'accesskeysecret', 'access_key_secret', 'access-key-secret'],
    entropy: 3.5,
    severity: 'critical',
  },
  {
    id: 'tencent-secret-id',
    description: 'Tencent Cloud SecretId',
    regex: re(String.raw`(?<![A-Za-z0-9])(AKID[A-Za-z0-9]{28,36})(?![A-Za-z0-9])`),
    secretGroup: 1,
    keywords: ['akid'],
    entropy: 3.0,
    severity: 'high',
  },
  {
    id: 'volcengine-access-key',
    description: 'Volcengine (ByteDance) Access Key ID',
    regex: re(String.raw`(?<![A-Za-z0-9])(AKLT[A-Za-z0-9_\-]{30,60})(?![A-Za-z0-9_\-])`),
    secretGroup: 1,
    keywords: ['aklt'],
    entropy: 3.0,
    severity: 'high',
    confidence: 0.85,
  },
  {
    id: 'dingtalk-webhook',
    description: 'DingTalk robot webhook access token',
    regex: re(String.raw`oapi\.dingtalk\.com/robot/send\?access_token=([a-f0-9]{64})`),
    secretGroup: 1,
    keywords: ['dingtalk'],
    severity: 'high',
  },
  {
    id: 'feishu-webhook',
    description: 'Feishu / Lark bot webhook',
    regex: re(String.raw`open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook/([0-9a-f\-]{36})`),
    secretGroup: 1,
    keywords: ['open-apis/bot'],
    severity: 'high',
  },
  {
    id: 'wecom-webhook',
    description: 'WeCom (企业微信) robot webhook key',
    regex: re(String.raw`qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=([0-9a-f\-]{36})`),
    secretGroup: 1,
    keywords: ['qyapi.weixin'],
    severity: 'high',
  },
  // --- structural credentials ---
  {
    id: 'jwt',
    description: 'JSON Web Token',
    regex: re(`${B}(eyJ[A-Za-z0-9_\\-]{10,}\\.eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,})${E}`),
    secretGroup: 1,
    keywords: ['eyj'],
    severity: 'high',
    confidence: 0.9,
    validate(token) {
      const header = decodeBase64(token.split('.')[0] ?? '');
      try {
        const parsed = header ? (JSON.parse(header) as Record<string, unknown>) : null;
        if (parsed && typeof parsed === 'object' && 'alg' in parsed) return true;
      } catch {
        /* fall through */
      }
      return { confidence: 0.6 };
    },
  },
  {
    id: 'connection-string-password',
    description: 'Password embedded in a database / broker connection string',
    regex: re(
      String.raw`(?<![A-Za-z0-9])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|oracle|jdbc:[a-z]+)://[^\s:/@'"]+:([^\s@/'"]+)@[^\s'"/]+`,
      'i',
    ),
    secretGroup: 1,
    keywords: ['://'],
    severity: 'critical',
    confidence: 0.9,
    validate: (_password, ctx) => !isExampleHost(ctx.text.slice(ctx.end + 1)),
  },
  {
    id: 'url-credentials',
    description: 'Credentials embedded in a URL (user:password@host)',
    regex: re(String.raw`(?<![A-Za-z0-9])(?:https?|ftps?|sftp|ssh|git|smtps?|ldaps?)://[^\s:/@'"]+:([^\s@/'"]+)@[^\s'"/]+`, 'i'),
    secretGroup: 1,
    keywords: ['://'],
    severity: 'high',
    confidence: 0.8,
    validate: (password, ctx) => password.length >= 3 && !isExampleHost(ctx.text.slice(ctx.end + 1)),
  },
  {
    id: 'bearer-token',
    description: 'Bearer token in an Authorization header',
    regex: re(String.raw`\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)`, 'i'),
    secretGroup: 1,
    keywords: ['bearer'],
    entropy: 3.5,
    severity: 'high',
    confidence: 0.8,
  },
  {
    id: 'basic-auth-header',
    description: 'HTTP Basic auth credentials',
    regex: re(String.raw`authorization["']?\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/]{8,}={0,2})`, 'i'),
    secretGroup: 1,
    keywords: ['basic'],
    severity: 'high',
    validate(b64) {
      const decoded = decodeBase64(b64);
      return decoded !== null && decoded.includes(':') ? true : { confidence: 0.5 };
    },
  },
  genericPassword,
  genericApiKey,
];
