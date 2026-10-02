# sensitive-guard

检测并脱敏用户消息中的敏感内容：**密钥 / 凭证**、**个人信息（中国 PII）**、**自定义敏感词**。

- 核心零运行时依赖，Node ≥ 18 和浏览器都能用，ESM + CJS 双产物
- 密钥检测参考 [gitleaks](https://github.com/gitleaks/gitleaks) 的算法：关键词预过滤 → 正则捕获组 → Shannon 熵阈值 → 占位符 / 示例值过滤 → 结构校验
- 内置 34 条密钥规则，覆盖 GitHub、OpenAI、Anthropic、AWS 等，也覆盖国内常用的阿里云、腾讯云、火山引擎、DeepSeek/Kimi/通义 `sk-` key，以及钉钉、飞书、企业微信 webhook
- PII 检测都带校验：身份证（校验位 + 出生日期）、银行卡（Luhn + BIN + 上下文）、统一社会信用代码（校验位）、手机号、邮箱
- 敏感词用 Aho–Corasick 自动机匹配，自带归一化（全角、大小写、`敏 感 词` / `敏*感*词` / 零宽字符），结果能准确映射回原文位置
- 可选接入 [secretlint](https://github.com/secretlint/secretlint)，作为异步的第二道深度扫描
- **Finding 默认不包含原文**，只给位置和打码后的预览，记日志也不会泄露密钥

```bash
npm i @team-harness/sensitive-guard
```

## 快速开始

```ts
import { createScanner } from '@team-harness/sensitive-guard';

const scanner = createScanner(); // 默认检测器：secrets() + pii()

const findings = scanner.scanSync('DATABASE_URL=postgres://admin:S3cr3t-P4ss@db:5432/app，手机 13812345678');
// [
//   { ruleId: 'secret.connection-string-password', category: 'secret', severity: 'critical',
//     confidence: 0.9, start: 30, end: 41, preview: 'S…s', detector: 'secrets', ... },
//   { ruleId: 'pii.cn-mobile', category: 'pii', severity: 'medium', ... }
// ]

const { text } = scanner.redactSync('DATABASE_URL=postgres://admin:S3cr3t-P4ss@db:5432/app');
// 'DATABASE_URL=postgres://admin:[REDACTED:secret.connection-string-password]@db:5432/app'
```

## 组合检测器

```ts
import { createScanner, secrets, pii, keywords, regexDetector, masks } from '@team-harness/sensitive-guard';
import { secretlint } from '@team-harness/sensitive-guard/secretlint';

const scanner = createScanner({
  detectors: [
    secrets(),                                     // 同步，微秒到毫秒级
    pii({ include: ['cn-id-card', 'cn-mobile', 'bank-card'] }),
    keywords({
      lists: [
        { label: 'internal', words: ['Project Phoenix', '内部代号'], severity: 'high' },
        { label: 'abuse', words: loadWordList(), severity: 'medium' },
      ],
      exceptions: ['assassin'],                    // 覆盖命中的白名单词
      charMap: traditionalToSimplified,            // 可选：繁→简、形近字映射
    }),
    regexDetector('corp', [
      { id: 'corp.employee-id', pattern: /\bEMP-\d{6}\b/, severity: 'medium' },
    ]),
    secretlint(),                                  // 异步，只在 scan()/redact() 中运行
  ],
  minSeverity: 'medium',
  minConfidence: 0.6,
  allowlist: ['ci-bot@corp.cn', /^sk-test-/],
  disableRules: ['pii.email', 'keyword.*'],        // 支持尾部 * 通配
});

// 发送前的同步快路径（跳过异步检测器）
if (scanner.hasSensitiveSync(message, 'high')) warnUser();

// 入库前的完整扫描 + 脱敏
const { text, findings } = await scanner.redact(message, { mask: masks.partial(4, 4) });
```

### 脱敏方式

| masker | 效果 |
|---|---|
| `masks.label`（默认） | `[REDACTED:secret.github-token]` |
| `masks.plain` | `[REDACTED]` |
| `masks.char('*')` | 等长 `****` |
| `masks.partial(4, 4)` | `ghp_****…****Q2xY` |
| 自定义 `(finding, original) => string` | 任意 |

## Finding 结构

```ts
interface Finding {
  ruleId: string;        // 'secret.github-token' | 'pii.cn-id-card' | 'keyword.<label>' | ...
  detector: string;      // 'secrets' | 'pii' | 'keywords' | 'secretlint' | 自定义 id
  category: 'secret' | 'pii' | 'keyword' | 'custom';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;    // 0..1
  start: number;         // 原文中的 UTF-16 偏移，[start, end)
  end: number;
  preview: string;       // 打码后的预览，可以安全写日志
  description?: string;
  tag?: string;          // 关键词表的 label
  match?: string;        // 只有在 createScanner({ includeMatch: true }) 时才有
}
```

多个检测器命中重叠区间时，默认保留最强的一条（比较顺序：severity → confidence → 区间长度）。比如 `OPENAI_API_KEY=sk-...` 只会报 `secret.sk-api-key`，不会再额外报一条 generic。如果需要保留全部结果，设置 `dedupe: false`。

## 密钥检测

### 算法

每条规则（`SecretRule`）依次经过：

1. **关键词预过滤**：规则的 `keywords` 都不出现在消息中时直接跳过，大部分消息只会跑少数几条规则
2. **正则 + `secretGroup`**：用捕获组精确定位密钥本身。例如连接串只标出密码部分，脱敏后连接串的其余部分仍然可读
3. **熵阈值**：密钥的 Shannon 熵（bits/char）低于 `entropy` 的丢弃。`password` ≈ 2.75，40 位随机串 ≈ 4.5+
4. **占位符 / 示例值过滤**：`${TOKEN}`、`<your-key>`、`process.env.X`、`xxxx`、`****`、`changeme`、`AKIAIOSFODNN7EXAMPLE` 等都会被丢弃
5. **结构校验（`validate`）**：比如 JWT header 能解码出 `alg`、Basic auth 解码后含 `:`、通用赋值规则排除代码（`req.body.password`、`getToken()`、`password: string`）、版本号、路径

通用规则（`generic-password` / `generic-api-key`）支持中文写法：`密码是 abc12345`、`服务器密码：Qw3rty!@#`、`my password is Hunter2!`。

### 内置规则

| ruleId | 说明 | 默认 severity |
|---|---|---|
| `secret.private-key` | 私钥块（RSA / EC / DSA / OpenSSH / PGP / PKCS#8），粘贴被截断也能识别 | critical |
| `secret.aws-access-key-id` | AWS access key ID | high |
| `secret.aws-secret-access-key` | AWS secret access key | critical |
| `secret.github-token` | GitHub token（PAT、OAuth、App、refresh、fine-grained PAT） | critical |
| `secret.gitlab-token` | GitLab token（PAT、pipeline trigger、deploy、runner、feed） | critical |
| `secret.slack-token` | Slack token | critical |
| `secret.slack-webhook` | Slack incoming webhook URL | high |
| `secret.anthropic-api-key` | Anthropic API key | critical |
| `secret.openai-api-key` | OpenAI API key（project / service account / admin / legacy） | critical |
| `secret.sk-api-key` | OpenAI 兼容的 `sk-` key（DeepSeek、Moonshot/Kimi、DashScope/通义、SiliconFlow、旧版 OpenAI 等） | critical |
| `secret.google-api-key` | Google API key | high |
| `secret.stripe-key` | Stripe secret / restricted key（test key 降为 medium） | critical |
| `secret.npm-token` | npm access token | critical |
| `secret.pypi-token` | PyPI upload token | critical |
| `secret.huggingface-token` | Hugging Face access token | high |
| `secret.sendgrid-api-key` | SendGrid API key | high |
| `secret.shopify-token` | Shopify access token | high |
| `secret.telegram-bot-token` | Telegram bot token | high |
| `secret.discord-webhook` | Discord webhook URL | high |
| `secret.azure-storage-key` | Azure storage account key | critical |
| `secret.alibaba-access-key-id` | 阿里云 AccessKey ID | high |
| `secret.alibaba-access-key-secret` | 阿里云 AccessKey Secret | critical |
| `secret.tencent-secret-id` | 腾讯云 SecretId | high |
| `secret.volcengine-access-key` | 火山引擎 Access Key ID | high |
| `secret.dingtalk-webhook` | 钉钉机器人 webhook access_token | high |
| `secret.feishu-webhook` | 飞书 / Lark 机器人 webhook | high |
| `secret.wecom-webhook` | 企业微信机器人 webhook key | high |
| `secret.jwt` | JSON Web Token | high |
| `secret.connection-string-password` | 数据库 / 消息队列连接串中的密码 | critical |
| `secret.url-credentials` | URL 中的 `user:password@host` | high |
| `secret.bearer-token` | Authorization: Bearer | high |
| `secret.basic-auth-header` | Authorization: Basic | high |
| `secret.generic-password` | 密码赋值（含 密码 / 口令 / 密钥 / 令牌） | high |
| `secret.generic-api-key` | 通用 api_key / token / secret 赋值 | high |

### 自定义规则

```ts
secrets({
  disable: ['jwt'],                    // 关闭内置规则
  allowlist: ['sk-known-public-demo'], // 永不上报的值
  ignoreExamples: true,                // 默认 true：忽略 EXAMPLE / sample / dummy 等示例值
  extraRules: [
    {
      id: 'acme-token',
      description: 'ACME internal token',
      regex: /(?<![A-Za-z0-9_])(acme_[a-z0-9]{32})(?![A-Za-z0-9_])/,
      secretGroup: 1,
      keywords: ['acme_'],
      entropy: 3.5,
      severity: 'critical',
      validate: (secret, ctx) => true, // 可返回 false 或 { severity, confidence }
    },
  ],
});
```

### 接入 secretlint（可选）

secretlint 的规则维护得更全，但扫一条消息约需 10–30ms，而且是异步的。适合放在入库前做第二道扫描。

```bash
npm i @secretlint/core @secretlint/secretlint-rule-preset-recommend
```

```ts
import { secretlint } from '@team-harness/sensitive-guard/secretlint';
createScanner({ detectors: [secrets(), pii(), secretlint()] }); // 和内置规则的重叠结果会自动去重
```

## PII 检测

| ruleId | 校验方式 | 默认 severity |
|---|---|---|
| `pii.cn-id-card` | GB 11643 校验位 + 合法出生日期（大小写 x 均可） | high |
| `pii.bank-card` | Luhn + 卡组织 BIN；附近有"卡号 / 银行卡 / card"等上下文时置信度 0.9，否则视为可能是订单号 / 雪花 ID，降为 medium、置信度 0.5 | high |
| `pii.cn-mobile` | 1[3-9] 号段，支持 `+86`、空格和短横线分隔 | medium |
| `pii.cn-uscc` | 统一社会信用代码，GB 32100 校验位 | low |
| `pii.email` | 语法校验，排除 example.com 等示例域名 | low |
| `pii.ipv4` | 需要通过 `include` 显式开启 | low |

```ts
pii({ include: ['cn-id-card', 'bank-card'], severity: { 'cn-mobile': 'high' } });
```

## 敏感词

本包**不附带词表**：什么算敏感取决于业务和所在法域，需要你自己提供。匹配前会做归一化：

- NFKC：全角转半角、兼容字符（`ＡＢＣ` → `abc`）
- 转小写
- 去掉噪声字符：空白、零宽字符、ASCII 和中文标点。所以 `敏 感 词`、`敏*感*词`、`f.u.c.k` 都能命中
- `charMap`：单字符替换表，可以接 opencc 生成的繁→简表，或者形近字表

纯 ASCII 的词默认要求在原文中是独立单词，`ass` 不会命中 `class`。可以用 `asciiWordBoundary: false` 关闭。

## 性能

在 23MB 的真实代码语料（node_modules）上，同步检测器（secrets + pii）吞吐约 **11 MB/s**。在同一份语料上，密钥规则只命中了 1 条，是 secretlint 测试夹具里一个格式真实的 1Password Secret Key。

所有正则都是有界量词，测试中包含针对灾难性回溯的对抗输入。

## 开发

```bash
npm install
npm test          # vitest
npm run typecheck
npm run build     # tsup → dist/ (ESM + CJS + d.ts)
```

测试里的所有假凭证都在运行时用带种子的伪随机数拼接生成（见 `test/helpers.ts`），仓库中不存在任何字面量密钥。

## 致谢

部分密钥规则的正则改编自 [gitleaks](https://github.com/gitleaks/gitleaks)（MIT）和 [secretlint](https://github.com/secretlint/secretlint)（MIT）。

## License

MIT
