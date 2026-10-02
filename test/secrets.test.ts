import { describe, expect, it } from 'vitest';
import { createScanner, secrets, shannonEntropy } from '../src';
import { fake, randStr } from './helpers';

const scanner = createScanner({ detectors: [secrets()] });
const ruleIds = (text: string) => scanner.scanSync(text).map((f) => f.ruleId);
const only = (text: string) => {
  const f = scanner.scanSync(text);
  expect(f, `findings for: ${text}`).toHaveLength(1);
  return f[0]!;
};

describe('provider-specific secrets', () => {
  const cases: Array<[string, () => string, string]> = [
    ['GitHub PAT', fake.githubPat, 'secret.github-token'],
    ['GitHub fine-grained PAT', fake.githubFineGrained, 'secret.github-token'],
    ['GitLab PAT', fake.gitlabPat, 'secret.gitlab-token'],
    ['AWS access key id', fake.awsKeyId, 'secret.aws-access-key-id'],
    ['OpenAI project key', fake.openaiProject, 'secret.openai-api-key'],
    ['sk- style key (DeepSeek/Moonshot/…)', fake.skKey, 'secret.sk-api-key'],
    ['Anthropic key', fake.anthropic, 'secret.anthropic-api-key'],
    ['Google API key', fake.googleApiKey, 'secret.google-api-key'],
    ['Stripe live key', fake.stripeLive, 'secret.stripe-key'],
    ['npm token', fake.npmToken, 'secret.npm-token'],
    ['Slack bot token', fake.slackBot, 'secret.slack-token'],
    ['Aliyun AccessKey ID', fake.aliyunId, 'secret.alibaba-access-key-id'],
    ['Tencent SecretId', fake.tencentId, 'secret.tencent-secret-id'],
    ['JWT', fake.jwt, 'secret.jwt'],
  ];

  for (const [name, gen, id] of cases) {
    it(`detects ${name} with exact offsets`, () => {
      const token = gen();
      const text = `帮我看看为什么请求失败了，我用的 key 是 ${token} ，谢谢`;
      const f = only(text);
      expect(f.ruleId).toBe(id);
      expect(text.slice(f.start, f.end)).toBe(token);
      expect(f.category).toBe('secret');
    });
  }

  it('reports only the secret part of webhooks', () => {
    const url = fake.dingtalkUrl();
    const f = only(`告警机器人: ${url}`);
    expect(f.ruleId).toBe('secret.dingtalk-webhook');
    expect(f.end - f.start).toBe(64);
    expect(url.endsWith(`告警机器人: ${url}`.slice(f.start, f.end))).toBe(true);

    const feishu = fake.feishuUrl();
    expect(only(`hook=${feishu}`).ruleId).toBe('secret.feishu-webhook');
  });

  it('downgrades Stripe test keys', () => {
    expect(only(`STRIPE_KEY=${fake.stripeTest()}`).severity).toBe('medium');
  });

  it('detects AWS secret access key with context', () => {
    const secret = fake.awsSecret();
    const f = scanner.scanSync(`aws_secret_access_key = ${secret}`).find((x) => x.ruleId === 'secret.aws-secret-access-key');
    expect(f?.severity).toBe('critical');
  });

  it('detects a full private key block and a truncated one', () => {
    const key = fake.privateKey();
    const f = only(`这是我的 key:\n${key}\n怎么用？`);
    expect(f.ruleId).toBe('secret.private-key');
    expect(f.severity).toBe('critical');

    const truncated = key.split('\n').slice(0, 3).join('\n');
    const t = only(`pasted: ${truncated}`);
    expect(t.ruleId).toBe('secret.private-key');
    expect(t.end).toBe(`pasted: ${truncated}`.length);

    const headerOnly = only('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(headerOnly.severity).toBe('high');
    expect(headerOnly.confidence).toBeLessThan(0.7);
  });

  it('isolates the password inside connection strings', () => {
    const text = 'DATABASE_URL=postgres://admin:S3cr3t-P4ss@db.internal:5432/app';
    const f = only(text);
    expect(f.ruleId).toBe('secret.connection-string-password');
    expect(text.slice(f.start, f.end)).toBe('S3cr3t-P4ss');

    const mongo = 'mongodb+srv://svc:Xk29_pq!z@cluster0.abcde.mongodb.net/db';
    expect(scanner.scanSync(mongo).map((x) => mongo.slice(x.start, x.end))).toEqual(['Xk29_pq!z']);
  });

  it('detects bearer and basic auth headers', () => {
    const tok = randStr(40);
    expect(ruleIds(`curl -H "Authorization: Bearer ${tok}" https://api.x.com`)).toEqual(['secret.bearer-token']);
    const basic = Buffer.from('admin:hunter2pass').toString('base64');
    expect(ruleIds(`Authorization: Basic ${basic}`)).toEqual(['secret.basic-auth-header']);
  });

  it('prefers the specific rule when a generic rule overlaps', () => {
    const key = fake.skKey();
    expect(ruleIds(`OPENAI_API_KEY=${key}`)).toEqual(['secret.sk-api-key']);
    const jwt = fake.jwt();
    expect(ruleIds(`Authorization: Bearer ${jwt}`)).toEqual(['secret.jwt']);
  });
});

describe('generic assignments', () => {
  it.each([
    ['DB_PASSWORD=Sup3rS3cret!', 'Sup3rS3cret!'],
    ['"password": "correct-horse-42"', 'correct-horse-42'],
    ['密码是 abc12345', 'abc12345'],
    ['服务器密码：Qw3rty!@#2024', 'Qw3rty!@#2024'],
    ['my password is Hunter2!', 'Hunter2!'],
    ['The admin password is Abc12345.', 'Abc12345'],
  ])('password: %s', (text, expected) => {
    const f = only(text);
    expect(f.ruleId).toBe('secret.generic-password');
    expect(text.slice(f.start, f.end)).toBe(expected);
  });

  it('generic api key / token / secret', () => {
    const v = fake.generic32();
    for (const text of [`api_key: "${v}"`, `const clientSecret = '${v}'`, `X_AUTH_TOKEN=${v}`, `"app_secret": "${v}"`]) {
      const f = only(text);
      expect(f.ruleId, text).toBe('secret.generic-api-key');
      expect(text.slice(f.start, f.end)).toBe(v);
    }
  });
});

describe('false positives that must NOT be reported', () => {
  it.each([
    'password: string;',
    'password = req.body.password',
    'const pwd = getPassword()',
    'password: Password',
    'the password is incorrect',
    '密码是正确的',
    'password: ********',
    'password=${DB_PASSWORD}',
    'api_key: <your-api-key>',
    'OPENAI_API_KEY=sk-your-key-here',
    'token: process.env.GITHUB_TOKEN',
    'max_tokens: 4096',
    'tokenizer: bert-base-uncased-v2-123',
    'refresh_token_expiry_seconds: 3600',
    'secret_name: my_app_secret_name',
    'AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'commit 3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a',
    'request_id: 550e8400-e29b-41d4-a716-446655440000',
    'see https://github.com/team-harness/sensitive-guard for details',
    'postgres://user:${PGPASSWORD}@localhost/db',
    'author: John Smith',
    'secretary: Alice',
    'pwd: /home/claude/project',
    // found by scanning node_modules
    'generateKeyPair(cb: (err: Error | null, publicKey: string, privateKey: NonSharedBuffer) => void)',
    'const password = result.groups?.password;',
    'const token = this.tokens[0]!.value;',
    '"@secretlint/secretlint-rule-1password": "13.0.6",',
    '"secret-handshake": "^2.10.4"',
    "const options = new URL('https://abc:xyz@example.com');",
    'https://a:b@host.internal/path',
    'GCP_SERVICE_ACCOUNT_P12_PASSWORD = "notasecret"',
    'setPrivateKey(privateKey: NodeJS.ArrayBufferView): void;',
    'nextLastSignificantToken = "?NonExpressionParenEnd";',
    '* object.passphrase is optional. Encrypted keys will be decrypted',
  ])('%s', (text) => {
    expect(scanner.scanSync(text)).toEqual([]);
  });
});

describe('options', () => {
  it('disable / extraRules / allowlist', () => {
    const tok = fake.githubPat();
    expect(createScanner({ detectors: [secrets({ disable: ['github-token'] })] }).scanSync(tok)).toEqual([]);
    expect(createScanner({ detectors: [secrets({ allowlist: [tok] })] }).scanSync(tok)).toEqual([]);

    const custom = createScanner({
      detectors: [
        secrets({
          rules: [],
          extraRules: [{ id: 'internal-token', description: 'ACME token', regex: /acme_[a-z0-9]{24}/, keywords: ['acme_'], entropy: 3 }],
        }),
      ],
    });
    const v = `acme_${randStr(24, 'abcdefghijklmnopqrstuvwxyz0123456789')}`;
    expect(custom.scanSync(`token ${v}`).map((f) => f.ruleId)).toEqual(['secret.internal-token']);
  });

  it('ignoreExamples=false reports documented example keys', () => {
    const s = createScanner({ detectors: [secrets({ ignoreExamples: false })] });
    expect(s.scanSync('AKIAIOSFODNN7EXAMPLE').map((f) => f.ruleId)).toEqual(['secret.aws-access-key-id']);
  });
});

describe('entropy', () => {
  it('orders words below random strings', () => {
    expect(shannonEntropy('password')).toBeLessThan(3);
    expect(shannonEntropy(randStr(40))).toBeGreaterThan(4.5);
  });
});
