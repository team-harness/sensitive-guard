import { describe, expect, it } from 'vitest';
import { createScanner, keywords, maskPreview, masks, pii, regexDetector, secrets, type AsyncDetector } from '../src';
import { secretlint } from '../src/adapters/secretlint';
import { cnId, fake, randStr } from './helpers';

describe('scanner', () => {
  const scanner = createScanner();

  it('default detectors find secrets and PII in one message', () => {
    const tok = fake.githubPat();
    const id = cnId('11010519491231002');
    const text = `token=${tok}，身份证 ${id}，手机 13812345678`;
    const f = scanner.scanSync(text);
    expect(f.map((x) => x.ruleId)).toEqual(['secret.github-token', 'pii.cn-id-card', 'pii.cn-mobile']);
    expect(f.every((x) => x.start < x.end)).toBe(true);
  });

  it('never includes the raw match unless asked, and previews are masked', () => {
    const tok = fake.githubPat();
    const [f] = scanner.scanSync(tok);
    expect(f).not.toHaveProperty('match');
    expect(f!.preview).not.toContain(tok.slice(4, -4));
    expect(f!.preview.startsWith(tok.slice(0, 4))).toBe(true);
    expect(JSON.stringify(f)).not.toContain(tok);

    const [g] = createScanner({ includeMatch: true }).scanSync(tok);
    expect(g!.match).toBe(tok);
  });

  it('previews reveal at most a quarter of short secrets', () => {
    expect(maskPreview('S3cr3t-P4ss')).toBe('S…s');
    expect(maskPreview('13812345678')).toBe('1…8');
    expect(maskPreview('hunter2')).toBe('********');
    for (const s of ['abcdefgh', 'S3cr3t-P4ss', randStr(16), randStr(40), randStr(200)]) {
      const shown = maskPreview(s).replace(/[…*]/g, '').length;
      expect(shown / s.length).toBeLessThanOrEqual(0.25);
    }
  });

  it('minSeverity / minConfidence / disableRules / allowlist', () => {
    const text = `mail a@corp.cn phone 13812345678 key ${fake.githubPat()}`;
    expect(createScanner({ minSeverity: 'high' }).scanSync(text).map((f) => f.ruleId)).toEqual(['secret.github-token']);
    expect(createScanner({ disableRules: ['pii.*'] }).scanSync(text).map((f) => f.ruleId)).toEqual(['secret.github-token']);
    expect(createScanner({ allowlist: ['a@corp.cn', /^138/] }).scanSync(text).map((f) => f.ruleId)).toEqual([
      'secret.github-token',
    ]);
    expect(createScanner({ minConfidence: 0.96 }).scanSync(text).map((f) => f.ruleId)).toEqual(['secret.github-token']);
  });

  it('dedupe keeps the strongest overlapping finding', () => {
    const s = createScanner({
      detectors: [
        regexDetector('a', [{ id: 'weak', pattern: /abc/, severity: 'low' }]),
        regexDetector('b', [{ id: 'strong', pattern: /abcdef/, severity: 'high' }]),
      ],
    });
    expect(s.scanSync('xx abcdef').map((f) => f.ruleId)).toEqual(['strong']);
    const all = createScanner({ dedupe: false, detectors: [regexDetector('a', [{ id: 'weak', pattern: /abc/ }, { id: 'strong', pattern: /abcdef/ }])] });
    expect(all.scanSync('abcdef')).toHaveLength(2);
  });

  it('redaction with built-in maskers', () => {
    const tok = fake.githubPat();
    const text = `use ${tok} now`;
    expect(scanner.redactSync(text).text).toBe('use [REDACTED:secret.github-token] now');
    expect(scanner.redactSync(text, { mask: masks.plain }).text).toBe('use [REDACTED] now');
    expect(scanner.redactSync(text, { mask: masks.char('#') }).text).toBe(`use ${'#'.repeat(tok.length)} now`);
    const partial = scanner.redactSync(text, { mask: masks.partial(4, 2) }).text;
    expect(partial).toBe(`use ${tok.slice(0, 4)}${'*'.repeat(tok.length - 6)}${tok.slice(-2)} now`);
  });

  it('redacts only the password inside a connection string', () => {
    const { text } = scanner.redactSync('postgres://admin:S3cr3t-P4ss@db:5432/app');
    expect(text).toBe('postgres://admin:[REDACTED:secret.connection-string-password]@db:5432/app');
  });

  it('hasSensitiveSync', () => {
    expect(scanner.hasSensitiveSync('hello world')).toBe(false);
    expect(scanner.hasSensitiveSync('a@corp.cn')).toBe(true);
    expect(scanner.hasSensitiveSync('a@corp.cn', 'high')).toBe(false);
  });

  it('async detectors run in scan() but not scanSync()', async () => {
    const remote: AsyncDetector = {
      id: 'remote-moderation',
      async: true,
      detect: async (text) => {
        const i = text.indexOf('bad');
        return i < 0 ? [] : [{ ruleId: 'remote.bad', category: 'custom', severity: 'medium', confidence: 0.7, start: i, end: i + 3 }];
      },
    };
    const s = createScanner({ detectors: [secrets(), remote] });
    expect(s.scanSync('this is bad')).toEqual([]);
    const f = await s.scan('this is bad');
    expect(f.map((x) => [x.detector, x.ruleId])).toEqual([['remote-moderation', 'remote.bad']]);
    expect((await s.redact('this is bad')).text).toBe('this is [REDACTED:remote.bad]');
  });

  it('drops out-of-range findings from misbehaving detectors', () => {
    const s = createScanner({
      detectors: [{ id: 'broken', detect: () => [{ ruleId: 'x', category: 'custom', severity: 'high', confidence: 1, start: 5, end: 500 }] }],
    });
    expect(s.scanSync('short')).toEqual([]);
  });
});

describe('secretlint adapter', () => {
  it('maps secretlint messages to findings', async () => {
    const tok = fake.githubPat();
    const s = createScanner({ detectors: [secretlint()] });
    const text = `my token ${tok}`;
    const f = await s.scan(text);
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe('secretlint.GITHUB_TOKEN');
    expect(text.slice(f[0]!.start, f[0]!.end)).toBe(tok);
  });

  it('combines with the built-in detector (deduped)', async () => {
    const tok = fake.githubPat();
    const s = createScanner({ detectors: [secrets(), secretlint()] });
    const f = await s.scan(`my token ${tok}`);
    expect(f).toHaveLength(1);
  });

  it('does not let secretlint spans swallow adjacent Chinese text', async () => {
    const s = createScanner({ detectors: [secretlint()] });
    const cases: Array<[string, string]> = [
      ['连接串 postgres://admin:S3cr3t-P4ss@db:5432/app，token 在下面', 'postgres://admin:S3cr3t-P4ss@db:5432/app'],
      ['mysql://root:Pa55word@10.0.0.1:3306/app。谢谢', 'mysql://root:Pa55word@10.0.0.1:3306/app'],
    ];
    for (const [text, span] of cases) {
      const [f] = await s.scan(text);
      expect(text.slice(f!.start, f!.end)).toBe(span);
    }
  });

  it('keeps the tighter built-in finding when secretlint overlaps it', async () => {
    const tok = fake.githubPat();
    const msg = `DATABASE_URL=postgres://admin:S3cr3t-P4ss@db:5432/app，token ${tok}，谢谢`;
    const s = createScanner({ detectors: [secrets(), secretlint()] });
    const { text, findings } = await s.redact(msg, { mask: masks.plain });
    expect(findings.map((f) => f.ruleId)).toEqual(['secret.connection-string-password', 'secret.github-token']);
    expect(text).toBe('DATABASE_URL=postgres://admin:[REDACTED]@db:5432/app，token [REDACTED]，谢谢');
  });
});

describe('performance', () => {
  it('scans ~200 KB of mixed text quickly and without pathological backtracking', () => {
    const s = createScanner({ detectors: [secrets(), pii(), keywords({ words: Array.from({ length: 5000 }, (_, i) => `word${i}x`) })] });
    const chunk = `Some log line with id=${randStr(18, '0123456789')} and password: string; token_count=42 key=value 敏感 \n`;
    const big = chunk.repeat(Math.ceil(200_000 / chunk.length));
    const t0 = performance.now();
    s.scanSync(big);
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(2000);

    const adversarial = `password=${'a'.repeat(50_000)} ${'1 '.repeat(20_000)} ${'-'.repeat(50_000)}`;
    const t1 = performance.now();
    s.scanSync(adversarial);
    expect(performance.now() - t1).toBeLessThan(2000);
  });
});
