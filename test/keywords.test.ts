import { describe, expect, it } from 'vitest';
import { AhoCorasick, createScanner, keywords, normalize } from '../src';

describe('AhoCorasick', () => {
  it('finds overlapping matches', () => {
    const ac = new AhoCorasick(['he', 'she', 'his', 'hers']);
    const hits = ac.search('ushers').map((m) => [ac.patterns[m.pattern], m.start, m.end]);
    expect(hits).toEqual([
      ['she', 1, 4],
      ['he', 2, 4],
      ['hers', 2, 6],
    ]);
  });

  it('handles astral code points', () => {
    const ac = new AhoCorasick(['𠮷野']);
    expect(ac.search('我是𠮷野家')).toEqual([{ pattern: 0, start: 2, end: 5 }]);
  });
});

describe('normalize', () => {
  it('maps normalized indices back to original offsets', () => {
    const src = 'Ａ b*Ｃ';
    const n = normalize(src);
    expect(n.text).toBe('abc');
    expect(n.starts).toEqual([0, 2, 4]);
    expect(n.ends).toEqual([1, 3, 5]);
  });
});

describe('keywords detector', () => {
  const scanner = createScanner({
    detectors: [
      keywords({
        lists: [
          { label: 'blocked', words: ['敏感词', 'project-x'], severity: 'high' },
          { label: 'profanity', words: ['ass'], severity: 'low' },
        ],
        exceptions: ['assassin'],
        charMap: { 詞: '词', 敏: '敏' },
      }),
    ],
  });
  const hits = (t: string) => scanner.scanSync(t).map((f) => [f.ruleId, t.slice(f.start, f.end)]);

  it.each([
    ['这是敏感词', '敏感词'],
    ['这是 敏 感 词 吧', '敏 感 词'],
    ['这是敏*感*词', '敏*感*词'],
    ['这是敏​感​词', '敏​感​词'],
    ['繁體：敏感詞', '敏感詞'],
    ['codename PROJECT-X leaked', 'PROJECT-X'],
    ['ｐｒｏｊｅｃｔ－ｘ', 'ｐｒｏｊｅｃｔ－ｘ'],
  ])('%s', (text, span) => {
    expect(hits(text)).toEqual([['keyword.blocked', span]]);
  });

  it('respects ascii word boundaries and exceptions', () => {
    expect(hits('class Foo {}')).toEqual([]);
    expect(hits('assassin creed')).toEqual([]);
    expect(hits('you ass')).toEqual([['keyword.profanity', 'ass']]);
  });

  it('redacts the original span including inserted noise', () => {
    const { text } = scanner.redactSync('这是敏*感*词!');
    expect(text).toBe('这是[REDACTED:keyword.blocked]!');
  });

  it('flat word list', () => {
    const s = createScanner({ detectors: [keywords({ words: ['机密'] })] });
    const [f] = s.scanSync('这是公司机密');
    expect(f?.ruleId).toBe('keyword.keywords');
    expect(f?.severity).toBe('medium');
  });

  it('empty list is a no-op', () => {
    expect(createScanner({ detectors: [keywords({ words: [] })] }).scanSync('anything')).toEqual([]);
  });
});
