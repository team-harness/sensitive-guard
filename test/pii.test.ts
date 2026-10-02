import { describe, expect, it } from 'vitest';
import { createScanner, isValidCnIdCard, isValidUscc, luhn, pii } from '../src';
import { cnId, luhnComplete, uscc } from './helpers';

const scanner = createScanner({ detectors: [pii()] });
const found = (text: string) => scanner.scanSync(text).map((f) => [f.ruleId, text.slice(f.start, f.end)]);

describe('validators', () => {
  it('cn id card checksum + birth date', () => {
    const id = cnId('11010519491231002');
    expect(isValidCnIdCard(id)).toBe(true);
    const wrongCheck = id.slice(0, 17) + (id[17] === '0' ? '1' : '0');
    expect(isValidCnIdCard(wrongCheck)).toBe(false);
    expect(isValidCnIdCard(cnId('11010519490231002'))).toBe(false); // Feb 31
    expect(isValidCnIdCard(cnId('11010530000101002'))).toBe(false); // future
  });

  it('luhn', () => {
    expect(luhn('4111111111111111')).toBe(true);
    expect(luhn('4111111111111112')).toBe(false);
  });

  it('uscc checksum', () => {
    const code = uscc('91350100M000100Y4');
    expect(isValidUscc(code)).toBe(true);
    expect(isValidUscc(`${code.slice(0, 17)}${code[17] === '0' ? '1' : '0'}`)).toBe(false);
  });
});

describe('pii detector', () => {
  it('detects a valid ID card and ignores an invalid one', () => {
    const id = cnId('44030619900307123');
    expect(found(`身份证 ${id} 请核对`)).toEqual([['pii.cn-id-card', id]]);
    const bad = id.slice(0, 17) + (id[17] === '0' ? '1' : '0');
    expect(found(`身份证 ${bad}`)).toEqual([]);
  });

  it('detects lower-case x check digit', () => {
    // find a prefix whose check digit is X
    for (let i = 100; i < 999; i++) {
      const id = cnId(`11010519800101${i}`);
      if (id.endsWith('X')) {
        expect(found(`id:${id.toLowerCase()}`)).toEqual([['pii.cn-id-card', id.toLowerCase()]]);
        return;
      }
    }
    throw new Error('no X id generated');
  });

  it.each(['13812345678', '+86 138 1234 5678', '86-138-1234-5678', '199 1234 5678'])('mobile %s', (m) => {
    expect(found(`联系我 ${m} 谢谢`)).toEqual([['pii.cn-mobile', m]]);
  });

  it('does not treat other digit runs as mobiles', () => {
    expect(found('订单号 12812345678 和 238123456789')).toEqual([]);
    expect(found('timestamp 1700000000000')).toEqual([]);
  });

  it('bank cards: context raises confidence, bare runs are medium', () => {
    const card = luhnComplete('622202100112345678');
    const withCtx = scanner.scanSync(`我的银行卡号是 ${card}`);
    expect(withCtx.map((f) => f.ruleId)).toEqual(['pii.bank-card']);
    expect(withCtx[0]!.confidence).toBeGreaterThanOrEqual(0.9);
    expect(withCtx[0]!.severity).toBe('high');

    const bare = scanner.scanSync(`id=${card}`);
    expect(bare[0]!.severity).toBe('medium');

    const grouped = '4111 1111 1111 1111';
    expect(found(`card: ${grouped}`)).toEqual([['pii.bank-card', grouped]]);
  });

  it('ignores luhn-valid numbers without a card BIN (e.g. snowflake ids)', () => {
    const snowflake = luhnComplete('179012345678901234');
    expect(found(`message_id=${snowflake}`)).toEqual([]);
  });

  it('uscc and email', () => {
    const code = uscc('91110108MA01ABCD1');
    expect(found(`统一社会信用代码：${code}`)).toEqual([['pii.cn-uscc', code]]);
    expect(found('mail me at zhang.san+dev@corp-mail.cn.')).toEqual([['pii.email', 'zhang.san+dev@corp-mail.cn']]);
    expect(found('user@example.com')).toEqual([]);
  });

  it('ipv4 is opt-in', () => {
    expect(found('host 10.2.3.4')).toEqual([]);
    const s = createScanner({ detectors: [pii({ include: ['ipv4'] })] });
    expect(s.scanSync('host 10.2.3.4, loopback 127.0.0.1, version 1.2.3.4.5').map((f) => f.ruleId)).toEqual(['pii.ipv4']);
  });

  it('severity override', () => {
    const s = createScanner({ detectors: [pii({ severity: { email: 'high' } })] });
    expect(s.scanSync('a@corp.cn')[0]!.severity).toBe('high');
  });
});
