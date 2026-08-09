import { describe, expect, it } from 'vitest';

import { groupTemplateSchema } from '@kavrix/schemas';

import { builtInTemplates, getBuiltInTemplate } from '../src/index.js';

describe('built-in templates', () => {
  it('ships every required template as a valid dynamic schema', () => {
    expect(builtInTemplates).toHaveLength(10);
    for (const template of builtInTemplates) {
      expect(groupTemplateSchema.safeParse(template).success).toBe(true);
    }
  });

  it('marks high-risk built-in fields sensitive', () => {
    const email = getBuiltInTemplate('email');
    for (const stableKey of [
      'password',
      'totp_secret',
      'backup_codes',
      'app_passwords',
    ]) {
      expect(
        email.fields.find((field) => field.stableKey === stableKey)?.sensitive,
      ).toBe(true);
    }
  });

  it('keeps the custom template empty', () => {
    expect(getBuiltInTemplate('custom').fields).toEqual([]);
  });
});
