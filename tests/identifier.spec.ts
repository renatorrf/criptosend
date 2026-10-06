import { describe, expect, it } from 'vitest';

import { createSearchPath, quoteIdentifier } from '../src/database/identifier.js';

describe('SQL identifiers', () => {
  it('quotes a valid schema identifier', () => {
    expect(quoteIdentifier('criptsend_app')).toBe('"criptsend_app"');
    expect(createSearchPath('criptsend_app')).toBe('"criptsend_app", public');
  });

  it.each(['bad-schema', 'public; DROP TABLE users', '1schema', '']) (
    'rejects unsafe identifier %s',
    (identifier) => {
      expect(() => quoteIdentifier(identifier)).toThrow('Invalid SQL identifier.');
    },
  );
});
