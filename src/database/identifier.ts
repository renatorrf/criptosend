const SQL_IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function quoteIdentifier(identifier: string): string {
  if (!SQL_IDENTIFIER_PATTERN.test(identifier)) {
    throw new Error('Invalid SQL identifier.');
  }

  return `"${identifier}"`;
}

export function createSearchPath(schema: string): string {
  return `${quoteIdentifier(schema)}, public`;
}
