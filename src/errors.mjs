export class InvariantError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(message); this.name = 'InvariantError'; this.code = code; this.status = status; this.details = details;
  }
}
export function requireThat(condition, code, message, status = 400, details) {
  if (!condition) throw new InvariantError(code, message, status, details);
}
export const invalid = (message) => new InvariantError('INV-400-SCHEMA', message);
