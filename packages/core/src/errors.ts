/**
 * Error type whose `message` is always safe to show to a user or write to logs.
 * Internal detail (which may contain evidence values) is kept in `internalDetail`
 * and must never be returned by the API or written to structured logs.
 */
export class AdminSecOpsError extends Error {
  readonly code: string;
  readonly statusCode: number;
  readonly internalDetail: string | undefined;

  constructor(
    code: string,
    publicMessage: string,
    options?: { statusCode?: number; internalDetail?: string; cause?: unknown },
  ) {
    super(publicMessage, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'AdminSecOpsError';
    this.code = code;
    this.statusCode = options?.statusCode ?? 400;
    this.internalDetail = options?.internalDetail;
  }
}

export function isAdminSecOpsError(value: unknown): value is AdminSecOpsError {
  return value instanceof AdminSecOpsError;
}

/** Produce a message that is safe to surface for an unknown thrown value. */
export function toPublicErrorMessage(error: unknown): string {
  if (isAdminSecOpsError(error)) return error.message;
  return 'An unexpected internal error occurred.';
}
