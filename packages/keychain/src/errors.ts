export type KeychainErrorCode =
  | 'KEYCHAIN_UNAVAILABLE'
  | 'KEYCHAIN_ACCESS_DENIED'
  | 'KEYCHAIN_ABORTED'
  | 'KEYCHAIN_CORRUPTED'
  | 'KEYCHAIN_OPERATION_FAILED';

export class KeychainError extends Error {
  public override readonly name = 'KeychainError';

  public constructor(
    public readonly code: KeychainErrorCode,
    message: string,
  ) {
    super(message);
  }
}
