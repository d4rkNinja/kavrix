export type BackupErrorCode =
  | 'BACKUP_INVALID'
  | 'BACKUP_TOO_LARGE'
  | 'BACKUP_WRONG_VAULT'
  | 'BACKUP_AUTHENTICATION_FAILED'
  | 'BACKUP_DECRYPTABILITY_UNSUPPORTED'
  | 'BACKUP_INCOMPLETE'
  | 'BACKUP_COMMIT_UNCERTAIN';

export class BackupError extends Error {
  public override readonly name = 'BackupError';

  public constructor(
    public readonly code: BackupErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}
