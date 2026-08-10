export type PortableKeyFileErrorCode =
  | 'KEY_FILE_ALREADY_EXISTS'
  | 'KEY_FILE_BUSY'
  | 'KEY_FILE_INVALID_PATH'
  | 'KEY_FILE_NOT_FOUND'
  | 'KEY_FILE_OPERATION_FAILED'
  | 'KEY_FILE_UNSAFE';

const SAFE_MESSAGES: Readonly<Record<PortableKeyFileErrorCode, string>> = {
  KEY_FILE_ALREADY_EXISTS: 'The portable key file already exists.',
  KEY_FILE_BUSY: 'The portable key file is being changed by another process.',
  KEY_FILE_INVALID_PATH: 'The portable key file path is invalid.',
  KEY_FILE_NOT_FOUND: 'The portable key file was not found.',
  KEY_FILE_OPERATION_FAILED: 'The portable key file operation failed.',
  KEY_FILE_UNSAFE: 'The portable key file is not safe to use.',
};

export class PortableKeyFileError extends Error {
  public readonly code: PortableKeyFileErrorCode;

  public constructor(code: PortableKeyFileErrorCode) {
    super(SAFE_MESSAGES[code]);
    this.name = 'PortableKeyFileError';
    this.code = code;
  }
}
