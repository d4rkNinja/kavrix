export type ClipboardErrorCode =
  | 'CLIPBOARD_ABORTED'
  | 'CLIPBOARD_CHANGED'
  | 'CLIPBOARD_OPERATION_FAILED'
  | 'CLIPBOARD_TIMEOUT'
  | 'CLIPBOARD_UNAVAILABLE'
  | 'CLIPBOARD_VALIDATION_FAILED';

export class ClipboardError extends Error {
  public readonly code: ClipboardErrorCode;

  public constructor(code: ClipboardErrorCode, message: string) {
    super(message);
    this.name = 'ClipboardError';
    this.code = code;
  }
}
