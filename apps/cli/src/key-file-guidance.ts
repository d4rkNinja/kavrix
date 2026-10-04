import type { PortableKeyFileError } from '@kavrix/key-files';

/** Static, non-secret remediation shared by classic CLI and interactive setup. */
export function keyFileGuidance(error: PortableKeyFileError): string {
  if (error.code === 'KEY_FILE_UNSAFE') {
    return unsafeKeyFileGuidance();
  }
  if (error.code === 'KEY_FILE_NOT_FOUND') {
    return 'The portable key file or its parent directory was not found. Choose an existing private parent directory, or use the protected Kavrix default destination.';
  }
  if (error.code === 'KEY_FILE_ALREADY_EXISTS') {
    return 'That destination already exists. Choose a new filename; existing vault, key, and recovery files will not be overwritten.';
  }
  return error.message;
}

export function unsafeKeyFileGuidance(): string {
  return process.platform === 'win32'
    ? 'The portable key file or its parent directory is not safe to use. Choose a private folder on a local NTFS drive. In folder Properties > Security > Advanced, restrict write/delete/permission access to your account, SYSTEM, and Administrators; the key file itself must be private to your account and SYSTEM. Kavrix must verify these permissions before saving a key. Edit the destination and press Enter to check again.'
    : 'The portable key file or its parent directory is not safe to use. Choose a directory owned by your account with mode 700 and a key file with mode 600; links are not accepted. Edit the destination and press Enter to check again.';
}
