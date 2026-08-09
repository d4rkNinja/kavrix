export class AuthenticationError extends Error {
  public constructor() {
    super('Authentication failed');
    this.name = 'AuthenticationError';
  }
}

export class CryptoInputError extends Error {
  public constructor(message = 'Invalid cryptographic input') {
    super(message);
    this.name = 'CryptoInputError';
  }
}

export class LastValidSlotError extends Error {
  public constructor() {
    super('Operation would remove the last active unlock slot');
    this.name = 'LastValidSlotError';
  }
}
