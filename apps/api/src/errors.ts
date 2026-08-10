export class ApiAuthenticationError extends Error {
  public constructor() {
    super('Authentication failed');
    this.name = 'ApiAuthenticationError';
  }
}

export class ApiAuthorizationError extends Error {
  public constructor() {
    super('Authorization failed');
    this.name = 'ApiAuthorizationError';
  }
}

export class ApiValidationError extends Error {
  public constructor() {
    super('Request validation failed');
    this.name = 'ApiValidationError';
  }
}

export class ApiNotFoundError extends Error {
  public constructor() {
    super('Resource not found');
    this.name = 'ApiNotFoundError';
  }
}

export class ApiRateLimitError extends Error {
  public constructor() {
    super('Rate limit exceeded');
    this.name = 'ApiRateLimitError';
  }
}

export class ApiHttpsRequiredError extends Error {
  public constructor() {
    super('HTTPS is required');
    this.name = 'ApiHttpsRequiredError';
  }
}

export class ApiConflictError extends Error {
  public constructor(
    readonly entityType: 'vault' | 'group' | 'item' | 'attachment',
    readonly entityId: string,
    readonly expectedRevision: number | null,
    readonly currentRevision: number | null,
  ) {
    super('The opaque record has a revision conflict');
    this.name = 'ApiConflictError';
  }
}

export class ApiAtomicPublicationConflictError extends Error {
  public constructor() {
    super('The opaque migration publication has a revision conflict');
    this.name = 'ApiAtomicPublicationConflictError';
  }
}

export class ApiAttachmentConflictError extends Error {
  public constructor() {
    super('The opaque attachment stream has a conflict');
    this.name = 'ApiAttachmentConflictError';
  }
}

export class ApiUnsupportedMediaTypeError extends Error {
  public constructor() {
    super('Unsupported media type');
    this.name = 'ApiUnsupportedMediaTypeError';
  }
}
