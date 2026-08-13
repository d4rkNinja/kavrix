import type { ClockPort, IdGeneratorPort, VaultStoragePort } from '@kavrix/core';
import type {
  AeadEnvelope,
  ApiBearerToken,
  ApiSessionResponse,
  ApiScope,
  ControlListCursor,
  ControlListPageOptions,
  DeviceId,
  DeviceRecord,
  InviteId,
  PublicInviteRecord,
  EncryptedAuditRecord,
  OpaqueMutation,
  SchemaVersion,
  Sha256Digest,
  Timestamp,
  VaultBootstrapRequest,
  VaultBootstrapResponse,
  VaultId,
} from '@kavrix/schemas';

export type AuthorizationInvitePage = Readonly<{
  invites: readonly PublicInviteRecord[];
  nextCursor: ControlListCursor | null;
}>;

export type AuthorizationDevicePage = Readonly<{
  devices: readonly DeviceRecord[];
  nextCursor: ControlListCursor | null;
}>;

export type DeviceRevocationResult = 'revoked' | 'not-found' | 'last-active-device';

export type SessionPrincipal = Omit<ApiSessionResponse, 'scopes'> & {
  readonly scopes: readonly ApiScope[];
};

export interface InviteGrant {
  readonly id: InviteId;
  readonly tokenHash: Sha256Digest;
  readonly vaultId: VaultId;
  readonly scopes: readonly ApiScope[];
  readonly issuedByDeviceId: DeviceId;
  readonly createdAt: Timestamp;
  readonly expiresAt: Timestamp;
  readonly consumedAt?: Timestamp;
  readonly revokedAt?: Timestamp;
}

export interface InviteRedemption {
  readonly vaultId: VaultId;
  readonly scopes: readonly ApiScope[];
  readonly enrollmentExpiresAt: Timestamp;
}

export interface EnrollmentCompletion {
  readonly vaultId: VaultId;
  readonly deviceId: DeviceId;
  readonly schemaVersion: SchemaVersion;
  readonly encryptedLabel?: AeadEnvelope;
  readonly sessionTokenHash: Sha256Digest;
}

export interface AuthorizationPort {
  /** Returns null for unknown, expired, or revoked session hashes. */
  findSession(tokenHash: Sha256Digest, now: Date): Promise<SessionPrincipal | null>;
  createInvite(grant: InviteGrant): Promise<void>;
  /**
   * Atomically consumes or exactly replays an invite. Repeating the same
   * invite and independently generated enrollment hash returns the original redemption;
   * incompatible reuse fails closed. Replay is valid only before the stored
   * effective enrollment expiry. The successor hash must be globally unique
   * across invite, enrollment, and session credentials.
   */
  redeemInvite(
    inviteTokenHash: Sha256Digest,
    enrollmentTokenHash: Sha256Digest,
    enrollmentExpiresAt: Timestamp,
    now: Date,
  ): Promise<InviteRedemption | null>;
  /**
   * Atomically consumes or exactly replays enrollment with the same input and
   * independently generated session hash. A device-ID collision must fail without consuming
   * enrollment. Replay is valid only before the enrollment expiry. The session
   * hash must be globally unique across all bearer credential classes.
   * Persistence stores only hashes, never bearer tokens.
   */
  completeEnrollment(
    enrollmentTokenHash: Sha256Digest,
    completion: EnrollmentCompletion,
    now: Date,
  ): Promise<DeviceRecord | null>;
  listInvitePage(
    vaultId: VaultId,
    options: ControlListPageOptions,
    now: Date,
  ): Promise<AuthorizationInvitePage>;
  /**
   * Atomically transitions an active invite to revoked against redemption.
   * Exactly one concurrent redeem/revoke transition may win. Repeating an
   * already successful revocation is idempotent.
   */
  revokeInvite(
    vaultId: VaultId,
    inviteId: InviteId,
    revokedAt: Timestamp,
  ): Promise<boolean>;
  listDevicePage(
    vaultId: VaultId,
    options: ControlListPageOptions,
  ): Promise<AuthorizationDevicePage>;
  /**
   * Atomically marks the device revoked and invalidates all of its sessions.
   * The last active device is denied so revocation cannot strand a vault
   * without an authorized device. Repeating a successful revocation is
   * idempotent.
   */
  revokeDevice(
    vaultId: VaultId,
    deviceId: DeviceId,
    revokedAt: Timestamp,
  ): Promise<DeviceRevocationResult>;
}

export interface IssuedToken {
  readonly token: ApiBearerToken;
  readonly hash: Sha256Digest;
}

export interface TokenPort {
  issue(): Promise<IssuedToken>;
  hash(token: ApiBearerToken): Promise<Sha256Digest>;
}

export type VaultBootstrapInput = VaultBootstrapRequest & {
  readonly sessionTokenHash: Sha256Digest;
};

export interface VaultBootstrapPort {
  /**
   * Atomically creates the initial opaque vault, first device, active session,
   * and global credential claim. Exact retries return the same public receipt;
   * every collision or incompatible reuse fails closed as null.
   */
  bootstrap(input: VaultBootstrapInput): Promise<VaultBootstrapResponse | null>;
}

export interface RateLimitAttempt {
  readonly key: string;
  readonly limit: number;
  readonly windowSeconds: number;
  readonly now: Date;
}

export interface RateLimitPort {
  /** Must be an atomic shared consume operation in horizontally scaled deployments. */
  consume(attempt: RateLimitAttempt): Promise<boolean>;
}

export type ApiStoragePort = Pick<
  VaultStoragePort,
  | 'getVault'
  | 'pullSyncPage'
  | 'pushSyncBatch'
  | 'publishTemplateMigration'
  | 'getAttachment'
  | 'getGroup'
  | 'getItem'
  | 'beginAttachmentStream'
  | 'abortAttachmentStream'
  | 'getAttachmentStreamHeader'
  | 'getAttachmentChunk'
> & {
  /** Atomically commits one revision-bound key-slot change and its opaque audit sidecar. */
  commitKeySlotMutation(
    mutation: Extract<OpaqueMutation, { entityType: 'vault' }>,
    audit: EncryptedAuditRecord,
  ): Promise<void>;
};

export interface ApiPorts {
  readonly storage: ApiStoragePort;
  readonly authorization: AuthorizationPort;
  readonly tokens: TokenPort;
  readonly rateLimits: RateLimitPort;
  readonly clock: ClockPort;
  readonly inviteIds: IdGeneratorPort<InviteId>;
  readonly bootstrap: VaultBootstrapPort;
}
