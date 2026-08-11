import { createHash } from 'node:crypto';

import {
  canonicalJson,
  changeSequenceSchema,
  deviceIdSchema,
  outboundObservationContentSchema,
  outboundObservationKindSchema,
  outboundObservationSchema,
  protectedLocalDeviceStateSchema,
  sha256DigestSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  vaultIdSchema,
  type DeviceId,
  type OutboundObservation,
  type OutboundObservationKind,
  type ProtectedLocalDeviceState,
  type Sha256Digest,
  type SyncPushRequest,
  type SyncPushResponse,
  type TemplateMigrationPublicationResponse,
  type VaultId,
} from '@kavrix/schemas';

import { SyncLocalStateError, SyncProtocolError } from './errors.js';
import {
  parsePushResponse,
  parseTemplateMigrationPublicationResponse,
} from './validation.js';

const REQUEST_DOMAIN = 'kavrix/sync-observation/v1/request\0';
const RESPONSE_DOMAIN = 'kavrix/sync-observation/v1/response\0';
const DESCRIPTOR_DOMAIN = 'kavrix/sync-observation/v1/descriptor\0';

type ObservationRequest = SyncPushRequest;
type ObservationResponse = SyncPushResponse | TemplateMigrationPublicationResponse;

export type CreateOutboundObservationInput = Readonly<{
  kind: OutboundObservationKind;
  vaultId: VaultId;
  deviceId: DeviceId;
  request: unknown;
  response: unknown;
  replayFromServerSequence: number;
}>;

export function hashOutboundObservationRequest(
  kindInput: OutboundObservationKind,
  request: unknown,
): Sha256Digest {
  const kind = parseKind(kindInput);
  return hashCanonical(REQUEST_DOMAIN, parseRequest(kind, request));
}

export function hashOutboundObservationResponse(
  kindInput: OutboundObservationKind,
  response: unknown,
): Sha256Digest {
  const kind = parseKind(kindInput);
  return hashCanonical(RESPONSE_DOMAIN, parseResponse(kind, response));
}

export function computeOutboundObservationId(
  vaultIdInput: unknown,
  deviceIdInput: unknown,
  observationInput: unknown,
): Sha256Digest {
  const vaultId = vaultIdSchema.safeParse(vaultIdInput);
  const deviceId = deviceIdSchema.safeParse(deviceIdInput);
  const observation = outboundObservationContentSchema.safeParse(observationInput);
  if (!vaultId.success || !deviceId.success || !observation.success) {
    throw new SyncLocalStateError();
  }
  return hashCanonical(DESCRIPTOR_DOMAIN, {
    version: observation.data.version,
    kind: observation.data.kind,
    vaultId: vaultId.data,
    deviceId: deviceId.data,
    batchIdempotencyKey: observation.data.batchIdempotencyKey,
    requestHash: observation.data.requestHash,
    responseHash: observation.data.responseHash,
    responseVaultRevision: observation.data.responseVaultRevision,
    replayFromServerSequence: observation.data.replayFromServerSequence,
    requiredThroughServerSequence: observation.data.requiredThroughServerSequence,
  });
}

export function createOutboundObservation(
  input: CreateOutboundObservationInput,
): OutboundObservation {
  const kind = parseKind(input.kind);
  const vaultId = vaultIdSchema.safeParse(input.vaultId);
  const deviceId = deviceIdSchema.safeParse(input.deviceId);
  const replayFrom = changeSequenceSchema.safeParse(input.replayFromServerSequence);
  if (!vaultId.success || !deviceId.success || !replayFrom.success) {
    throw new SyncProtocolError();
  }

  const request = parseRequest(kind, input.request);
  if (request.vaultId !== vaultId.data) throw new SyncProtocolError();
  const response = parseBoundResponse(kind, input.response, request);
  const requiredThroughServerSequence = requiredThrough(
    kind,
    response,
    replayFrom.data,
  );
  const content = outboundObservationContentSchema.parse({
    version: 1,
    kind,
    batchIdempotencyKey: request.batchIdempotencyKey,
    requestHash: hashCanonical(REQUEST_DOMAIN, request),
    responseHash: hashCanonical(RESPONSE_DOMAIN, response),
    responseVaultRevision: response.serverVaultRevision,
    replayFromServerSequence: replayFrom.data,
    requiredThroughServerSequence,
  });
  return outboundObservationSchema.parse({
    ...content,
    observationId: computeOutboundObservationId(vaultId.data, deviceId.data, content),
  });
}

function parseKind(input: unknown): OutboundObservationKind {
  const parsed = outboundObservationKindSchema.safeParse(input);
  if (!parsed.success) throw new SyncProtocolError();
  return parsed.data;
}

export function validateOutboundObservationBinding(
  input: unknown,
): ProtectedLocalDeviceState {
  const parsed = protectedLocalDeviceStateSchema.safeParse(input);
  if (!parsed.success) throw new SyncLocalStateError();
  const observation = parsed.data.outboundObservation;
  if (observation === undefined) return parsed.data;
  const { observationId, ...content } = observation;
  if (
    computeOutboundObservationId(parsed.data.vaultId, parsed.data.deviceId, content) !==
    observationId
  ) {
    throw new SyncLocalStateError();
  }
  return parsed.data;
}

function parseRequest(
  kind: OutboundObservationKind,
  input: unknown,
): ObservationRequest {
  const parsed =
    kind === 'generic-push'
      ? syncPushRequestSchema.safeParse(input)
      : templateMigrationPublicationRequestSchema.safeParse(input);
  if (!parsed.success) throw new SyncProtocolError();
  return parsed.data;
}

function parseResponse(
  kind: OutboundObservationKind,
  input: unknown,
): ObservationResponse {
  const parsed =
    kind === 'generic-push'
      ? syncPushResponseSchema.safeParse(input)
      : templateMigrationPublicationResponseSchema.safeParse(input);
  if (!parsed.success) throw new SyncProtocolError();
  return parsed.data;
}

function parseBoundResponse(
  kind: OutboundObservationKind,
  input: unknown,
  request: ObservationRequest,
): ObservationResponse {
  if (kind === 'generic-push') {
    return parsePushResponse(
      input,
      request.vaultId,
      request.batchIdempotencyKey,
      request.mutations,
    );
  }
  return parseTemplateMigrationPublicationResponse(input, request);
}

function requiredThrough(
  kind: OutboundObservationKind,
  response: ObservationResponse,
  replayFrom: number,
): number {
  let required = replayFrom;
  if (kind === 'generic-push') {
    for (const result of (response as SyncPushResponse).results) {
      if (result.status === 'accepted') {
        required = Math.max(required, result.change.serverSequence);
      }
    }
    return changeSequenceSchema.parse(required);
  }
  for (const result of (response as TemplateMigrationPublicationResponse).results) {
    required = Math.max(required, result.change.serverSequence);
  }
  return changeSequenceSchema.parse(required);
}

function hashCanonical(domain: string, value: unknown): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(domain, 'ascii')
      .update(canonicalJson(value), 'utf8')
      .digest('base64url'),
  );
}
