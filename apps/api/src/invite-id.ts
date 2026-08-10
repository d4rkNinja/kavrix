import { randomUUID } from 'node:crypto';

import type { IdGeneratorPort } from '@kavrix/core';
import { inviteIdSchema, type InviteId } from '@kavrix/schemas';

export class NodeInviteIdPort implements IdGeneratorPort<InviteId> {
  public next(): InviteId {
    return inviteIdSchema.parse(`invite.${randomUUID()}`);
  }
}
