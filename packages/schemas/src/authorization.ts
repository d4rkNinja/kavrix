import { z } from 'zod';

export const API_SCOPE_VALUES = Object.freeze([
  'sync:read',
  'sync:write',
  'device:manage',
] as const);
export const MIN_API_SCOPES = 1;
export const MAX_API_SCOPES = API_SCOPE_VALUES.length;

export const apiScopeSchema = z.enum(API_SCOPE_VALUES);
export const apiScopesSchema = z
  .array(apiScopeSchema)
  .min(MIN_API_SCOPES)
  .max(MAX_API_SCOPES)
  .superRefine((scopes, context) => {
    if (new Set(scopes).size !== scopes.length) {
      context.addIssue({
        code: 'custom',
        message: 'API scopes must be unique',
      });
    }
  });

export type ApiScope = z.infer<typeof apiScopeSchema>;
