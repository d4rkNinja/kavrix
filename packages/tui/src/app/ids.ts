/** Stable screen identifiers for the interactive Kavrix app router. */
export const APP_SCREEN_IDS = [
  'home',
  'profiles',
  'vaults',
  'credentials',
  'session',
  'doctor',
  'recovery',
  'run',
  'policy',
  'agent',
  'browse',
  'help',
  'showcase',
] as const;

export type AppScreenId = (typeof APP_SCREEN_IDS)[number];

export interface AppMenuEntry {
  readonly id: AppScreenId;
  readonly label: string;
  readonly hint: string;
  readonly accent: 'cyan' | 'green' | 'yellow' | 'magenta' | 'blue' | 'red' | 'white';
  /** Compact strip label; defaults to a truncated `label` when omitted. */
  readonly short?: string;
}

/** Primary dashboard destinations (showcase stays reachable but secondary). */
export const APP_MENU: readonly AppMenuEntry[] = [
  {
    id: 'home',
    label: 'Home',
    hint: 'Status dashboard',
    accent: 'yellow',
    short: 'Home',
  },
  {
    id: 'profiles',
    label: 'Profiles',
    hint: 'Datastore routes',
    accent: 'yellow',
    short: 'Profiles',
  },
  {
    id: 'vaults',
    label: 'Vaults',
    hint: 'Vault selection',
    accent: 'yellow',
    short: 'Vaults',
  },
  {
    id: 'credentials',
    label: 'Credentials',
    hint: 'Masked secrets',
    accent: 'yellow',
    short: 'Creds',
  },
  {
    id: 'doctor',
    label: 'Doctor / heal',
    hint: 'Local health (not kit)',
    accent: 'yellow',
    short: 'Doctor',
  },
  {
    id: 'session',
    label: 'Session unlock',
    hint: 'OS keychain convenience',
    accent: 'yellow',
    short: 'Session',
  },
  {
    id: 'recovery',
    label: 'Recovery kit',
    hint: 'Key-material slots',
    accent: 'red',
    short: 'Recovery',
  },
  {
    id: 'run',
    label: 'Run preview',
    hint: 'Dry-run inject (not project env)',
    accent: 'yellow',
    short: 'Run',
  },
  {
    id: 'policy',
    label: 'Policy / Grant / Audit',
    hint: 'Authorization',
    accent: 'yellow',
    short: 'Policy',
  },
  {
    id: 'agent',
    label: 'Agent',
    hint: 'Broker dry-run',
    accent: 'yellow',
    short: 'Agent',
  },
  {
    id: 'browse',
    label: 'Vault context / service / item',
    hint: 'Vault hierarchy (not run --environment)',
    accent: 'yellow',
    short: 'Browse',
  },
  { id: 'help', label: 'Help', hint: 'Keymap', accent: 'white', short: 'Help' },
  {
    id: 'showcase',
    label: 'Storage docs',
    hint: 'Docs only (no vault ops)',
    accent: 'yellow',
    short: 'Docs',
  },
];
