/** Stable screen identifiers for the interactive Kavrix app router. */
export const APP_SCREEN_IDS = [
  'home',
  'profiles',
  'vaults',
  'credentials',
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
}

/** Primary dashboard destinations (showcase stays reachable but secondary). */
export const APP_MENU: readonly AppMenuEntry[] = [
  { id: 'home', label: 'Home', hint: 'Status dashboard', accent: 'yellow' },
  { id: 'profiles', label: 'Profiles', hint: 'Datastore routes', accent: 'yellow' },
  { id: 'vaults', label: 'Vaults', hint: 'Vault selection', accent: 'yellow' },
  {
    id: 'credentials',
    label: 'Credentials',
    hint: 'Masked secrets',
    accent: 'yellow',
  },
  {
    id: 'doctor',
    label: 'Doctor / heal',
    hint: 'Local health (not kit)',
    accent: 'yellow',
  },
  { id: 'recovery', label: 'Recovery kit', hint: 'Key-material slots', accent: 'red' },
  {
    id: 'run',
    label: 'Run preview',
    hint: 'Dry-run inject (not project env)',
    accent: 'yellow',
  },
  {
    id: 'policy',
    label: 'Policy / Grant / Audit',
    hint: 'Authorization',
    accent: 'yellow',
  },
  { id: 'agent', label: 'Agent', hint: 'Broker dry-run', accent: 'yellow' },
  {
    id: 'browse',
    label: 'Vault context / service / item',
    hint: 'Vault hierarchy (not run --environment)',
    accent: 'yellow',
  },
  { id: 'help', label: 'Help', hint: 'Keymap', accent: 'white' },
  {
    id: 'showcase',
    label: 'Storage docs',
    hint: 'Docs only (no vault ops)',
    accent: 'yellow',
  },
];
