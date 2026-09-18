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
  { id: 'home', label: 'Home', hint: 'Status dashboard', accent: 'cyan' },
  { id: 'profiles', label: 'Profiles', hint: 'Datastore routes', accent: 'blue' },
  { id: 'vaults', label: 'Vaults', hint: 'Vault selection', accent: 'magenta' },
  {
    id: 'credentials',
    label: 'Credentials',
    hint: 'Masked secrets',
    accent: 'green',
  },
  { id: 'doctor', label: 'Doctor', hint: 'Health checks', accent: 'yellow' },
  { id: 'recovery', label: 'Recovery', hint: 'Kit slots', accent: 'red' },
  { id: 'run', label: 'Run', hint: 'Dry-run inject', accent: 'cyan' },
  {
    id: 'policy',
    label: 'Policy / Grant / Audit',
    hint: 'Authorization',
    accent: 'blue',
  },
  { id: 'agent', label: 'Agent', hint: 'Broker dry-run', accent: 'magenta' },
  {
    id: 'browse',
    label: 'Context / Service / Item',
    hint: 'Structured browse',
    accent: 'green',
  },
  { id: 'help', label: 'Help', hint: 'Keymap', accent: 'white' },
  {
    id: 'showcase',
    label: 'Storage docs',
    hint: 'Docs only (no vault ops)',
    accent: 'yellow',
  },
];
