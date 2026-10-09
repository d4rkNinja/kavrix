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

export const HELP_TOPICS = [
  'Getting started',
  'Navigation',
  'Credentials',
  'Safety',
  'Display',
] as const;

/**
 * Coarse destination groups. Thirteen flat menu rows are not scannable; four
 * named groups let a first-time user find "where do secrets live" without
 * reading every label.
 */
export type AppNavGroup = 'setup' | 'secrets' | 'security' | 'tools';

export interface AppNavGroupInfo {
  readonly id: AppNavGroup;
  readonly label: string;
  readonly hint: string;
}

export const NAV_GROUPS: readonly AppNavGroupInfo[] = [
  {
    id: 'setup',
    label: 'Set up',
    hint: 'Choose where secrets are stored, and which vault to work in',
  },
  {
    id: 'secrets',
    label: 'Secrets',
    hint: 'Add, find, copy and reveal credential values',
  },
  {
    id: 'security',
    label: 'Security',
    hint: 'Unlock, local health, recovery slots and access rules',
  },
  {
    id: 'tools',
    label: 'Tools',
    hint: 'Dry runs, browsing, the keymap and storage docs',
  },
];

/**
 * One-line orientation for each screen. Rendered under the header so a user
 * always sees what this screen is for and which keys act on it, instead of
 * guessing from the tab strip alone.
 *
 * Copy is kept short enough to survive a 76-cell panel at the 80-column layout
 * matrix: a clipped hint loses the tail, and the tail is usually the key.
 */
export const SCREEN_GUIDES: Readonly<Record<AppScreenId, string>> = {
  home: 'Pick a destination below, or press : for every action.',
  profiles: 'Where secrets are stored. Enter uses it; n file, m MongoDB.',
  vaults: 'Which vault to work in. Enter uses it; n creates one.',
  credentials: '/ filters names · Enter detail · c copy · r reveal · n put.',
  session: 'Keep this vault unlocked without retyping the passphrase.',
  doctor: 'Local storage health and permissions. Press d to run checks.',
  recovery: 'Kit slots: n create, v verify, x revoke. Last slot protected.',
  run: 'Preview which credentials a command would receive.',
  policy: 'Policies, grants and the audit ring. n, g, r act on a row.',
  agent: 'Validate an agent dry-run against the project config. Press g.',
  browse: 'Browse context / service / item labels. Metadata only.',
  help: 'Pick a topic with j/k or arrows. Esc returns Home.',
  showcase: 'Read-only storage summary. No vault create or unlock here.',
};

/**
 * Effective guide line for a screen. While the Credentials name filter is
 * open every printable key is filter text, so the guide must describe that
 * state: advertising `n put` / `c copy` / `r reveal` there would name keys that
 * would type into the search instead of running — exactly what the footer's
 * filtering chip set already avoids.
 */
export function screenGuide(screen: AppScreenId, filtering = false): string {
  if (screen === 'credentials' && filtering) {
    return 'Name filter open: every key narrows the list. Esc clears.';
  }
  return SCREEN_GUIDES[screen];
}

export interface AppMenuEntry {
  readonly id: AppScreenId;
  readonly label: string;
  readonly hint: string;
  readonly accent: 'cyan' | 'green' | 'yellow' | 'magenta' | 'blue' | 'red' | 'white';
  /** Compact strip label; defaults to a truncated `label` when omitted. */
  readonly short?: string;
  /** Grouping shown on the Home menu. */
  readonly group: AppNavGroup;
}

/** Primary dashboard destinations (showcase stays reachable but secondary). */
export const APP_MENU: readonly AppMenuEntry[] = [
  {
    id: 'home',
    label: 'Home',
    hint: 'Status dashboard',
    accent: 'yellow',
    short: 'Home',
    group: 'setup',
  },
  {
    id: 'profiles',
    label: 'Profiles',
    hint: 'Choose where secrets are stored',
    accent: 'yellow',
    short: 'Profiles',
    group: 'setup',
  },
  {
    id: 'vaults',
    label: 'Vaults',
    hint: 'Vault selection',
    accent: 'yellow',
    short: 'Vaults',
    group: 'setup',
  },
  {
    id: 'credentials',
    label: 'Credentials',
    hint: 'Add, search, copy and edit secrets',
    accent: 'yellow',
    short: 'Creds',
    group: 'secrets',
  },
  {
    id: 'doctor',
    label: 'Doctor / heal',
    hint: 'Check storage and permissions',
    accent: 'yellow',
    short: 'Doctor',
    group: 'security',
  },
  {
    id: 'session',
    label: 'Session unlock',
    hint: 'Manage quick unlock',
    accent: 'yellow',
    short: 'Session',
    group: 'security',
  },
  {
    id: 'recovery',
    label: 'Recovery kit',
    hint: 'Create and check a recovery kit',
    accent: 'red',
    short: 'Recovery',
    group: 'security',
  },
  {
    id: 'run',
    label: 'Run preview',
    hint: 'Check secrets for a command',
    accent: 'yellow',
    short: 'Run',
    group: 'tools',
  },
  {
    id: 'policy',
    label: 'Policy / Grant / Audit',
    hint: 'Manage access and activity',
    accent: 'yellow',
    short: 'Policy',
    group: 'security',
  },
  {
    id: 'agent',
    label: 'Agent',
    hint: 'Broker dry-run',
    accent: 'yellow',
    short: 'Agent',
    group: 'tools',
  },
  {
    id: 'browse',
    label: 'Vault context / service / item',
    hint: 'Browse projects, services and items',
    accent: 'yellow',
    short: 'Browse',
    group: 'tools',
  },
  {
    id: 'help',
    label: 'Help',
    hint: 'Keymap',
    accent: 'white',
    short: 'Help',
    group: 'tools',
  },
  {
    id: 'showcase',
    label: 'Storage docs',
    hint: 'Docs only (no vault ops)',
    accent: 'yellow',
    short: 'Docs',
    group: 'tools',
  },
];
