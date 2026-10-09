import { APP_MENU, type AppScreenId } from './ids.js';
import type { AppKey, AppRouterState } from './router.js';
import { filteredCredentials } from './router.js';

/**
 * One action the current screen can perform, described in the same vocabulary
 * the footer chips use.
 *
 * `key` is the keystroke that would trigger the action, so choosing an entry in
 * the command palette goes through exactly the same router path as pressing it.
 * That single decision is what keeps the palette, the footer chips, and the
 * router from drifting apart: there is one behaviour and three descriptions.
 */
export interface ScreenCommand {
  /** Stable identifier, also used as the palette filter target. */
  readonly id: string;
  readonly keyLabel: string;
  readonly hint: string;
  readonly key: AppKey;
  /** Destructive actions are separated so the palette can mark them. */
  readonly danger?: boolean;
  /**
   * Returns why the action is unavailable right now, or null when it can run.
   * A blocked command stays visible with its reason instead of disappearing,
   * because "you cannot do this yet, here is the precondition" is the useful
   * answer.
   */
  readonly blocked: (state: AppRouterState) => string | null;
}

export interface CommandGroup {
  readonly label: string;
  readonly commands: readonly ScreenCommand[];
}

const KEY = (keyLabel: string): AppKey => ({ text: keyLabel });
const NAMED = (keyLabel: string, name: NonNullable<AppKey['name']>): AppKey => ({
  text: keyLabel,
  name,
});

const alwaysAvailable: ScreenCommand['blocked'] = () => null;

interface CommandOptions {
  readonly danger?: boolean;
  readonly blocked?: ScreenCommand['blocked'];
  /** Overrides the keystroke when the labelled key is not a single text key. */
  readonly key?: AppKey;
}

function command(
  id: string,
  keyLabel: string,
  hint: string,
  options: CommandOptions = {},
): ScreenCommand {
  return {
    id,
    keyLabel,
    hint,
    // Enter must carry `name: 'return'`, because that is what the router
    // dispatches on. Deriving it here keeps a displayed label and the key it
    // names from drifting apart.
    key:
      options.key ?? (keyLabel === 'Enter' ? NAMED(keyLabel, 'return') : KEY(keyLabel)),
    danger: options.danger ?? false,
    blocked: options.blocked ?? alwaysAvailable,
  };
}

/** An action that only applies when a row is selected. */
function needsRow(rowLabel: string): ScreenCommand['blocked'] {
  return (state) =>
    listLengthFor(state) > 0
      ? null
      : `Select ${rowLabel} first — j/k moves through the list.`;
}

function listLengthFor(state: AppRouterState): number {
  switch (state.screen) {
    case 'credentials':
      return filteredCredentials(state).length;
    case 'profiles':
      return state.snapshot.profiles.length;
    case 'vaults':
      return state.snapshot.vaults.length;
    case 'recovery':
      return state.snapshot.recovery.length;
    case 'policy':
      return state.snapshot.policies.length;
    default:
      return 0;
  }
}

function needsUnlock(verb: string): ScreenCommand['blocked'] {
  return (state) =>
    state.snapshot.home.unlocked ? null : `Unlock the vault first (u) to ${verb}.`;
}

const GLOBAL_COMMANDS: readonly ScreenCommand[] = [
  command('unlock', 'u', 'unlock vault', {
    blocked: (state) =>
      state.snapshot.home.unlocked ? 'The vault is already unlocked.' : null,
  }),
  command('lock', 'l', 'lock vault', {
    danger: true,
    blocked: (state) =>
      state.snapshot.home.unlocked ? null : 'The vault is already locked.',
  }),
  command('theme', 't', 'change theme'),
  command('toggle-ascii', 'a', 'toggle ascii'),
  command('help', '?', 'help'),
  command('next-screen', 'Tab', 'next screen', { key: { name: 'tab' } }),
  command('open-menu', 'Esc', 'back to home', { key: { name: 'escape' } }),
  command('quit', 'q', 'quit', { danger: true }),
];

function screenCommands(screen: AppScreenId): readonly ScreenCommand[] {
  switch (screen) {
    case 'home':
      return [
        // Home acts on the menu cursor, which always has twelve destinations, so
        // there is no "select a row first" precondition to state here.
        command('home-open', 'Enter', 'open selection'),
        command('refresh', 'r', 'refresh status'),
      ];
    case 'profiles':
      return [
        command('profile-use', 'Enter', 'use profile', {
          blocked: needsRow('a profile'),
        }),
        command('profile-new-file', 'n', 'new file profile'),
        command('profile-new-mongo', 'm', 'new mongodb profile'),
        command('profile-remove', 'x', 'remove profile', {
          danger: true,
          blocked: needsRow('a profile'),
        }),
      ];
    case 'vaults':
      return [
        command('vault-use', 'Enter', 'use vault', { blocked: needsRow('a vault') }),
        command('vault-new', 'n', 'new vault', {
          blocked: needsUnlock('create a vault'),
        }),
      ];
    case 'credentials':
      return [
        command('credential-detail', 'Enter', 'view masked detail', {
          blocked: needsRow('a credential'),
        }),
        command('credential-copy', 'c', 'copy to clipboard', {
          blocked: needsRow('a credential'),
        }),
        command('credential-reveal', 'r', 'reveal value', {
          danger: true,
          blocked: (state) =>
            needsRow('a credential')(state) ?? needsUnlock('reveal a value')(state),
        }),
        command('credential-put', 'n', 'add credential', {
          blocked: needsUnlock('add a credential'),
        }),
        command('credential-rename', 'm', 'rename', {
          blocked: (state) =>
            needsRow('a credential')(state) ??
            needsUnlock('rename a credential')(state),
        }),
        command('credential-remove', 'x', 'remove', {
          danger: true,
          blocked: (state) =>
            needsRow('a credential')(state) ??
            needsUnlock('remove a credential')(state),
        }),
        command('credential-search', '/', 'filter by name', {
          blocked: needsRow('a credential'),
        }),
      ];
    case 'session':
      return [
        command('session-enable', 'n', 'enable OS session unlock', {
          blocked: needsUnlock('enable session unlock'),
        }),
        command('session-remove', 'x', 'remove session unlock', {
          danger: true,
          blocked: (state) =>
            state.snapshot.session.enabled ? null : 'No session unlock is enabled.',
        }),
        command('session-refresh', 'Enter', 'refresh status'),
      ];
    case 'doctor':
      return [command('doctor-run', 'd', 'run health checks')];
    case 'recovery':
      return [
        command('recovery-create', 'n', 'create recovery kit'),
        command('recovery-verify', 'v', 'verify recovery kit'),
        command('recovery-revoke', 'x', 'revoke slot', {
          danger: true,
          blocked: needsRow('a recovery slot'),
        }),
      ];
    case 'run':
      return [
        command('run-preview', 'p', 'preview a run', {
          blocked: needsUnlock('preview a run'),
        }),
      ];
    case 'policy':
      return [
        command('policy-refresh', 'Enter', 'refresh list', {
          blocked: needsUnlock('read policies'),
        }),
        command('policy-new', 'n', 'new policy'),
        command('policy-remove', 'x', 'remove policy', {
          danger: true,
          // Naming the row, not just "a policy", so the message is actionable.
          blocked: (state) => {
            const id = selectedPolicyRow(state);
            return id === null
              ? 'Select a policy row first — j/k moves through the list.'
              : `Remove policy '${id}'?`;
          },
        }),
        command('grant-new', 'g', 'new grant'),
        command('grant-revoke', 'r', 'revoke grant', {
          danger: true,
          blocked: (state) => {
            const id = selectedGrantRow(state);
            return id === null
              ? 'Select a grant row first — j/k moves through the list.'
              : `Revoke grant '${id}'?`;
          },
        }),
      ];
    case 'agent':
      return [command('agent-validate', 'g', 'validate agent config')];
    case 'browse':
      return [
        command('browse-refresh', 'Enter', 'reload vault tree', {
          blocked: needsUnlock('browse the vault'),
        }),
      ];
    case 'help':
      return [
        command('help-topic', 'j/k', 'choose topic', {
          key: { text: 'j' },
          blocked: needsRow('a help topic'),
        }),
      ];
    case 'showcase':
      return [];
  }
}

/** The selected row's id when it is a policy, otherwise null. */
function selectedPolicyRow(state: AppRouterState): string | null {
  const row = state.snapshot.policies[state.listIndex];
  return row?.kind === 'policy' ? row.id : null;
}

/** The selected row's id when it is a grant, otherwise null. */
function selectedGrantRow(state: AppRouterState): string | null {
  const row = state.snapshot.policies[state.listIndex];
  return row?.kind === 'grant' ? row.id : null;
}

/**
 * Everything the current screen can do, in the order it should be read.
 *
 * Screen actions come first because they are what the user came for; the global
 * set follows because it is always the same. Grouping them keeps the palette
 * scannable, which is the whole point: a flat 30-item menu is not discoverable
 * either.
 */
export function commandGroups(state: AppRouterState): readonly CommandGroup[] {
  const screen = screenCommands(state.screen);
  const groups: CommandGroup[] = [];
  if (screen.length > 0) {
    const menuLabel =
      APP_MENU.find((entry) => entry.id === state.screen)?.label ?? 'This screen';
    groups.push({ label: menuLabel, commands: screen });
  }
  groups.push({ label: 'Always available', commands: GLOBAL_COMMANDS });
  return groups;
}

/** Flattened, order-preserving list used for cursor movement and digits 1-9. */
export function allCommands(state: AppRouterState): readonly ScreenCommand[] {
  return commandGroups(state).flatMap((group) => group.commands);
}

/**
 * Substring match over label, hint, key, and id. Matching everything when the
 * filter is empty keeps the palette usable as a plain menu.
 */
export function filterCommands(
  commands: readonly ScreenCommand[],
  filter: string,
): readonly ScreenCommand[] {
  const needle = filter.trim().toLowerCase();
  if (needle.length === 0) return commands;
  return commands.filter((entry) =>
    `${entry.keyLabel} ${entry.hint} ${entry.id}`.toLowerCase().includes(needle),
  );
}

/** True when a key opens the palette from the current state. */
export function isPaletteTrigger(key: AppKey): boolean {
  return key.text === ':' || (key.ctrl === true && key.text?.toLowerCase() === 'k');
}
