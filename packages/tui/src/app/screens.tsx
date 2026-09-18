import { Box, Text } from 'ink';
import type { ReactElement } from 'react';

import { BrandBanner } from '../showcase.js';
import { sanitizeTerminalText, secretMask } from '../terminal-text.js';
import type { AppSnapshot } from './backend.js';
import { APP_MENU } from './ids.js';
import type { AppOverlay, AppRouterState } from './router.js';
import {
  doctorStatusAccent,
  screenAccent,
  toneAccent,
  type AppAccent,
} from './theme.js';
import {
  CardRow,
  KeyChip,
  ModalFrame,
  Panel,
  SelectRow,
  StatusPill,
} from './widgets.js';

function tint(
  enabled: boolean,
  accent: AppAccent,
): Readonly<{ color: AppAccent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

function overlayCopy(
  overlay: AppOverlay,
  query: string,
  ascii: boolean,
): Readonly<{ title: string; body: string; accent: AppAccent; hint?: string }> | null {
  if (overlay === 'none') return null;
  const masked = '*'.repeat(Math.min(query.length, 32));
  const q = safe(query, ascii);
  switch (overlay) {
    case 'confirm-reveal':
      return {
        title: 'Confirm reveal',
        body: 'REVEAL selected secret? y/n',
        accent: 'red',
      };
    case 'confirm-lock':
      return { title: 'Confirm lock', body: 'Lock session? y/n', accent: 'yellow' };
    case 'confirm-remove':
      return {
        title: 'Confirm remove',
        body: 'Remove credential? y/n',
        accent: 'red',
      };
    case 'confirm-revoke-last':
      return {
        title: 'Recovery blocked',
        body: 'Final recovery slot — revoke blocked without CLI warning. Esc/n',
        accent: 'red',
      };
    case 'confirm-recovery-revoke':
      return {
        title: 'Revoke recovery',
        body: 'Revoke recovery slot? y/n',
        accent: 'red',
      };
    case 'confirm-policy-remove':
      return {
        title: 'Remove policy',
        body: 'Remove policy? y/n',
        accent: 'yellow',
      };
    case 'confirm-grant-revoke':
      return {
        title: 'Revoke grant',
        body: 'Revoke grant? y/n',
        accent: 'yellow',
      };
    case 'input-search':
      return { title: 'Search', body: `Search: ${q}_`, accent: 'cyan' };
    case 'input-run':
      return { title: 'Run preview', body: `Run creds: ${q}_`, accent: 'cyan' };
    case 'input-passphrase':
      return {
        title: 'Unlock vault',
        body: `Passphrase: ${masked}_`,
        accent: 'yellow',
        hint: 'Paste works (Ctrl+Shift+V / Cmd+V)',
      };
    case 'input-put-name':
      return { title: 'Put credential', body: `New name: ${q}_`, accent: 'green' };
    case 'input-put-value':
      return {
        title: 'Put value',
        body: `Value: ${masked}_`,
        accent: 'green',
        hint: 'Paste works (Ctrl+Shift+V / Cmd+V)',
      };
    case 'input-rename':
      return { title: 'Rename', body: `Rename to: ${q}_`, accent: 'green' };
    case 'input-profile-id':
      return {
        title: 'File profile',
        body: `Profile id: ${q}_`,
        accent: 'blue',
      };
    case 'input-profile-data-file':
      return {
        title: 'File profile',
        body: `Data file: ${q}_`,
        accent: 'blue',
      };
    case 'input-profile-key-file':
      return {
        title: 'File profile',
        body: `Key file: ${q}_`,
        accent: 'blue',
      };
    case 'input-profile-passphrase':
    case 'input-profile-passphrase-confirm':
      return {
        title: 'File profile passphrase',
        body: `Passphrase: ${masked}_`,
        accent: 'yellow',
      };
    case 'input-mongo-profile-id':
      return {
        title: 'Mongo profile',
        body: `Mongo profile id: ${q}_`,
        accent: 'blue',
      };
    case 'input-mongo-database':
      return {
        title: 'Mongo profile',
        body: `Mongo database: ${q}_`,
        accent: 'blue',
      };
    case 'input-mongo-key-file':
      return {
        title: 'Mongo profile',
        body: `Mongo key file: ${q}_`,
        accent: 'blue',
      };
    case 'input-mongo-url':
    case 'input-unlock-mongo-url':
      return {
        title:
          overlay === 'input-unlock-mongo-url' ? 'Unlock vault (MongoDB)' : 'Mongo URL',
        body: `Mongo URL: ${masked}_`,
        accent: 'yellow',
        hint: 'Paste works (Ctrl+Shift+V / Cmd+V)',
      };
    case 'input-mongo-passphrase':
    case 'input-mongo-passphrase-confirm':
      return {
        title: 'Mongo passphrase',
        body: `Passphrase: ${masked}_`,
        accent: 'yellow',
      };
    case 'input-recovery-file':
    case 'input-recovery-verify-file':
      return {
        title: 'Recovery file',
        body: `Recovery file: ${q}_`,
        accent: 'red',
      };
    case 'input-recovery-passphrase':
    case 'input-recovery-passphrase-confirm':
    case 'input-recovery-verify-passphrase':
      return {
        title: 'Recovery passphrase',
        body: `Recovery passphrase: ${masked}_`,
        accent: 'red',
      };
    case 'input-policy-id':
      return {
        title: 'Create policy',
        body: `Policy id: ${q}_`,
        accent: 'blue',
      };
    case 'input-policy-secret':
      return {
        title: 'Create policy',
        body: `Policy secret: ${q}_`,
        accent: 'blue',
      };
    case 'input-policy-command':
      return {
        title: 'Create policy',
        body: `Policy command: ${q}_`,
        accent: 'blue',
      };
    case 'input-grant-secret':
      return {
        title: 'Create grant',
        body: `Grant secret: ${q}_`,
        accent: 'blue',
      };
    case 'input-grant-command':
      return {
        title: 'Create grant',
        body: `Grant command: ${q}_`,
        accent: 'blue',
      };
    case 'input-grant-ttl':
      return {
        title: 'Create grant',
        body: `Grant TTL: ${q}_`,
        accent: 'blue',
      };
    case 'input-agent-name':
      return {
        title: 'Agent dry-run',
        body: `Agent name: ${q}_`,
        accent: 'magenta',
        hint: 'Must match an agent entry in the project config',
      };
    case 'input-agent-config':
      return {
        title: 'Agent config (optional)',
        body: `Config path: ${q}_`,
        accent: 'magenta',
        hint: 'Empty Enter uses default kavrix.yaml discovery',
      };
  }
}

export function AppChrome({
  state,
  children,
}: Readonly<{
  state: AppRouterState;
  children: ReactElement | ReactElement[];
}>): ReactElement {
  const { color, ascii, width, height } = state;
  const home = state.snapshot.home;
  const accent = screenAccent(state.screen);
  const overlay = overlayCopy(state.overlay, state.query, ascii);
  const ellipsis = ascii ? '...' : '…';
  const vaultShort =
    home.vaultId === null
      ? '-'
      : home.vaultId.length > 12
        ? `${home.vaultId.slice(0, 10)}${ellipsis}`
        : home.vaultId;

  return (
    <Box flexDirection="column" width={width} height={height}>
      <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
        <BrandBanner color={color} ascii={ascii} dualTone />
        <Box flexDirection="row" columnGap={1} flexWrap="wrap" marginTop={0}>
          <StatusPill
            label="lock"
            value={home.unlocked ? 'open' : 'locked'}
            accent={home.unlocked ? 'green' : 'yellow'}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="profile"
            value={home.profileId ?? '-'}
            accent="blue"
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="vault"
            value={vaultShort}
            accent="magenta"
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="creds"
            value={String(home.credentialCount)}
            accent="green"
            color={color}
            ascii={ascii}
          />
        </Box>
      </Panel>

      <Box flexDirection="column" flexGrow={1} paddingX={0} paddingY={0}>
        {overlay === null ? (
          children
        ) : (
          <ModalFrame
            title={overlay.title}
            accent={overlay.accent}
            ascii={ascii}
            color={color}
            width={width}
          >
            <Text bold {...tint(color, overlay.accent)}>
              {safe(overlay.body, ascii)}
            </Text>
            {overlay.hint === undefined ? null : (
              <Text {...tint(color, 'cyan')}>{safe(overlay.hint, ascii)}</Text>
            )}
            <Text {...tint(color, 'gray')}>
              {safe(
                overlay.title.startsWith('Confirm') ||
                  overlay.title.startsWith('Revoke') ||
                  overlay.title.startsWith('Remove') ||
                  overlay.title.startsWith('Recovery blocked')
                  ? 'y confirm · n/Esc cancel'
                  : 'Enter continue · Esc cancel',
                ascii,
              )}
            </Text>
          </ModalFrame>
        )}
      </Box>

      <Footer state={state} />
    </Box>
  );
}

function Footer({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, message, snapshot } = state;
  const notice = message ?? snapshot.notice;
  const noticeAccent = toneAccent(snapshot.noticeTone);
  const sep = ascii ? ' | ' : ' · ';
  const chips = footerChips(state.screen);
  return (
    <Box flexDirection="column">
      {notice === null ? null : (
        <Panel accent={noticeAccent} ascii={ascii} color={color} paddingX={1}>
          <Text {...tint(color, noticeAccent)}>{safe(notice, ascii)}</Text>
        </Panel>
      )}
      <Panel accent="gray" ascii={ascii} color={color} paddingX={1}>
        <Box flexDirection="row" columnGap={1} flexWrap="wrap">
          {chips.map((chip, index) => (
            <Box key={`${chip.keyLabel}-${chip.hint}`} flexDirection="row">
              {index === 0 ? null : <Text {...tint(color, 'gray')}>{sep}</Text>}
              <KeyChip
                keyLabel={chip.keyLabel}
                hint={chip.hint}
                color={color}
                keyAccent={chip.accent}
              />
            </Box>
          ))}
        </Box>
      </Panel>
    </Box>
  );
}

function footerChips(screen: AppRouterState['screen']): readonly Readonly<{
  keyLabel: string;
  hint: string;
  accent: AppAccent;
}>[] {
  const commonTail = [
    { keyLabel: 'Esc', hint: 'home', accent: 'yellow' as const },
    { keyLabel: '?', hint: 'help', accent: 'white' as const },
    { keyLabel: 'q', hint: 'quit', accent: 'red' as const },
  ];
  switch (screen) {
    case 'credentials':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: 'cyan' },
        { keyLabel: 'c', hint: 'copy', accent: 'green' },
        { keyLabel: 'r', hint: 'reveal', accent: 'red' },
        { keyLabel: 'n', hint: 'put', accent: 'green' },
        { keyLabel: 'm', hint: 'rename', accent: 'magenta' },
        { keyLabel: 'x', hint: 'remove', accent: 'red' },
        { keyLabel: '/', hint: 'search', accent: 'magenta' },
        { keyLabel: 'u', hint: 'unlock', accent: 'green' },
        ...commonTail,
      ];
    case 'profiles':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: 'cyan' },
        { keyLabel: 'Enter', hint: 'use', accent: 'green' },
        { keyLabel: 'n', hint: 'file', accent: 'blue' },
        { keyLabel: 'm', hint: 'mongo', accent: 'blue' },
        ...commonTail,
      ];
    case 'home':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: 'cyan' },
        { keyLabel: 'Enter', hint: 'open', accent: 'green' },
        { keyLabel: 'u', hint: 'unlock', accent: 'green' },
        { keyLabel: 'l', hint: 'lock', accent: 'yellow' },
        { keyLabel: 'r', hint: 'refresh', accent: 'cyan' },
        ...commonTail,
      ];
    default:
      return [
        { keyLabel: 'j/k', hint: 'move', accent: 'cyan' },
        { keyLabel: 'Enter', hint: 'open', accent: 'green' },
        { keyLabel: 'u', hint: 'unlock', accent: 'green' },
        { keyLabel: 'l', hint: 'lock', accent: 'yellow' },
        ...commonTail,
      ];
  }
}

export function HomeScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot, menuIndex, width } = state;
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  const wide = width >= 80;
  const statusPanel = (
    <Panel
      title="Home / Dashboard"
      accent="cyan"
      ascii={ascii}
      color={color}
      {...(wide ? { flexGrow: 1 } : {})}
      paddingX={1}
      paddingY={0}
    >
      <StatusBlock snapshot={snapshot} color={color} ascii={ascii} />
    </Panel>
  );
  const navPanel = (
    <Panel
      title="Navigate"
      accent="magenta"
      ascii={ascii}
      color={color}
      {...(wide ? { flexGrow: 1 } : {})}
      paddingX={1}
      paddingY={0}
    >
      {(() => {
        const labelWidth = Math.max(...entries.map((entry) => entry.label.length), 8);
        return entries.map((entry, index) => {
          const active = index === menuIndex;
          return (
            <SelectRow
              key={entry.id}
              active={active}
              label={entry.label}
              hint={entry.hint}
              accent={entry.accent}
              color={color}
              ascii={ascii}
              labelWidth={labelWidth}
            />
          );
        });
      })()}
    </Panel>
  );
  if (wide) {
    return (
      <Box flexDirection="row" columnGap={1} flexGrow={1}>
        {statusPanel}
        {navPanel}
      </Box>
    );
  }
  return (
    <Box flexDirection="column" gap={0} flexGrow={1}>
      {statusPanel}
      {navPanel}
    </Box>
  );
}

function StatusBlock({
  snapshot,
  color,
  ascii,
}: Readonly<{ snapshot: AppSnapshot; color: boolean; ascii: boolean }>): ReactElement {
  const home = snapshot.home;
  return (
    <Box flexDirection="column">
      <Text {...tint(color, home.unlocked ? 'green' : 'yellow')}>
        {home.unlocked
          ? ascii
            ? '[OK] Unlocked'
            : '\u25cf Unlocked'
          : ascii
            ? '[!] Locked'
            : '\u25cb Locked'}
      </Text>
      <Text>
        Datastore:{' '}
        <Text {...tint(color, 'cyan')}>{safe(home.datastore ?? '(none)', ascii)}</Text>
      </Text>
      <Text {...tint(color, 'gray')}>{safe(home.message, ascii)}</Text>
    </Box>
  );
}

export function ProfilesScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii } = state;
  return (
    <Box flexDirection="column" flexGrow={1}>
      <ListScreen
        state={state}
        title="Profiles"
        accent="blue"
        empty="No datastore profiles found. Press n (file) or m (mongodb)."
        rows={state.snapshot.profiles.map((profile) => ({
          id: profile.id,
          primary: `${profile.id} (${profile.datastore})${profile.selected ? ' *' : ''}`,
          secondary: profile.detail,
        }))}
      />
      <Text {...tint(color, 'gray')}>
        {safe(
          'Enter = use · n = file profile · m = mongodb profile (URL+passphrase on stdin frames)',
          ascii,
        )}
      </Text>
    </Box>
  );
}

export function VaultsScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Vaults"
      accent="magenta"
      empty="No vaults yet. Select a profile, then unlock (u)."
      rows={state.snapshot.vaults.map((vault) => ({
        id: vault.id,
        primary: `${vault.id}${vault.selected ? ' *' : ''}`,
        secondary: vault.detail,
      }))}
    />
  );
}

export function CredentialsScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, listIndex, revealedName, revealedValue, snapshot } = state;
  return (
    <Box flexDirection="column" flexGrow={1}>
      <Panel
        title="Credentials"
        accent="green"
        ascii={ascii}
        color={color}
        paddingX={1}
      >
        <Text {...tint(color, 'gray')}>
          Values stay masked. c copy · r then y REVEAL (15s) · n put · m rename · x
          remove.
        </Text>
        {state.snapshot.credentials.length === 0 ? (
          <Text {...tint(color, 'yellow')}>
            {safe(
              snapshot.home.unlocked
                ? 'No credentials yet. Press n to put one.'
                : 'Vault locked. Press u to unlock, then n to put.',
              ascii,
            )}
          </Text>
        ) : (
          state.snapshot.credentials.map((credential, index) => {
            const active = index === listIndex;
            const revealed = revealedName === credential.name;
            return (
              <Box key={credential.name} flexDirection="column" marginTop={0}>
                <CardRow
                  active={active}
                  title={credential.name}
                  subtitle={revealed ? '' : credential.maskedValue || secretMask(ascii)}
                  accent="green"
                  color={color}
                  ascii={ascii}
                />
                {revealed ? (
                  <Panel
                    accent="red"
                    ascii={ascii}
                    color={color}
                    paddingX={1}
                    kind="panel"
                  >
                    <Text bold {...tint(color, 'red')}>
                      {safe(`REVEAL: ${revealedValue ?? ''}`, ascii)}
                    </Text>
                  </Panel>
                ) : null}
              </Box>
            );
          })
        )}
      </Panel>
    </Box>
  );
}

export function DoctorScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, listIndex } = state;
  const rows = state.snapshot.doctor;
  return (
    <Panel
      title="Doctor"
      accent="yellow"
      ascii={ascii}
      color={color}
      paddingX={1}
      flexGrow={1}
    >
      {rows.length === 0 ? (
        <Text {...tint(color, 'yellow')}>
          {safe('Press d to run doctor checks.', ascii)}
        </Text>
      ) : (
        rows.map((check, index) => {
          const active = index === listIndex;
          const statusAccent = doctorStatusAccent(check.status);
          return (
            <SelectRow
              key={check.name}
              active={active}
              label={`${check.status.toUpperCase()} ${check.name}`}
              hint={check.detail}
              accent={statusAccent}
              color={color}
              ascii={ascii}
            />
          );
        })
      )}
    </Panel>
  );
}

export function RecoveryScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Recovery"
      accent="red"
      empty="No recovery slots. n create · v verify · Enter/x revoke (last slot blocked)."
      rows={state.snapshot.recovery.map((slot) => ({
        id: slot.slotId,
        primary: `${slot.slotId} [${slot.status}]`,
        secondary: slot.detail,
      }))}
    />
  );
}

export function RunScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  return (
    <Panel
      title="Run (dry preview)"
      accent="cyan"
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Text {...tint(color, 'gray')}>
        Press p, type credential names, Enter. Secrets are never placed on argv.
      </Text>
      <Text>{safe(snapshot.runPreview, ascii)}</Text>
    </Panel>
  );
}

export function PolicyScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Policy / Grant / Audit"
      accent="blue"
      empty="No rows. Enter refresh · n policy · x remove · g grant · r revoke grant."
      rows={state.snapshot.policies.map((row) => ({
        id: `${row.kind}:${row.id}`,
        primary: `${row.kind} ${row.id}`,
        secondary: row.summary,
      }))}
    />
  );
}

export function AgentScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  return (
    <Panel title="Agent" accent="magenta" ascii={ascii} color={color} paddingX={1}>
      <Text {...tint(color, 'gray')}>
        {safe(
          'Press g to run kavrix agent run --dry-run. You will be asked for a real agent name (and optional --config). No default agent is invented.',
          ascii,
        )}
      </Text>
      <Text>{safe(snapshot.agentStatus || '(no dry-run yet)', ascii)}</Text>
    </Panel>
  );
}

export function StorageDocsScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  const home = snapshot.home;
  const doctor = snapshot.doctor;
  return (
    <Panel
      title="Storage docs (read-only)"
      accent="yellow"
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Text bold {...tint(color, 'yellow')}>
        {safe('DOCS ONLY — no vault create/unlock/mutate from this screen.', ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>
        {safe(
          'Interactive storage picker lives in kavrix init. This TUI screen only summarizes the active profile.',
          ascii,
        )}
      </Text>
      <Text>
        {safe(
          `Active profile: ${home.profileId ?? '(none)'} · datastore: ${home.datastore ?? '(none)'} · vault: ${home.vaultId ?? '(none)'} · ${home.unlocked ? 'unlocked' : 'locked'}`,
          ascii,
        )}
      </Text>
      <Text {...tint(color, 'gray')}>{safe(home.message, ascii)}</Text>
      <Text bold {...(color ? { color: 'cyan' as const } : {})}>
        {safe('Storage choices (from init docs)', ascii)}
      </Text>
      <Text>
        {safe('• Local encrypted file — ciphertext stays on this device.', ascii)}
      </Text>
      <Text>
        {safe('• MongoDB — sync opaque ciphertext through your own deployment.', ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>
        {safe(
          'Both keep client-side encryption; the datastore never receives a vault key.',
          ascii,
        )}
      </Text>
      {doctor.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text bold {...(color ? { color: 'cyan' as const } : {})}>
            {safe('Doctor (last run)', ascii)}
          </Text>
          {doctor.slice(0, 8).map((check) => (
            <Text key={check.name}>
              {safe(
                `${check.status.toUpperCase()} ${check.name}: ${check.detail}`,
                ascii,
              )}
            </Text>
          ))}
        </Box>
      ) : (
        <Text {...tint(color, 'gray')}>
          {safe(
            'No doctor results yet — open Doctor and press d to run real checks.',
            ascii,
          )}
        </Text>
      )}
    </Panel>
  );
}

export function BrowseScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Context / Service / Item"
      accent="green"
      empty="No browse rows. Unlock and press Enter to load context/service/item lists."
      rows={state.snapshot.browse.map((node) => ({
        id: node.id,
        primary: `${node.kind}: ${node.label}`,
        secondary: node.detail,
      }))}
    />
  );
}

export function HelpScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii } = state;
  const lines = [
    '--- Getting started ---',
    '1) Profiles: n file or m mongodb, then Enter to select',
    '2) Unlock with u (paste works in passphrase / URL overlays)',
    '3) Credentials: n put · c copy (no on-screen plaintext) · r then y REVEAL',
    '',
    '--- Copy / paste ---',
    'Paste into overlays: Ctrl+Shift+V / Cmd+V (bracketed paste; never submits Enter)',
    'Copy credential: c on Credentials (clipboard clears in ~30s; OSC 52 preferred)',
    'Terminal select/copy still works (Shift+drag if the terminal needs it)',
    'Mouse tracking is NOT enabled — OS drag-select is not stolen',
    '',
    '--- Keymap ---',
    'Global: j/k or arrows move, Enter open, Esc Home, q quit',
    'Credentials: c copy · r reveal · n put · m rename · x remove · / search',
    'Profiles: Enter use · n file · m mongodb (URL+passphrase on stdin frames)',
    'Session: u unlock · l lock (clears revealed state)',
    'Doctor: d · Recovery: n/c create · v verify · Enter/x revoke',
    'Run: p · Agent: g dry-run (prompts for agent name) · Policy: n/x/g/r · Browse: Enter refresh',
    'Display: a ASCII · NO_COLOR / TERM=dumb disable color · win32 ASCII default',
  ];
  return (
    <Panel
      title="Help / Keymap"
      accent="white"
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      {lines.map((line, index) => (
        <Text key={`${String(index)}:${line}`}>
          {safe(line.length === 0 ? ' ' : line, ascii)}
        </Text>
      ))}
    </Panel>
  );
}

function ListScreen({
  state,
  title,
  accent,
  empty,
  rows,
}: Readonly<{
  state: AppRouterState;
  title: string;
  accent: AppAccent;
  empty: string;
  rows: readonly Readonly<{ id: string; primary: string; secondary: string }>[];
}>): ReactElement {
  const { color, ascii, listIndex } = state;
  return (
    <Panel
      title={title}
      accent={accent}
      ascii={ascii}
      color={color}
      paddingX={1}
      flexGrow={1}
    >
      {rows.length === 0 ? (
        <Text {...tint(color, 'yellow')}>{safe(empty, ascii)}</Text>
      ) : (
        rows.map((row, index) => {
          const active = index === listIndex;
          return (
            <SelectRow
              key={row.id}
              active={active}
              label={row.primary}
              hint={row.secondary}
              accent={accent}
              color={color}
              ascii={ascii}
            />
          );
        })
      )}
    </Panel>
  );
}

export function renderActiveScreen(state: AppRouterState): ReactElement {
  switch (state.screen) {
    case 'home':
      return <HomeScreen state={state} />;
    case 'profiles':
      return <ProfilesScreen state={state} />;
    case 'vaults':
      return <VaultsScreen state={state} />;
    case 'credentials':
      return <CredentialsScreen state={state} />;
    case 'doctor':
      return <DoctorScreen state={state} />;
    case 'recovery':
      return <RecoveryScreen state={state} />;
    case 'run':
      return <RunScreen state={state} />;
    case 'policy':
      return <PolicyScreen state={state} />;
    case 'agent':
      return <AgentScreen state={state} />;
    case 'browse':
      return <BrowseScreen state={state} />;
    case 'help':
      return <HelpScreen state={state} />;
    case 'showcase':
      return <StorageDocsScreen state={state} />;
  }
}
