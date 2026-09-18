import { Box, Text } from 'ink';
import type { ReactElement } from 'react';

import { BrandBanner } from '../showcase.js';
import { sanitizeTerminalText, secretMask } from '../terminal-text.js';
import type { AppSnapshot } from './backend.js';
import { APP_MENU } from './ids.js';
import type { AppRouterState } from './router.js';
import {
  boxLine,
  pointerGlyph,
  sectionTitle,
  toneAccent,
  type AppAccent,
} from './theme.js';

function tint(
  enabled: boolean,
  accent: AppAccent,
): Readonly<{ color: AppAccent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

export function AppChrome({
  state,
  children,
}: Readonly<{ state: AppRouterState; children: ReactElement | ReactElement[] }>): ReactElement {
  const { color, ascii, width } = state;
  const home = state.snapshot.home;
  return (
    <Box flexDirection="column" width={width}>
      <BrandBanner color={color} ascii={ascii} />
      <Text {...tint(color, 'gray')}>
        {safe(
          `profile=${home.profileId ?? '-'} vault=${home.vaultId ?? '-'} unlocked=${home.unlocked ? 'yes' : 'no'} creds=${String(home.credentialCount)}`,
          ascii,
        )}
      </Text>
      <Text {...tint(color, 'cyan')}>{boxLine(ascii, Math.min(width, 72))}</Text>
      {children}
      <Text {...tint(color, 'cyan')}>{boxLine(ascii, Math.min(width, 72))}</Text>
      <Footer state={state} />
    </Box>
  );
}

function Footer({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, overlay, message, snapshot } = state;
  const notice = message ?? snapshot.notice;
  const noticeAccent = toneAccent(snapshot.noticeTone);
  let overlayHint = '';
  if (overlay === 'confirm-reveal') overlayHint = ' REVEAL? y/n';
  if (overlay === 'confirm-lock') overlayHint = ' Lock session? y/n';
  if (overlay === 'confirm-remove') overlayHint = ' Remove credential? y/n';
  if (overlay === 'confirm-revoke-last')
    overlayHint = ' Final recovery slot — revoke blocked without CLI warning. Esc/n';
  if (overlay === 'input-search') overlayHint = ` Search: ${safe(state.query, ascii)}_`;
  if (overlay === 'input-run') overlayHint = ` Run creds: ${safe(state.query, ascii)}_`;
  if (overlay === 'input-passphrase')
    overlayHint = ` Passphrase: ${'*'.repeat(Math.min(state.query.length, 32))}_`;
  if (overlay === 'input-put-name')
    overlayHint = ` New name: ${safe(state.query, ascii)}_`;
  if (overlay === 'input-put-value')
    overlayHint = ` Value: ${'*'.repeat(Math.min(state.query.length, 32))}_`;
  if (overlay === 'input-rename')
    overlayHint = ` Rename to: ${safe(state.query, ascii)}_`;
  return (
    <Box flexDirection="column">
      {notice === null ? null : (
        <Text {...tint(color, noticeAccent)}>{safe(notice, ascii)}</Text>
      )}
      {overlayHint.length === 0 ? null : (
        <Text bold {...tint(color, 'yellow')}>
          {safe(overlayHint, ascii)}
        </Text>
      )}
      <Text {...tint(color, 'gray')}>
        {ascii
          ? 'j/k move | Enter open | Esc home | / search | u unlock | l lock | a ascii | ? help | q quit'
          : 'j/k move · Enter open · Esc home · / search · u unlock · l lock · a ascii · ? help · q quit'}
      </Text>
    </Box>
  );
}

export function HomeScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot, menuIndex } = state;
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  const pointer = pointerGlyph(ascii);
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, 'cyan')}>
        {sectionTitle('Home / Dashboard', ascii)}
      </Text>
      <StatusBlock snapshot={snapshot} color={color} ascii={ascii} />
      <Text bold {...tint(color, 'magenta')}>
        Navigate
      </Text>
      {entries.map((entry, index) => {
        const active = index === menuIndex;
        return (
          <Text key={entry.id} bold={active} {...tint(color, active ? entry.accent : 'gray')}>
            {active ? pointer : ' '} {safe(entry.label, ascii)}{' '}
            <Text {...tint(color, 'gray')}>{safe(entry.hint, ascii)}</Text>
          </Text>
        );
      })}
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
        {home.unlocked ? (ascii ? '[OK] Unlocked' : '● Unlocked') : ascii ? '[!] Locked' : '○ Locked'}
      </Text>
      <Text>
        Datastore:{' '}
        <Text {...tint(color, 'cyan')}>{safe(home.datastore ?? '(none)', ascii)}</Text>
      </Text>
      <Text>{safe(home.message, ascii)}</Text>
    </Box>
  );
}

export function ProfilesScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Profiles"
      accent="blue"
      empty="No datastore profiles found."
      rows={state.snapshot.profiles.map((profile) => ({
        id: profile.id,
        primary: `${profile.id} (${profile.datastore})${profile.selected ? ' *' : ''}`,
        secondary: profile.detail,
      }))}
    />
  );
}

export function VaultsScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Vaults"
      accent="magenta"
      empty="No vaults in the current profile."
      rows={state.snapshot.vaults.map((vault) => ({
        id: vault.id,
        primary: `${vault.id}${vault.selected ? ' *' : ''}`,
        secondary: vault.detail,
      }))}
    />
  );
}

export function CredentialsScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, listIndex, revealedName, revealedValue } = state;
  const pointer = pointerGlyph(ascii);
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, 'green')}>
        {sectionTitle('Credentials', ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>
        Values stay masked. n put · m rename · x remove · r then y REVEAL (15s).
      </Text>
      {state.snapshot.credentials.length === 0 ? (
        <Text {...tint(color, 'yellow')}>No credentials (unlock or refresh).</Text>
      ) : (
        state.snapshot.credentials.map((credential, index) => {
          const active = index === listIndex;
          const revealed = revealedName === credential.name;
          return (
            <Box key={credential.name} flexDirection="column">
              <Text bold={active} {...tint(color, active ? 'green' : 'gray')}>
                {active ? pointer : ' '} {safe(credential.name, ascii)}
              </Text>
              <Text {...tint(color, revealed ? 'red' : 'gray')}>
                {'    '}
                {revealed
                  ? safe(`REVEAL: ${revealedValue ?? ''}`, ascii)
                  : safe(credential.maskedValue || secretMask(ascii), ascii)}
              </Text>
            </Box>
          );
        })
      )}
    </Box>
  );
}

export function DoctorScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Doctor"
      accent="yellow"
      empty="Press d to run doctor checks."
      rows={state.snapshot.doctor.map((check) => ({
        id: check.name,
        primary: `${check.status.toUpperCase()} ${check.name}`,
        secondary: check.detail,
      }))}
    />
  );
}

export function RecoveryScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Recovery"
      accent="red"
      empty="No recovery slot metadata loaded."
      rows={state.snapshot.recovery.map((slot) => ({
        id: slot.slotId,
        primary: `${slot.slotId} [${slot.status}]`,
        secondary: slot.detail,
      }))}
    />
  );
}

export function RunScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, 'cyan')}>
        {sectionTitle('Run (dry preview)', ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>
        Press p, type credential names, Enter. Secrets are never placed on argv.
      </Text>
      <Text>{safe(snapshot.runPreview, ascii)}</Text>
    </Box>
  );
}

export function PolicyScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Policy / Grant / Audit"
      accent="blue"
      empty="No policy, grant, or audit rows."
      rows={state.snapshot.policies.map((row) => ({
        id: `${row.kind}:${row.id}`,
        primary: `${row.kind} ${row.id}`,
        secondary: row.summary,
      }))}
    />
  );
}

export function AgentScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, 'magenta')}>
        {sectionTitle('Agent', ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>Press g for an agent config dry-run.</Text>
      <Text>{safe(snapshot.agentStatus, ascii)}</Text>
    </Box>
  );
}

export function BrowseScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  return (
    <ListScreen
      state={state}
      title="Context / Service / Item"
      accent="green"
      empty="No structured vault projection loaded."
      rows={state.snapshot.browse.map((node) => ({
        id: node.id,
        primary: `${node.kind}: ${node.label}`,
        secondary: node.detail,
      }))}
    />
  );
}

export function HelpScreen({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii } = state;
  const lines = [
    'Global: j/k or arrows move, Enter open, Esc back to Home, q quit',
    'Home: choose a destination from the colorful menu',
    'Credentials: / search, n put, m rename, x remove, r then y REVEAL (15s)',
    'Session: u unlock, l lock (clears revealed state)',
    'Doctor: d refresh checks | Recovery: final-slot revoke is blocked here',
    'Run: p dry-preview credential injection (no argv secrets)',
    'Agent: g dry-run | Policy/Browse: Enter refreshes rows',
    'Display: a toggles ASCII; NO_COLOR / TERM=dumb disable color',
    'Windows: ASCII borders default on win32; paths use node:path joins',
  ];
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, 'white')}>
        {sectionTitle('Help / Keymap', ascii)}
      </Text>
      {lines.map((line) => (
        <Text key={line}>{safe(line, ascii)}</Text>
      ))}
    </Box>
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
  const pointer = pointerGlyph(ascii);
  return (
    <Box flexDirection="column" gap={1}>
      <Text bold {...tint(color, accent)}>
        {sectionTitle(title, ascii)}
      </Text>
      {rows.length === 0 ? (
        <Text {...tint(color, 'yellow')}>{safe(empty, ascii)}</Text>
      ) : (
        rows.map((row, index) => {
          const active = index === listIndex;
          return (
            <Box key={row.id} flexDirection="column">
              <Text bold={active} {...tint(color, active ? accent : 'gray')}>
                {active ? pointer : ' '} {safe(row.primary, ascii)}
              </Text>
              <Text {...tint(color, 'gray')}>{'    '}{safe(row.secondary, ascii)}</Text>
            </Box>
          );
        })
      )}
    </Box>
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
      return (
        <Box flexDirection="column">
          <Text bold {...tint(state.color, 'yellow')}>
            {sectionTitle('Storage showcase', state.ascii)}
          </Text>
          <Text {...tint(state.color, 'gray')}>
            Presentational init helper remains available via kavrix init flows.
          </Text>
        </Box>
      );
  }
}
