import { Box, Text } from 'ink';
import type { ReactElement } from 'react';

import { resolveMotionPolicy } from '../motion.js';
import { resolveProductIdentity } from '../product.js';
import { BrandBanner } from '../showcase.js';
import { sanitizeTerminalText, secretMask } from '../terminal-text.js';
import type { AppSnapshot } from './backend.js';
import { APP_MENU } from './ids.js';
import {
  filteredCredentials,
  visibleListWindow,
  type AppOverlay,
  type AppRouterState,
} from './router.js';
import {
  accentColor,
  CHROME,
  doctorStatusAccent,
  screenAccent,
  toneAccent,
  type AppAccent,
} from './theme.js';
import {
  CardRow,
  EmptyState,
  KeyChip,
  ModalFrame,
  MotionEnter,
  NoticeBar,
  Panel,
  SelectRow,
  StatusPill,
  useListStagger,
} from './widgets.js';

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

function allowMotion(): boolean {
  return resolveMotionPolicy().animate;
}

function overlayCopy(
  overlay: AppOverlay,
  query: string,
  ascii: boolean,
  pendingName: string | null = null,
): Readonly<{ title: string; body: string; accent: AppAccent; hint?: string }> | null {
  if (overlay === 'none') return null;
  const masked = '*'.repeat(Math.min(query.length, 32));
  const q = safe(query, ascii);
  switch (overlay) {
    case 'credential-detail':
      return {
        title: 'Credential detail',
        body: `Name: ${safe(pendingName ?? '(selected)', ascii)}  Value: ${secretMask(ascii)}  r REVEAL · c copy · Esc close`,
        accent: CHROME.accent,
        hint: 'Values stay masked until an explicit REVEAL.',
      };
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
    case 'confirm-remove-profile':
      return {
        title: 'Remove profile',
        body: `Remove profile '${safe(pendingName ?? '(selected)', ascii)}'? Key and data files are kept. y/n`,
        accent: 'red',
      };
    case 'input-vault-label':
      return {
        title: 'New vault',
        body: `Vault label: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-search':
      return { title: 'Search', body: `Search: ${q}_`, accent: CHROME.accent };
    case 'input-run':
      return { title: 'Run preview', body: `Run creds: ${q}_`, accent: CHROME.accent };
    case 'input-passphrase':
      return {
        title: 'Unlock vault',
        body: `Passphrase: ${masked}_`,
        accent: 'yellow',
        hint: 'Paste works (Ctrl+Shift+V / Cmd+V)',
      };
    case 'input-put-name':
      return {
        title: 'Put credential',
        body: `New name: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-put-value':
      return {
        title: 'Put value',
        body: `Value: ${masked}_`,
        accent: CHROME.accent,
        hint: 'Paste works (Ctrl+Shift+V / Cmd+V)',
      };
    case 'input-rename':
      return { title: 'Rename', body: `Rename to: ${q}_`, accent: CHROME.accent };
    case 'input-profile-id':
      return {
        title: 'File profile',
        body: `Profile id: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-profile-data-file':
      return {
        title: 'File profile',
        body: `Data file: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-profile-key-file':
      return {
        title: 'File profile',
        body: `Key file: ${q}_`,
        accent: CHROME.accent,
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
        accent: CHROME.accent,
      };
    case 'input-mongo-database':
      return {
        title: 'Mongo profile',
        body: `Mongo database: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-mongo-key-file':
      return {
        title: 'Mongo profile',
        body: `Mongo key file: ${q}_`,
        accent: CHROME.accent,
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
        title: 'Recovery kit file',
        body: `Recovery kit file: ${q}_`,
        accent: 'red',
      };
    case 'input-recovery-passphrase':
    case 'input-recovery-passphrase-confirm':
    case 'input-recovery-verify-passphrase':
      return {
        title: 'Recovery-kit passphrase',
        body: `Recovery-kit passphrase: ${masked}_`,
        accent: 'red',
      };
    case 'input-policy-id':
      return {
        title: 'Create policy',
        body: `Policy id: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-policy-secret':
      return {
        title: 'Create policy',
        body: `Policy secret: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-policy-command':
      return {
        title: 'Create policy',
        body: `Policy command: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-grant-secret':
      return {
        title: 'Create grant',
        body: `Grant secret: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-grant-command':
      return {
        title: 'Create grant',
        body: `Grant command: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-grant-ttl':
      return {
        title: 'Create grant',
        body: `Grant TTL: ${q}_`,
        accent: CHROME.accent,
      };
    case 'input-agent-name':
      return {
        title: 'Agent dry-run',
        body: `Agent name: ${q}_`,
        accent: CHROME.accent,
        hint: 'Must match an agent entry in the project config',
      };
    case 'input-agent-config':
      return {
        title: 'Agent config (optional)',
        body: `Config path: ${q}_`,
        accent: CHROME.accent,
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
  const { color, ascii, width } = state;
  const home = state.snapshot.home;
  const accent = screenAccent(state.screen);
  const overlay = overlayCopy(state.overlay, state.query, ascii, state.pendingName);
  const product = resolveProductIdentity();
  const motion = allowMotion();
  const ellipsis = ascii ? '...' : '…';
  const vaultShort =
    home.vaultId === null
      ? '-'
      : home.vaultId.length > 12
        ? `${home.vaultId.slice(0, 10)}${ellipsis}`
        : home.vaultId;

  // Prefer content-sized height over pinning to the full TTY rows. Fixed
  // height={rows} + flexGrow panels blank on some maximized TTYs (Ink/Yoga).
  return (
    <Box flexDirection="column" width={width}>
      <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
        <BrandBanner color={color} ascii={ascii} dualTone />
        <Box flexDirection="row" columnGap={1} flexWrap="wrap" marginTop={0}>
          <StatusPill
            label="product"
            value={product.productLabel}
            accent={CHROME.accent}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="lock"
            value={home.unlocked ? 'open' : 'locked'}
            accent={home.unlocked ? CHROME.success : CHROME.warning}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="profile"
            value={home.profileId ?? '-'}
            accent={CHROME.heading}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="vault"
            value={vaultShort}
            accent={CHROME.heading}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="creds"
            value={String(home.credentialCount)}
            accent={CHROME.heading}
            color={color}
            ascii={ascii}
          />
        </Box>
      </Panel>

      <Box flexDirection="column" flexGrow={1} paddingX={0} paddingY={0}>
        {overlay === null ? (
          <MotionEnter enabled={motion && state.sessionReady} key={state.screen}>
            {children}
          </MotionEnter>
        ) : (
          <ModalFrame
            title={overlay.title}
            accent={overlay.accent}
            ascii={ascii}
            color={color}
            width={width}
            animate={motion}
          >
            <Text bold {...accentColor(color, overlay.accent)}>
              {safe(overlay.body, ascii)}
            </Text>
            {overlay.hint === undefined ? null : (
              <Text {...accentColor(color, CHROME.muted)}>
                {safe(overlay.hint, ascii)}
              </Text>
            )}
            <Text {...accentColor(color, CHROME.muted)}>
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
  const { color, ascii, message, snapshot, width } = state;
  const notice = message ?? snapshot.notice;
  const noticeAccent = toneAccent(snapshot.noticeTone);
  const sep = ascii ? ' | ' : ' · ';
  const chips = prioritizeFooterChips(footerChips(state.screen), width);
  return (
    <Box flexDirection="column">
      {notice === null ? null : (
        <NoticeBar message={notice} accent={noticeAccent} color={color} ascii={ascii} />
      )}
      <Panel accent={CHROME.muted} ascii={ascii} color={color} paddingX={1}>
        <Box flexDirection="row" columnGap={1} flexWrap="wrap">
          {chips.map((chip, index) => (
            <Box key={`${chip.keyLabel}-${chip.hint}`} flexDirection="row">
              {index === 0 ? null : (
                <Text {...accentColor(color, CHROME.muted)}>{sep}</Text>
              )}
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
  const key = CHROME.accent;
  const commonTail = [
    { keyLabel: 'Esc', hint: 'home', accent: key },
    { keyLabel: '?', hint: 'help', accent: CHROME.heading },
    { keyLabel: 'q', hint: 'quit', accent: CHROME.danger },
  ];
  switch (screen) {
    case 'credentials':
      return [
        { keyLabel: 'Enter', hint: 'detail', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'c', hint: 'copy', accent: key },
        { keyLabel: 'r', hint: 'reveal', accent: CHROME.danger },
        { keyLabel: 'n', hint: 'put', accent: key },
        { keyLabel: 'm', hint: 'rename', accent: key },
        { keyLabel: 'x', hint: 'remove', accent: CHROME.danger },
        { keyLabel: '/', hint: 'search', accent: key },
        { keyLabel: 'u', hint: 'unlock', accent: key },
        ...commonTail,
      ];
    case 'profiles':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'use', accent: key },
        { keyLabel: 'n', hint: 'file', accent: key },
        { keyLabel: 'm', hint: 'mongo', accent: key },
        { keyLabel: 'x', hint: 'remove', accent: CHROME.danger },
        ...commonTail,
      ];
    case 'vaults':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'use', accent: key },
        { keyLabel: 'n', hint: 'new vault', accent: key },
        { keyLabel: 'u', hint: 'unlock', accent: key },
        ...commonTail,
      ];
    case 'policy':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'refresh', accent: key },
        { keyLabel: 'n', hint: 'new policy', accent: key },
        { keyLabel: 'x', hint: 'remove policy', accent: CHROME.danger },
        { keyLabel: 'g', hint: 'new grant', accent: key },
        { keyLabel: 'r', hint: 'revoke grant', accent: CHROME.danger },
        ...commonTail,
      ];
    case 'recovery':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'n', hint: 'create kit', accent: key },
        { keyLabel: 'v', hint: 'verify kit', accent: key },
        { keyLabel: 'x', hint: 'revoke', accent: CHROME.danger },
        ...commonTail,
      ];
    case 'doctor':
      return [
        { keyLabel: 'd', hint: 'run checks', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...commonTail,
      ];
    case 'run':
      return [
        { keyLabel: 'p', hint: 'pick creds', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...commonTail,
      ];
    case 'agent':
      return [
        { keyLabel: 'g', hint: 'dry-run', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...commonTail,
      ];
    case 'browse':
      return [
        { keyLabel: 'Enter', hint: 'refresh', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...commonTail,
      ];
    case 'home':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'open', accent: key },
        { keyLabel: 'u', hint: 'unlock', accent: key },
        { keyLabel: 'l', hint: 'lock', accent: CHROME.warning },
        { keyLabel: 'r', hint: 'refresh', accent: key },
        ...commonTail,
      ];
    default:
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'open', accent: key },
        { keyLabel: 'u', hint: 'unlock', accent: key },
        { keyLabel: 'l', hint: 'lock', accent: CHROME.warning },
        ...commonTail,
      ];
  }
}

const FOOTER_PREFERRED_KEYS = new Set(['Enter', 'Esc', 'q']);

/** Keep critical keys on small terminals; overflow is summarized. */
export function prioritizeFooterChips(
  chips: readonly Readonly<{
    keyLabel: string;
    hint: string;
    accent: AppAccent;
  }>[],
  width: number,
): readonly Readonly<{
  keyLabel: string;
  hint: string;
  accent: AppAccent;
}>[] {
  if (chips.length === 0) return chips;
  const budget = Math.max(20, width - 4);
  const estimate = (chip: Readonly<{ keyLabel: string; hint: string }>): number =>
    chip.keyLabel.length + chip.hint.length + 4;
  const overflowCost = estimate({ keyLabel: '+99', hint: 'more' });
  const remainingPreferredCost = (fromIndex: number): number => {
    let cost = 0;
    for (let index = fromIndex; index < chips.length; index += 1) {
      const chip = chips[index];
      if (chip !== undefined && FOOTER_PREFERRED_KEYS.has(chip.keyLabel)) {
        cost += estimate(chip);
      }
    }
    return cost;
  };
  const kept: (typeof chips)[number][] = [];
  let used = 0;
  let hidden = 0;
  for (let index = 0; index < chips.length; index += 1) {
    const chip = chips[index];
    if (chip === undefined) continue;
    const cost = estimate(chip);
    if (FOOTER_PREFERRED_KEYS.has(chip.keyLabel)) {
      kept.push(chip);
      used += cost;
      continue;
    }
    const reserve = remainingPreferredCost(index + 1) + overflowCost;
    if (kept.length > 0 && used + cost + reserve > budget) {
      hidden += 1;
      continue;
    }
    kept.push(chip);
    used += cost;
  }
  if (hidden > 0) {
    kept.push({
      keyLabel: `+${String(hidden)}`,
      hint: 'more',
      accent: CHROME.muted,
    });
  }
  return kept;
}

export function HomeScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot, menuIndex, width } = state;
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  const pendingAt = useListStagger(entries.length, allowMotion());
  const wide = width >= 80;
  const statusPanel = (
    <Panel
      title="Home / Dashboard"
      accent={CHROME.accent}
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
      accent={CHROME.accent}
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
              pending={pendingAt(index)}
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
      <Text
        bold
        {...accentColor(color, home.unlocked ? CHROME.success : CHROME.warning)}
      >
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
        <Text {...accentColor(color, CHROME.heading)}>
          {safe(home.datastore ?? '(none)', ascii)}
        </Text>
      </Text>
      <Text {...accentColor(color, CHROME.muted)}>{safe(home.message, ascii)}</Text>
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
        accent={CHROME.accent}
        empty="No datastore profiles found. Press n (file) or m (mongodb)."
        rows={state.snapshot.profiles.map((profile) => ({
          id: profile.id,
          primary: `${profile.id} (${profile.datastore})${profile.selected ? ' *' : ''}`,
          secondary: profile.detail,
        }))}
      />
      <Text {...accentColor(color, CHROME.muted)}>
        {safe(
          'Enter = use · n = file profile · m = mongodb profile · x = remove profile (files are kept)',
          ascii,
        )}
      </Text>
    </Box>
  );
}

export function VaultsScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii } = state;
  return (
    <Box flexDirection="column" flexGrow={1}>
      <ListScreen
        state={state}
        title="Vaults"
        accent={CHROME.accent}
        empty="No vaults yet. Select a profile, then unlock (u)."
        rows={state.snapshot.vaults.map((vault) => ({
          id: vault.id,
          primary: `${vault.id}${vault.selected ? ' *' : ''}`,
          secondary: vault.detail,
        }))}
      />
      <Text {...accentColor(color, CHROME.muted)}>
        {safe(
          'Enter = use selected vault · n = create a new vault (unlock first with u)',
          ascii,
        )}
      </Text>
    </Box>
  );
}

export function CredentialsScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, listIndex, revealedName, revealedValue, snapshot } = state;
  const filtered = filteredCredentials(state);
  const windowSize = Math.max(6, Math.min(20, state.height - 12));
  const window = visibleListWindow(filtered, listIndex, windowSize);
  const pendingAt = useListStagger(window.items.length, allowMotion());
  return (
    <Box flexDirection="column" flexGrow={1}>
      <Panel
        title="Credentials"
        accent={CHROME.accent}
        ascii={ascii}
        color={color}
        paddingX={1}
      >
        <Text {...accentColor(color, CHROME.muted)}>
          {safe(
            `Values stay masked. Enter opens detail · c copy · r then y REVEAL (15s) · n put. ${String(filtered.length)}/${String(snapshot.credentials.length)} shown${state.credentialFilter.length > 0 ? ` (filter: ${state.credentialFilter})` : ''}.`,
            ascii,
          )}
        </Text>
        {filtered.length === 0 ? (
          <EmptyState
            title={
              snapshot.home.unlocked
                ? state.credentialFilter.length > 0
                  ? 'No credentials match this search.'
                  : 'No credentials yet. Press n to put one.'
                : 'Vault locked. Press u to unlock, then n to put.'
            }
            hint={
              snapshot.home.unlocked
                ? 'Names are visible; values stay masked until an explicit reveal. Enter opens detail.'
                : 'Unlock first. Secrets are never accepted on the command line.'
            }
            color={color}
            ascii={ascii}
          />
        ) : (
          window.items.map((credential, offset) => {
            const index = window.start + offset;
            const active = index === listIndex;
            const revealed = revealedName === credential.name;
            return (
              <Box key={credential.name} flexDirection="column" marginTop={0}>
                <CardRow
                  active={active}
                  title={credential.name}
                  subtitle={revealed ? '' : credential.maskedValue || secretMask(ascii)}
                  accent={CHROME.accent}
                  color={color}
                  ascii={ascii}
                  pending={pendingAt(offset)}
                />
                {revealed ? (
                  <Panel
                    accent={CHROME.danger}
                    ascii={ascii}
                    color={color}
                    paddingX={1}
                    kind="panel"
                  >
                    <Text bold {...accentColor(color, CHROME.danger)}>
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
      title="Doctor / heal (local health, not recovery kit)"
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
      flexGrow={1}
    >
      {rows.length === 0 ? (
        <EmptyState
          title="Press d to run doctor checks."
          hint="Checks stay on this machine. Failures are generic — they never name unlock material."
          color={color}
          ascii={ascii}
        />
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
      title="Recovery kit (key material)"
      accent={CHROME.danger}
      empty="No recovery-kit slots. n create · v verify · Enter/x revoke (last slot blocked). Doctor heal is a different command."
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
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Text {...accentColor(color, CHROME.muted)}>
        Press p, type credential names, Enter. Secrets are never placed on argv.
      </Text>
      <Text>{safe(snapshot.runPreview, ascii)}</Text>
    </Panel>
  );
}

export function PolicyScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, listIndex } = state;
  const rows = state.snapshot.policies;
  const pendingAt = useListStagger(rows.length, allowMotion());
  const statusTag = (status: string): string => `[${status.toUpperCase()}]`;
  return (
    <Panel
      title="Policy / Grant / Audit"
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
      flexGrow={1}
    >
      {rows.length === 0 ? (
        <EmptyState
          title="No rows yet. Press n to create a policy, g to issue a grant, Enter to load."
          hint="n = create policy · x = remove policy · g = create grant · r = revoke grant"
          color={color}
          ascii={ascii}
        />
      ) : (
        rows.map((row, index) => {
          const active = index === listIndex;
          const inactiveGrant =
            row.kind === 'grant' && row.status !== undefined && row.status !== 'active';
          const label =
            row.kind === 'grant' && row.status !== undefined
              ? `${row.kind} ${row.id} ${statusTag(row.status)}`
              : `${row.kind} ${row.id}`;
          const rowAccent = inactiveGrant
            ? CHROME.muted
            : row.kind === 'grant'
              ? CHROME.success
              : CHROME.accent;
          return (
            <SelectRow
              key={`${row.kind}:${row.id}`}
              active={active}
              label={label}
              hint={row.summary}
              accent={rowAccent}
              color={color}
              ascii={ascii}
              pending={pendingAt(index)}
            />
          );
        })
      )}
    </Panel>
  );
}

export function AgentScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  return (
    <Panel
      title="Agent"
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Text {...accentColor(color, CHROME.muted)}>
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
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Text bold {...accentColor(color, CHROME.warning)}>
        {safe('DOCS ONLY — no vault create/unlock/mutate from this screen.', ascii)}
      </Text>
      <Text {...accentColor(color, CHROME.muted)}>
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
      <Text {...accentColor(color, CHROME.muted)}>{safe(home.message, ascii)}</Text>
      <Text bold {...accentColor(color, CHROME.heading)}>
        {safe('Storage choices (from init docs)', ascii)}
      </Text>
      <Text>
        {safe('• Local encrypted file — ciphertext stays on this device.', ascii)}
      </Text>
      <Text>
        {safe('• MongoDB — sync opaque ciphertext through your own deployment.', ascii)}
      </Text>
      <Text {...accentColor(color, CHROME.muted)}>
        {safe(
          'Both keep client-side encryption; the datastore never receives a vault key.',
          ascii,
        )}
      </Text>
      {doctor.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text bold {...accentColor(color, CHROME.heading)}>
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
        <Text {...accentColor(color, CHROME.muted)}>
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
      title="Vault context / service / item"
      accent={CHROME.accent}
      empty="No vault-context rows. Unlock and press Enter to load vault context / service / item lists (not run --environment)."
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
    '3) Credentials: Enter detail · n put · c copy (no on-screen plaintext) · r then y REVEAL',
    '',
    '--- Copy / paste ---',
    'Paste into overlays: Ctrl+Shift+V / Cmd+V (bracketed paste; never submits Enter)',
    'Copy credential: c on Credentials (clipboard clears in ~30s; OSC 52 preferred)',
    'Terminal select/copy still works (Shift+drag if the terminal needs it)',
    'Mouse tracking is NOT enabled — OS drag-select is not stolen',
    '',
    '--- Keymap ---',
    'Global: j/k or arrows move, Enter open, Esc Home, q quit',
    'Credentials: Enter detail · c copy · r reveal · n put · m rename · x remove · / search',
    'Profiles: Enter use · n file · m mongodb · x remove (key/data files are kept)',
    'Vaults: Enter use · n create a new vault in the selected database (unlock first)',
    'Session: u unlock · l lock (clears revealed state)',
    'Doctor / heal: d (local health, not key recovery). Recovery kit: n/c create · v verify · Enter/x revoke',
    'Run: p (project-file --environment is CLI-only). Agent: g dry-run.',
    'Policy: n create · x remove · g create grant · r revoke grant · Enter refresh',
    'Vault context browse: Enter refresh',
    'Display: a ASCII · NO_COLOR / TERM=dumb disable color · win32 ASCII default',
    'Motion: KAVRIX_TUI_REDUCED_MOTION=1 skips splash, stagger, and status pulse',
  ];
  return (
    <Panel
      title="Help / Keymap"
      accent={CHROME.heading}
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
  const pendingAt = useListStagger(rows.length, allowMotion());
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
        <EmptyState
          title={empty}
          hint="j/k move · Enter opens the selected row when one exists."
          color={color}
          ascii={ascii}
        />
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
              pending={pendingAt(index)}
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
