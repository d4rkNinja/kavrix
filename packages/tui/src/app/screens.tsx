import { Box, Text } from 'ink';
import type { ReactElement } from 'react';

import { resolveMotionPolicy, useCursorVisible } from '../motion.js';
import { PRODUCT_LABEL } from '../product.js';
import { sanitizeTerminalText, secretMask } from '../terminal-text.js';
import type { AppSnapshot } from './backend.js';
import { APP_MENU, HELP_TOPICS } from './ids.js';
import { useAppInteraction } from './interaction.js';
import { ClickTarget } from './mouse.js';
import { TerminalViewport, terminalFullscreenEnabled } from './viewport.js';
import {
  filteredCredentials,
  credentialWindowSize,
  paletteWindow,
  visibleListWindow,
  type AppOverlay,
  type AppRouterState,
} from './router.js';
import { commandGroups, allCommands } from './commands.js';
import {
  accentColor,
  CHROME,
  doctorStatusAccent,
  maskBullets,
  pointerGlyph,
  screenAccent,
  THEMES,
  toneAccent,
  type AppAccent,
} from './theme.js';
import {
  CardRow,
  EmptyState,
  KeyChip,
  ModalFrame,
  MotionEnter,
  Panel,
  RevealCountdown,
  SectionTitle,
  SelectRow,
  SingleLine,
  StatusPill,
  TabNav,
  useListStagger,
} from './widgets.js';

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

export interface FooterChip {
  readonly keyLabel: string;
  readonly hint: string;
  readonly accent: AppAccent;
}

/**
 * Theme picker rows: one line per installed theme, numbered like the tab
 * strip, cursor-marked, with each label painted in its own theme accent so
 * the row previews the palette. The committed theme carries an active tag.
 */
function ThemePickerRows({
  color,
  ascii,
  cursor,
  activeId,
}: Readonly<{
  color: boolean;
  ascii: boolean;
  cursor: number;
  activeId: string;
}>): ReactElement {
  const interaction = useAppInteraction();
  const pointer = pointerGlyph(ascii);
  return (
    <Box flexDirection="column">
      {THEMES.map((theme, index) => {
        const selected = index === cursor;
        const active = theme.id === activeId;
        return (
          <ClickTarget
            key={theme.id}
            enabled={interaction.enabled}
            onClick={() => {
              interaction.dispatch({ type: 'select-theme', index });
            }}
          >
            <Box flexDirection="row" columnGap={1}>
              <Text {...accentColor(color, CHROME.muted)}>
                {selected ? pointer : ' '}
                {String(index + 1)}{' '}
              </Text>
              <Text bold={selected} {...accentColor(color, theme.accent)}>
                {safe(theme.label, ascii)}
              </Text>
              {active ? (
                <Text {...accentColor(color, CHROME.muted)}>[active]</Text>
              ) : null}
            </Box>
          </ClickTarget>
        );
      })}
    </Box>
  );
}

function allowMotion(): boolean {
  return resolveMotionPolicy().animate;
}

/**
 * Command palette rows: every action this screen can perform, grouped, with its
 * key and a one-line description. Blocked actions stay visible with the reason
 * they cannot run, because "unlock first" is the answer a new user needs and a
 * missing row is not.
 */
export function CommandPaletteRows({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii } = state;
  const interaction = useAppInteraction();
  const { rows, start } = paletteWindow(state);
  const cursor = state.paletteIndex;
  const filter = safe(state.paletteFilter, ascii);
  // The catalogue is rebuilt on every call, so membership and cursor position
  // are matched by stable id rather than by object identity.
  const visibleIds = new Set(rows.map((entry) => entry.id));

  return (
    <Box flexDirection="column">
      {filter.length === 0 ? null : (
        <Box flexDirection="row" columnGap={1}>
          <Text {...accentColor(color, CHROME.muted)}>filter</Text>
          <Text bold {...accentColor(color, CHROME.accent)}>
            {filter}
          </Text>
          {rows.length === 0 ? (
            <Text {...accentColor(color, CHROME.danger)}>no matches</Text>
          ) : null}
        </Box>
      )}
      {rows.length === 0 ? (
        <EmptyState
          title="No matching action"
          hint="Backspace clears the filter; Esc closes the palette."
          color={color}
          ascii={ascii}
        />
      ) : null}
      {commandGroups(state).map((group) => {
        const groupRows = group.commands.filter((entry) => visibleIds.has(entry.id));
        if (groupRows.length === 0) return null;
        return (
          <Box key={group.label} flexDirection="column">
            {start === 0 && filter.length === 0 ? (
              <SectionTitle
                label={safe(group.label, ascii)}
                ascii={ascii}
                color={color}
              />
            ) : null}
            {groupRows.map((entry) => {
              const index = allCommands(state).findIndex((row) => row.id === entry.id);
              const blocked = entry.blocked(state);
              const selected = index === cursor;
              const accent: AppAccent =
                blocked === null
                  ? entry.danger === true
                    ? CHROME.danger
                    : CHROME.accent
                  : CHROME.muted;
              return (
                <Box key={entry.id} flexDirection="row" columnGap={1}>
                  <Text
                    {...accentColor(color, selected ? CHROME.heading : CHROME.muted)}
                  >
                    {selected ? pointerGlyph(ascii) : ' '}
                  </Text>
                  <ClickTarget
                    enabled={interaction.enabled}
                    onClick={() => {
                      interaction.dispatch({
                        type: 'select-row',
                        index: Math.max(0, index),
                        activate: true,
                        nowMs: 0,
                      });
                    }}
                  >
                    <KeyChip
                      keyLabel={entry.keyLabel}
                      hint={entry.hint}
                      color={color}
                      keyAccent={accent}
                      disabled={blocked !== null}
                      active={selected}
                    />
                  </ClickTarget>
                  <Text
                    dimColor={blocked !== null}
                    {...accentColor(color, CHROME.muted)}
                  >
                    {safe(blocked ?? '', ascii)}
                  </Text>
                </Box>
              );
            })}
          </Box>
        );
      })}
    </Box>
  );
}

function overlayCopy(
  overlay: AppOverlay,
  query: string,
  ascii: boolean,
  pendingName: string | null = null,
): Readonly<{ title: string; body: string; accent: AppAccent; hint?: string }> | null {
  if (overlay === 'none') return null;
  const masked = maskBullets(query.length, ascii);
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
    case 'confirm-session-revoke':
      return {
        title: 'Remove session',
        body: 'Remove session unlock? The passphrase will be required again. y/n',
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
    case 'theme-picker':
      return {
        title: 'Theme',
        body: '(theme list)',
        accent: CHROME.accent,
        hint: 'Arrow keys or 1-5 preview live; Enter applies and saves; Esc restores.',
      };
    case 'command-palette':
      return {
        title: 'Actions',
        body: '(palette list)',
        accent: CHROME.accent,
        hint: 'j/k or 1-9 move · Enter runs · type to filter · Esc closes',
      };
    case 'input-run':
      return {
        title: 'Run preview',
        body: `Run credentials: ${q}_`,
        accent: CHROME.accent,
      };
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
  const interaction = useAppInteraction();
  const { color, ascii, width } = state;
  const home = state.snapshot.home;
  const accent = screenAccent(state.screen);
  const overlay = overlayCopy(state.overlay, state.query, ascii, state.pendingName);
  const motion = allowMotion();
  const ellipsis = ascii ? '...' : '…';
  const vaultShort =
    home.vaultId === null
      ? '-'
      : home.vaultId.length > 12
        ? `${home.vaultId.slice(0, 10)}${ellipsis}`
        : home.vaultId;
  const isDetailOverlay = state.overlay === 'credential-detail';
  const isThemePicker = state.overlay === 'theme-picker';
  const isPalette = state.overlay === 'command-palette';
  const isConfirmOverlay =
    overlay !== null &&
    !isDetailOverlay &&
    !isPalette &&
    (overlay.title.startsWith('Confirm') ||
      overlay.title.startsWith('Revoke') ||
      overlay.title.startsWith('Remove') ||
      overlay.title.startsWith('Recovery blocked'));
  const isInputOverlay =
    overlay !== null &&
    !isConfirmOverlay &&
    !isDetailOverlay &&
    !isThemePicker &&
    !isPalette;
  // Blink only while a typing overlay owns the screen; otherwise the clock
  // would repaint the whole chrome twice a second for nothing.
  const caret = useCursorVisible(motion && isInputOverlay);
  const overlayBody = overlay?.body ?? '';
  const fullTypedBody = isInputOverlay ? overlayBody.replace(/_$/u, '') : overlayBody;
  const inputCells = Math.max(12, width - 8);
  const glyphs = Array.from(fullTypedBody);
  const prefixLength = Math.floor(inputCells / 3);
  const ellipsisSize = ascii ? 3 : 1;
  const typedBody =
    (isInputOverlay || isDetailOverlay) && glyphs.length > inputCells
      ? `${glyphs.slice(0, prefixLength).join('')}${ascii ? '...' : '…'}${glyphs.slice(-(inputCells - prefixLength - ellipsisSize)).join('')}`
      : fullTypedBody;

  const fullscreen = terminalFullscreenEnabled();
  const compactOverlay = overlay !== null && state.height < 16;
  const overlayActions = (
    <OverlayActions
      color={color}
      compact={compactOverlay}
      kind={
        isConfirmOverlay
          ? 'confirm'
          : isThemePicker
            ? 'theme'
            : isDetailOverlay
              ? 'detail'
              : 'input'
      }
    />
  );

  // Keep child panels content-sized; a flexible spacer fills the viewport
  // without stretching their internals or clipping footer actions.
  return (
    <TerminalViewport width={width} height={state.height}>
      {compactOverlay ? (
        <SingleLine {...accentColor(color, CHROME.heading)}>
          {safe(
            `${PRODUCT_LABEL} / ${home.profileId ?? 'no profile'} / ${vaultShort}`,
            ascii,
          )}
        </SingleLine>
      ) : (
        <>
          <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
            <Box flexDirection="row" justifyContent="space-between">
              <SingleLine bold {...accentColor(color, CHROME.accent)}>
                {PRODUCT_LABEL} /{' '}
                {safe(
                  APP_MENU.find((entry) => entry.id === state.screen)?.short ??
                    state.screen,
                  ascii,
                )}
              </SingleLine>
              <KeyChip
                keyLabel="t"
                hint="theme"
                color={color}
                disabled={state.overlay !== 'none' || interaction.busy}
              />
            </Box>
            <Box flexDirection="row" columnGap={1} overflow="hidden">
              <StatusPill
                label="lock"
                value={
                  home.unlocked && state.snapshot.session.enabled
                    ? 'open·session'
                    : home.unlocked
                      ? 'open'
                      : 'locked'
                }
                accent={home.unlocked ? CHROME.success : CHROME.warning}
                color={color}
                ascii={ascii}
              />
              <SingleLine {...accentColor(color, CHROME.heading)}>
                {safe(`${home.profileId ?? 'no profile'} / ${vaultShort}`, ascii)}
              </SingleLine>
              {width >= 72 ? (
                <Text {...accentColor(color, CHROME.muted)}>
                  {String(home.credentialCount)} credentials
                </Text>
              ) : null}
            </Box>
          </Panel>

          <TabNav
            activeId={state.screen}
            navigable={state.overlay === 'none'}
            color={color}
            ascii={ascii}
            width={width}
          />
        </>
      )}

      <Box
        flexDirection="column"
        flexShrink={0}
        // A modal spends its rows on the frame, so it gets a tighter budget than
        // the screen body. The confirm/apply row must survive that budget: a
        // clipped action row leaves the user with no way to tell what Enter does.
        maxHeight={Math.max(
          1,
          state.height -
            (compactOverlay
              ? fullscreen
                ? 4
                : 2
              : overlay === null
                ? 10
                : state.height < 20
                  ? 4
                  : 7),
        )}
        overflow="hidden"
        paddingX={0}
        paddingY={0}
      >
        {overlay === null ? (
          <MotionEnter enabled={false} key={`${state.screen}:${state.navDirection}`}>
            {children}
          </MotionEnter>
        ) : (
          <ModalFrame
            title={overlay.title}
            accent={overlay.accent}
            ascii={ascii}
            color={color}
            width={width}
            animate={false}
          >
            {isThemePicker ? (
              <ThemePickerRows
                color={color}
                ascii={ascii}
                cursor={state.themeCursor}
                activeId={state.themeId}
              />
            ) : null}
            {isPalette ? <CommandPaletteRows state={state} /> : null}
            {isThemePicker || isPalette ? null : (
              <Text bold {...accentColor(color, overlay.accent)}>
                {safe(typedBody, ascii)}
                {isInputOverlay ? (
                  <Text {...accentColor(color, overlay.accent)}>
                    {caret ? '_' : ' '}
                  </Text>
                ) : null}
              </Text>
            )}
            {overlay.hint === undefined || state.height < 22 ? null : (
              <Text {...accentColor(color, CHROME.muted)}>
                {safe(overlay.hint, ascii)}
              </Text>
            )}
            {fullscreen ? null : overlayActions}
          </ModalFrame>
        )}
      </Box>

      <Box flexGrow={1} minHeight={0} />
      {fullscreen && overlay !== null ? (
        <Box flexShrink={0} paddingX={1}>
          {overlayActions}
        </Box>
      ) : null}
      <Footer state={state} />
    </TerminalViewport>
  );
}

function OverlayActions({
  color,
  compact,
  kind,
}: Readonly<{
  color: boolean;
  compact: boolean;
  kind: 'confirm' | 'theme' | 'detail' | 'input';
}>): ReactElement {
  return (
    <Box flexDirection="row" columnGap={1} flexWrap="wrap" marginTop={compact ? 0 : 1}>
      {kind === 'confirm' ? (
        <>
          <KeyChip
            keyLabel="y"
            hint="confirm"
            color={color}
            keyAccent={CHROME.success}
          />
          <KeyChip keyLabel="n" hint="cancel" color={color} keyAccent={CHROME.danger} />
          <KeyChip keyLabel="Esc" hint="cancel" color={color} />
        </>
      ) : kind === 'theme' ? (
        <>
          <KeyChip keyLabel="Enter" hint="apply theme" color={color} />
          <KeyChip keyLabel="Esc" hint="cancel" color={color} />
        </>
      ) : kind === 'detail' ? (
        <>
          <KeyChip keyLabel="r" hint="REVEAL" color={color} keyAccent={CHROME.danger} />
          <KeyChip keyLabel="c" hint="copy" color={color} />
          <KeyChip keyLabel="Esc" hint="close" color={color} />
        </>
      ) : (
        <>
          <KeyChip keyLabel="Enter" hint="continue" color={color} />
          <KeyChip keyLabel="Esc" hint="cancel" color={color} />
          <KeyChip keyLabel="^V" hint="paste" color={color} keyAccent={CHROME.muted} />
          {/* Line editing was once Backspace-only; these two are the bindings a
              linear field can honour exactly, and they are what make a long path
              typo recoverable without retyping the tail. */}
          <KeyChip keyLabel="^W" hint="word" color={color} keyAccent={CHROME.muted} />
          <KeyChip keyLabel="^U" hint="clear" color={color} keyAccent={CHROME.muted} />
        </>
      )}
    </Box>
  );
}

function Footer({ state }: Readonly<{ state: AppRouterState }>): ReactElement {
  const interaction = useAppInteraction();
  const { color, ascii, message, snapshot, width } = state;
  const notice = interaction.busy
    ? (interaction.busyLabel ?? 'Working... q quits.')
    : (message ?? snapshot.notice);
  if (state.overlay !== 'none' && notice === null) return <></>;
  const noticeAccent = toneAccent(snapshot.noticeTone);
  const sep = ascii ? ' | ' : ' · ';
  const chips = prioritizeFooterChips(
    footerChips(state),
    width,
    footerPreferredKeys(state),
  );
  return (
    <Box flexDirection="column" flexShrink={0}>
      {notice === null ? null : (
        <SingleLine {...accentColor(color, noticeAccent)}>
          {safe(notice, ascii)}
        </SingleLine>
      )}
      {state.overlay !== 'none' ? null : (
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
      )}
    </Box>
  );
}

/** A selected profile whose vault is still locked: unlock is the only next step. */
function vaultLocked(state: AppRouterState): boolean {
  const home = state.snapshot.home;
  return home.profileId !== null && !home.unlocked;
}

export function footerChips(state: AppRouterState): readonly FooterChip[] {
  const key = CHROME.accent;
  // Global keys truly work from every screen, so they are advertised from every
  // screen. A key that behaves the same everywhere but is only shown somewhere
  // is the definition of a hidden feature.
  const globalTail: readonly FooterChip[] = [
    ...(state.snapshot.home.unlocked
      ? [{ keyLabel: 'l', hint: 'lock', accent: CHROME.warning }]
      : []),
    { keyLabel: ':', hint: 'actions', accent: CHROME.heading },
    { keyLabel: 't', hint: 'theme', accent: key },
    { keyLabel: 'Tab', hint: 'screens', accent: key },
    { keyLabel: 'Esc', hint: 'home', accent: key },
    { keyLabel: '?', hint: 'help', accent: CHROME.heading },
    { keyLabel: 'a', hint: 'ascii', accent: CHROME.muted },
    { keyLabel: 'q', hint: 'quit', accent: CHROME.danger },
  ];
  // `u` unlocks from every screen, so the affordance is advertised on all of
  // them while the vault is locked.
  const unlockTail: readonly FooterChip[] = vaultLocked(state)
    ? [{ keyLabel: 'u', hint: 'unlock', accent: key }]
    : [];
  switch (state.screen) {
    case 'help':
      return [
        { keyLabel: 'j/k', hint: 'topic', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'credentials':
      // While names are being filtered, every printable key is filter text. A
      // chip for `n` or `c` here would type into the search instead of running,
      // so the footer advertises only the keys that still act on the list.
      if (state.filtering) {
        return [
          { keyLabel: 'Enter', hint: 'detail', accent: key },
          { keyLabel: 'j/k', hint: 'move', accent: key },
          { keyLabel: 'Backspace', hint: 'edit', accent: key },
          { keyLabel: 'Esc', hint: 'clear filter', accent: CHROME.heading },
          { keyLabel: 'Tab', hint: 'screens', accent: key },
        ];
      }
      return [
        { keyLabel: 'Enter', hint: 'detail', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'c', hint: 'copy', accent: key },
        { keyLabel: 'r', hint: 'reveal', accent: CHROME.danger },
        { keyLabel: 'n', hint: 'put', accent: key },
        { keyLabel: 'm', hint: 'rename', accent: key },
        { keyLabel: 'x', hint: 'remove', accent: CHROME.danger },
        { keyLabel: '/', hint: 'filter', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'profiles':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'use', accent: key },
        { keyLabel: 'n', hint: 'file', accent: key },
        { keyLabel: 'm', hint: 'mongo', accent: key },
        { keyLabel: 'x', hint: 'remove', accent: CHROME.danger },
        ...unlockTail,
        ...globalTail,
      ];
    case 'vaults':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'use', accent: key },
        { keyLabel: 'n', hint: 'new vault', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'policy':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'refresh', accent: key },
        { keyLabel: 'n', hint: 'new policy', accent: key },
        { keyLabel: 'x', hint: 'remove policy', accent: CHROME.danger },
        { keyLabel: 'g', hint: 'new grant', accent: key },
        { keyLabel: 'r', hint: 'revoke grant', accent: CHROME.danger },
        ...unlockTail,
        ...globalTail,
      ];
    case 'recovery':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'n', hint: 'create kit', accent: key },
        { keyLabel: 'v', hint: 'verify kit', accent: key },
        { keyLabel: 'x', hint: 'revoke', accent: CHROME.danger },
        ...unlockTail,
        ...globalTail,
      ];
    case 'session':
      return [
        { keyLabel: 'n', hint: 'enable', accent: key },
        { keyLabel: 'x', hint: 'remove', accent: CHROME.danger },
        { keyLabel: 'Enter', hint: 'refresh', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'doctor':
      return [
        { keyLabel: 'd', hint: 'run checks', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'run':
      return [
        { keyLabel: 'p', hint: 'pick credentials', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'agent':
      return [
        { keyLabel: 'g', hint: 'dry-run', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'browse':
      return [
        { keyLabel: 'Enter', hint: 'refresh', accent: key },
        { keyLabel: 'j/k', hint: 'move', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
    case 'home':
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'open', accent: key },
        ...unlockTail,
        { keyLabel: 'r', hint: 'refresh', accent: key },
        ...globalTail,
      ];
    case 'showcase':
      // Read-only by design: advertising a row action here would be a promise
      // this screen cannot keep.
      return [...unlockTail, ...globalTail];
    default:
      return [
        { keyLabel: 'j/k', hint: 'move', accent: key },
        { keyLabel: 'Enter', hint: 'open', accent: key },
        ...unlockTail,
        ...globalTail,
      ];
  }
}

/** Footer keys that must survive overflow for the current session state. */
function footerPreferredKeys(state: AppRouterState): ReadonlySet<string> {
  return vaultLocked(state) ? FOOTER_UNLOCK_PREFERRED_KEYS : FOOTER_PREFERRED_KEYS;
}

const FOOTER_PREFERRED_KEYS: ReadonlySet<string> = new Set(['Enter', 'Esc', 'q']);
const FOOTER_UNLOCK_PREFERRED_KEYS: ReadonlySet<string> = new Set([
  ...FOOTER_PREFERRED_KEYS,
  'u',
]);

/** Keep critical keys on small terminals; overflow is summarized. */
export function prioritizeFooterChips(
  chips: readonly FooterChip[],
  width: number,
  preferredKeys: ReadonlySet<string> = FOOTER_PREFERRED_KEYS,
): readonly FooterChip[] {
  if (chips.length === 0) return chips;
  const budget = Math.max(20, width - 4);
  const estimate = (chip: Readonly<{ keyLabel: string; hint: string }>): number =>
    chip.keyLabel.length + chip.hint.length + 5;
  const overflowCost = estimate({ keyLabel: '+99', hint: 'more' });
  const remainingPreferredCost = (fromIndex: number): number => {
    let cost = 0;
    for (let index = fromIndex; index < chips.length; index += 1) {
      const chip = chips[index];
      if (chip !== undefined && preferredKeys.has(chip.keyLabel)) {
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
    if (preferredKeys.has(chip.keyLabel)) {
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
  const interaction = useAppInteraction();
  const { color, ascii, snapshot, menuIndex, width } = state;
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  const pendingAt = useListStagger(entries.length, allowMotion());
  const wide = width >= 80;
  const window = visibleListWindow(
    entries,
    menuIndex,
    Math.max(1, state.height - (wide ? 14 : 15)),
  );
  const statusPanel = (
    <Panel
      title="Home / Dashboard"
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      {...(wide ? { width: Math.floor((width - 1) * 0.35) } : {})}
      paddingX={1}
      paddingY={0}
    >
      <StatusBlock snapshot={snapshot} color={color} ascii={ascii} />
      <Text bold {...accentColor(color, CHROME.heading)}>
        Next step
      </Text>
      {snapshot.home.profileId === null ? (
        <KeyChip keyLabel="2" hint="create a profile" color={color} />
      ) : vaultLocked(state) ? (
        <Box flexDirection="column">
          <KeyChip keyLabel="u" hint="unlock your vault" color={color} />
          <KeyChip keyLabel="U" hint="use passphrase" color={color} />
        </Box>
      ) : (
        <KeyChip keyLabel="4" hint="browse credentials" color={color} />
      )}
      {wide && state.height >= 24 ? (
        <Box flexDirection="column" marginTop={1}>
          <SingleLine {...accentColor(color, CHROME.muted)}>
            Secrets stay masked.
          </SingleLine>
          <SingleLine {...accentColor(color, CHROME.muted)}>
            {interaction.mouse ? 'Click / wheel to move' : 'Arrows / Enter to open'}
          </SingleLine>
          <KeyChip keyLabel="r" hint="refresh session" color={color} />
        </Box>
      ) : null}
    </Panel>
  );
  const navPanel = (
    <Panel
      title="Choose an action"
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      {...(wide ? { width: width - 1 - Math.floor((width - 1) * 0.35) } : {})}
      paddingX={1}
      paddingY={0}
    >
      {(() => {
        const labelOf = (entry: (typeof entries)[number]): string => {
          const number = APP_MENU.indexOf(entry) + 1;
          // Only 1-9 are wired as digit shortcuts; later rows keep the slot
          // so labels stay aligned without advertising dead numbers.
          return `${number <= 9 ? `${String(number)} ` : '  '}${entry.short ?? entry.label}`;
        };
        const labelWidth = Math.max(
          ...entries.map((entry) => labelOf(entry).length),
          8,
        );
        return window.items.map((entry, offset) => {
          const index = window.start + offset;
          const active = index === menuIndex;
          return (
            <SelectRow
              key={entry.id}
              active={active}
              label={labelOf(entry)}
              {...(width >= 80 ? { hint: entry.hint } : {})}
              accent={entry.accent}
              color={color}
              ascii={ascii}
              labelWidth={labelWidth}
              pending={pendingAt(index)}
              onPress={() => {
                interaction.dispatch({
                  type: 'select-row',
                  index,
                  activate: true,
                  nowMs: state.nowMs,
                });
              }}
            />
          );
        });
      })()}
      <Text
        dimColor
      >{`${String(window.start + 1)}-${String(window.start + window.items.length)} / ${String(entries.length)} destinations`}</Text>
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
      <SingleLine {...accentColor(color, CHROME.muted)}>
        {safe(
          snapshot.home.profileId === null
            ? 'Start: 2 Profiles > create a profile'
            : vaultLocked(state)
              ? 'Next: u Unlock your selected vault'
              : 'Ready: 4 Credentials > choose a secret',
          ascii,
        )}
      </SingleLine>
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
      <SingleLine {...accentColor(color, CHROME.muted)}>
        {safe(home.message, ascii)}
      </SingleLine>
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
        activateRows
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
        activateRows
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
  const interaction = useAppInteraction();
  const { color, ascii, listIndex, revealedName, revealedValue, snapshot } = state;
  const filtered = filteredCredentials(state);
  const windowSize = credentialWindowSize(state);
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
            `Values stay masked. ${String(filtered.length)}/${String(snapshot.credentials.length)} credentials${
              state.credentialFilter.length > 0
                ? ` · filter: ${state.credentialFilter}${state.filtering ? '_' : ''}`
                : ''
            }`,
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
                ? state.credentialFilter.length > 0
                  ? 'Backspace edits the filter; Esc clears it. Enter opens detail once a row matches.'
                  : 'Names are visible; values stay masked until an explicit reveal. Enter opens detail.'
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
                  onPress={() => {
                    interaction.dispatch({
                      type: 'select-row',
                      index,
                      activate: true,
                      nowMs: state.nowMs,
                    });
                  }}
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
                    <RevealCountdown
                      expiresAtMs={state.revealedUntilMs}
                      nowMs={state.nowMs}
                      color={color}
                      ascii={ascii}
                    />
                  </Panel>
                ) : null}
              </Box>
            );
          })
        )}
        {filtered.length > 0 ? (
          <Text
            dimColor
          >{`${String(window.start + 1)}-${String(window.start + window.items.length)} / ${String(filtered.length)}  |  ${state.filtering ? 'Esc clears the filter' : '/ filter names'}`}</Text>
        ) : null}
      </Panel>
    </Box>
  );
}

export function SessionScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const { color, ascii, snapshot } = state;
  const session = snapshot.session;
  const rows = session.enabled
    ? [
        {
          id: 'session-state',
          primary: `${session.expired ? 'EXPIRED' : 'ACTIVE'} session unlock`,
          secondary: session.expired
            ? 'Unlock with the passphrase (u), then press n to enable a new session.'
            : `Created ${session.createdAt ?? 'unknown'} · auto-lock ${String(session.ttlHours ?? 0)}h`,
        },
      ]
    : [];
  return (
    <Box flexDirection="column" flexGrow={1}>
      <ListScreen
        state={state}
        title="Session unlock (OS keychain)"
        accent={CHROME.accent}
        empty="No session unlock for this profile. Unlock with the passphrase (u), then press n to enable."
        rows={rows}
      />
      <Text {...accentColor(color, CHROME.muted)}>
        {safe(
          'n = enable (after passphrase unlock) · x = remove · Enter = refresh status',
          ascii,
        )}
      </Text>
    </Box>
  );
}

export function DoctorScreen({
  state,
}: Readonly<{ state: AppRouterState }>): ReactElement {
  const interaction = useAppInteraction();
  const { color, ascii, listIndex } = state;
  const rows = state.snapshot.doctor;
  const window = visibleListWindow(rows, listIndex, Math.max(1, state.height - 15));
  const pendingAt = useListStagger(rows.length, allowMotion());
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
        window.items.map((check, offset) => {
          const index = window.start + offset;
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
              pending={pendingAt(index)}
              onPress={() => {
                interaction.dispatch({ type: 'select-row', index, nowMs: state.nowMs });
              }}
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
  const interaction = useAppInteraction();
  const { color, ascii, listIndex } = state;
  const rows = state.snapshot.policies;
  const window = visibleListWindow(rows, listIndex, Math.max(1, state.height - 15));
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
        window.items.map((row, offset) => {
          const index = window.start + offset;
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
              onPress={() => {
                interaction.dispatch({ type: 'select-row', index, nowMs: state.nowMs });
              }}
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
  const interaction = useAppInteraction();
  const { color, ascii } = state;
  const lines = [
    'Getting started: 2 Profiles > n file / m MongoDB > Enter use > u unlock.',
    '4 Credentials: Enter detail / n put / c copy / r then y REVEAL.',
    'Paste into overlays: Ctrl+Shift+V / Cmd+V. Paste never submits Enter.',
    'Tab / Shift+Tab cycle; digits 1-9 jump to screens.',
    'Mouse: click actions / wheel to move. Shift+drag selects terminal text.',
    'Vault relocks after 2 minutes without actions or 15 minutes since unlock.',
    'Use --no-mouse for native selection. Run: project-file --environment is CLI-only.',
  ];
  const topics = [
    state.width < 60
      ? [
          'Getting started: 2 Profiles, then u.',
          '4 Credentials: Enter detail, c copy.',
          'Paste: Ctrl+Shift+V / Cmd+V.',
          'Arrows choose the help topic.',
        ]
      : lines,
    [
      'Arrows or j/k move; Enter opens.',
      'Home / End: first / last row.',
      'PgUp / PgDn: jump through lists.',
      'Tab / Shift+Tab cycle screens.',
      'Digits 1-9 jump. Esc goes Home.',
      'Click tabs, rows, and action chips.',
      'Profiles / Vaults: select, then use.',
    ],
    [
      'Enter: masked detail. c: copy.',
      'n: put. m: rename. x: remove.',
      '/: filter names as you type. Esc clears.',
      'r then y: REVEAL. Remasks after 15 seconds.',
      'Terminal clipboard: best-effort clear after ~30s while Kavrix is open. System clipboard: clear manually.',
    ],
    [
      'u: unlock. Shift+U: use passphrase. l: confirm lock.',
      'Recovery: n create / v verify.',
      'Doctor: d checks local health.',
      'Policy: n create / g grant.',
      'Revokes and removals ask first.',
    ],
    [
      't: choose theme. Enter saves it.',
      'a: toggle ASCII borders and text.',
      'NO_COLOR disables colors.',
      '--no-mouse: native selection.',
      'KAVRIX_TUI_REDUCED_MOTION=1',
    ],
  ];
  const topic = Math.max(0, Math.min(HELP_TOPICS.length - 1, state.listIndex));
  return (
    <Panel
      title="Help / Keymap"
      accent={CHROME.heading}
      ascii={ascii}
      color={color}
      paddingX={1}
    >
      <Box flexDirection="row" columnGap={1}>
        {HELP_TOPICS.map((label, index) => (
          <KeyChip
            key={label}
            keyLabel={index === topic ? '>' : ''}
            hint={
              state.width >= 80
                ? (label.split(' ')[0] ?? label)
                : (['Start', 'Keys', 'Secrets', 'Safety', 'View'][index] ?? label)
            }
            active={index === topic}
            color={color}
            onPress={() => {
              interaction.dispatch({ type: 'select-row', index, nowMs: state.nowMs });
            }}
          />
        ))}
      </Box>
      {topic > 0 ? (
        <Text bold {...accentColor(color, CHROME.heading)}>
          {HELP_TOPICS[topic]}
        </Text>
      ) : null}
      {(topics[topic] ?? []).map((line, index) => (
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
  activateRows = false,
}: Readonly<{
  state: AppRouterState;
  title: string;
  accent: AppAccent;
  empty: string;
  rows: readonly Readonly<{ id: string; primary: string; secondary: string }>[];
  /**
   * Enables two-step row activation for lists whose rows change real state, such
   * as switching the active datastore profile or vault. The first click selects,
   * and only a click on an already selected row applies.
   */
  activateRows?: boolean;
}>): ReactElement {
  const interaction = useAppInteraction();
  const { color, ascii, listIndex } = state;
  const window = visibleListWindow(rows, listIndex, Math.max(1, state.height - 17));
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
        window.items.map((row, offset) => {
          const index = window.start + offset;
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
              onPress={() => {
                interaction.dispatch({
                  type: 'select-row',
                  index,
                  activate: activateRows && index === listIndex && state.listPinned,
                  nowMs: state.nowMs,
                });
              }}
            />
          );
        })
      )}
      {rows.length > 0 ? (
        <Text
          dimColor
        >{`${String(window.start + 1)}-${String(window.start + window.items.length)} / ${String(rows.length)}  |  arrows / wheel to move`}</Text>
      ) : null}
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
    case 'session':
      return <SessionScreen state={state} />;
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
