import { Box, Text } from 'ink';
import { useEffect, useState, type ReactElement } from 'react';
import { sanitizeTerminalText } from '../terminal-text.js';
import { resolveMotionPolicy, useCursorVisible } from '../motion.js';
import { PRODUCT_LABEL } from '../product.js';
import { useInputInteraction } from './interaction.js';
import { ClickTarget } from './mouse.js';
import { TerminalViewport } from './viewport.js';
import {
  onboardingStepFocus,
  isPathStep,
  type OnboardingKey,
  type OnboardingState,
} from './onboarding-router.js';
import {
  accentColor,
  CHROME,
  maskBullets,
  toneGlyph,
  type AppAccent,
} from './theme.js';
import {
  ErrorState,
  KeyChip,
  LoadingState,
  Panel,
  ProgressBar,
  SelectRow,
  StatusPill,
  SingleLine,
} from './widgets.js';

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

/** Presentational onboarding chrome for first-paint tests (no Ink hooks). */
export function renderOnboardingScreen(state: OnboardingState): ReactElement {
  return <OnboardingChrome state={state} />;
}

export function OnboardingChrome({
  state,
  registerViewInput,
  invalidateFrame,
}: Readonly<{
  state: OnboardingState;
  registerViewInput?: (handler: (key: OnboardingKey) => boolean) => () => void;
  invalidateFrame?: () => void;
}>): ReactElement {
  const { color, ascii, width, height } = state;
  const interaction = useInputInteraction();
  const focus = onboardingStepFocus(state.step, state.storage);
  const caret = useCursorVisible(
    resolveMotionPolicy().animate && isMaskedStep(state.step),
  );
  const [details, setDetails] = useState(false);
  const [page, setPage] = useState(0);
  const wide = width >= 100 && height >= 24;
  const compact = height < 18;
  const notice = state.error ?? state.message;
  const accent: AppAccent =
    state.step === 'success'
      ? CHROME.success
      : state.step === 'error'
        ? CHROME.danger
        : CHROME.accent;
  const pageRows = Math.max(2, height - (compact ? 10 : height >= 24 ? 15 : 11));
  const guidanceLines = wrapGuidance(
    safe(
      'Path controls: Ctrl+D secure default, Ctrl+B browse folders, Ctrl+R review permission repair, Enter recheck. Cursor: arrows, Home/End, Ctrl+A/E/U. Folder browser: Enter open, Ctrl+S choose folder, Ctrl+P parent, Esc back. ' +
        (state.step === 'review' ? reviewSummary(state).join(' | ') + ' | ' : '') +
        (state.toolView?.kind === 'repair'
          ? `Repair directory: ${state.toolView.directory}. Confirmation restricts this Kavrix directory to its owner; file contents remain unchanged. Windows may tighten inherited child access. `
          : state.toolView?.kind === 'folders'
            ? `Current folder: ${state.toolView.directory}. `
            : '') +
        (notice ??
          'Follow the active step. Secrets stay masked; keyboard navigation always works.'),
      ascii,
    ),
    Math.max(12, width - 10),
  );
  const pages = Math.max(1, Math.ceil(guidanceLines.length / pageRows));
  const currentPage = Math.min(page, pages - 1);
  const continueHint = details
    ? 'next'
    : state.step === 'welcome'
      ? 'start'
      : state.step === 'error'
        ? 'review'
        : state.step === 'success'
          ? 'finish'
          : state.step === 'review'
            ? 'create'
            : state.toolView?.kind === 'repair'
              ? 'repair'
              : state.toolView?.kind === 'folders'
                ? 'open'
                : compact
                  ? 'next'
                  : 'continue';
  const toggleHelp = (): void => {
    invalidateFrame?.();
    setPage(0);
    setDetails(!details);
  };
  const nextPage = (): void => {
    invalidateFrame?.();
    if (currentPage + 1 < pages) setPage(currentPage + 1);
    else setDetails(false);
  };

  useEffect(
    () =>
      registerViewInput?.((key) => {
        if (key.name === 'help') {
          toggleHelp();
          return true;
        }
        if (!details || (key.ctrl === true && key.text === 'c')) return false;
        invalidateFrame?.();
        if (key.name === 'escape') setDetails(false);
        else if (key.name === 'return') nextPage();
        else if (key.name === 'down') setPage(Math.min(pages - 1, currentPage + 1));
        else if (key.name === 'up') setPage(Math.max(0, currentPage - 1));
        return true;
      }),
    [registerViewInput, details, currentPage, pages],
  );

  return (
    <TerminalViewport width={width} height={height}>
      <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
        <Box flexDirection="row" columnGap={1}>
          <SingleLine bold {...accentColor(color, CHROME.accent)}>
            {PRODUCT_LABEL} / SETUP
          </SingleLine>
          {!compact ? (
            <StatusPill
              label="storage"
              value={state.storage ?? 'choose'}
              accent={CHROME.heading}
              color={color}
              ascii={ascii}
            />
          ) : null}
        </Box>
        {!compact ? (
          <SingleLine {...accentColor(color, CHROME.muted)}>
            Private keys on your device. Encrypted data in your chosen storage.
          </SingleLine>
        ) : null}
      </Panel>

      <Box
        flexDirection="row"
        flexGrow={1}
        flexShrink={1}
        minHeight={0}
        overflow="hidden"
        paddingX={width >= 80 ? 2 : 1}
        paddingY={height >= 24 ? 1 : 0}
        columnGap={2}
      >
        {wide && !details ? <SetupGuide state={state} /> : null}
        <Box
          flexDirection="column"
          flexGrow={1}
          minWidth={0}
          minHeight={0}
          overflow="hidden"
        >
          {details ? (
            <ClickTarget
              onScroll={(delta) => {
                invalidateFrame?.();
                setPage((value) => Math.max(0, Math.min(pages - 1, value + delta)));
              }}
            >
              <Panel
                title="Setup guidance"
                accent={accent}
                ascii={ascii}
                color={color}
                paddingX={1}
              >
                <Text>
                  {guidanceLines
                    .slice(currentPage * pageRows, (currentPage + 1) * pageRows)
                    .join('\n')}
                </Text>
                <SingleLine {...accentColor(color, CHROME.muted)}>
                  {safe(
                    `Page ${String(currentPage + 1)}/${String(pages)} - Enter / arrows / wheel`,
                    ascii,
                  )}
                </SingleLine>
              </Panel>
            </ClickTarget>
          ) : (
            <>
              <SingleLine bold {...accentColor(color, accent)}>
                {safe(
                  `ACTIVE ${String(focus.index)}/${String(focus.total)} - ${focus.title}`,
                  ascii,
                )}
              </SingleLine>
              {!compact ? (
                <>
                  <SingleLine {...accentColor(color, CHROME.muted)}>
                    {safe(focus.cue, ascii)}
                  </SingleLine>
                  {state.step === 'creating' || state.step === 'error' ? null : (
                    <ProgressBar
                      progress={(focus.index - 1) / Math.max(1, focus.total - 1)}
                      width={Math.max(8, Math.min(36, width - 30))}
                      color={color}
                      ascii={ascii}
                      accent={accent}
                    />
                  )}
                </>
              ) : null}
              <Box flexDirection="column" flexShrink={0} marginTop={compact ? 0 : 1}>
                {renderOnboardingBody(state, caret, interaction.press)}
              </Box>
              {notice === null ? null : (
                <Box
                  flexDirection="column"
                  flexShrink={1}
                  minHeight={0}
                  maxHeight={compact ? 1 : Math.max(2, Math.floor(height / 3))}
                  overflow="hidden"
                  marginTop={compact ? 0 : 1}
                >
                  <Text
                    {...accentColor(
                      color,
                      state.error === null ? CHROME.muted : CHROME.danger,
                    )}
                  >
                    {safe(
                      compact && state.step === 'welcome' ? focus.cue : notice,
                      ascii,
                    )}
                  </Text>
                </Box>
              )}
            </>
          )}
        </Box>
      </Box>

      <Panel accent={CHROME.muted} ascii={ascii} color={color} paddingX={1}>
        {isPathStep(state.step) ? (
          <Box flexDirection="row" columnGap={1}>
            <KeyChip
              keyLabel="^D"
              hint="default"
              color={color}
              disabled={state.pendingTool !== null}
              onPress={() => {
                interaction.press({ text: 'd', ctrl: true });
              }}
            />
            <KeyChip
              keyLabel="^B"
              hint="browse"
              color={color}
              disabled={state.pendingTool !== null}
              onPress={() => {
                interaction.press({ text: 'b', ctrl: true });
              }}
            />
            <KeyChip
              keyLabel="^R"
              hint="repair"
              color={color}
              disabled={state.pendingTool !== null}
              onPress={() => {
                interaction.press({ text: 'r', ctrl: true });
              }}
            />
          </Box>
        ) : null}

        {state.step === 'review' && state.toolView === null ? (
          <Box flexDirection="row" columnGap={1}>
            {[
              'profile',
              state.storage === 'file' ? 'data' : 'db',
              'key',
              'recovery',
            ].map((label, index) => (
              <KeyChip
                key={label}
                keyLabel={String(index + 1)}
                hint={label}
                color={color}
                disabled={interaction.busy}
                onPress={() => {
                  interaction.press({ text: String(index + 1) });
                }}
              />
            ))}
          </Box>
        ) : null}
        <Box flexDirection="row" columnGap={1} flexWrap="wrap">
          <KeyChip
            keyLabel="Enter"
            button={height >= 24 && width >= 60}
            hint={continueHint}
            color={color}
            disabled={interaction.busy}
            onPress={() => {
              if (details) nextPage();
              else interaction.press({ name: 'return' });
            }}
          />
          <KeyChip
            keyLabel="Esc"
            button={height >= 24 && width >= 60}
            hint="back"
            color={color}
            disabled={interaction.busy}
            onPress={() => {
              if (details) {
                invalidateFrame?.();
                setDetails(false);
              } else interaction.press({ name: 'escape' });
            }}
          />
          <KeyChip
            keyLabel="^G"
            hint="help"
            color={color}
            button={height >= 24 && width >= 60}
            onPress={toggleHelp}
          />
          <KeyChip
            keyLabel="^C"
            button={height >= 24 && width >= 60}
            hint={
              compact && (state.step === 'review' || state.toolView !== null)
                ? ''
                : 'quit'
            }
            color={color}
            disabled={interaction.busy}
            keyAccent={CHROME.danger}
            onPress={() => {
              interaction.press({ text: 'c', ctrl: true });
            }}
          />
        </Box>
      </Panel>
    </TerminalViewport>
  );
}

/** Paginate public instructions only: never include the input query or key material. */
function wrapGuidance(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/u)) {
    if (line.length > 0 && line.length + word.length + 1 > width) {
      lines.push(line);
      line = '';
    }
    const glyphs = Array.from(word);
    while (glyphs.length > width) {
      if (line.length > 0) {
        lines.push(line);
        line = '';
      }
      lines.push(glyphs.splice(0, width).join(''));
    }
    line = line.length === 0 ? glyphs.join('') : line + ' ' + glyphs.join('');
  }
  if (line.length > 0) lines.push(line);
  return lines;
}

function SetupGuide({ state }: Readonly<{ state: OnboardingState }>): ReactElement {
  const stages = [
    'Choose storage',
    'Profile location',
    'Protected key',
    'Owner access',
    'Recovery kit',
    'Finish setup',
  ];
  const step = state.step;
  const active =
    step === 'welcome' || step === 'storage'
      ? 0
      : step.includes('profile-id') ||
          step === 'file-data-file' ||
          step === 'mongo-database'
        ? 1
        : step.endsWith('key-file')
          ? 2
          : step.includes('recovery')
            ? 4
            : step.includes('passphrase') || step === 'mongo-url'
              ? 3
              : 5;
  return (
    <Box width={24} flexShrink={0} flexDirection="column">
      <Text bold {...accentColor(state.color, CHROME.heading)}>
        YOUR SETUP
      </Text>
      {stages.map((label, index) => (
        <Box key={label} marginTop={1}>
          <Text
            bold={active === index}
            {...accentColor(
              state.color,
              active === index ? CHROME.accent : CHROME.muted,
            )}
          >
            {index < active ? '[+] ' : active === index ? '[>] ' : '[ ] '}
            {label}
          </Text>
        </Box>
      ))}
      <Box marginTop={2}>
        <Text {...accentColor(state.color, CHROME.muted)}>
          Local-first. Values stay masked. Use Help for full instructions.
        </Text>
      </Box>
    </Box>
  );
}

function renderOnboardingBody(
  state: OnboardingState,
  caret: boolean,
  press: (key: OnboardingKey) => void,
): ReactElement {
  const { ascii, color, query } = state;
  const masked = maskBullets(Array.from(query).length, ascii);

  if (state.toolView?.kind === 'repair') {
    return (
      <Panel title="Confirm directory repair" ascii={ascii} color={color} paddingX={1}>
        <SingleLine>{safe(state.toolView.directory, ascii)}</SingleLine>
        <Text>
          Restrict this Kavrix directory to its owner. File contents remain unchanged.
        </Text>
        <Text>Enter confirms repair. Esc cancels.</Text>
      </Panel>
    );
  }
  if (state.toolView?.kind === 'folders') {
    const view = state.toolView;
    const rows = Math.max(1, Math.min(8, state.height - 11));
    const start = Math.max(0, state.folderIndex - rows + 1);
    return (
      <Panel title="Choose folder" ascii={ascii} color={color} paddingX={1}>
        <SingleLine>{safe(view.directory, ascii)}</SingleLine>
        {view.entries.slice(start, start + rows).map((entry, offset) => (
          <SelectRow
            key={entry.path}
            active={state.folderIndex === start + offset}
            label={safe(entry.name, ascii)}
            color={color}
            ascii={ascii}
            accent={CHROME.accent}
            onPress={() => {
              press({ text: String(start + offset + 1) });
            }}
          />
        ))}
        <Box flexDirection="row" columnGap={1}>
          <KeyChip
            keyLabel="^S"
            hint="use folder"
            color={color}
            onPress={() => {
              press({ text: 's', ctrl: true });
            }}
          />
          <KeyChip
            keyLabel="^P"
            hint="parent"
            color={color}
            onPress={() => {
              press({ text: 'p', ctrl: true });
            }}
          />
        </Box>
        {view.truncated ? <Text>Listing limited; open a subfolder.</Text> : null}
      </Panel>
    );
  }
  if (state.step === 'review') {
    const summary = reviewSummary(state);
    const rows = state.height < 18 ? 1 : summary.length;
    const start =
      state.height < 18 ? Math.min(state.folderIndex, summary.length - rows) : 0;
    return (
      <Panel title="Review before creating" ascii={ascii} color={color} paddingX={1}>
        {summary.slice(start, start + rows).map((line) => (
          <SingleLine key={line}>{safe(line, ascii)}</SingleLine>
        ))}
        {state.height < 18 ? (
          <Text>Arrows: review all. ^G: full details.</Text>
        ) : (
          <Text>Protected inputs entered (hidden). Enter creates.</Text>
        )}
      </Panel>
    );
  }

  if (state.step === 'welcome') {
    return (
      <Panel
        title="Welcome"
        accent={CHROME.accent}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={state.height >= 24 ? 1 : 0}
      >
        <Text bold {...accentColor(color, CHROME.accent)}>
          {safe('Initialize a Kavrix vault', ascii)}
        </Text>
        {state.height < 18 ? null : (
          <Text {...accentColor(color, CHROME.muted)}>
            {safe(
              'Interactive setup creates a real profile, vault, and verified recovery kit.',
              ascii,
            )}
          </Text>
        )}
        {state.height < 18 ? null : (
          <Text {...accentColor(color, CHROME.muted)}>
            {safe('Secrets stay masked. Press Enter to choose storage.', ascii)}
          </Text>
        )}
        {state.height < 32 ? null : (
          <Text {...accentColor(color, CHROME.muted)}>
            {safe(
              'Steps: storage · profile id · key file · owner passphrase · recovery kit · session unlock.',
              ascii,
            )}
          </Text>
        )}
      </Panel>
    );
  }

  if (state.step === 'storage') {
    return (
      <Panel
        title="Storage"
        accent={CHROME.accent}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={state.height >= 24 ? 1 : 0}
      >
        <SelectRow
          active={state.storageIndex === 0}
          label="1  Local encrypted file"
          onPress={() => {
            press({ text: '1' });
          }}
          hint="Simplest for one device"
          accent={CHROME.accent}
          color={color}
          ascii={ascii}
        />
        <SelectRow
          active={state.storageIndex === 1}
          label="2  MongoDB"
          onPress={() => {
            press({ text: '2' });
          }}
          hint="Shared / remote datastore"
          accent={CHROME.accent}
          color={color}
          ascii={ascii}
        />
      </Panel>
    );
  }

  if (state.step === 'creating') {
    return (
      <Panel
        title="Creating"
        accent={CHROME.warning}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={state.height >= 24 ? 1 : 0}
      >
        <LoadingState
          label={stageLabel(state)}
          color={color}
          ascii={ascii}
          animate={resolveMotionPolicy().animate}
        />
        <Text {...accentColor(color, CHROME.muted)}>
          {safe(
            `Elapsed ${String(state.elapsedSeconds)}s. Recovery is verified before completion.`,
            ascii,
          )}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'enable-session') {
    return (
      <Panel
        title="Session unlock"
        accent={CHROME.accent}
        ascii={state.ascii}
        color={state.color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...accentColor(state.color, CHROME.success)}>
          {safe('SETUP COMPLETE', state.ascii)}
        </Text>
        <Text>
          {safe(
            'Enable OS session unlock? Future unlocks then use Windows Hello / the OS credential store instead of the passphrase.',
            state.ascii,
          )}
        </Text>
        <Text {...accentColor(state.color, CHROME.muted)}>
          {safe(
            'Enter = enable now · Esc = skip (passphrase always still works; enable later from the Session screen)',
            state.ascii,
          )}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'success') {
    return (
      <Panel
        title="Success"
        accent={CHROME.success}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...accentColor(color, CHROME.success)}>
          {`${toneGlyph('success', ascii).trim()} ${safe('SETUP COMPLETE', ascii)}`}
        </Text>
        <ProgressBar
          progress={1}
          width={24}
          color={color}
          ascii={ascii}
          accent={CHROME.success}
        />
        <Text {...accentColor(color, CHROME.success)}>
          {safe(
            `Profile selected: ${state.completedProfileId ?? state.profileId ?? 'default'}`,
            ascii,
          )}
        </Text>
        {state.completedRecoveryFile !== null ? (
          <Text {...accentColor(color, CHROME.success)}>
            {safe(`Recovery kit verified: ${state.completedRecoveryFile}`, ascii)}
          </Text>
        ) : null}
        <Text {...accentColor(color, CHROME.muted)}>
          {safe('Press Enter to finish, then run: kavrix tui', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'error') {
    return (
      <Panel
        title="Error"
        accent={CHROME.danger}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <ErrorState
          title={state.error ?? 'Setup failed.'}
          recovery="Enter/r review destinations · Esc/q quit"
          color={color}
          ascii={ascii}
        />
      </Panel>
    );
  }

  const title = inputTitle(state.step);
  const protectedInput = isMaskedStep(state.step);
  const prefix = protectedInput && state.height < 18 ? '' : `${title}: `;
  const value = protectedInput ? masked : safe(query, ascii);
  const cells = state.width - (state.width >= 100 && state.height >= 24 ? 34 : 10);
  const room = Math.max(4, cells - prefix.length - 1);
  const glyphs = Array.from(value);
  const cursor = Math.max(0, Math.min(state.cursor ?? glyphs.length, glyphs.length));
  const begin = Math.max(0, cursor - room + 1);
  const window = glyphs.slice(begin, begin + room - 1);
  window.splice(cursor - begin, 0, caret ? '_' : ' ');
  const visible = window.join('');
  const body = prefix + visible;
  return (
    <Panel
      {...(state.height < 18 ? {} : { title: `ACTIVE · ${title}` })}
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
      paddingY={state.height >= 24 ? 1 : 0}
    >
      <SingleLine bold {...accentColor(color, CHROME.accent)}>
        {safe(body, ascii)}
      </SingleLine>
      {isMaskedStep(state.step) ? (
        <Text {...accentColor(color, CHROME.muted)}>
          {safe('Paste works (Ctrl+Shift+V / Cmd+V)', ascii)}
        </Text>
      ) : null}
      {state.step === 'mongo-url' ? (
        <KeyChip
          keyLabel="^T"
          hint={state.connectionVerified ? 'connection verified' : 'test connection'}
          color={color}
          disabled={state.pendingTool !== null}
          onPress={() => {
            press({ text: 't', ctrl: true });
          }}
        />
      ) : null}
      {state.pendingTool !== null || state.checkingDestination ? (
        <Text>Checking… {String(state.elapsedSeconds)}s</Text>
      ) : null}
    </Panel>
  );
}

function reviewSummary(state: OnboardingState): string[] {
  return [
    `Storage: ${state.storage ?? 'choose'}; profile: ${state.profileId ?? 'default'}`,
    state.storage === 'file'
      ? `Data: ${state.dataFile ?? ''}`
      : `Database: ${state.database ?? ''}; connection: ${state.connectionVerified ? 'verified' : 'needs test'}`,
    `Key: ${state.keyFile ?? ''}`,
    `Recovery: ${state.recoveryFile ?? ''}`,
    `Vault: ${state.profileId ?? 'default'}-vault; protected inputs hidden`,
  ];
}

function stageLabel(state: OnboardingState): string {
  switch (state.progress?.stage) {
    case 'checking-permissions':
      return 'Checking protected destinations';
    case 'connecting':
      return 'Connecting to MongoDB';
    case 'creating-storage':
      return 'Creating encrypted storage';
    case 'creating-vault':
      return 'Creating vault';
    case 'creating-recovery':
      return 'Creating recovery kit';
    case 'verifying-recovery':
      return 'Verifying recovery kit';
    default:
      return 'Preparing setup';
  }
}

function inputTitle(step: OnboardingState['step']): string {
  switch (step) {
    case 'file-profile-id':
    case 'mongo-profile-id':
      return 'Profile id';
    case 'file-data-file':
      return 'Data file';
    case 'file-key-file':
    case 'mongo-key-file':
      return 'Key file';
    case 'mongo-database':
      return 'Database name';
    case 'mongo-url':
      return 'MongoDB URL';
    case 'file-passphrase':
    case 'mongo-passphrase':
      return 'Owner passphrase';
    case 'file-passphrase-confirm':
    case 'mongo-passphrase-confirm':
      return 'Confirm owner passphrase';
    case 'file-recovery-passphrase':
    case 'mongo-recovery-passphrase':
      return 'Recovery-kit passphrase';
    case 'file-recovery-passphrase-confirm':
    case 'mongo-recovery-passphrase-confirm':
      return 'Confirm recovery-kit passphrase';
    case 'file-recovery-file':
    case 'mongo-recovery-file':
      return 'Recovery kit path';
    default:
      return 'Value';
  }
}

function isMaskedStep(step: OnboardingState['step']): boolean {
  return (
    step === 'file-passphrase' ||
    step === 'file-passphrase-confirm' ||
    step === 'file-recovery-passphrase' ||
    step === 'file-recovery-passphrase-confirm' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm' ||
    step === 'mongo-recovery-passphrase' ||
    step === 'mongo-recovery-passphrase-confirm'
  );
}
