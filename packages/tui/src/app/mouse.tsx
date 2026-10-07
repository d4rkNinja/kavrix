import { StringDecoder } from 'node:string_decoder';
import { PassThrough } from 'node:stream';

import { Box, measureElement, type BoxProps, type DOMElement } from 'ink';
import {
  createContext,
  useContext,
  useEffect,
  useRef,
  type ReactElement,
  type ReactNode,
  type RefObject,
} from 'react';

const SGR_MOUSE_PREFIX = '\u001B[<';
const X10_MOUSE_PREFIX = '\u001B[M';
const BRACKETED_PASTE_START = '\u001B[200~';
const BRACKETED_PASTE_END = '\u001B[201~';
const SGR_MOUSE_PATTERN = new RegExp(
  `^${String.fromCharCode(27)}\\[<(\\d{1,3});(\\d{1,5});(\\d{1,5})([Mm])$`,
);
/**
 * Longest well-formed SGR report is `ESC[<` + button(3) + `;` + column(5) + `;`
 * + row(5) + `M` = 19 cells. The bound only has to exceed that, so a frame that
 * never terminates is abandoned quickly instead of swallowing a screenful of
 * keystrokes typed into a masked field.
 */
const MAX_MOUSE_REPORT_LENGTH = 24;
const MAX_PASTE_LENGTH = 64 * 1024;
/**
 * A control-sequence tail whose `ESC` has already been consumed: `[A` (arrows),
 * `[1;5C` (modified arrows), `[5~` (paged keys), and `<0;4;9M` / `[<0;4;9M` (a
 * mouse report split mid-frame). Both introducers are control-sequence syntax
 * that cannot begin text a user typed, which is what makes dropping them safe.
 */
const ORPHAN_CSI_TAIL_PATTERN = /^(?:\[|<)[0-9;<>?]*[ -/]*[@-~]/u;
const MAX_MOUSE_COORDINATE = 10_000;
const X10_COORDINATE_OFFSET = 32;
const MOUSE_MOTION_BIT = 32;
const MOUSE_WHEEL_BIT = 64;
const MOUSE_EXTRA_BUTTON_BIT = 128;
const ENABLE_MOUSE = '\u001B[?1000h\u001B[?1006h';
const DISABLE_MOUSE = '\u001B[?1006l\u001B[?1000l';

export type MouseEvent =
  | Readonly<{ type: 'click'; x: number; y: number }>
  | Readonly<{ type: 'scroll'; x: number; y: number; delta: -1 | 1 }>;

export interface MouseRegionHandlers {
  readonly onClick?: () => void;
  readonly onScroll?: (delta: -1 | 1) => void;
}

interface MouseRegion extends MouseRegionHandlers {
  readonly getBounds: () => MouseBounds | null;
  readonly priority: number;
  readonly order: number;
}

interface MouseBounds {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface MouseInputOptions {
  readonly stdin: NodeJS.ReadStream;
  readonly stdout: NodeJS.WriteStream;
  readonly enabled?: boolean;
  /**
   * Zero-based terminal position of Ink's live layout region. Prefer Ink's
   * `alternateScreen: true` with no `<Static>` content, which makes this 0,0.
   */
  readonly viewportOrigin?: Readonly<{ x: number; y: number }>;
  /** Delay before an ambiguous split escape prefix is released as keyboard input. */
  readonly escapeTimeoutMs?: number;
  /**
   * Monotonic id of the frame currently on screen. Reports decoded from one read
   * share a snapshot of it, so a click aimed at a frame that has already been
   * replaced is dropped instead of being resolved against new geometry.
   */
  readonly getFrame?: () => number;
  /** Reject pointer reports while a layout update is pending or not yet painted. */
  readonly isInputReady?: () => boolean;
}

export interface MouseInput {
  readonly stdin: NodeJS.ReadStream;
  readonly enabled: boolean;
  /**
   * Resolves once click regions are registered *as of this call*, or immediately
   * when tracking is disabled. Region handlers are installed from passive
   * effects, so input delivered before that flush lands on nothing. The chrome
   * remounts on navigation, which disposes and re-registers every region, so this
   * re-checks the live set instead of latching a one-shot readiness flag.
   */
  readonly whenInteractive: () => Promise<void>;
  registerRegion(region: Omit<MouseRegion, 'order'>): () => void;
  dispose(): void;
}

interface DecodedInput {
  readonly input: string;
  readonly events: readonly MouseEvent[];
}

interface Quarantine {
  remaining: number;
  awaitPasteEnd: boolean;
}

/**
 * Incrementally removes mouse reports before Ink can broadcast them through
 * useInput. Mouse-looking malformed frames are discarded rather than exposed as
 * text, which keeps control bytes out of secret and confirmation fields.
 *
 * Every discard path is bounded: a frame that never terminates, and a paste that
 * never ends, both release the decoder back to normal scanning. Input must never
 * be starved by a malformed frame, and a stuck paste flag must never silence
 * clicks for the rest of the session.
 */
export class SgrMouseDecoder {
  #pending = '';
  #inBracketedPaste = false;
  #pasteRemaining = 0;
  #quarantine: Quarantine | null = null;
  /** Set once an ambiguous `ESC` tail is released, see `#swallowOrphanContinuation`. */
  #awaitingContinuation = false;
  /** Set when a held introducer was dropped, so its final byte can be consumed. */
  #awaitingFinalByte = false;

  push(chunk: string): DecodedInput {
    let source = this.#pending + chunk;
    this.#pending = '';
    source = this.#swallowOrphanContinuation(source);
    let input = '';
    const events: MouseEvent[] = [];

    while (source.length > 0) {
      if (this.#quarantine !== null) {
        const step = this.#quarantineStep(source);
        source = step.source;
        input += step.input;
        continue;
      }

      if (this.#inBracketedPaste) {
        this.#pasteRemaining -= source.length;
        if (this.#pasteRemaining <= 0) {
          input += BRACKETED_PASTE_END;
          this.#inBracketedPaste = false;
          continue;
        }
      }

      const escapeIndex = source.indexOf('\u001B');
      if (escapeIndex === -1) {
        input += source;
        break;
      }

      input += source.slice(0, escapeIndex);
      source = source.slice(escapeIndex);

      if (source.startsWith(BRACKETED_PASTE_START)) {
        input += BRACKETED_PASTE_START;
        source = source.slice(BRACKETED_PASTE_START.length);
        // A nested start must not extend the budget, or a stream of repeated
        // starts would keep mouse reporting suppressed indefinitely.
        if (!this.#inBracketedPaste) {
          this.#pasteRemaining = MAX_PASTE_LENGTH;
        }
        this.#inBracketedPaste = true;
        continue;
      }

      if (source.startsWith(BRACKETED_PASTE_END)) {
        input += BRACKETED_PASTE_END;
        source = source.slice(BRACKETED_PASTE_END.length);
        this.#inBracketedPaste = false;
        continue;
      }

      if (
        SGR_MOUSE_PREFIX.startsWith(source) ||
        X10_MOUSE_PREFIX.startsWith(source) ||
        BRACKETED_PASTE_START.startsWith(source) ||
        BRACKETED_PASTE_END.startsWith(source)
      ) {
        this.#pending = source;
        break;
      }

      if (source.startsWith(X10_MOUSE_PREFIX)) {
        const x10Length = X10_MOUSE_PREFIX.length + 3;
        if (source.length < x10Length) {
          if (source.length <= MAX_MOUSE_REPORT_LENGTH) {
            this.#pending = source;
            break;
          }

          source = source.slice(1);
          continue;
        }

        const report = source.slice(X10_MOUSE_PREFIX.length, x10Length);
        source = source.slice(x10Length);
        const event = parseX10Report(report);
        if (event !== null && !this.#inBracketedPaste) {
          events.push(event);
        }
        continue;
      }

      if (!source.startsWith(SGR_MOUSE_PREFIX)) {
        input += source[0] ?? '';
        source = source.slice(1);
        continue;
      }

      const finalIndex = findMouseTerminator(source, SGR_MOUSE_PREFIX.length);
      if (finalIndex === -1) {
        // A prefix longer than any valid report is malformed. Dropping it keeps
        // a hostile prefix from starving every later keystroke, and resuming
        // normal scanning is what makes that recovery possible.
        if (source.length <= MAX_MOUSE_REPORT_LENGTH) {
          this.#pending = source;
        }
        break;
      }

      const report = source.slice(0, finalIndex + 1);
      source = source.slice(finalIndex + 1);
      if (report.length > MAX_MOUSE_REPORT_LENGTH) {
        continue;
      }

      const event = parseMouseReport(report);
      if (event && !this.#inBracketedPaste) {
        events.push(event);
      }
    }

    return { input, events };
  }

  /**
   * A released `ESC` tail means a control sequence was still incomplete when the
   * escape window closed, so its remainder may still arrive as a separate read.
   * Forwarding that remainder would type raw CSI bytes (`[B` for a split arrow
   * key, `[<0;4;9M` for a split report) straight into a masked passphrase and
   * submit the corrupted value.
   *
   * When only `ESC` was released the remainder still carries its `[` or `<`
   * introducer, which is control-sequence syntax no one types, so it is dropped.
   * When the introducer itself was dropped the remainder may be a bare final
   * byte, which is indistinguishable from typing — ambiguity resolves closed, so
   * exactly one leading final byte is consumed. The loss is a single visible
   * character the user retypes; the alternative is submitting a wrong secret.
   */
  #swallowOrphanContinuation(source: string): string {
    if (this.#awaitingContinuation) {
      this.#awaitingContinuation = false;
      const tail = ORPHAN_CSI_TAIL_PATTERN.exec(source);
      if (tail !== null) return source.slice(tail[0].length);
    }
    const swallowFinalByte = this.#awaitingFinalByte;
    this.#awaitingFinalByte = false;
    if (!swallowFinalByte || source.length === 0) return source;
    const code = source.codePointAt(0) ?? 0;
    return code >= 0x40 && code <= 0x7e ? source.slice(1) : source;
  }

  /**
   * Drops a timed-out ambiguous tail. The byte budget guarantees the decoder
   * returns to normal scanning, and an interrupted bracketed paste is always
   * closed here so a stale paste flag cannot silence clicks for the session.
   */
  #quarantineStep(source: string): { source: string; input: string } {
    const quarantine = this.#quarantine;
    if (quarantine === null) {
      return { source, input: '' };
    }

    if (quarantine.awaitPasteEnd) {
      const pasteEndIndex = source.indexOf(BRACKETED_PASTE_END);
      if (pasteEndIndex !== -1) {
        this.#quarantine = null;
        this.#inBracketedPaste = false;
        return { source: '', input: BRACKETED_PASTE_END };
      }
    }

    const finalIndex = findMouseTerminator(source, 0);
    if (finalIndex !== -1) {
      this.#quarantine = null;
    } else {
      quarantine.remaining -= Math.min(source.length, quarantine.remaining);
      if (quarantine.remaining > 0) {
        return { source: '', input: '' };
      }

      this.#quarantine = null;
    }

    // The remainder of this read is still ambiguous tail. Dropping it is the
    // deliberate fail-closed choice: the decoder hands the stream back to
    // normal scanning on the next read rather than risking terminal bytes in a
    // masked field.
    return { source: '', input: quarantine.awaitPasteEnd ? BRACKETED_PASTE_END : '' };
  }

  flushPending(): string {
    const pending = this.#pending;
    this.#pending = '';
    if (pending.startsWith(SGR_MOUSE_PREFIX) || pending.startsWith(X10_MOUSE_PREFIX)) {
      const awaitPasteEnd = this.#inBracketedPaste;
      this.#inBracketedPaste = false;
      this.#pasteRemaining = 0;
      this.#quarantine = {
        remaining: MAX_MOUSE_REPORT_LENGTH,
        awaitPasteEnd,
      };
      return '';
    }

    // A lone `ESC` is byte-identical to the first byte of a mouse report, so
    // only the escape window can tell them apart. Forward exactly that byte so
    // the Escape key keeps working. Anything longer is already control-sequence
    // syntax, and Ink resolves a released `ESC[` as literal input — which types a
    // stray `[` into whatever field is focused — so it is dropped and the
    // continuation guard is armed for the remainder.
    if (pending.length > 0) {
      this.#awaitingContinuation = true;
      if (pending === '\u001B') {
        return pending;
      }
      this.#awaitingFinalByte = true;
      return '';
    }

    return pending;
  }

  hasPending(): boolean {
    return this.#pending.length > 0;
  }
}

function findMouseTerminator(value: string, from: number): number {
  for (let index = from; index < value.length; index += 1) {
    if (value[index] === 'M' || value[index] === 'm') {
      return index;
    }
  }

  return -1;
}

function decodeMouseButton(button: number): MouseEvent | null {
  if ((button & MOUSE_EXTRA_BUTTON_BIT) !== 0 || (button & MOUSE_MOTION_BIT) !== 0) {
    return null;
  }

  if ((button & MOUSE_WHEEL_BIT) !== 0) {
    // Wheel motion carries no text, so modifier chords stay safe to honour.
    switch (button & 0x03) {
      case 0:
        return { type: 'scroll', x: 0, y: 0, delta: -1 };
      case 1:
        return { type: 'scroll', x: 0, y: 0, delta: 1 };
      default:
        return null;
    }
  }

  if (button === 0) {
    return { type: 'click', x: 0, y: 0 };
  }

  return null;
}

function parseMouseReport(report: string): MouseEvent | null {
  const match = SGR_MOUSE_PATTERN.exec(report);
  if (!match) {
    return null;
  }

  const button = Number(match[1]);
  const column = Number(match[2]);
  const row = Number(match[3]);
  const final = match[4];
  if (
    !Number.isSafeInteger(button) ||
    button > 127 ||
    !Number.isSafeInteger(column) ||
    column < 1 ||
    column > MAX_MOUSE_COORDINATE ||
    !Number.isSafeInteger(row) ||
    row < 1 ||
    row > MAX_MOUSE_COORDINATE
  ) {
    return null;
  }

  if (final !== 'M') {
    return null;
  }

  const event = decodeMouseButton(button);
  return event === null ? null : { ...event, x: column - 1, y: row - 1 };
}

/**
 * Legacy X10 encoding, used by terminals that honour mouse tracking but ignore
 * SGR 1006. Its payload bytes are printable, so they must be consumed here or
 * they would land in masked secret fields as literal text.
 */
function parseX10Report(report: string): MouseEvent | null {
  if (report.length !== 3) {
    return null;
  }

  const button = report.charCodeAt(0) - X10_COORDINATE_OFFSET;
  const column = report.charCodeAt(1) - X10_COORDINATE_OFFSET;
  const row = report.charCodeAt(2) - X10_COORDINATE_OFFSET;
  if (
    button < 0 ||
    button > 127 ||
    column < 1 ||
    column > MAX_MOUSE_COORDINATE ||
    row < 1 ||
    row > MAX_MOUSE_COORDINATE
  ) {
    return null;
  }

  const event = decodeMouseButton(button);
  return event === null ? null : { ...event, x: column - 1, y: row - 1 };
}

function contains(bounds: MouseBounds, event: MouseEvent): boolean {
  return (
    bounds.width > 0 &&
    bounds.height > 0 &&
    event.x >= bounds.x &&
    event.x < bounds.x + bounds.width &&
    event.y >= bounds.y &&
    event.y < bounds.y + bounds.height
  );
}

function measureVisibleBounds(node: DOMElement): MouseBounds {
  let bounds = measureElement(node);
  let ancestor = node.parentNode;

  while (ancestor) {
    const clipX =
      ancestor.style.overflow === 'hidden' || ancestor.style.overflowX === 'hidden';
    const clipY =
      ancestor.style.overflow === 'hidden' || ancestor.style.overflowY === 'hidden';
    if (clipX || clipY) {
      const clippingBounds = measureElement(ancestor);
      const left = clipX ? Math.max(bounds.x, clippingBounds.x) : bounds.x;
      const top = clipY ? Math.max(bounds.y, clippingBounds.y) : bounds.y;
      const right = clipX
        ? Math.min(bounds.x + bounds.width, clippingBounds.x + clippingBounds.width)
        : bounds.x + bounds.width;
      const bottom = clipY
        ? Math.min(bounds.y + bounds.height, clippingBounds.y + clippingBounds.height)
        : bounds.y + bounds.height;
      bounds = {
        x: left,
        y: top,
        width: Math.max(0, right - left),
        height: Math.max(0, bottom - top),
      };
    }

    ancestor = ancestor.parentNode;
  }

  return bounds;
}

export function createMouseInput(options: MouseInputOptions): MouseInput {
  const decoder = new SgrMouseDecoder();
  const utf8 = new StringDecoder('utf8');
  const filteredInput = new PassThrough();
  const regions = new Set<MouseRegion>();
  const origin = options.viewportOrigin ?? { x: 0, y: 0 };
  const escapeTimeoutMs = options.escapeTimeoutMs ?? 30;
  const getFrame = options.getFrame ?? ((): number => 0);
  const enabled =
    options.enabled !== false && options.stdin.isTTY && options.stdout.isTTY;
  let order = 0;
  let disposed = false;
  let pendingTimer: NodeJS.Timeout | undefined;
  const regionWaiters: (() => void)[] = [];
  const settleRegionWaiters = (): void => {
    if (regionWaiters.length === 0) return;
    const waiters = regionWaiters.splice(0, regionWaiters.length);
    for (const resolve of waiters) {
      resolve();
    }
  };

  Object.defineProperties(filteredInput, {
    isTTY: { value: options.stdin.isTTY },
    setRawMode: {
      value: (value: boolean): NodeJS.ReadStream => {
        options.stdin.setRawMode(value);
        return filteredInput as unknown as NodeJS.ReadStream;
      },
    },
    ref: {
      value: (): NodeJS.ReadStream => {
        options.stdin.ref();
        return filteredInput as unknown as NodeJS.ReadStream;
      },
    },
    unref: {
      value: (): NodeJS.ReadStream => {
        options.stdin.unref();
        return filteredInput as unknown as NodeJS.ReadStream;
      },
    },
  });

  const clearPendingTimer = (): void => {
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      pendingTimer = undefined;
    }
  };

  const dispatch = (frame: number, event: MouseEvent): void => {
    // Coordinates only mean something relative to the frame the user saw. Every
    // report in one read is decoded against the same snapshot, so once the first
    // click repaints, the rest of that read is resolving against stale geometry.
    if (frame !== getFrame() || options.isInputReady?.() === false) {
      return;
    }

    const candidates = [...regions]
      .filter((region) => {
        if (event.type === 'click' ? !region.onClick : !region.onScroll) {
          return false;
        }

        const bounds = region.getBounds();
        return bounds ? contains(bounds, event) : false;
      })
      .sort(
        (left, right) => right.priority - left.priority || right.order - left.order,
      );
    const target = candidates[0];
    if (!target) {
      return;
    }

    if (event.type === 'click') {
      target.onClick?.();
    } else {
      target.onScroll?.(event.delta);
    }
  };

  const consume = (chunk: Buffer | string): void => {
    clearPendingTimer();
    const text = typeof chunk === 'string' ? chunk : utf8.write(chunk);
    const frame = getFrame();
    const decoded = decoder.push(text);
    if (decoded.input.length > 0) {
      filteredInput.write(decoded.input);
    }

    for (const event of decoded.events) {
      dispatch(frame, { ...event, x: event.x - origin.x, y: event.y - origin.y });
    }

    if (decoder.hasPending()) {
      pendingTimer = setTimeout(() => {
        pendingTimer = undefined;
        const pending = decoder.flushPending();
        if (pending.length > 0 && !disposed) {
          filteredInput.write(pending);
        }
      }, escapeTimeoutMs);
    }
  };

  const deactivateTerminal = (): void => {
    if (!enabled) {
      return;
    }

    options.stdout.write(DISABLE_MOUSE);
  };

  // Ink restores the screen on its own teardown, but nothing there knows about
  // mouse reporting. Without this, an abnormal exit leaves the user's shell
  // tracking the mouse and every later click injects a report into the prompt.
  const onProcessExit = (): void => {
    deactivateTerminal();
  };

  const dispose = (): void => {
    if (disposed) {
      return;
    }

    disposed = true;
    clearPendingTimer();
    // Never leave an awaiter pending across teardown.
    settleRegionWaiters();
    process.removeListener('exit', onProcessExit);
    options.stdin.removeListener('data', consume);
    options.stdin.removeListener('end', onEnd);
    options.stdin.removeListener('close', onClose);
    options.stdin.removeListener('error', onError);
    regions.clear();
    try {
      deactivateTerminal();
    } finally {
      filteredInput.end();
    }
  };

  const onEnd = (): void => {
    const rest = utf8.end();
    if (rest.length > 0) {
      consume(rest);
    }
    dispose();
  };
  const onClose = (): void => {
    dispose();
  };
  const onError = (error: Error): void => {
    try {
      dispose();
    } finally {
      filteredInput.destroy(error);
    }
  };

  if (enabled) {
    try {
      options.stdout.write(ENABLE_MOUSE);
    } catch (error) {
      try {
        deactivateTerminal();
      } finally {
        filteredInput.destroy();
      }
      throw error;
    }
    process.once('exit', onProcessExit);
  }

  options.stdin.on('data', consume);
  options.stdin.once('end', onEnd);
  options.stdin.once('close', onClose);
  options.stdin.once('error', onError);

  return {
    stdin: filteredInput as unknown as NodeJS.ReadStream,
    enabled,
    whenInteractive: () =>
      // A disposed controller has no future registration, so resolve rather than
      // hang; a caller awaiting readiness during teardown gets a clean answer.
      enabled && !disposed && regions.size === 0
        ? new Promise<void>((resolve) => {
            regionWaiters.push(resolve);
          })
        : Promise.resolve(),
    registerRegion(region) {
      const registered: MouseRegion = { ...region, order: order++ };
      regions.add(registered);
      settleRegionWaiters();
      return () => regions.delete(registered);
    },
    dispose,
  };
}

const MouseContext = createContext<MouseInput | null>(null);

export interface MouseProviderProps {
  readonly controller: MouseInput;
  readonly children?: ReactNode;
}

export function MouseProvider({
  controller,
  children,
}: MouseProviderProps): ReactElement {
  return <MouseContext.Provider value={controller}>{children}</MouseContext.Provider>;
}

export interface MouseRegionOptions {
  readonly enabled?: boolean;
  readonly priority?: number;
}

export function useMouseRegion(
  ref: RefObject<DOMElement | null>,
  handlers: MouseRegionHandlers,
  options: MouseRegionOptions = {},
): void {
  const mouse = useContext(MouseContext);
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;
  const hasOnClick = handlers.onClick !== undefined;
  const hasOnScroll = handlers.onScroll !== undefined;

  useEffect(() => {
    if (!mouse?.enabled || options.enabled === false) {
      return undefined;
    }

    return mouse.registerRegion({
      getBounds: () => {
        if (!ref.current) {
          return null;
        }

        return measureVisibleBounds(ref.current);
      },
      ...(hasOnClick ? { onClick: () => handlersRef.current.onClick?.() } : {}),
      ...(hasOnScroll
        ? {
            onScroll: (delta: -1 | 1) => handlersRef.current.onScroll?.(delta),
          }
        : {}),
      priority: options.priority ?? 0,
    });
  }, [mouse, options.enabled, options.priority, ref, hasOnClick, hasOnScroll]);
}

export interface ClickTargetProps extends BoxProps, MouseRegionHandlers {
  readonly enabled?: boolean;
  readonly priority?: number;
  readonly children?: ReactNode;
}

export function ClickTarget({
  enabled,
  priority,
  onClick,
  onScroll,
  children,
  ...boxProps
}: ClickTargetProps): ReactElement {
  const ref = useRef<DOMElement>(null);
  useMouseRegion(
    ref,
    {
      ...(onClick ? { onClick } : {}),
      ...(onScroll ? { onScroll } : {}),
    },
    {
      ...(enabled === undefined ? {} : { enabled }),
      ...(priority === undefined ? {} : { priority }),
    },
  );
  return (
    <Box ref={ref} flexDirection="column" flexShrink={0} {...boxProps}>
      {children}
    </Box>
  );
}
