import { Box } from 'ink';
import type { ReactElement, ReactNode } from 'react';

/** Screen readers and dumb terminals retain the accessible, line-oriented UI. */
export function terminalFullscreenEnabled(): boolean {
  return process.env['INK_SCREEN_READER'] !== 'true' && process.env['TERM'] !== 'dumb';
}

/** Bound the root, while allowing the body to shrink before footer controls. */
export function TerminalViewport({
  width,
  height,
  children,
}: Readonly<{
  width: number;
  height: number;
  children: ReactNode;
}>): ReactElement {
  const fullscreen = terminalFullscreenEnabled();
  return (
    <Box
      flexDirection="column"
      width={width}
      {...(fullscreen
        ? { minHeight: height, maxHeight: height, overflow: 'hidden' as const }
        : {})}
    >
      {children}
    </Box>
  );
}
