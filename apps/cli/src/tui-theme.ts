/**
 * Canonical TUI theme identifiers shared by light command registration and the
 * heavy TUI session module. Kept import-free so `kavrix tui` registration does
 * not pull the session stack (zod, crypto, schemas) into every CLI invocation.
 */
export const TUI_THEME_IDS = ['gold', 'ocean', 'magma', 'forest', 'violet'] as const;

export function isTuiThemeId(value: string): value is (typeof TUI_THEME_IDS)[number] {
  return (TUI_THEME_IDS as readonly string[]).includes(value);
}
