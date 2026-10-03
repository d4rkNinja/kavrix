import { createContext, useContext, type ReactNode, type ReactElement } from 'react';

import type { AppRouterAction, AppKey } from './router.js';

export interface AppInteraction {
  readonly dispatch: (action: AppRouterAction) => void;
  readonly press: (key: AppKey) => void;
  readonly enabled: boolean;
  readonly mouse: boolean;
  readonly busy: boolean;
}

const InteractionContext = createContext<AppInteraction>({
  dispatch: () => undefined,
  press: () => undefined,
  enabled: false,
  mouse: false,
  busy: false,
});

/** Presentation emits the same guarded intents as keyboard navigation. */
export function AppInteractionProvider({
  value,
  children,
}: Readonly<{ value: AppInteraction; children: ReactNode }>): ReactElement {
  return (
    <InteractionContext.Provider value={value}>{children}</InteractionContext.Provider>
  );
}

export function useAppInteraction(): AppInteraction {
  return useContext(InteractionContext);
}

/**
 * Maps a chip label to the key it emits. Labels that are not single keystrokes
 * (`+N more` overflow hints, `j/k`, `^V`) have no key and stay non-clickable.
 */
export function keyForChip(label: string): AppKey | null {
  if (label === 'Enter') return { name: 'return' };
  if (label === 'Esc') return { name: 'escape' };
  if (label === 'Tab') return { name: 'tab' };
  return label.length === 1 ? { text: label } : null;
}
