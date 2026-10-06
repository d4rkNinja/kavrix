import { createContext, useContext, type ReactNode, type ReactElement } from 'react';

import type { AppRouterAction, AppKey } from './router.js';

export interface AppInteraction {
  readonly dispatch: (action: AppRouterAction) => void;
  readonly press: (key: AppKey) => void;
  readonly enabled: boolean;
  readonly mouse: boolean;
  readonly busy: boolean;
  readonly busyLabel?: string;
}

const InteractionContext = createContext<AppInteraction>({
  dispatch: () => undefined,
  press: () => undefined,
  enabled: false,
  mouse: false,
  busy: false,
});

type InputInteraction = Pick<AppInteraction, 'press' | 'enabled' | 'mouse' | 'busy'>;
const InputContext = createContext<InputInteraction | null>(null);

/** Setup uses keyboard intents without acquiring the main app's navigation port. */
export function InputInteractionProvider({
  value,
  children,
}: Readonly<{
  value: InputInteraction;
  children: ReactNode;
}>): ReactElement {
  return <InputContext.Provider value={value}>{children}</InputContext.Provider>;
}

export function useInputInteraction(): InputInteraction {
  const app = useAppInteraction();
  return useContext(InputContext) ?? app;
}

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
