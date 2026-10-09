import { NAV_GROUPS, type AppMenuEntry, type AppNavGroup } from './ids.js';

/**
 * A Home-menu row: either a group band that names what follows, or one
 * destination. Bands are presentation only — they never consume a cursor slot,
 * so `index` stays the index into the destination list and the router's
 * existing menu-index semantics are unchanged.
 */
export type NavRow =
  | Readonly<{ kind: 'band'; group: AppNavGroup; count: number }>
  | Readonly<{ kind: 'entry'; entry: AppMenuEntry; index: number }>;

/**
 * Interleaves group bands with their destinations. Groups render in
 * {@link NAV_GROUPS} order regardless of where their entries sit in
 * `APP_MENU`, so the list reads as named sections rather than one flat wall.
 */
export function groupedNavRows(entries: readonly AppMenuEntry[]): readonly NavRow[] {
  const position = new Map<AppMenuEntry, number>(
    entries.map((entry, index) => [entry, index]),
  );
  const rows: NavRow[] = [];
  for (const group of NAV_GROUPS) {
    const owned = entries.filter((entry) => entry.group === group.id);
    if (owned.length === 0) continue;
    rows.push({ kind: 'band', group: group.id, count: owned.length });
    for (const entry of owned) {
      rows.push({ kind: 'entry', entry, index: position.get(entry) ?? 0 });
    }
  }
  return rows;
}

export interface NavWindow {
  readonly rows: readonly NavRow[];
  readonly start: number;
  readonly end: number;
}

/**
 * Bounded window over grouped rows that always contains the cursor and never
 * ends on a group band. A trailing band would promise destinations that are
 * scrolled out of view, so the window shifts left (or drops the band when it is
 * already at the top) instead of leaving an orphaned heading behind.
 */
export function groupedNavWindow(
  rows: readonly NavRow[],
  cursorIndex: number,
  size: number,
): NavWindow {
  const budget = Math.max(1, Math.floor(size));
  if (rows.length <= budget) {
    return { rows, start: 0, end: rows.length };
  }
  const cursorRow = rows.findIndex(
    (row) => row.kind === 'entry' && row.index === cursorIndex,
  );
  const anchor = cursorRow < 0 ? 0 : cursorRow;
  const maxStart = rows.length - budget;
  // Keep a couple of rows above the cursor so movement stays calm on a long
  // list, while never scrolling past the last section.
  const desired = Math.max(0, anchor - Math.min(2, Math.floor(budget / 4)));
  let start = Math.min(maxStart, Math.max(0, desired));
  let end = Math.min(rows.length, start + budget);
  while (end > start + 1 && rows[end - 1]?.kind === 'band') {
    if (start > 0) {
      start -= 1;
      end -= 1;
      continue;
    }
    end -= 1;
    break;
  }
  return { rows: rows.slice(start, end), start, end };
}
