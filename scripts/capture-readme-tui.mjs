/** Render the shipped Ink components with explicitly synthetic, masked metadata. */
import { mkdir, copyFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { stripVTControlCharacters } from 'node:util';
delete process.env.NO_COLOR;
process.env.TERM = 'xterm-256color';
process.env.FORCE_COLOR = '1';
process.env.KAVRIX_TUI_REDUCED_MOTION = '1';
const { createElement } = await import('react');
const { renderToString } = await import('ink');
const { emptySnapshot } = await import('../packages/tui/src/app/backend.ts');
const { createInitialAppRouterState, navigateToScreen, transitionAppRouter } =
  await import('../packages/tui/src/app/router.ts');
const { AppChrome, renderActiveScreen } =
  await import('../packages/tui/src/app/screens.tsx');

const require = createRequire(import.meta.url);
const inkRequire = createRequire(require.resolve('ink'));
const { default: stringWidth } = await import(
  pathToFileURL(inkRequire.resolve('string-width')).href
);
const sharpPath = process.env.KAVRIX_SCREENSHOT_SHARP;
const { default: sharp } = await import(
  sharpPath ? pathToFileURL(resolve(sharpPath)).href : 'sharp'
);
const width = 104;
const height = 34;
const names = [
  'github/deploy',
  'cloud/development',
  'database/readonly',
  'registry/pull',
  'monitoring/ingest',
  'mail/notifications',
];
const snapshot = {
  ...emptySnapshot('Demo metadata only. Credential values stay masked.'),
  home: {
    profileId: 'demo',
    vaultId: 'development',
    unlocked: true,
    credentialCount: names.length,
    datastore: 'file',
    message: 'Your development vault is ready.',
  },
  profiles: [
    { id: 'demo', datastore: 'file', selected: true, detail: 'Local encrypted file' },
  ],
  vaults: [
    {
      id: 'development',
      selected: true,
      credentialCount: names.length,
      detail: 'Development workspace',
    },
  ],
  credentials: names.map((name) => ({ name, maskedValue: '••••••••' })),
};
const home = transitionAppRouter(
  createInitialAppRouterState({ width, height, ascii: false, color: true }),
  { type: 'hydrate', snapshot },
).state;
const credentials = navigateToScreen(home, 'credentials');
const actions = transitionAppRouter(credentials, {
  type: 'key',
  key: { text: ':' },
  nowMs: 0,
}).state;
const frames = [
  ['home-unlocked', 'Home · grouped destinations', home],
  ['credentials', 'Credentials · masked by default', credentials],
  ['actions', 'Actions · discover the available commands', actions],
];
const palette = [
  '#17202b',
  '#ee7474',
  '#8ed49f',
  '#eac778',
  '#89b4fa',
  '#cba6f7',
  '#89dceb',
  '#dbe2ee',
  '#a7b3c4',
  '#f69898',
  '#a6e3b5',
  '#f9df9a',
  '#aacbff',
  '#dec3ff',
  '#b4ecf4',
  '#f4f7fb',
];
const cell = 9.35;
const line = 23;
const imageWidth = Math.ceil(width * cell + 48);
const imageHeight = height * line + 94;
const escapeXml = (text) =>
  text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

function terminalSvg(output, label) {
  const parts = [];
  let fg = 7;
  let bg = null;
  let bold = false;
  let dim = false;
  for (const [row, text] of output.split('\n').entries()) {
    let column = 0;
    for (const chunk of text.split(/(\x1b\[[\d;]*m)/u)) {
      if (chunk.startsWith('\x1b[')) {
        for (const code of chunk.slice(2, -1).split(';').map(Number)) {
          if (code === 0) {
            fg = 7;
            bg = null;
            bold = false;
            dim = false;
          } else if (code === 1) bold = true;
          else if (code === 2) dim = true;
          else if (code === 22) {
            bold = false;
            dim = false;
          } else if (code === 39) fg = 7;
          else if (code === 49) bg = null;
          else if (code >= 30 && code <= 37) fg = code - 30;
          else if (code >= 90 && code <= 97) fg = code - 90 + 8;
          else if (code >= 40 && code <= 47) bg = code - 40;
          else if (code >= 100 && code <= 107) bg = code - 100 + 8;
        }
        continue;
      }
      const clean = stripVTControlCharacters(chunk);
      const cells = stringWidth(clean);
      if (cells === 0) continue;
      const x = 24 + column * cell;
      const y = 60 + row * line;
      if (bg !== null)
        parts.push(
          `<rect x="${x}" y="${y - 18}" width="${cells * cell}" height="${line}" fill="${palette[bg]}"/>`,
        );
      let offset = 0;
      for (const glyph of clean) {
        const gx = x + offset * cell;
        const cx = gx + cell / 2;
        const cy = y - 6;
        const directions = {
          '─': 'lr',
          '│': 'ud',
          '┌': 'rd',
          '┐': 'ld',
          '└': 'ru',
          '┘': 'lu',
          '╭': 'rd',
          '╮': 'ld',
          '╰': 'ru',
          '╯': 'lu',
          '├': 'urd',
          '┤': 'uld',
          '┬': 'lrd',
          '┴': 'lru',
          '┼': 'lrud',
          '═': 'lr',
          '║': 'ud',
          '╔': 'rd',
          '╗': 'ld',
          '╚': 'ru',
          '╝': 'lu',
        }[glyph];
        if (directions) {
          const ends = {
            l: [gx, cy],
            r: [gx + cell, cy],
            u: [cx, cy - line / 2],
            d: [cx, cy + line / 2],
          };
          let path = [...directions]
            .map((direction) => `M${cx},${cy}L${ends[direction].join(',')}`)
            .join('');
          if ('╭╮╰╯'.includes(glyph)) {
            const sx = directions.includes('l') ? -1 : 1;
            const sy = directions.includes('u') ? -1 : 1;
            path = `M${cx + (sx * cell) / 2},${cy}L${cx + sx * 3},${cy}Q${cx},${cy} ${cx},${cy + sy * 3}L${cx},${cy + (sy * line) / 2}`;
          } else if ('═║╔╗╚╝'.includes(glyph)) {
            path = [-1.5, 1.5]
              .map((delta) => {
                if (glyph === '═') return `M${gx},${cy + delta}H${gx + cell}`;
                if (glyph === '║')
                  return `M${cx + delta},${cy - line / 2}V${cy + line / 2}`;
                const sx = directions.includes('l') ? -1 : 1;
                const sy = directions.includes('u') ? -1 : 1;
                return `M${cx + (sx * cell) / 2},${cy + delta * sy}H${cx + delta * sx}V${cy + (sy * line) / 2}`;
              })
              .join('');
          }
          parts.push(
            `<path d="${path}" stroke="${palette[fg]}" stroke-width="1" opacity="${dim ? 0.85 : 1}"/>`,
          );
        } else if (glyph.trim()) {
          parts.push(
            `<text x="${gx}" y="${y}" fill="${palette[fg]}" opacity="${dim ? 0.85 : 1}" font-weight="${bold ? 700 : 400}">${escapeXml(glyph)}</text>`,
          );
        }
        offset += stringWidth(glyph);
      }
      column += cells;
    }
    if (column > width)
      throw new Error(`Screenshot exceeds viewport: ${column} cells.`);
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${imageWidth}" height="${imageHeight}">
    <rect width="100%" height="100%" rx="12" fill="#10151d"/>
    <path d="M0 39H${imageWidth}" stroke="#293342"/>
    <g font-family="Consolas, monospace" font-size="17">
      <text x="24" y="25" fill="#eac778">kavrix tui</text>
      <text x="160" y="25" fill="#a7b3c4">${escapeXml(label)}</text>
      ${parts.join('\n')}
      <text x="24" y="${imageHeight - 17}" font-size="13" fill="#788597">CURRENT INK UI · DEMONSTRATION METADATA · NO SECRET VALUES</text>
    </g>
  </svg>`;
}

const assetRoot = resolve('docs/assets');
const mediaRoot = resolve('apps/cli/media');
await mkdir(assetRoot, { recursive: true });
await mkdir(mediaRoot, { recursive: true });
const pixels = [];
for (const [id, label, state] of frames) {
  const output = renderToString(
    createElement(AppChrome, {
      state,
      children: renderActiveScreen(state),
    }),
    { columns: width },
  );
  if (output.split('\n').length !== height) throw new Error('Unexpected frame height.');
  const svg = Buffer.from(terminalSvg(output, label));
  await sharp(svg)
    .png()
    .toFile(resolve(assetRoot, `demo-frame-${id}.png`));
  pixels.push(await sharp(svg).ensureAlpha().raw().toBuffer());
}
await sharp(Buffer.concat(pixels), {
  raw: {
    width: imageWidth,
    height: imageHeight * frames.length,
    channels: 4,
    pageHeight: imageHeight,
  },
})
  .gif({ delay: [4000, 5000, 5000], loop: 0, colours: 128 })
  .toFile(resolve(assetRoot, 'kavrix-tui-demo.gif'));
await copyFile(
  resolve(assetRoot, 'demo-frame-home-unlocked.png'),
  resolve(mediaRoot, 'demo-frame-home-unlocked.png'),
);
await copyFile(
  resolve(assetRoot, 'kavrix-tui-demo.gif'),
  resolve(mediaRoot, 'kavrix-tui-demo.gif'),
);
console.log(
  'Captured current Home, Credentials and Actions; refreshed README PNG/GIF copies.',
);
