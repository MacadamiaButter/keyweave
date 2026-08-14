// README media integrity. The 2026-08-13 media commit gave the README images, and images
// rot differently from prose: a renamed file fails silently on GitHub as a broken embed
// while every suite stays green, because nothing executes a markdown link. These gates make
// that rot loud. Added at the orchestrator's review-round close, named as a residual by the
// media commit's own author: "a future edit that renames a file will fail silently with
// 552+78 still green".
//
// The byte window mirrors the site-side gate for the same files: the floor catches a
// truncated or placeholder write pretending to be an image, the cap catches an unoptimized
// re-capture quietly turning the repo into a media dump.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const MEDIA_DIR = join(REPO_ROOT, 'docs', 'media');
const BYTE_FLOOR = 1024;
const BYTE_CAP = 1572864; // 1.5 MiB

const readme = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8');
const imageRefs = [...readme.matchAll(/!\[([^\]]*)\]\(([^)]+)\)/g)].map((m) => ({
  alt: m[1],
  path: m[2],
}));

describe('README image embeds', () => {
  it('has at least the four embeds the media commit added', () => {
    expect(imageRefs.length).toBeGreaterThanOrEqual(4);
  });

  it('every embedded path resolves to a real file in this repository', () => {
    for (const ref of imageRefs) {
      expect(ref.path.startsWith('docs/media/'), `${ref.path} lives outside docs/media`).toBe(
        true,
      );
      expect(existsSync(join(REPO_ROOT, ref.path)), `${ref.path} does not resolve`).toBe(true);
    }
  });

  it('every embedded image carries non-empty alt text', () => {
    for (const ref of imageRefs) {
      expect(ref.alt.trim().length, `${ref.path} has empty alt text`).toBeGreaterThan(10);
    }
  });

  it('the provenance record is linked from the same section', () => {
    expect(readme.includes('docs/media/PROVENANCE.md')).toBe(true);
  });
});

describe('docs/media contents', () => {
  const files = readdirSync(MEDIA_DIR).filter((f) => /\.(png|gif)$/.test(f));

  it('holds the eight capture files', () => {
    expect(files.length).toBe(8);
  });

  it('every media file sits inside the byte window', () => {
    for (const f of files) {
      const size = statSync(join(MEDIA_DIR, f)).size;
      expect(size, `${f} is ${size} B, under the ${BYTE_FLOOR} B floor`).toBeGreaterThan(
        BYTE_FLOOR,
      );
      expect(size, `${f} is ${size} B, over the ${BYTE_CAP} B cap`).toBeLessThanOrEqual(
        BYTE_CAP,
      );
    }
  });

  it('every media file has a row in PROVENANCE.md', () => {
    const provenance = readFileSync(join(MEDIA_DIR, 'PROVENANCE.md'), 'utf8');
    for (const f of files) {
      expect(provenance.includes(f), `${f} has no provenance entry`).toBe(true);
    }
  });
});
