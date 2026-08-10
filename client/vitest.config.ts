import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // The box is RAM-constrained and Argon2id derivations are memory-heavy: run test
    // files serially (no parallel forks) to keep peak memory low.
    pool: 'forks',
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
