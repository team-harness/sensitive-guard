import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    secretlint: 'src/adapters/secretlint.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  treeshake: true,
  external: ['@secretlint/core', '@secretlint/secretlint-rule-preset-recommend'],
});
