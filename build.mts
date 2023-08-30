import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/main.mts'],
  bundle: true,
  outfile: 'dist/main.mjs',
  format: 'esm',
  platform: 'node',
  target: 'esnext',
  external: ['path'],
  banner: {
    // This is absolutely vital: https://github.com/evanw/esbuild/pull/2067#issuecomment-1324171716
    js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
  },
});
