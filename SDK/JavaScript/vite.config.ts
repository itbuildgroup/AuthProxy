import path from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index'),
      name: 'auth-proxy-sdk',
      formats: ['cjs'],
      fileName: `auth_proxy`,
    },
    rollupOptions: {
      external: [],
      output: {
        globals: {},
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  plugins: [
    dts({
      // @ts-ignore
      outputDir: 'dist/types',
      include: ['src/**/*'],
      rollupTypes: true,
    })
  ]
});
