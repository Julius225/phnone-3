import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  server: {
    proxy: {
      '/api.php': {
        target: process.env.VITE_PHP_PROXY_TARGET || 'http://localhost/my%20phome%203',
        changeOrigin: true,
      },
    },
  },
});