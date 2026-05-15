// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://hosnian-prime.github.io',
  base: '/geonosis',
  vite: {
    plugins: [tailwindcss()],
  },
});
