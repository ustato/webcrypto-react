import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        fs: {
            // https://vitejs.dev/config/server-options.html#server-fs-allow
            allow: ['.'],
        },
    },
});
