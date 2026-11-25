import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Базовый путь: новый UI отдаётся BFF (analytics) под /app/; legacy остаётся на /.
export default defineConfig({
  base: "/app/",
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/v3": "http://127.0.0.1:8080",
      "/v4": "http://127.0.0.1:8080",
      "/hf": "http://127.0.0.1:8080",
    },
  },
});
