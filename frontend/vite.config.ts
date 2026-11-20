import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig(({ mode }) => {
  const target =
    loadEnv(mode, ".", "VIRTUALANCHOO_").VIRTUALANCHOO_API_TARGET ||
    "http://127.0.0.1:8765";
  return {
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes("/node_modules/")) {
              if (id.includes("/@xyflow/") || id.includes("/zustand/"))
                return "topology";
              if (
                id.includes("/recharts/") ||
                id.includes("/d3-") ||
                id.includes("/victory-vendor/")
              )
                return "charts";
              if (/\/(react|react-dom|scheduler)\//.test(id)) return "react";
            }
          },
        },
      },
    },
    plugins: [react(), tailwindcss()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      proxy: {
        "/api": { target, changeOrigin: true },
        "/docs": { target, changeOrigin: true },
        "/openapi.json": { target, changeOrigin: true },
        "/ws": {
          target: target.replace(/^http/, "ws"),
          ws: true,
          changeOrigin: true,
        },
      },
    },
  };
});
