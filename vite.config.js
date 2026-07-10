import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig } from "vite";
import {
  rootStaticAssets,
  sites,
} from "./build/sites-vite-plugin.js";

export default defineConfig({
  build: {
    emptyOutDir: false,
  },
  plugins: [
    rootStaticAssets(),
    sites(),
    cloudflare({
      viteEnvironment: { name: "server" },
      config: {
        main: "./worker/index.js",
        compatibility_date: "2026-07-10",
        assets: {
          binding: "ASSETS",
          run_worker_first: true,
        },
      },
    }),
  ],
});
