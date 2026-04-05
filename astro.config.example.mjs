/**
 * RankShield for EmDash — Example astro.config.mjs
 *
 * Copy this into your EmDash project and replace the API key.
 */

import { defineConfig } from "astro/config";
import emdash from "emdash/astro";
import { d1 } from "emdash/db";
import { rankShield } from "@rankshield/emdash-security";

export default defineConfig({
  integrations: [
    emdash({
      database: d1(),

      // Trusted mode — works on any platform
      plugins: [
        rankShield({
          apiKey:         import.meta.env.RANKSHIELD_API_KEY,
          mode:           "protect",
          blockThreshold: 75,
          showBadge:      true,
        }),
      ],

      // Sandboxed mode — Cloudflare only, maximum security
      // sandboxed: [
      //   rankShield({
      //     apiKey: import.meta.env.RANKSHIELD_API_KEY,
      //     mode:   "protect",
      //   }),
      // ],
    }),
  ],
});
