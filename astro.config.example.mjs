/**
 * RankShield for EmDash — Example astro.config.mjs
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — Methods and systems in this software are covered by
 * provisional patent applications RS-001-PROV, RS-002-PROV, RS-007-PROV
 * filed April 5, 2026 by Jamie Kloncz / SEO Elite Agency.
 *
 * Copy this into your EmDash project and replace the API key.
 * Full documentation: https://rankshield.seoeliteagency.com
 */

import { defineConfig } from "astro/config";
import emdash from "emdash/astro";
import { d1 } from "emdash/db";
import { rankShield } from "@rankshield/emdash-security";

export default defineConfig({
  integrations: [
    emdash({
      database: d1(),

      // ── OPTION 1: Trusted mode (any platform) ──────────────────────────
      // Runs in-process with your Astro site.
      // Works on Cloudflare, Node.js, Netlify, Vercel.
      plugins: [
        rankShield({
          apiKey:         import.meta.env.RANKSHIELD_API_KEY,
          mode:           "protect",  // "monitor" | "protect" | "paranoid"
          blockThreshold: 75,         // 0-100, lower = more aggressive
          showBadge:      true,       // show security badge on site
          // alertWebhook: "https://hooks.slack.com/...", // optional
        }),
      ],

      // ── OPTION 2: Sandboxed mode (Cloudflare only) ─────────────────────
      // Maximum security. Plugin runs in isolated V8 isolate.
      // Can ONLY reach sea-shield-production.up.railway.app.
      // Zero access to your database, content, or other plugins.
      //
      // sandboxed: [
      //   rankShield({
      //     apiKey: import.meta.env.RANKSHIELD_API_KEY,
      //     mode:   "protect",
      //   }),
      // ],
    }),
  ],
});
