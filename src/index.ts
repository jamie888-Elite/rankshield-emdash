/**
 * RankShield for EmDash — Plugin Descriptor
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — The methods and systems implemented in this software
 * are covered by the following provisional patent applications filed
 * April 5, 2026 by Jamie Kloncz / SEO Elite Agency:
 *   RS-001-PROV — Cross-Channel Persistent Attacker Identity via Hardware Behavioral Fingerprinting
 *   RS-002-PROV — Behavioral Fingerprint Persistence Across IP Rotation and VPN Masking
 *   RS-007-PROV — Sandboxed CMS Plugin Architecture for Real-Time Black Hat Defense
 *
 * This file runs at BUILD TIME in Vite (imported in astro.config.mjs).
 * It must be side-effect-free — no API calls, no runtime logic.
 *
 * The descriptor declares:
 *  - Plugin identity and version
 *  - Required capabilities (enforced in sandboxed mode)
 *  - Allowed external hosts (enforced in sandboxed mode)
 *  - Storage schema for threat intelligence data
 *  - Admin pages and dashboard widgets
 *
 * @see https://github.com/emdash-cms/emdash/blob/main/skills/creating-plugins/SKILL.md
 */

import type { PluginDescriptor } from "emdash";

export interface RankShieldOptions {
  /** Your RankShield API key from https://rankshield.io/dashboard */
  apiKey: string;
  /**
   * Protection mode:
   * - "monitor"  — log threats, do not block (default for first 24h)
   * - "protect"  — block confirmed threats, log suspected
   * - "paranoid" — block all suspicious signals immediately
   */
  mode?: "monitor" | "protect" | "paranoid";
  /**
   * Threat score threshold for blocking (0–100).
   * protect mode default: 75
   * paranoid mode default: 50
   */
  blockThreshold?: number;
  /** Whether to show the security badge on your site */
  showBadge?: boolean;
  /** Webhook URL to receive real-time attack notifications */
  alertWebhook?: string;
}

export function rankShield(options: RankShieldOptions): PluginDescriptor {
  if (!options.apiKey) {
    throw new Error(
      "[RankShield] Missing required apiKey. Get yours at https://rankshield.io"
    );
  }

  return {
    id: "rankshield-security",
    version: "1.0.0",
    format: "standard",
    entrypoint: "@rankshield/emdash-security/sandbox",

    // ── CAPABILITIES ──────────────────────────────────────────────────────
    // Declared in the descriptor — enforced by EmDash in sandboxed mode.
    // Users see these in the marketplace consent dialog before installing.
    capabilities: [
      "network:fetch",   // Required to call RankShield API for threat intelligence
    ],

    // Only traffic to our API is permitted — no other outbound connections
    allowedHosts: [
      "sea-shield-production.up.railway.app",
      "api.rankshield.io",
    ],

    // ── STORAGE ───────────────────────────────────────────────────────────
    // Scoped to this plugin automatically — cannot access other plugins' data
    storage: {
      // Persistent attacker fingerprint profiles
      attackerProfiles: {
        indexes: ["fingerprint", "lastSeen", "threatScore", "blocked"],
      },
      // Time-series threat events for the 30-day trend chart
      threatEvents: {
        indexes: ["timestamp", "blocked", "reason", "ip"],
      },
      // Per-request analysis cache (TTL managed in plugin logic)
      requestCache: {
        indexes: ["fingerprint", "decision", "timestamp"],
      },
    },

    // ── ADMIN UI ──────────────────────────────────────────────────────────
    adminPages: [
      {
        path: "/rankshield",
        label: "RankShield",
        icon: "shield-check",
      },
      {
        path: "/rankshield/threats",
        label: "Threat Intelligence",
        icon: "alert-triangle",
      },
      {
        path: "/rankshield/settings",
        label: "Security Settings",
        icon: "settings",
      },
    ],

    adminWidgets: [
      {
        id: "rankshield-status",
        title: "Security Status",
        size: "half",
      },
      {
        id: "rankshield-trend",
        title: "Attack Volume — 30 Days",
        size: "full",
      },
    ],

    // ── OPTIONS (passed to sandbox-entry.ts) ──────────────────────────────
    options: {
      apiKey: options.apiKey,
      mode: options.mode ?? "protect",
      blockThreshold: options.blockThreshold ?? (options.mode === "paranoid" ? 50 : 75),
      showBadge: options.showBadge ?? true,
      alertWebhook: options.alertWebhook ?? null,
    },
  };
}

// Default export for convenience
export default rankShield;
