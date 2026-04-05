/**
 * RankShield for EmDash — Plugin Descriptor
 *
 * Runs at BUILD TIME in Vite (imported in astro.config.mjs).
 * Must be side-effect-free — no API calls, no runtime logic.
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

    capabilities: [
      "network:fetch",
    ],

    allowedHosts: [
      "sea-shield-production.up.railway.app",
      "api.rankshield.io",
    ],

    storage: {
      attackerProfiles: {
        indexes: ["fingerprint", "lastSeen", "threatScore", "blocked"],
      },
      threatEvents: {
        indexes: ["timestamp", "blocked", "reason", "ip"],
      },
      requestCache: {
        indexes: ["fingerprint", "decision", "timestamp"],
      },
    },

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

    options: {
      apiKey: options.apiKey,
      mode: options.mode ?? "protect",
      blockThreshold: options.blockThreshold ?? (options.mode === "paranoid" ? 50 : 75),
      showBadge: options.showBadge ?? true,
      alertWebhook: options.alertWebhook ?? null,
    },
  };
}

export default rankShield;
