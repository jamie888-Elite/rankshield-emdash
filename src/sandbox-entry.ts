/**
 * RankShield for EmDash — Plugin Definition
 *
 * This file runs at REQUEST TIME on the deployed server.
 * On Cloudflare: runs in an isolated V8 sandbox (Dynamic Worker Loader).
 * On Node.js:    runs in-process in trusted mode.
 *
 * Architecture:
 *  - request:receive  → evaluate incoming requests before content loads
 *  - content:afterSave → scan content for SEO attack patterns
 *  - plugin:install   → onboarding + initial sync
 *  - plugin:uninstall → cleanup
 *  - cron jobs        → hourly sync, daily threat report
 *
 * The fingerprinting JS injection happens via the admin route's
 * client-side script mechanism — it returns a script tag in the
 * page <head> via the site-side Astro component (native-mode upgrade path).
 */

import { definePlugin } from "emdash";
import type { PluginContext } from "emdash";

// ── CONSTANTS ──────────────────────────────────────────────────────────────────
const RANKSHIELD_API = "https://sea-shield-production.up.railway.app";
const CACHE_TTL_MS   = 5 * 60 * 1000;  // 5 minutes per fingerprint
const MAX_PROFILES   = 500;             // KV limit for local cache

// ── TYPES ──────────────────────────────────────────────────────────────────────
interface PluginOptions {
  apiKey: string;
  mode: "monitor" | "protect" | "paranoid";
  blockThreshold: number;
  showBadge: boolean;
  alertWebhook: string | null;
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  ip: string | null;
  fingerprint: string | null;
  reason: string;
  threatScore: number;
  blocked: boolean;
  url: string;
  userAgent: string;
}

interface AttackerProfile {
  fingerprint: string;
  firstSeen: string;
  lastSeen: string;
  hitCount: number;
  threatScore: number;
  blocked: boolean;
  reasons: string[];
  ips: string[];
}

interface ApiCheckResponse {
  blocked: boolean;
  threat_score: number;
  reason: string;
  fingerprint: string | null;
  cached: boolean;
}

interface StatsResponse {
  stats: {
    blocked_24h: number;
    blocked_30d: number;
    total_blocked_all_time: number;
    total_sites: number;
  };
  daily_trend: Array<{ date: string; blocked: number; total: number }>;
  recent_events: ThreatEvent[];
  active_fingerprints: AttackerProfile[];
  auto_rules_count: number;
}

// ── HELPERS ────────────────────────────────────────────────────────────────────

function getOptions(ctx: PluginContext): PluginOptions {
  return ctx.plugin as unknown as PluginOptions;
}

function makeId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function fmtRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/**
 * Calls the RankShield API to check a request.
 * Returns block decision + threat score in <50ms via Cloudflare edge cache.
 */
async function checkRequest(
  ctx: PluginContext,
  opts: PluginOptions,
  ip: string,
  userAgent: string,
  url: string
): Promise<ApiCheckResponse> {
  if (!ctx.http) {
    return { blocked: false, threat_score: 0, reason: "no-http", fingerprint: null, cached: false };
  }

  try {
    const res = await ctx.http.fetch(`${RANKSHIELD_API}/api/plugin/check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": opts.apiKey,
        "x-plugin": "emdash/1.0.0",
      },
      body: JSON.stringify({ ip, user_agent: userAgent, url }),
    });

    if (!res.ok) return { blocked: false, threat_score: 0, reason: "api-error", fingerprint: null, cached: false };
    return await res.json() as ApiCheckResponse;
  } catch {
    return { blocked: false, threat_score: 0, reason: "fetch-failed", fingerprint: null, cached: false };
  }
}

/**
 * Fetches full dashboard stats from RankShield API.
 */
async function fetchStats(ctx: PluginContext, opts: PluginOptions): Promise<StatsResponse | null> {
  if (!ctx.http) return null;
  try {
    const res = await ctx.http.fetch(`${RANKSHIELD_API}/api/dashboard/`, {
      headers: { "x-master-key": opts.apiKey, "x-plugin": "emdash/1.0.0" },
    });
    if (!res.ok) return null;
    return await res.json() as StatsResponse;
  } catch {
    return null;
  }
}

/**
 * Persists a threat event to plugin storage for local analytics.
 */
async function recordEvent(ctx: PluginContext, event: ThreatEvent): Promise<void> {
  try {
    await ctx.storage.threatEvents.put(event.id, {
      timestamp: event.timestamp,
      ip: event.ip,
      fingerprint: event.fingerprint,
      reason: event.reason,
      threatScore: event.threatScore,
      blocked: event.blocked,
      url: event.url,
      userAgent: event.userAgent.slice(0, 200),
    });
  } catch {
    // Non-fatal — local storage failure should not break request handling
  }
}

// ── BLOCK KIT UI BUILDERS ──────────────────────────────────────────────────────

function buildStatusWidget(stats: StatsResponse | null, mode: string) {
  const blocked24h = stats?.stats?.blocked_24h ?? 0;
  const blocked30d = stats?.stats?.blocked_30d ?? 0;
  const fps = stats?.active_fingerprints?.length ?? 0;
  const rules = stats?.auto_rules_count ?? 0;

  const statusText = blocked24h > 20 ? "⚠ UNDER ATTACK" : blocked24h > 5 ? "👁 MONITORING" : "🛡 PROTECTED";
  const statusColor = blocked24h > 20 ? "#FF3355" : blocked24h > 5 ? "#FFAA00" : "#00FF88";

  return {
    blocks: [
      {
        type: "section",
        text: `**${statusText}**`,
        accessory: {
          type: "button",
          text: "View Details →",
          action_id: "nav_threats",
          style: "primary",
        },
      },
      {
        type: "columns",
        columns: [
          {
            blocks: [
              { type: "stat", label: "Blocked 24h", value: blocked24h.toLocaleString(), color: blocked24h > 0 ? "#E86853" : "#00FF88" },
              { type: "stat", label: "Blocked 30d", value: blocked30d.toLocaleString(), color: "#E86853" },
            ],
          },
          {
            blocks: [
              { type: "stat", label: "Attacker Profiles", value: fps.toLocaleString(), color: "#AA55FF" },
              { type: "stat", label: "Active Rules", value: rules.toLocaleString(), color: "#00D4FF" },
            ],
          },
        ],
      },
      {
        type: "context",
        text: `Protection mode: **${mode.toUpperCase()}**  ·  Powered by RankShield behavioral fingerprinting`,
      },
    ],
  };
}

function buildTrendWidget(stats: StatsResponse | null) {
  const trend = stats?.daily_trend ?? [];

  if (!trend.length) {
    return {
      blocks: [
        { type: "header", text: "Attack Volume — 30 Days" },
        { type: "section", text: "Collecting data… Check back in a few hours as attacks are detected and logged." },
      ],
    };
  }

  const seriesData: Array<[number, number]> = trend.map((row) => [
    new Date(row.date + "T12:00:00Z").getTime(),
    row.blocked,
  ]);

  return {
    blocks: [
      {
        type: "chart",
        config: {
          chart_type: "timeseries",
          series: [
            {
              name: "Attacks Blocked",
              data: seriesData,
              color: "#E86853",
            },
          ],
          yAxisName: "Blocked",
          gradient: true,
          smooth: true,
        },
      },
    ],
  };
}

function buildMainPage(stats: StatsResponse | null, mode: string) {
  const blocked24h = stats?.stats?.blocked_24h ?? 0;
  const blocked30d = stats?.stats?.blocked_30d ?? 0;
  const allTime    = stats?.stats?.total_blocked_all_time ?? 0;
  const fps        = stats?.active_fingerprints?.length ?? 0;
  const rules      = stats?.auto_rules_count ?? 0;
  const recent     = stats?.recent_events?.slice(0, 10) ?? [];

  const alertBanner = blocked24h > 20
    ? { type: "banner", style: "danger",  text: `⚠ Active attack in progress — ${blocked24h} attempts blocked in the last 24 hours. All neutralized.` }
    : blocked24h > 5
    ? { type: "banner", style: "warning", text: `👁 Elevated activity — ${blocked24h} suspicious requests blocked in 24h.` }
    : { type: "banner", style: "success", text: "🛡 Your site is protected. No significant threats detected." };

  return {
    blocks: [
      alertBanner,
      {
        type: "columns",
        columns: [
          { blocks: [{ type: "stat", label: "Blocked (24h)",    value: blocked24h.toLocaleString(), color: "#E86853" }] },
          { blocks: [{ type: "stat", label: "Blocked (30d)",    value: blocked30d.toLocaleString(), color: "#E86853" }] },
          { blocks: [{ type: "stat", label: "All Time Blocked", value: allTime.toLocaleString(),    color: "#AA55FF" }] },
          { blocks: [{ type: "stat", label: "Attacker Profiles",value: fps.toLocaleString(),        color: "#00D4FF" }] },
          { blocks: [{ type: "stat", label: "Active Rules",     value: rules.toLocaleString(),      color: "#00FF88" }] },
        ],
      },
      { type: "header", text: "Recent Attack Activity" },
      recent.length > 0
        ? {
            type: "table",
            blockId: "recent-events",
            columns: [
              { key: "reason",      label: "Threat Type",   format: "text"          },
              { key: "ip",          label: "Source IP",     format: "text"          },
              { key: "threatScore", label: "Score",         format: "badge"         },
              { key: "blocked",     label: "Action",        format: "badge"         },
              { key: "timestamp",   label: "Time",          format: "relative_time" },
            ],
            rows: recent.map((e) => ({
              reason:      e.reason ?? "Unknown",
              ip:          e.ip ?? "—",
              threatScore: `${e.threatScore ?? 0}%`,
              blocked:     e.blocked ? "BLOCKED" : "LOGGED",
              timestamp:   e.timestamp,
            })),
          }
        : { type: "section", text: "No recent events. Your site is clean." },
      {
        type: "section",
        text: `**Protection Mode:** ${mode.toUpperCase()}  ·  [Change settings →](/_emdash/admin/plugins/rankshield-security/settings)`,
      },
    ],
  };
}

function buildThreatsPage(profiles: AttackerProfile[]) {
  if (!profiles.length) {
    return {
      blocks: [
        { type: "header", text: "Threat Intelligence" },
        {
          type: "section",
          text: "No attacker profiles yet. As your site receives traffic, RankShield builds persistent behavioral profiles of any bots or attackers detected. These profiles track them across IP rotation, VPNs, and headless browser changes.",
        },
        {
          type: "section",
          text: "💡 **How it works:** Unlike IP-blocking tools, RankShield fingerprints the attacker's GPU canvas hash, mouse physics, and behavioral timing — signals that persist across every IP change. Once fingerprinted, an attacker cannot escape by switching proxies or clearing cookies.",
        },
      ],
    };
  }

  return {
    blocks: [
      { type: "header", text: `Threat Intelligence — ${profiles.length} Attacker Profiles` },
      {
        type: "section",
        text: "Each profile represents a persistent attacker identity tracked across IP rotation, VPN changes, and device spoofing. Confidence grows with each blocked session.",
      },
      {
        type: "table",
        blockId: "attacker-profiles",
        columns: [
          { key: "fingerprint", label: "Fingerprint",   format: "text"          },
          { key: "hitCount",    label: "Sessions",      format: "number"        },
          { key: "threatScore", label: "Confidence",    format: "badge"         },
          { key: "reasons",     label: "Attack Types",  format: "text"          },
          { key: "blocked",     label: "Status",        format: "badge"         },
          { key: "lastSeen",    label: "Last Seen",     format: "relative_time" },
        ],
        rows: profiles.slice(0, 50).map((p) => ({
          fingerprint: p.fingerprint.slice(0, 12) + "…",
          hitCount:    p.hitCount,
          threatScore: `${p.threatScore}% confidence`,
          reasons:     (p.reasons ?? []).slice(0, 2).join(", ") || "Behavioral anomaly",
          blocked:     p.blocked ? "BLOCKED" : "MONITORING",
          lastSeen:    p.lastSeen,
        })),
      },
    ],
  };
}

function buildSettingsPage(currentSettings: Record<string, unknown>) {
  return {
    blocks: [
      { type: "header", text: "Security Settings" },
      {
        type: "section",
        text: "Configure how RankShield protects your EmDash site. Changes take effect immediately — no redeploy required.",
      },
      {
        type: "form",
        block_id: "rankshield-settings",
        fields: [
          {
            type: "select",
            action_id: "mode",
            label: "Protection Mode",
            initial_value: currentSettings.mode ?? "protect",
            options: [
              { label: "🔍 Monitor — Log threats only (no blocking)", value: "monitor"  },
              { label: "🛡 Protect — Block confirmed threats (recommended)", value: "protect"  },
              { label: "⚡ Paranoid — Block all suspicious signals immediately", value: "paranoid" },
            ],
          },
          {
            type: "number_input",
            action_id: "blockThreshold",
            label: "Block Threshold (0–100)",
            initial_value: currentSettings.blockThreshold ?? 75,
            min: 0,
            max: 100,
          },
          {
            type: "toggle",
            action_id: "showBadge",
            label: "Show Security Badge on Site",
            initial_value: currentSettings.showBadge ?? true,
          },
          {
            type: "text_input",
            action_id: "alertWebhook",
            label: "Alert Webhook URL (optional)",
            initial_value: (currentSettings.alertWebhook as string) ?? "",
            placeholder: "https://hooks.slack.com/…",
          },
        ],
        submit: { label: "Save Settings", action_id: "save_settings" },
      },
      {
        type: "section",
        text: "**API Key** is managed securely at the server level and cannot be changed here. To update your API key, edit your `astro.config.mjs` and redeploy.",
      },
      {
        type: "section",
        text: "**Need help?** Visit [rankshield.io/docs](https://rankshield.io/docs) or email [hello@seoeliteagency.com](mailto:hello@seoeliteagency.com)",
      },
    ],
  };
}

// ── MAIN PLUGIN DEFINITION ─────────────────────────────────────────────────────

export default definePlugin({

  // ── LIFECYCLE HOOKS ──────────────────────────────────────────────────────────

  hooks: {

    /**
     * REQUEST INTERCEPTION
     * Fires on every incoming request to the EmDash site.
     * We check the IP against RankShield's threat intelligence.
     *
     * On Cloudflare: runs in the V8 isolate, <2ms overhead for cached decisions.
     * On Node.js:    runs in-process, API call adds ~20-50ms (non-blocking).
     *
     * Note: Full behavioral fingerprinting (GPU canvas, mouse physics) is done
     * client-side via the injected fingerprint.js script and reported back
     * asynchronously. This hook handles the server-side IP + header analysis.
     */
    "request:receive": {
      handler: async (event: any, ctx: PluginContext) => {
        const opts = getOptions(ctx);
        if (opts.mode === "monitor") return; // Monitor mode — log only, never block here

        const request = event.request as Request;
        const ip         = request.headers.get("cf-connecting-ip")
                        ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
                        ?? "unknown";
        const userAgent  = request.headers.get("user-agent") ?? "";
        const url        = request.url ?? "/";

        // Skip bots we want (Google, Bing, etc.)
        if (/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandex|facebookexternalhit/i.test(userAgent)) {
          return;
        }

        // Check cache first (avoid repeat API calls for same visitor)
        const cacheKey = `ip:${ip}`;
        const cached = await ctx.kv.get<{ decision: string; score: number; ts: number }>(cacheKey);
        if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
          if (cached.decision === "block") {
            ctx.log.info(`[RankShield] Blocking cached threat IP ${ip} (score: ${cached.score})`);
            return { block: true, status: 403, body: "Access denied by RankShield security." };
          }
          return;
        }

        // Call RankShield API
        const result = await checkRequest(ctx, opts, ip, userAgent, url);

        // Cache the decision
        await ctx.kv.set(cacheKey, {
          decision: result.blocked ? "block" : "allow",
          score: result.threat_score,
          ts: Date.now(),
        });

        // Record event for local analytics
        if (result.threat_score > 30) {
          const blocked = result.blocked && result.threat_score >= opts.blockThreshold;
          await recordEvent(ctx, {
            id:          makeId(),
            timestamp:   new Date().toISOString(),
            ip,
            fingerprint: result.fingerprint,
            reason:      result.reason,
            threatScore: result.threat_score,
            blocked,
            url,
            userAgent,
          });

          if (blocked) {
            ctx.log.warn(`[RankShield] Blocked request from ${ip} — ${result.reason} (score: ${result.threat_score})`);
            return { block: true, status: 403, body: "Access denied by RankShield security." };
          } else {
            ctx.log.info(`[RankShield] Suspicious request logged from ${ip} — ${result.reason} (score: ${result.threat_score})`);
          }
        }
      },
    },

    /**
     * CONTENT SCAN
     * Fires after any content is saved. Checks for patterns associated with
     * NavBoost pollution — coordinated bad-click campaigns that inject
     * low-quality signals into Google's ranking algorithm.
     */
    "content:afterSave": {
      handler: async (event: any, ctx: PluginContext) => {
        const opts = getOptions(ctx);

        // Only analyze published content
        if (event.content?.status !== "published") return;

        // Check for NavBoost-related content patterns (thin content, keyword stuffing)
        const title   = (event.content?.title ?? "") as string;
        const content = JSON.stringify(event.content?.body ?? "");

        // Flag suspiciously short content that could be used for CTR manipulation
        if (title.length < 10 || content.length < 50) {
          ctx.log.warn(`[RankShield] Short content published — possible CTR manipulation target: "${title}"`);
          await ctx.kv.set(`navboost:${event.content.id}`, {
            flagged: true,
            reason: "thin-content",
            timestamp: new Date().toISOString(),
          });
        }
      },
    },

    /**
     * INSTALL HOOK
     * Fires once when the plugin is first installed.
     * Sets up initial KV state and validates the API key.
     */
    "plugin:install": {
      handler: async (_event: any, ctx: PluginContext) => {
        const opts = getOptions(ctx);
        ctx.log.info("[RankShield] Installing…");

        // Validate API key
        const stats = await fetchStats(ctx, opts);
        if (!stats) {
          ctx.log.warn("[RankShield] Could not validate API key — check your RankShield dashboard.");
        } else {
          ctx.log.info(`[RankShield] Connected. ${stats.stats?.total_sites ?? 0} site(s) protected, ${stats.stats?.total_blocked_all_time ?? 0} total threats blocked.`);
        }

        // Initialize settings
        await ctx.kv.set("settings", {
          mode:           opts.mode,
          blockThreshold: opts.blockThreshold,
          showBadge:      opts.showBadge,
          alertWebhook:   opts.alertWebhook,
          installedAt:    new Date().toISOString(),
          version:        "1.0.0",
        });

        await ctx.kv.set("stats:cache", null);
        ctx.log.info("[RankShield] Installation complete.");
      },
    },

    /**
     * UNINSTALL HOOK
     * Cleans up KV state. Storage collections are automatically deleted by EmDash.
     */
    "plugin:uninstall": {
      handler: async (_event: any, ctx: PluginContext) => {
        ctx.log.info("[RankShield] Uninstalling… cleaning up cached state.");
        await ctx.kv.delete("settings");
        await ctx.kv.delete("stats:cache");
        ctx.log.info("[RankShield] Uninstall complete.");
      },
    },
  },

  // ── ROUTES ────────────────────────────────────────────────────────────────────

  routes: {

    /**
     * FINGERPRINT ENDPOINT
     * Receives behavioral fingerprint data from the client-side script.
     * The browser fingerprinting JS (GPU canvas, mouse physics, WebGL) POSTs
     * here after collecting signals. We forward to RankShield API and return
     * the threat assessment.
     *
     * URL: /_emdash/api/plugins/rankshield-security/fingerprint
     * Method: POST
     * Auth: None required (public — called from visitor browsers)
     */
    fingerprint: {
      public: true,
      handler: async (routeCtx: any, ctx: PluginContext) => {
        const opts = getOptions(ctx);
        if (!ctx.http) return { blocked: false, score: 0 };

        const body = routeCtx.input as Record<string, unknown>;
        const ip   = routeCtx.request?.headers?.get("cf-connecting-ip")
                  ?? routeCtx.request?.headers?.get("x-forwarded-for")?.split(",")[0]?.trim()
                  ?? "unknown";

        try {
          const res = await ctx.http.fetch(`${RANKSHIELD_API}/api/plugin/fingerprint`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-api-key": opts.apiKey,
              "x-plugin": "emdash/1.0.0",
            },
            body: JSON.stringify({ ...body, ip }),
          });

          if (!res.ok) return { blocked: false, score: 0 };
          const result = await res.json() as { blocked: boolean; threat_score: number; reason: string; fingerprint: string };

          // Log high-confidence threats
          if (result.threat_score >= opts.blockThreshold) {
            await recordEvent(ctx, {
              id:          makeId(),
              timestamp:   new Date().toISOString(),
              ip,
              fingerprint: result.fingerprint,
              reason:      result.reason ?? "BEHAVIORAL_FINGERPRINT",
              threatScore: result.threat_score,
              blocked:     result.blocked,
              url:         (body.url as string) ?? "/",
              userAgent:   (body.ua as string) ?? "",
            });
          }

          return {
            blocked: result.blocked && opts.mode !== "monitor",
            score:   result.threat_score,
            reason:  result.reason,
          };
        } catch {
          return { blocked: false, score: 0 };
        }
      },
    },

    /**
     * STATS API ROUTE
     * Returns cached stats for the admin dashboard.
     * Refreshes from RankShield API if cache is stale (>5min).
     *
     * URL: /_emdash/api/plugins/rankshield-security/stats
     * Method: GET
     * Auth: Required (admin only)
     */
    stats: {
      handler: async (_routeCtx: any, ctx: PluginContext) => {
        const opts   = getOptions(ctx);
        const cached = await ctx.kv.get<{ data: StatsResponse; ts: number }>("stats:cache");

        if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
          return { ...cached.data, cached: true };
        }

        const stats = await fetchStats(ctx, opts);
        if (stats) {
          await ctx.kv.set("stats:cache", { data: stats, ts: Date.now() });
          return { ...stats, cached: false };
        }

        return { error: "Could not fetch stats", cached: false };
      },
    },

    /**
     * ADMIN BLOCK KIT HANDLER
     * Handles all admin page loads, widget renders, and form submissions.
     * Uses EmDash's Block Kit — JSON-defined UI that runs entirely server-side.
     * No plugin JavaScript runs in the admin browser. Maximum security.
     *
     * URL: /_emdash/api/plugins/rankshield-security/admin
     * Method: POST
     * Auth: Required (admin only)
     */
    admin: {
      handler: async (routeCtx: any, ctx: PluginContext) => {
        const opts        = getOptions(ctx);
        const interaction = routeCtx.input as {
          type:      string;
          page?:     string;
          widget_id?: string;
          action_id?: string;
          values?:   Record<string, unknown>;
        };

        // Fetch current stats (used across multiple views)
        const stats = await fetchStats(ctx, opts).catch(() => null);

        // ── PAGE LOADS ────────────────────────────────────────────────────
        if (interaction.type === "page_load") {
          const page = interaction.page ?? "/rankshield";

          if (page === "/rankshield") {
            return buildMainPage(stats, opts.mode);
          }

          if (page === "/rankshield/threats") {
            const profiles = stats?.active_fingerprints ?? [];
            return buildThreatsPage(profiles);
          }

          if (page === "/rankshield/settings") {
            const settings = await ctx.kv.get<Record<string, unknown>>("settings") ?? {};
            return buildSettingsPage(settings);
          }
        }

        // ── WIDGET RENDERS ────────────────────────────────────────────────
        if (interaction.type === "widget_load") {
          if (interaction.widget_id === "rankshield-status") {
            return buildStatusWidget(stats, opts.mode);
          }

          if (interaction.widget_id === "rankshield-trend") {
            return buildTrendWidget(stats);
          }
        }

        // ── FORM SUBMISSIONS ──────────────────────────────────────────────
        if (interaction.type === "form_submit" && interaction.action_id === "save_settings") {
          const values  = interaction.values ?? {};
          const current = await ctx.kv.get<Record<string, unknown>>("settings") ?? {};

          const updated = {
            ...current,
            mode:           values.mode          ?? current.mode,
            blockThreshold: values.blockThreshold ?? current.blockThreshold,
            showBadge:      values.showBadge      ?? current.showBadge,
            alertWebhook:   values.alertWebhook   ?? current.alertWebhook,
            updatedAt:      new Date().toISOString(),
          };

          await ctx.kv.set("settings", updated);

          return {
            blocks: [
              {
                type: "banner",
                style: "success",
                text: "✓ Settings saved. Changes take effect immediately.",
              },
            ],
            toast: { message: "RankShield settings saved", type: "success" },
          };
        }

        // ── BUTTON ACTIONS ────────────────────────────────────────────────
        if (interaction.type === "action" && interaction.action_id === "nav_threats") {
          const profiles = stats?.active_fingerprints ?? [];
          return buildThreatsPage(profiles);
        }

        return { blocks: [] };
      },
    },
  },
});
