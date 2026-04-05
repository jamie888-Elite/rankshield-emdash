/**
 * RankShield for EmDash — Plugin Runtime Engine
 * Runs at REQUEST TIME in the sandboxed Worker isolate.
 */

import { definePlugin } from "emdash";
import type { PluginContext } from "emdash";

// ── CONSTANTS ──────────────────────────────────────────────────────────────────
const RANKSHIELD_API = "https://sea-shield-production.up.railway.app";
const CACHE_TTL_MS   = 5 * 60 * 1000;

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

async function recordEvent(ctx: PluginContext, event: ThreatEvent): Promise<void> {
  try {
    await ctx.storage.threatEvents.put(event.id, {
      timestamp:   event.timestamp,
      ip:          event.ip,
      fingerprint: event.fingerprint,
      reason:      event.reason,
      threatScore: event.threatScore,
      blocked:     event.blocked,
      url:         event.url,
      userAgent:   event.userAgent.slice(0, 200),
    });
  } catch { /* non-fatal */ }
}

// ── BLOCK KIT UI ───────────────────────────────────────────────────────────────

function buildStatusWidget(stats: StatsResponse | null, mode: string) {
  const blocked24h = stats?.stats?.blocked_24h ?? 0;
  const blocked30d = stats?.stats?.blocked_30d ?? 0;
  const fps        = stats?.active_fingerprints?.length ?? 0;
  const rules      = stats?.auto_rules_count ?? 0;
  const statusText = blocked24h > 20 ? "⚠ UNDER ATTACK" : blocked24h > 5 ? "👁 MONITORING" : "🛡 PROTECTED";

  return {
    blocks: [
      {
        type: "section",
        text: `**${statusText}**`,
        accessory: { type: "button", text: "View Details →", action_id: "nav_threats", style: "primary" },
      },
      {
        type: "columns",
        columns: [
          { blocks: [
            { type: "stat", label: "Blocked 24h",        value: blocked24h.toLocaleString(), color: blocked24h > 0 ? "#E86853" : "#00FF88" },
            { type: "stat", label: "Blocked 30d",        value: blocked30d.toLocaleString(), color: "#E86853" },
          ]},
          { blocks: [
            { type: "stat", label: "Attacker Profiles",  value: fps.toLocaleString(),        color: "#AA55FF" },
            { type: "stat", label: "Active Rules",       value: rules.toLocaleString(),      color: "#00D4FF" },
          ]},
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
        { type: "header",  text: "Attack Volume — 30 Days" },
        { type: "section", text: "Collecting data… Check back as attacks are detected and logged." },
      ],
    };
  }
  const seriesData: Array<[number, number]> = trend.map((row) => [
    new Date(row.date + "T12:00:00Z").getTime(),
    row.blocked,
  ]);
  return {
    blocks: [{
      type: "chart",
      config: {
        chart_type: "timeseries",
        series: [{ name: "Attacks Blocked", data: seriesData, color: "#E86853" }],
        yAxisName: "Blocked",
        gradient: true,
        smooth: true,
      },
    }],
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
    ? { type: "banner", style: "danger",  text: `⚠ Active attack — ${blocked24h} attempts blocked in 24h. All neutralized.` }
    : blocked24h > 5
    ? { type: "banner", style: "warning", text: `👁 Elevated activity — ${blocked24h} suspicious requests blocked in 24h.` }
    : { type: "banner", style: "success", text: "🛡 Your site is protected. No significant threats detected." };

  return {
    blocks: [
      alertBanner,
      {
        type: "columns",
        columns: [
          { blocks: [{ type: "stat", label: "Blocked (24h)",     value: blocked24h.toLocaleString(), color: "#E86853" }] },
          { blocks: [{ type: "stat", label: "Blocked (30d)",     value: blocked30d.toLocaleString(), color: "#E86853" }] },
          { blocks: [{ type: "stat", label: "All Time Blocked",  value: allTime.toLocaleString(),    color: "#AA55FF" }] },
          { blocks: [{ type: "stat", label: "Attacker Profiles", value: fps.toLocaleString(),        color: "#00D4FF" }] },
          { blocks: [{ type: "stat", label: "Active Rules",      value: rules.toLocaleString(),      color: "#00FF88" }] },
        ],
      },
      { type: "header", text: "Recent Attack Activity" },
      recent.length > 0
        ? {
            type: "table",
            blockId: "recent-events",
            columns: [
              { key: "reason",      label: "Threat Type", format: "text"          },
              { key: "ip",          label: "Source IP",   format: "text"          },
              { key: "threatScore", label: "Score",       format: "badge"         },
              { key: "blocked",     label: "Action",      format: "badge"         },
              { key: "timestamp",   label: "Time",        format: "relative_time" },
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
    ],
  };
}

function buildThreatsPage(profiles: AttackerProfile[]) {
  if (!profiles.length) {
    return {
      blocks: [
        { type: "header",  text: "Threat Intelligence" },
        { type: "section", text: "No attacker profiles yet. As traffic arrives, RankShield builds persistent behavioral profiles of any bots detected — tracking them across IP rotation, VPNs, and headless browser changes." },
        { type: "section", text: "💡 **How it works:** RankShield fingerprints the attacker's GPU canvas hash, mouse physics, and behavioral timing — signals that persist across every IP change. Once fingerprinted, an attacker cannot escape by switching proxies or clearing cookies." },
      ],
    };
  }
  return {
    blocks: [
      { type: "header",  text: `Threat Intelligence — ${profiles.length} Attacker Profiles` },
      { type: "section", text: "Each profile represents a persistent attacker identity tracked across IP rotation, VPN changes, and device spoofing. Confidence grows with each blocked session." },
      {
        type: "table",
        blockId: "attacker-profiles",
        columns: [
          { key: "fingerprint", label: "Fingerprint",  format: "text"          },
          { key: "hitCount",    label: "Sessions",     format: "number"        },
          { key: "threatScore", label: "Confidence",   format: "badge"         },
          { key: "reasons",     label: "Attack Types", format: "text"          },
          { key: "blocked",     label: "Status",       format: "badge"         },
          { key: "lastSeen",    label: "Last Seen",    format: "relative_time" },
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
      { type: "header",  text: "Security Settings" },
      { type: "section", text: "Configure how RankShield protects your EmDash site. Changes take effect immediately — no redeploy required." },
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
              { label: "🔍 Monitor — Log threats only (no blocking)",              value: "monitor"  },
              { label: "🛡 Protect — Block confirmed threats (recommended)",        value: "protect"  },
              { label: "⚡ Paranoid — Block all suspicious signals immediately",    value: "paranoid" },
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
    ],
  };
}

// ── PLUGIN DEFINITION ──────────────────────────────────────────────────────────

export default definePlugin({

  hooks: {

    "request:receive": {
      handler: async (event: any, ctx: PluginContext) => {
        const opts = getOptions(ctx);
        if (opts.mode === "monitor") return;

        const request   = event.request as Request;
        const ip        = request.headers.get("cf-connecting-ip")
                       ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
                       ?? "unknown";
        const userAgent = request.headers.get("user-agent") ?? "";
        const url       = request.url ?? "/";

        // Skip legitimate crawlers
        if (/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandex|facebookexternalhit/i.test(userAgent)) return;

        // Check KV cache first
        const cacheKey = `ip:${ip}`;
        const cached   = await ctx.kv.get<{ decision: string; score: number; ts: number }>(cacheKey);
        if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
          if (cached.decision === "block") {
            ctx.log.info(`[RankShield] Blocking cached threat IP ${ip}`);
            return { block: true, status: 403, body: "Access denied by RankShield security." };
          }
          return;
        }

        const result = await checkRequest(ctx, opts, ip, userAgent, url);

        await ctx.kv.set(cacheKey, {
          decision: result.blocked ? "block" : "allow",
          score:    result.threat_score,
          ts:       Date.now(),
        });

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
            ctx.log.warn(`[RankShield] Blocked ${ip} — ${result.reason} (score: ${result.threat_score})`);
            return { block: true, status: 403, body: "Access denied by RankShield security." };
          }
        }
      },
    },

    "content:afterSave": {
      handler: async (event: any, ctx: PluginContext) => {
        if (event.content?.status !== "published") return;
        const title   = (event.content?.title ?? "") as string;
        const content = JSON.stringify(event.content?.body ?? "");
        if (title.length < 10 || content.length < 50) {
          ctx.log.warn(`[RankShield] Thin content detected — possible CTR manipulation target: "${title}"`);
          await ctx.kv.set(`navboost:${event.content.id}`, {
            flagged:   true,
            reason:    "thin-content",
            timestamp: new Date().toISOString(),
          });
        }
      },
    },

    "plugin:install": {
      handler: async (_event: any, ctx: PluginContext) => {
        const opts  = getOptions(ctx);
        ctx.log.info("[RankShield] Installing…");
        const stats = await fetchStats(ctx, opts);
        if (!stats) {
          ctx.log.warn("[RankShield] Could not validate API key — check your RankShield dashboard.");
        } else {
          ctx.log.info(`[RankShield] Connected. ${stats.stats?.total_blocked_all_time ?? 0} total threats blocked across network.`);
        }
        await ctx.kv.set("settings", {
          mode:           opts.mode,
          blockThreshold: opts.blockThreshold,
          showBadge:      opts.showBadge,
          alertWebhook:   opts.alertWebhook,
          installedAt:    new Date().toISOString(),
          version:        "1.0.0",
        });
        ctx.log.info("[RankShield] Installation complete.");
      },
    },

    "plugin:uninstall": {
      handler: async (_event: any, ctx: PluginContext) => {
        await ctx.kv.delete("settings");
        await ctx.kv.delete("stats:cache");
        ctx.log.info("[RankShield] Uninstalled and cleaned up.");
      },
    },
  },

  routes: {

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
              "x-api-key":    opts.apiKey,
              "x-plugin":     "emdash/1.0.0",
            },
            body: JSON.stringify({ ...body, ip }),
          });
          if (!res.ok) return { blocked: false, score: 0 };
          const result = await res.json() as { blocked: boolean; threat_score: number; reason: string; fingerprint: string };

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
              userAgent:   (body.ua  as string) ?? "",
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

    admin: {
      handler: async (routeCtx: any, ctx: PluginContext) => {
        const opts        = getOptions(ctx);
        const interaction = routeCtx.input as {
          type:       string;
          page?:      string;
          widget_id?: string;
          action_id?: string;
          values?:    Record<string, unknown>;
        };

        const stats = await fetchStats(ctx, opts).catch(() => null);

        if (interaction.type === "page_load") {
          if (interaction.page === "/rankshield")          return buildMainPage(stats, opts.mode);
          if (interaction.page === "/rankshield/threats")  return buildThreatsPage(stats?.active_fingerprints ?? []);
          if (interaction.page === "/rankshield/settings") {
            const settings = await ctx.kv.get<Record<string, unknown>>("settings") ?? {};
            return buildSettingsPage(settings);
          }
        }

        if (interaction.type === "widget_load") {
          if (interaction.widget_id === "rankshield-status") return buildStatusWidget(stats, opts.mode);
          if (interaction.widget_id === "rankshield-trend")  return buildTrendWidget(stats);
        }

        if (interaction.type === "form_submit" && interaction.action_id === "save_settings") {
          const values  = interaction.values ?? {};
          const current = await ctx.kv.get<Record<string, unknown>>("settings") ?? {};
          await ctx.kv.set("settings", {
            ...current,
            mode:           values.mode           ?? current.mode,
            blockThreshold: values.blockThreshold  ?? current.blockThreshold,
            showBadge:      values.showBadge        ?? current.showBadge,
            alertWebhook:   values.alertWebhook     ?? current.alertWebhook,
            updatedAt:      new Date().toISOString(),
          });
          return {
            blocks: [{ type: "banner", style: "success", text: "✓ Settings saved. Changes take effect immediately." }],
            toast:  { message: "RankShield settings saved", type: "success" },
          };
        }

        if (interaction.type === "action" && interaction.action_id === "nav_threats") {
          return buildThreatsPage(stats?.active_fingerprints ?? []);
        }

        return { blocks: [] };
      },
    },
  },
});
