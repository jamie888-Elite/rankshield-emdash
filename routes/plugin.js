/**
 * RankShield Plugin API Routes
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — The methods and systems implemented in this software
 * are covered by the following provisional patent applications filed
 * April 5, 2026 by Jamie Kloncz / SEO Elite Agency:
 *   RS-001-PROV — Cross-Channel Persistent Attacker Identity via Hardware Behavioral Fingerprinting
 *   RS-002-PROV — Behavioral Fingerprint Persistence Across IP Rotation and VPN Masking
 *   RS-007-PROV — Sandboxed CMS Plugin Architecture for Real-Time Black Hat Defense
 *
 * Handles requests from the EmDash plugin:
 *   POST /api/plugin/check       — server-side IP/UA check before page load
 *   POST /api/plugin/fingerprint — client-side hardware fingerprint analysis
 */

const express = require('express');
const router  = express.Router();
const db      = require('../src/db');
const { authenticateSite } = require('../middleware/auth');

// ── CONSTANTS ────────────────────────────────────────────────────────────────
const BLOCK_THRESHOLD   = 75;   // threat score to auto-block
const FLAG_THRESHOLD    = 40;   // threat score to log
const CACHE_TTL_MS      = 5 * 60 * 1000; // 5 minutes

// Simple in-memory cache for IP decisions (upgrade to Redis later)
const ipCache = new Map();

// ── HELPERS ──────────────────────────────────────────────────────────────────

function cleanCache() {
  const now = Date.now();
  for (const [key, val] of ipCache) {
    if (now - val.ts > CACHE_TTL_MS) ipCache.delete(key);
  }
}

/**
 * Score an IP address against known attacker database
 * Returns { score, reason, blocked, fingerprint }
 */
async function scoreIp(ip, userAgent, siteId) {
  // Check cache
  const cacheKey = `${siteId}:${ip}`;
  const cached = ipCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return { ...cached.result, cached: true };
  }

  let score  = 0;
  let reason = 'clean';
  let fingerprint = null;

  try {
    // Check if this IP has recent blocked events on ANY site (cross-site intel)
    const ipCheck = await db.query(`
      SELECT
        COUNT(*) as hit_count,
        COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count,
        MAX(created_at) as last_seen,
        MODE() WITHIN GROUP (ORDER BY reason) as top_reason
      FROM events
      WHERE ip = $1
        AND created_at > NOW() - INTERVAL '30 days'
    `, [ip]);

    const ipData = ipCheck.rows[0];
    const hitCount     = parseInt(ipData.hit_count)     || 0;
    const blockedCount = parseInt(ipData.blocked_count) || 0;

    // Previously blocked on any site — high confidence threat
    if (blockedCount > 0) {
      score  = Math.min(95, 60 + (blockedCount * 5));
      reason = ipData.top_reason || 'PREVIOUSLY_BLOCKED';
    }
    // High hit count without conversion — suspicious
    else if (hitCount > 50) {
      score  = Math.min(70, 40 + Math.floor(hitCount / 10));
      reason = 'HIGH_REQUEST_VOLUME';
    }

    // Check for known headless/bot user agent patterns
    if (userAgent) {
      const ua = userAgent.toLowerCase();
      if (/headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver/i.test(ua)) {
        score  = Math.max(score, 85);
        reason = 'HEADLESS_BROWSER_DETECTED';
      }
      // Missing or minimal user agent
      if (ua.length < 20) {
        score  = Math.max(score, 60);
        reason = 'INVALID_USER_AGENT';
      }
    }

    // Check against active auto-rules for this site
    const rulesCheck = await db.query(`
      SELECT rule_key, rule_value, action
      FROM rules
      WHERE site_id = $1
        AND active = true
        AND rule_key = 'ip_block'
        AND rule_value = $2
      LIMIT 1
    `, [siteId, ip]);

    if (rulesCheck.rows.length > 0) {
      score  = 100;
      reason = 'IP_BLOCKED_BY_RULE';
    }

    // Check IP prefix against known attacker prefixes
    const ipPrefix = ip.split('.').slice(0, 3).join('.');
    const prefixCheck = await db.query(`
      SELECT COUNT(*) as count
      FROM events
      WHERE ip_prefix = $1
        AND blocked = true
        AND created_at > NOW() - INTERVAL '7 days'
    `, [ipPrefix]);

    const prefixCount = parseInt(prefixCheck.rows[0]?.count) || 0;
    if (prefixCount > 10) {
      score  = Math.max(score, 65);
      reason = reason === 'clean' ? 'SUSPICIOUS_IP_PREFIX' : reason;
    }

  } catch (err) {
    console.error('[Plugin] Score IP error:', err.message);
    // Fail open — don't block on DB errors
    return { score: 0, reason: 'db-error', blocked: false, fingerprint: null, cached: false };
  }

  const blocked = score >= BLOCK_THRESHOLD;
  const result  = { score, reason, blocked, fingerprint, cached: false };

  // Cache the decision
  ipCache.set(cacheKey, { result, ts: Date.now() });
  if (ipCache.size > 5000) cleanCache();

  return result;
}

/**
 * Score a behavioral fingerprint against known attacker profiles
 */
async function scoreFingerprint(fpData, ip, siteId) {
  const {
    hw_hash,
    canvas,
    webgl,
    audio,
    mouse,
    scroll,
    env,
  } = fpData;

  let score  = 0;
  let reason = 'clean';

  // ── HEADLESS DETECTION ──────────────────────────────────────────────────
  if (env?.isHeadless || env?.isAutomated) {
    score  = Math.max(score, 90);
    reason = 'HEADLESS_BROWSER_DETECTED';
  }

  // WebDriver attribute present
  if (env?.ua && /webdriver/i.test(env.ua)) {
    score  = Math.max(score, 85);
    reason = 'WEBDRIVER_DETECTED';
  }

  // ── MOUSE PHYSICS ───────────────────────────────────────────────────────
  if (mouse && mouse.samples > 5) {
    // Curve ratio < 1.05 = almost perfectly straight line = bot
    if (mouse.curveRatio < 1.05 && mouse.curveRatio > 0) {
      score  = Math.max(score, 75);
      reason = 'LINEAR_MOUSE_MOVEMENT';
    }
    // Zero jitter = no human hand tremor = bot
    if (mouse.jitter === 0 && mouse.samples > 20) {
      score  = Math.max(score, 70);
      reason = reason === 'clean' ? 'NO_MOUSE_JITTER' : reason;
    }
    // Very high velocity = programmatic movement
    if (parseFloat(mouse.avgVelocity) > 3000) {
      score  = Math.max(score, 65);
      reason = reason === 'clean' ? 'HIGH_MOUSE_VELOCITY' : reason;
    }
  }

  // ── SCROLL BEHAVIOR ─────────────────────────────────────────────────────
  if (scroll && scroll.samples > 3) {
    // Linear scroll = programmatic = bot
    if (scroll.linear === true) {
      score  = Math.max(score, 60);
      reason = reason === 'clean' ? 'LINEAR_SCROLL_PATTERN' : reason;
    }
  }

  // ── HARDWARE FINGERPRINT DATABASE CHECK ─────────────────────────────────
  if (hw_hash) {
    try {
      const fpCheck = await db.query(`
        SELECT
          COUNT(*) as hit_count,
          COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count,
          MAX(created_at) as last_seen,
          MODE() WITHIN GROUP (ORDER BY reason) as top_reason
        FROM events
        WHERE fingerprint = $1
          AND created_at > NOW() - INTERVAL '90 days'
      `, [hw_hash]);

      const fpData2    = fpCheck.rows[0];
      const hitCount   = parseInt(fpData2.hit_count)     || 0;
      const blockedCount = parseInt(fpData2.blocked_count) || 0;

      if (blockedCount > 0) {
        score  = Math.max(score, Math.min(98, 70 + (blockedCount * 3)));
        reason = fpData2.top_reason || 'KNOWN_ATTACKER_FINGERPRINT';
      } else if (hitCount > 100) {
        score  = Math.max(score, 55);
        reason = reason === 'clean' ? 'HIGH_FINGERPRINT_VOLUME' : reason;
      }
    } catch (err) {
      console.error('[Plugin] Fingerprint DB check error:', err.message);
    }
  }

  // ── ENVIRONMENT ANOMALIES ───────────────────────────────────────────────
  if (env) {
    // No plugins at all in non-Firefox browser = suspicious
    if (env.plugins === 0 && !/firefox/i.test(env.ua || '')) {
      score  = Math.max(score, 45);
      reason = reason === 'clean' ? 'NO_BROWSER_PLUGINS' : reason;
    }
    // Missing language settings
    if (!env.langs || env.langs === '') {
      score  = Math.max(score, 50);
      reason = reason === 'clean' ? 'MISSING_LANGUAGE_SETTINGS' : reason;
    }
  }

  const blocked = score >= BLOCK_THRESHOLD;
  return { score, reason, blocked, fingerprint: hw_hash || null };
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

/**
 * POST /api/plugin/check
 * Server-side request check — called by the plugin's request:receive hook
 * before any page content is served. Must respond in <50ms.
 *
 * Auth: x-api-key (site API key)
 * Body: { ip, user_agent, url }
 * Returns: { blocked, threat_score, reason, fingerprint, cached }
 */
router.post('/check', authenticateSite, async (req, res) => {
  const { ip, user_agent, url } = req.body;

  if (!ip) {
    return res.status(400).json({ error: 'Missing ip field' });
  }

  try {
    const result = await scoreIp(ip, user_agent, req.site.id);

    // Log significant threats to events table
    if (result.score >= FLAG_THRESHOLD) {
      const ipPrefix = ip.split('.').slice(0, 3).join('.');
      db.query(`
        INSERT INTO events
          (site_id, event_type, ip, ip_prefix, user_agent, url, reason, blocked, fingerprint)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        req.site.id,
        'plugin_check',
        ip,
        ipPrefix,
        (user_agent || '').slice(0, 500),
        (url || '/').slice(0, 500),
        result.reason,
        result.blocked,
        result.fingerprint,
      ]).catch(err => console.error('[Plugin] Event insert error:', err.message));
    }

    return res.json({
      blocked:      result.blocked,
      threat_score: result.score,
      reason:       result.reason,
      fingerprint:  result.fingerprint,
      cached:       result.cached,
    });

  } catch (err) {
    console.error('[Plugin] /check error:', err.message);
    // Fail open — never block legitimate traffic due to API errors
    return res.json({ blocked: false, threat_score: 0, reason: 'error', fingerprint: null, cached: false });
  }
});

/**
 * POST /api/plugin/fingerprint
 * Receives hardware behavioral fingerprint from client-side collection script.
 * Scores the fingerprint and returns block decision.
 *
 * Auth: x-api-key (site API key)
 * Body: { canvas, webgl, audio, fonts, hw_hash, mouse, scroll, env, ts, url, ua, ip }
 * Returns: { blocked, threat_score, reason, fingerprint }
 */
router.post('/fingerprint', authenticateSite, async (req, res) => {
  const body = req.body;
  const ip   = body.ip
            || req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.ip
            || 'unknown';

  try {
    const result = await scoreFingerprint(body, ip, req.site.id);

    // Store fingerprint event for all significant detections
    if (result.score >= FLAG_THRESHOLD || result.fingerprint) {
      const ipPrefix = ip.split('.').slice(0, 3).join('.');
      db.query(`
        INSERT INTO events
          (site_id, event_type, ip, ip_prefix, user_agent, url, reason, blocked, fingerprint, detail)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        req.site.id,
        'fingerprint',
        ip,
        ipPrefix,
        (body.ua || body.env?.ua || '').slice(0, 500),
        (body.url || '/').slice(0, 500),
        result.reason,
        result.blocked,
        result.fingerprint,
        JSON.stringify({
          score:       result.score,
          mouseJitter: body.mouse?.jitter,
          curveRatio:  body.mouse?.curveRatio,
          scrollLinear: body.scroll?.linear,
          isHeadless:  body.env?.isHeadless,
          isAutomated: body.env?.isAutomated,
        }),
      ]).catch(err => console.error('[Plugin] Fingerprint insert error:', err.message));

      // If this is a confirmed attacker, add auto-rule to block their IP
      if (result.blocked && result.score >= 85 && ip !== 'unknown') {
        db.query(`
          INSERT INTO rules (site_id, rule_key, rule_value, action, confidence, auto_generated)
          VALUES ($1, 'ip_block', $2, 'block', $3, true)
          ON CONFLICT (site_id, rule_key, rule_value) DO UPDATE
            SET confidence = GREATEST(rules.confidence, $3),
                updated_at = NOW()
        `, [req.site.id, ip, result.score])
        .catch(err => console.error('[Plugin] Rule insert error:', err.message));
      }
    }

    return res.json({
      blocked:      result.blocked,
      threat_score: result.score,
      reason:       result.reason,
      fingerprint:  result.fingerprint,
    });

  } catch (err) {
    console.error('[Plugin] /fingerprint error:', err.message);
    return res.json({ blocked: false, threat_score: 0, reason: 'error', fingerprint: null });
  }
});

module.exports = router;
