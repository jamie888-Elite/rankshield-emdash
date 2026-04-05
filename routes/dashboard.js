/**
 * RankShield API
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — Methods and systems in this software are covered by
 * provisional patent applications RS-001-PROV through RS-007-PROV
 * filed April 5, 2026 by Jamie Kloncz / SEO Elite Agency.
 */

const express = require('express');
const router = express.Router();
const db = require('../src/db');
const { authenticateAdmin } = require('../middleware/auth');

// GET /api/dashboard
router.get('/', authenticateAdmin, async (req, res) => {
  try {
    const stats = await db.query(`
      SELECT
        COUNT(DISTINCT s.id) as total_sites,
        COUNT(e.id) as total_events_all_time,
        COUNT(CASE WHEN e.blocked = true THEN 1 END) as total_blocked_all_time,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as events_24h,
        COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as blocked_24h,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as events_1h,
        COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '30 days' THEN 1 END) as blocked_30d,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '30 days' THEN 1 END) as events_30d,
        COUNT(DISTINCT CASE WHEN e.created_at > NOW() - INTERVAL '24 hours' THEN e.ip END) as unique_attacker_ips_24h
      FROM sites s
      LEFT JOIN events e ON e.site_id = s.id
      WHERE s.active = true
    `);

    const sites = await db.query(`
      SELECT s.id, s.domain, s.platform, s.client_name, s.active,
        COUNT(e.id) as total_events,
        COUNT(CASE WHEN e.blocked = true THEN 1 END) as total_blocked,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as events_24h,
        COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as blocked_24h,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as events_1h,
        COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '30 days' THEN 1 END) as blocked_30d,
        COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '30 days' THEN 1 END) as events_30d,
        MAX(e.created_at) as last_event_at
      FROM sites s
      LEFT JOIN events e ON e.site_id = s.id
      GROUP BY s.id
      ORDER BY events_24h DESC
    `);

    const attack_reasons = await db.query(`
      SELECT reason, COUNT(*) as count, COUNT(DISTINCT ip) as unique_ips, COUNT(DISTINCT site_id) as sites_hit
      FROM events
      WHERE created_at > NOW() - INTERVAL '24 hours' AND blocked = true
      GROUP BY reason ORDER BY count DESC LIMIT 10
    `);

    const top_ips = await db.query(`
      SELECT ip, ip_prefix, COUNT(*) as hit_count, COUNT(DISTINCT site_id) as sites_hit,
             MAX(user_agent) as user_agent, MAX(created_at) as last_seen
      FROM events
      WHERE created_at > NOW() - INTERVAL '24 hours' AND blocked = true
      GROUP BY ip, ip_prefix
      ORDER BY sites_hit DESC, hit_count DESC LIMIT 20
    `);

    const cross_site = await db.query(`
      SELECT ip, ip_prefix, COUNT(DISTINCT site_id) as sites_targeted,
             array_agg(DISTINCT domain) as domains, COUNT(*) as total_hits, MAX(user_agent) as user_agent
      FROM events
      WHERE created_at > NOW() - INTERVAL '24 hours'
      GROUP BY ip, ip_prefix
      HAVING COUNT(DISTINCT site_id) > 1
      ORDER BY sites_targeted DESC, total_hits DESC LIMIT 10
    `);

    const recent = await db.query(`
      SELECT e.domain, e.event_type, e.reason, e.ip, e.ip_prefix,
             e.user_agent, e.url, e.detail, e.blocked, e.created_at
      FROM events e ORDER BY e.created_at DESC LIMIT 5000
    `);

    const fingerprints = await db.query(`
      SELECT fingerprint_key, fingerprint_type, description, confidence,
             hit_count, sites_affected, last_seen_at
      FROM fingerprints
      WHERE active = true AND fingerprint_type != 'prediction'
      ORDER BY confidence DESC, hit_count DESC LIMIT 20
    `);

    const predictions_row = await db.query(`
      SELECT description FROM fingerprints
      WHERE fingerprint_key = 'prediction_engine_latest' LIMIT 1
    `);

    let predictions = [];
    if (predictions_row.rows.length > 0) {
      try { predictions = JSON.parse(predictions_row.rows[0].description); } catch(e) {}
    }

    const auto_rules = await db.query(`
      SELECT COUNT(*) as count FROM rules WHERE rule_key LIKE 'auto_%' AND active = true
    `);


    const daily_trend = await db.query(`
      SELECT
        DATE(created_at AT TIME ZONE 'UTC') as date,
        COUNT(*) as total,
        COUNT(CASE WHEN blocked = true THEN 1 END) as blocked
      FROM events
      WHERE created_at > NOW() - INTERVAL '30 days'
      GROUP BY DATE(created_at AT TIME ZONE 'UTC')
      ORDER BY date ASC
    `);

    res.json({
      generated_at: new Date().toISOString(),
      stats: stats.rows[0],
      auto_rules_count: parseInt(auto_rules.rows[0].count),
      sites: sites.rows,
      attack_reasons: attack_reasons.rows,
      top_attacker_ips: top_ips.rows,
      cross_site_attacks: cross_site.rows,
      recent_events: recent.rows,
      active_fingerprints: fingerprints.rows,
      predictions,
      daily_trend: daily_trend.rows,
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// POST /api/dashboard/analyze — manually trigger pattern engine
router.post('/analyze', authenticateAdmin, async (req, res) => {
  try {
    const { runPatternEngine, predictNextMoves } = require('../src/patternEngine');
    res.json({ success: true, message: 'Pattern engine triggered — results in 30 seconds' });
    setImmediate(async () => {
      await runPatternEngine();
      await predictNextMoves();
    });
  } catch (err) {
    console.error('Manual analysis error:', err);
  }
});


// GET /api/dashboard/trend — daily attack counts for charts (all sites or per site)
router.get('/trend', authenticateAdmin, async (req, res) => {
  const days = Math.min(parseInt(req.query.days || 30), 90);
  try {
    const { rows } = await db.query(`
      SELECT 
        DATE(created_at AT TIME ZONE 'UTC') as date,
        COUNT(*) as total,
        COUNT(CASE WHEN blocked = true THEN 1 END) as blocked,
        COUNT(DISTINCT ip) as unique_ips
      FROM events
      WHERE created_at > NOW() - INTERVAL '${days} days'
      GROUP BY DATE(created_at AT TIME ZONE 'UTC')
      ORDER BY date ASC
    `);
    res.json({ days, trend: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
