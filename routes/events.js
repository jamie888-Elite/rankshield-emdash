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
const { authenticateSite } = require('../middleware/auth');
const { checkIP, getAbuseRisk } = require('../src/abuseipdb');
const { classifyEvent } = require('../src/classifier');
const { shouldHoneypot, isInObservation, startHoneypotSession, recordHoneypotEvent, shouldBlockNow, finalizeHoneypotSession } = require('../src/honeypotAgent');

// Event-driven threat bus — fires on every confirmed block
// Closes L11 from scheduled (15min max lag) to real-time (<60s)
const { pushToCrossClientBus } = require('../src/enterpriseTenantAgent');

// IP prefix extractor
function ipPrefix(ip) {
  if (!ip) return null;
  const parts = ip.split('.');
  return parts.length >= 3 ? parts.slice(0, 3).join('.') + '.0/24' : null;
}

// POST /api/event — receive block event from client WordPress site
router.post('/', authenticateSite, async (req, res) => {
  const {
    event_type, reason, ip, user_agent, url,
    referrer, detail, blocked = true,
  } = req.body;

  if (!event_type && !reason) {
    return res.status(400).json({ error: 'event_type or reason is required' });
  }

  // Extract IP prefix
  const ip_prefix = ip
    ? ip.split('.').slice(0, 2).join('.')
    : null;

  // Check AbuseIPDB in background — don't block the response
  let abuse_data = null;
  let abuse_risk = 'unknown';

  try {
    // Check AbuseIPDB asynchronously
    checkIP(ip).then(async (abuseResult) => {
      if (!abuseResult) return;

      abuse_risk = getAbuseRisk(abuseResult);

      // If high abuse score — update the event and create a fingerprint
      if (abuseResult.abuse_score >= 50) {
        await db.query(`
          UPDATE events SET detail = detail || $1 WHERE ip = $2 AND created_at > NOW() - INTERVAL '1 minute'
        `, [
          ` | AbuseIPDB: score=${abuseResult.abuse_score} reports=${abuseResult.total_reports} isp="${abuseResult.isp}"`,
          ip,
        ]).catch(() => {});

        // Auto-fingerprint high-abuse IPs
        await db.query(`
          INSERT INTO fingerprints
            (fingerprint_key, fingerprint_type, description, confidence, hit_count, sites_affected, example_ip, last_seen_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
          ON CONFLICT (fingerprint_key) DO UPDATE SET
            hit_count = fingerprints.hit_count + 1,
            confidence = GREATEST(fingerprints.confidence, $4),
            last_seen_at = NOW()
        `, [
          `abuseipdb_${ip.replace(/\./g, '_').replace(/:/g, '_')}`,
          'abuseipdb',
          `IP ${ip} — AbuseIPDB score: ${abuseResult.abuse_score}/100, ${abuseResult.total_reports} reports, ISP: ${abuseResult.isp}, Country: ${abuseResult.country}`,
          Math.min(40 + abuseResult.abuse_score, 99),
          1,
          [req.site.domain],
          ip,
        ]).catch(() => {});
      }
    }).catch(() => {});

  } catch (err) {
    // Non-fatal — continue storing event
  }

  try {
    const result = await db.query(
      `INSERT INTO events
         (site_id, domain, event_type, reason, ip, ip_prefix, user_agent, url, referrer, detail, platform, blocked)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING id`,
      [
        req.site.id,
        req.site.domain,
        event_type || reason,
        reason || event_type,
        ip || null,
        ip_prefix,
        user_agent ? user_agent.substring(0, 500) : null,
        url ? url.substring(0, 500) : null,
        referrer ? referrer.substring(0, 500) : null,
        detail ? detail.substring(0, 500) : null,
        req.site.platform,
        blocked,
      ]
    );

    const eventId = result.rows[0].id;
    res.json({ success: true, event_id: eventId });

    // Fire honeypot + classifier in background — never delays the response
    if (blocked && ip) {
      // EVENT-DRIVEN THREAT BUS — propagates this block to all clients in <60s
      // This replaces the 15-minute scheduled cycle for high-confidence blocks
      setImmediate(async () => {
        try {
          const threatScore = parseInt(req.body.threat_score || req.body.score || 0);
          const cf_asn      = parseInt(req.body.cf_asn || 0) || null;
          if (threatScore >= 75 && ip) {
            // Push IP to cross-client bus immediately
            await pushToCrossClientBus(
              'ip', ip,
              Math.min(95, 50 + Math.floor(threatScore / 2)),
              [reason || event_type || 'confirmed_block'],
              'smb',
              null,
              { site_id: req.site.id, domain: req.site.domain, cf_asn }
            );
            // Push /24 prefix if high-volume attack
            const prefix = ipPrefix(ip);
            if (prefix && threatScore >= 88) {
              await pushToCrossClientBus('ip_prefix', prefix, 72, ['confirmed_block_prefix'], 'smb', null, null);
            }
          }
        } catch (e) { /* silent — never block response */ }
      });
      setImmediate(async () => {
        try {
          const session = await isInObservation(ip);
          if (session) {
            await recordHoneypotEvent(ip, { url, reason, ts: new Date().toISOString() });
            if (await shouldBlockNow(ip, session)) {
              await finalizeHoneypotSession(ip, ip_prefix, user_agent, session);
            }
          }
        } catch (e) { /* silent */ }
      });
      setImmediate(() => {
        classifyEvent({
          ip,
          ip_prefix,
          user_agent,
          domain: req.site.domain,
          site_id: req.site.id,
          reason: reason || event_type,
          event_id: eventId,
        }).catch(err => console.error('[Events] Classifier error:', err.message));
      });
    }
  } catch (err) {
    console.error('Event store error:', err);
    res.status(500).json({ error: 'Failed to store event' });
  }
});

// GET /api/event/recent — get recent events for requesting site
router.get('/recent', authenticateSite, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 5000);

  try {
    const result = await db.query(
      `SELECT event_type, reason, ip, ip_prefix, user_agent, url, detail, blocked, created_at
       FROM events
       WHERE site_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.site.id, limit]
    );

    res.json({ events: result.rows, site: req.site.domain });
  } catch (err) {
    console.error('Recent events error:', err);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});


// GET /api/event/trend — daily attack counts for a site (for client charts)
router.get('/trend', authenticateSite, async (req, res) => {
  const days = Math.min(parseInt(req.query.days || 30), 90);
  try {
    const { rows } = await db.query(`
      SELECT 
        DATE(created_at AT TIME ZONE 'UTC') as date,
        COUNT(*) as total,
        COUNT(CASE WHEN blocked = true THEN 1 END) as blocked,
        COUNT(DISTINCT ip) as unique_ips
      FROM events
      WHERE site_id = $1
        AND created_at > NOW() - INTERVAL '${days} days'
      GROUP BY DATE(created_at AT TIME ZONE 'UTC')
      ORDER BY date ASC
    `, [req.site.id]);
    res.json({ days, trend: rows, site: req.site.domain });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
