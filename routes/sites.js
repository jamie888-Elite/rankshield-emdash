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
const { v4: uuidv4 } = require('uuid');
const { authenticateAdmin, authenticateSite } = require('../middleware/auth');

// POST /api/sites/register — register a new client site (admin only)
router.post('/register', authenticateAdmin, async (req, res) => {
  const { domain, platform = 'wordpress', client_name, client_email, agency_email } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'domain is required' });
  }

  // Clean domain
  const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

  // Generate API key
  const api_key = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');

  try {
    const result = await db.query(
      `INSERT INTO sites (domain, platform, api_key, client_name, client_email, agency_email)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (domain) DO UPDATE SET
         platform = EXCLUDED.platform,
         client_name = EXCLUDED.client_name,
         client_email = EXCLUDED.client_email,
         agency_email = EXCLUDED.agency_email,
         updated_at = NOW()
       RETURNING *`,
      [
        cleanDomain,
        platform,
        api_key,
        client_name || null,
        client_email || null,
        agency_email || 'hello@seoeliteagency.com',
      ]
    );

    res.json({
      success: true,
      site: {
        id: result.rows[0].id,
        domain: result.rows[0].domain,
        platform: result.rows[0].platform,
        api_key: result.rows[0].api_key,
        client_name: result.rows[0].client_name,
        created_at: result.rows[0].created_at,
      },
      message: `Site registered. Add this API key to your WordPress/Shopify plugin: ${result.rows[0].api_key}`,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Failed to register site' });
  }
});

// GET /api/sites/me — get current site info
router.get('/me', authenticateSite, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT 
         s.id, s.domain, s.platform, s.client_name, s.plan, s.created_at,
         COUNT(e.id) as total_events,
         COUNT(CASE WHEN e.blocked = true THEN 1 END) as total_blocked,
         COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as events_24h,
         COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as blocked_24h,
         MAX(e.created_at) as last_event_at
       FROM sites s
       LEFT JOIN events e ON e.site_id = s.id
       WHERE s.id = $1
       GROUP BY s.id`,
      [req.site.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Site info error:', err);
    res.status(500).json({ error: 'Failed to fetch site info' });
  }
});

// GET /api/sites/all — list all sites (admin only)
router.get('/all', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT 
         s.id, s.domain, s.platform, s.client_name, s.client_email, 
         s.active, s.created_at, s.api_key, s.plan,
         COUNT(e.id) as total_events,
         COUNT(CASE WHEN e.blocked = true THEN 1 END) as total_blocked,
         COUNT(CASE WHEN e.blocked = true AND e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as blocked_24h,
         COUNT(CASE WHEN e.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as events_24h,
         MAX(e.created_at) as last_event_at
       FROM sites s
       LEFT JOIN events e ON e.site_id = s.id
       WHERE s.active = true
       GROUP BY s.id
       ORDER BY total_blocked DESC`
    );

    res.json({ sites: result.rows, total: result.rows.length });
  } catch (err) {
    console.error('Sites list error:', err);
    res.status(500).json({ error: 'Failed to fetch sites' });
  }
});

module.exports = router;
