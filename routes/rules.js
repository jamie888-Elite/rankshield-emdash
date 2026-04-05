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
const { authenticateSite, authenticateAdmin } = require('../middleware/auth');

// GET /api/rules — get all active rules for requesting site's platform
router.get('/', authenticateSite, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT rule_key, rule_type, payload, description, confidence
       FROM rules
       WHERE active = true
         AND (platform = 'all' OR platform = $1)
       ORDER BY confidence DESC`,
      [req.site.platform]
    );

    // Also get confirmed IP prefixes from fingerprints with high confidence
    const prefixes = await db.query(
      `SELECT fingerprint_key, description, confidence, example_ip
       FROM fingerprints
       WHERE fingerprint_type = 'ip_prefix'
         AND confidence >= 80
         AND active = true
       ORDER BY confidence DESC, hit_count DESC
       LIMIT 50`
    );

    res.json({
      rules: result.rows,
      confirmed_prefixes: prefixes.rows,
      generated_at: new Date().toISOString(),
      site: req.site.domain,
    });
  } catch (err) {
    console.error('Rules error:', err);
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

// POST /api/rules — add a new rule (admin only)
router.post('/', authenticateAdmin, async (req, res) => {
  const { rule_key, rule_type, platform = 'all', payload, description, confidence = 80 } = req.body;

  if (!rule_key || !rule_type || !payload) {
    return res.status(400).json({ error: 'rule_key, rule_type, and payload are required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO rules (rule_key, rule_type, platform, payload, description, confidence)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (rule_key) DO UPDATE SET
         rule_type = EXCLUDED.rule_type,
         platform = EXCLUDED.platform,
         payload = EXCLUDED.payload,
         description = EXCLUDED.description,
         confidence = EXCLUDED.confidence,
         updated_at = NOW()
       RETURNING *`,
      [rule_key, rule_type, platform, JSON.stringify(payload), description, confidence]
    );

    res.json({ success: true, rule: result.rows[0] });
  } catch (err) {
    console.error('Add rule error:', err);
    res.status(500).json({ error: 'Failed to add rule' });
  }
});

module.exports = router;
