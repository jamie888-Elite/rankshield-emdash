/**
 * RankShield API — Sea Shield Production Server
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — The methods and systems implemented in this software
 * are covered by the following provisional patent applications filed
 * April 5, 2026 by Jamie Kloncz / SEO Elite Agency:
 *   RS-001-PROV — Cross-Channel Persistent Attacker Identity via Hardware Behavioral Fingerprinting
 *   RS-002-PROV — Behavioral Fingerprint Persistence Across IP Rotation and VPN Masking
 *   RS-004-PROV — Real-Time LSA Lead Fraud Scoring Before Automatic Billing Threshold Activation
 *   RS-005-PROV — Server-Side Behavioral Scoring Middleware for Performance Max Campaign Defense
 *   RS-006-PROV — Probabilistic Competitor Attack Attribution via Temporal Correlation
 *   RS-007-PROV — Sandboxed CMS Plugin Architecture for Real-Time Black Hat Defense
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-master-key'],
}));
app.use(express.json({ limit: '10kb' }));

// Rate limiting — simple in-memory (upgrade to Redis later)
const requestCounts = new Map();
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  const key = `${ip}:${Math.floor(Date.now() / 60000)}`; // per minute bucket
  const count = (requestCounts.get(key) || 0) + 1;
  requestCounts.set(key, count);

  // Clean old entries every 1000 requests
  if (requestCounts.size > 1000) {
    const now = Math.floor(Date.now() / 60000);
    for (const [k] of requestCounts) {
      if (parseInt(k.split(':')[1]) < now - 2) requestCounts.delete(k);
    }
  }

  if (count > 300) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  next();
});

// Routes
app.use('/api/event',     require('../routes/events'));
app.use('/api/sites',     require('../routes/sites'));
app.use('/api/rules',     require('../routes/rules'));
app.use('/api/dashboard', require('../routes/dashboard'));
app.use('/api/plugin',    require('../routes/plugin'));

// Health check — Railway uses this to verify the app is running
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SEA Shield API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Root
app.get('/', (req, res) => {
  res.json({
    service: 'SEA Shield API',
    version: '1.0.0',
    by: 'SEO Elite Agency',
    endpoints: [
      'POST /api/event',
      'GET  /api/event/recent',
      'POST /api/sites/register',
      'GET  /api/sites/me',
      'GET  /api/sites/all',
      'GET  /api/rules',
      'POST /api/rules',
      'GET  /api/dashboard',
      'POST /api/plugin/check',
      'POST /api/plugin/fingerprint',
      'GET  /health',
    ],
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`SEA Shield API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
