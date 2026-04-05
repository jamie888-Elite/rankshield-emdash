# Changelog

All notable changes to RankShield for EmDash will be documented here.

---

## [1.0.0] — 2026-04-05

### First release — the first security plugin for EmDash CMS

#### Added
- GPU canvas rendering hash extraction for hardware-level attacker fingerprinting
- WebGL renderer parameter signature for persistent GPU identity tracking
- Audio context oscillator response hash for CPU-level device identification
- Mouse physics analysis engine — curve ratio, jitter coefficient, Fitts's Law detection
- Scroll behavior entropy analysis for bot vs human classification
- Headless browser detection — WebDriver, PhantomJS, Puppeteer, and Chrome headless indicators
- Server-side request interception via `request:receive` hook — blocks known attackers before page loads
- NavBoost signal pollution detection via `content:afterSave` hook
- KV cache layer — 5-minute decision cache per IP, zero redundant API calls
- Three-mode protection system — monitor, protect, paranoid
- Configurable block threshold (0–100)
- Public fingerprint API route — receives behavioral signals from visitor browsers
- Admin stats route with 5-minute cache
- Full Block Kit admin dashboard — zero plugin JavaScript in browser
- Security Overview page — live threat status, blocked counts, 30-day trend chart, recent attack feed
- Threat Intelligence page — full attacker profile database with confidence scores
- Settings page — live configuration, no redeploy required
- Security Status dashboard widget (half width)
- Attack Volume 30-day trend chart widget (full width)
- Alert banners — green/amber/red based on attack intensity
- Plugin install hook — API key validation and state initialization
- Plugin uninstall hook — clean state removal
- Sandboxed execution support — runs in isolated Cloudflare Dynamic Worker
- Trusted mode support — runs in-process on Node.js
- EmDash marketplace compatible — standard plugin format
- `network:fetch` only capability — minimum possible permission surface
- Single allowed host — `sea-shield-production.up.railway.app`
- MIT license

#### Patent Notice
Methods described in this release are covered by provisional patent applications
RS-001-PROV, RS-002-PROV, and RS-007-PROV filed April 5, 2026 by Jamie Kloncz / SEO Elite Agency.

---

## Roadmap

### [1.1.0] — Planned
- Google Ads click fraud defense integration
- PMax campaign audience exclusion signal injection
- LSA lead fraud scoring before 30-second billing threshold
- Webhook alerts for Slack, Discord, and custom endpoints

### [1.2.0] — Planned
- Federated threat network — cross-site attacker profile sharing
- Competitor attack attribution reports
- GBP monitoring for LSA account sabotage detection
- Meta and TikTok audience network fraud defense

### [2.0.0] — Planned
- Native plugin format with React admin components
- Real-time threat map visualization
- Automated Google Ads API exclusion list management
- AI-powered attack prediction engine
