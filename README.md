# RankShield for EmDash

**The first and only security plugin built for EmDash CMS.**

Protect your site from black-hat SEO attacks, bot traffic, NavBoost manipulation, and CTR fraud using behavioral fingerprinting — not IP blocking.

[![EmDash Compatible](https://img.shields.io/badge/EmDash-v0.1.0%2B-orange)](https://github.com/emdash-cms/emdash)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Powered by RankShield](https://img.shields.io/badge/Powered%20by-RankShield-E86853)](https://rankshield.seoeliteagency.com)

---

## Why RankShield?

Every other security plugin blocks IPs. **IP blocking is broken.**

Modern bots rotate through residential proxies and VPNs. Block one IP, the attacker has 50,000 more. RankShield fingerprints the **attacker**, not the IP.

We extract a hardware-level identity that persists across every IP rotation:

- **GPU Canvas Hash** — Unique per graphics processor. Cannot be spoofed without physical hardware replacement.
- **WebGL Renderer Signature** — GPU vendor + renderer parameters. Stable across every proxy change.
- **Audio Context Fingerprint** — CPU audio processing characteristics. Hardware-specific.
- **Mouse Physics Analysis** — Bots move differently than humans. Velocity curves, jitter, and Fitts's Law patterns identify automated tools in milliseconds.

Once fingerprinted, an attacker **cannot escape** by:
- Rotating to a new IP ✗
- Using a VPN or Tor ✗
- Clearing cookies or cache ✗
- Switching headless browser instances ✗
- Using residential proxy networks ✗

---

## Installation

### 1. Get your API key
Sign up at [rankshield.seoeliteagency.com](https://rankshield.seoeliteagency.com) and get your free API key.

### 2. Install the plugin
```bash
npm install @rankshield/emdash-security
```

### 3. Add to your EmDash config
```typescript
// astro.config.mjs
import { defineConfig } from "astro/config";
import emdash from "emdash/astro";
import { d1 } from "emdash/db";
import { rankShield } from "@rankshield/emdash-security";

export default defineConfig({
  integrations: [
    emdash({
      database: d1(),
      plugins: [
        rankShield({
          apiKey: import.meta.env.RANKSHIELD_API_KEY,
          mode: "protect",
          showBadge: true,
        }),
      ],
    }),
  ],
});
```

### 4. Set your environment variable
```bash
RANKSHIELD_API_KEY=your_api_key_here
```

### 5. Deploy
```bash
npm run deploy
```

That's it. RankShield starts protecting your site immediately.

---

## Configuration

```typescript
rankShield({
  apiKey:         "your_api_key",       // Required
  mode:           "protect",            // "monitor" | "protect" | "paranoid"
  blockThreshold: 75,                   // 0–100, lower = more aggressive
  showBadge:      true,                 // Show security badge on site
  alertWebhook:   "https://hooks.slack.com/...", // Optional
})
```

| Mode | Behavior |
|---|---|
| `monitor` | Log threats only — never block |
| `protect` | Block confirmed threats (recommended) |
| `paranoid` | Block all suspicious signals immediately |

---

## Sandboxed Deployment (Cloudflare)

```typescript
emdash({
  database:  d1(),
  sandboxed: [
    rankShield({ apiKey: import.meta.env.RANKSHIELD_API_KEY }),
  ],
})
```

In sandboxed mode the plugin runs in a completely isolated V8 isolate with zero access to your database, content, or other plugins. It can only reach `sea-shield-production.up.railway.app` — nothing else.

---

## Admin Dashboard

Find RankShield in your EmDash admin sidebar under **Security**.

- **Overview** — live threat status, blocked counts, 30-day trend chart, recent attack feed
- **Threat Intelligence** — full attacker profile database with confidence scores and attack type breakdown
- **Settings** — switch protection mode, adjust threshold, configure webhooks — no redeploy needed

---

## How It Works

```
Visitor Request
      │
      ▼
[RankShield Sandbox — Cloudflare Worker Isolate]
      │
      ├── Check IP against threat database (<50ms)
      │   ├── Known attacker  → BLOCK immediately
      │   └── Unknown         → ALLOW and continue
      │
      ▼
[Page Loads — Fingerprint Script Activates]
      │
      ├── GPU canvas hash    (2ms)
      ├── WebGL renderer     (1ms)
      ├── Audio context      (100ms async)
      ├── Mouse physics      (2.5s window)
      └── POST to /fingerprint endpoint
                │
                ▼
      [RankShield API — Behavioral Analysis]
                │
                ├── score < 50   → ALLOW
                ├── score 50–75  → LOG
                └── score > 75   → BLOCK + evidence record
```

---

## Capabilities

| Capability | Why needed |
|---|---|
| `network:fetch` | Call the RankShield API at `sea-shield-production.up.railway.app` |

**Not requested:** `read:content`, `write:content`, `read:media`, `read:users`, `email:send`

The plugin never touches your content, database, media, or user records.

---

## Pricing

| Plan | Sites | Attacks/mo | Price |
|---|---|---|---|
| Free | 1 | 10,000 | $0 |
| Starter | 3 | 100,000 | $97/mo |
| Agency | 25 | Unlimited | $297/mo |
| Enterprise | Unlimited | Unlimited | $497/mo |

[Start for free at rankshield.seoeliteagency.com →](https://rankshield.seoeliteagency.com)

---

## Patent Notice

The cross-channel persistent attacker identity system described in this plugin is covered by pending patent applications filed by SEO Elite Agency (April 5, 2026):

- **Patent App RS-001-PROV** — Cross-Channel Persistent Attacker Identity via Hardware Behavioral Fingerprinting
- **Patent App RS-002-PROV** — Behavioral Fingerprint Persistence Across IP Rotation and VPN Masking
- **Patent App RS-007-PROV** — Sandboxed CMS Plugin Architecture for Real-Time Black Hat Defense

Commercial use of this software is permitted under the MIT license. Independent implementation of the described methods for commercial purposes may require a license. Contact [hello@seoeliteagency.com](mailto:hello@seoeliteagency.com).

---

## Contributing

Issues and pull requests welcome.

For security disclosures, email [hello@seoeliteagency.com](mailto:hello@seoeliteagency.com).

---

## License

MIT © SEO Elite Agency

---

*RankShield is the first security plugin for EmDash CMS. Built by [SEO Elite Agency](https://seoeliteagency.com) — the team behind the RankShield behavioral threat defense platform.*
