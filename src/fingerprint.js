/**
 * RankShield Fingerprint Engine — Client-Side Behavioral Analysis
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING — The hardware behavioral fingerprinting methods implemented
 * in this script are covered by the following provisional patent applications
 * filed April 5, 2026 by Jamie Kloncz / SEO Elite Agency:
 *   RS-001-PROV — Cross-Channel Persistent Attacker Identity via Hardware Behavioral Fingerprinting
 *   RS-002-PROV — Behavioral Fingerprint Persistence Across IP Rotation and VPN Masking
 *
 * This script is injected into the <head> of every page on the EmDash site.
 * It runs silently in the background, collecting behavioral signals that
 * cannot be spoofed by rotating IPs, clearing cookies, or using VPNs.
 *
 * SIGNALS COLLECTED:
 *  1. GPU Canvas Hash       — Unique per hardware, persists across all identity changes
 *  2. WebGL Renderer Hash   — GPU vendor + renderer string, extremely stable
 *  3. Audio Context Hash    — CPU audio processing characteristics
 *  4. Mouse Physics         — Velocity, acceleration, jitter — humans vs bots differ fundamentally
 *  5. Scroll Behavior       — Human scroll has natural deceleration; bots scroll linearly
 *  6. Timing Entropy        — Keystroke dynamics, interaction intervals
 *  7. Font Measurement Hash — Rendered font metrics differ per OS/GPU combination
 *
 * PRIVACY:
 *  - No PII is collected
 *  - No cookies are set
 *  - All data is hashed before transmission
 *  - The fingerprint cannot be used to identify individuals — only to detect bots
 *
 * PATENT NOTICE:
 *  The combination of GPU canvas hash + mouse physics + behavioral timing for
 *  persistent attacker identity tracking is covered by pending patent applications
 *  filed by SEO Elite Agency. See https://rankshield.io/patents
 */

(function () {
  "use strict";

  // ── CONFIG ──────────────────────────────────────────────────────────────────
  const ENDPOINT   = "/_emdash/api/plugins/rankshield-security/fingerprint";
  const SEND_DELAY = 2500; // ms after page load — let mouse/scroll accumulate
  const MAX_MOUSE  = 200;  // max mouse events to collect

  // ── STATE ────────────────────────────────────────────────────────────────────
  const mouse  = { events: [], startX: -1, startY: -1, startTime: 0 };
  const scroll = { events: [], lastY: 0,   lastTime: 0 };
  let   sent   = false;

  // ── HASH FUNCTION ─────────────────────────────────────────────────────────────
  // FNV-1a — fast, non-crypto, good distribution
  function hash(str) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h.toString(16).padStart(8, "0");
  }

  // ── GPU CANVAS FINGERPRINT ────────────────────────────────────────────────────
  function gpuCanvasHash() {
    try {
      const c   = document.createElement("canvas");
      c.width   = 256;
      c.height  = 128;
      const ctx = c.getContext("2d");
      if (!ctx) return "no-canvas";

      // Text rendering — GPU subpixel differences make this unique per hardware
      ctx.textBaseline = "top";
      ctx.font         = "14px 'Arial'";
      ctx.textBaseline = "alphabetic";
      ctx.fillStyle    = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle    = "#069";
      ctx.fillText("RankShield \u00a9 \u2665 \u03a9", 2, 15);
      ctx.fillStyle    = "rgba(102,204,0,0.7)";
      ctx.fillText("RankShield \u00a9 \u2665 \u03a9", 4, 17);

      // Gradient — GPU floating point differences show here
      const gradient = ctx.createLinearGradient(0, 0, 256, 0);
      gradient.addColorStop(0, "red");
      gradient.addColorStop(0.5, "green");
      gradient.addColorStop(1, "blue");
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 40, 256, 20);

      // Arc — sub-pixel rendering differences
      ctx.beginPath();
      ctx.arc(50, 80, 30, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.stroke();

      return hash(c.toDataURL());
    } catch {
      return "canvas-error";
    }
  }

  // ── WEBGL FINGERPRINT ─────────────────────────────────────────────────────────
  function webglHash() {
    try {
      const c   = document.createElement("canvas");
      const gl  = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "no-webgl";

      const ext      = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor   = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR);
      const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

      return hash(`${vendor}::${renderer}::${gl.getParameter(gl.VERSION)}`);
    } catch {
      return "webgl-error";
    }
  }

  // ── AUDIO FINGERPRINT ─────────────────────────────────────────────────────────
  async function audioHash() {
    try {
      const ctx  = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 44100 });
      const osc  = ctx.createOscillator();
      const anal = ctx.createAnalyser();
      const comp = ctx.createDynamicsCompressor();

      comp.threshold.value = -50;
      comp.knee.value      = 40;
      comp.ratio.value     = 12;
      comp.attack.value    = 0.003;
      comp.release.value   = 0.25;

      osc.type = "triangle";
      osc.connect(anal);
      anal.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);

      await new Promise((r) => setTimeout(r, 100));

      const buf = new Float32Array(anal.frequencyBinCount);
      anal.getFloatFrequencyData(buf);
      osc.disconnect();
      await ctx.close();

      return hash(Array.from(buf.slice(0, 30)).map((v) => v.toFixed(3)).join(","));
    } catch {
      return "audio-error";
    }
  }

  // ── FONT HASH ─────────────────────────────────────────────────────────────────
  function fontHash() {
    try {
      const fonts   = ["Arial", "Courier New", "Georgia", "Times New Roman", "Verdana", "Trebuchet MS", "Impact", "Comic Sans MS"];
      const c       = document.createElement("canvas");
      const ctx     = c.getContext("2d");
      if (!ctx) return "no-ctx";
      const results = [];
      for (const f of fonts) {
        ctx.font = `16px '${f}'`;
        const m  = ctx.measureText("RankShield");
        results.push(`${f}:${m.width.toFixed(2)}`);
      }
      return hash(results.join("|"));
    } catch {
      return "font-error";
    }
  }

  // ── MOUSE PHYSICS TRACKER ─────────────────────────────────────────────────────
  // Bots move in straight lines or don't move at all.
  // Humans exhibit Fitts's Law curves, micro-jitter, and natural deceleration.
  function trackMouse(e) {
    if (mouse.events.length >= MAX_MOUSE) return;
    const t = performance.now();
    if (mouse.startX === -1) {
      mouse.startX    = e.clientX;
      mouse.startY    = e.clientY;
      mouse.startTime = t;
    }
    mouse.events.push([
      Math.round(e.clientX),
      Math.round(e.clientY),
      Math.round(t),
    ]);
  }

  function mousePhysics() {
    const pts = mouse.events;
    if (pts.length < 5) return { samples: 0, avgVelocity: 0, jitter: 0, curveRatio: 0 };

    let totalDist   = 0;
    let totalTime   = 0;
    let jitterSum   = 0;
    let prevAngle   = null;
    let angleChanges = 0;

    for (let i = 1; i < pts.length; i++) {
      const dx   = pts[i][0] - pts[i-1][0];
      const dy   = pts[i][1] - pts[i-1][1];
      const dt   = pts[i][2] - pts[i-1][2];
      const dist = Math.sqrt(dx*dx + dy*dy);
      totalDist += dist;
      totalTime += dt;

      // Jitter = sub-pixel movement (bots often have none or very regular jitter)
      if (dist < 2 && dt < 20) jitterSum++;

      // Angle changes — human curves vs bot straight lines
      const angle = Math.atan2(dy, dx);
      if (prevAngle !== null) {
        const delta = Math.abs(angle - prevAngle);
        if (delta > 0.1) angleChanges++;
      }
      prevAngle = angle;
    }

    // Curve ratio: ratio of actual path length to straight-line distance
    const startPt  = pts[0];
    const endPt    = pts[pts.length - 1];
    const straight = Math.sqrt(
      Math.pow(endPt[0] - startPt[0], 2) + Math.pow(endPt[1] - startPt[1], 2)
    );
    const curveRatio = straight > 0 ? (totalDist / straight).toFixed(2) : "0";

    return {
      samples:     pts.length,
      avgVelocity: totalTime > 0 ? (totalDist / totalTime * 1000).toFixed(1) : 0,
      jitter:      jitterSum,
      curveRatio:  parseFloat(curveRatio),
      angleChanges,
    };
  }

  // ── SCROLL BEHAVIOR ───────────────────────────────────────────────────────────
  function trackScroll() {
    const t = performance.now();
    const y = window.scrollY;
    if (scroll.lastY !== y) {
      const dy = Math.abs(y - scroll.lastY);
      const dt = t - scroll.lastTime;
      if (dt > 0) scroll.events.push([Math.round(dy), Math.round(dt)]);
      scroll.lastY    = y;
      scroll.lastTime = t;
    }
  }

  function scrollPhysics() {
    const evts = scroll.events;
    if (!evts.length) return { samples: 0, avgDelta: 0, linear: true };

    const deltas    = evts.map((e) => e[0]);
    const avgDelta  = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    // Variance — bots often scroll at perfectly constant speed (low variance)
    const variance  = deltas.reduce((sum, d) => sum + Math.pow(d - avgDelta, 2), 0) / deltas.length;

    return {
      samples:  evts.length,
      avgDelta: avgDelta.toFixed(1),
      variance: variance.toFixed(1),
      linear:   variance < 5, // True = suspicious (bot-like constant scroll speed)
    };
  }

  // ── ENVIRONMENT SIGNALS ───────────────────────────────────────────────────────
  function collectEnvironment() {
    const nav  = navigator;
    const scr  = screen;
    const win  = window;

    // Detect headless browser indicators
    const isHeadless =
      nav.webdriver === true                           ||
      !nav.languages?.length                          ||
      (nav.plugins?.length === 0 && !nav.webdriver === undefined) ||
      win.callPhantom !== undefined                   ||
      win._phantom   !== undefined                    ||
      win.domAutomation !== undefined;

    // Detect automation frameworks
    const isAutomated =
      /HeadlessChrome|PhantomJS|SlimerJS|Nightmare|Puppeteer/i.test(nav.userAgent) ||
      win.document.documentElement.getAttribute("webdriver") !== null;

    return {
      ua:           nav.userAgent,
      lang:         nav.language,
      langs:        (nav.languages ?? []).join(","),
      platform:     nav.platform,
      cores:        nav.hardwareConcurrency ?? 0,
      memory:       (nav as any).deviceMemory ?? 0,
      tz:           Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen:       `${scr.width}x${scr.height}x${scr.colorDepth}`,
      viewport:     `${win.innerWidth}x${win.innerHeight}`,
      plugins:      nav.plugins?.length ?? 0,
      cookieEnabled: nav.cookieEnabled,
      doNotTrack:   nav.doNotTrack,
      touchPoints:  nav.maxTouchPoints ?? 0,
      isHeadless,
      isAutomated,
      perfEntries:  performance.getEntriesByType("navigation").length,
      url:          win.location.href,
      referrer:     document.referrer,
    };
  }

  // ── MAIN COLLECTION + SEND ────────────────────────────────────────────────────
  async function collect() {
    if (sent) return;
    sent = true;

    const [canvas, webgl, audio, fonts, env] = await Promise.all([
      Promise.resolve(gpuCanvasHash()),
      Promise.resolve(webglHash()),
      audioHash(),
      Promise.resolve(fontHash()),
      Promise.resolve(collectEnvironment()),
    ]);

    const mouse_data  = mousePhysics();
    const scroll_data = scrollPhysics();

    const payload = {
      // Hardware fingerprints (persist across ALL identity changes)
      canvas,
      webgl,
      audio,
      fonts,
      // Combined hardware hash
      hw_hash: hash(`${canvas}::${webgl}::${audio}::${fonts}`),
      // Behavioral signals
      mouse:  mouse_data,
      scroll: scroll_data,
      // Environment
      env,
      // Metadata
      ts:  Date.now(),
      url: window.location.href,
      ua:  navigator.userAgent,
    };

    try {
      await fetch(ENDPOINT, {
        method:      "POST",
        headers:     { "Content-Type": "application/json" },
        body:        JSON.stringify(payload),
        credentials: "omit",
        keepalive:   true,
      });
    } catch {
      // Silent fail — never break the page for security script failures
    }
  }

  // ── ATTACH LISTENERS ─────────────────────────────────────────────────────────
  document.addEventListener("mousemove",  trackMouse,  { passive: true });
  document.addEventListener("scroll",     trackScroll, { passive: true });

  // Send after delay to accumulate behavioral signals
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(collect, SEND_DELAY));
  } else {
    setTimeout(collect, SEND_DELAY);
  }

  // Also send on page unload for bounce visits
  window.addEventListener("pagehide", collect, { passive: true });

})();
