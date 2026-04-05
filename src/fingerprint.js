/**
 * RankShield Fingerprint Engine — Client-Side Behavioral Analysis
 *
 * Injected into every page. Collects hardware-level signals that
 * cannot be spoofed by IP rotation, VPNs, or cookie clearing.
 *
 * Signals: GPU canvas hash, WebGL renderer, audio context,
 * mouse physics, scroll behavior, font metrics, environment.
 */

(function () {
  "use strict";

  const ENDPOINT   = "/_emdash/api/plugins/rankshield-security/fingerprint";
  const SEND_DELAY = 2500;
  const MAX_MOUSE  = 200;

  const mouse  = { events: [], startX: -1, startY: -1, startTime: 0 };
  const scroll = { events: [], lastY: 0, lastTime: 0 };
  let   sent   = false;

  // FNV-1a hash — fast, good distribution
  function hash(str) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h.toString(16).padStart(8, "0");
  }

  // GPU Canvas — unique per graphics hardware, persists across ALL identity changes
  function gpuCanvasHash() {
    try {
      const c   = document.createElement("canvas");
      c.width   = 256;
      c.height  = 128;
      const ctx = c.getContext("2d");
      if (!ctx) return "no-canvas";

      ctx.textBaseline = "alphabetic";
      ctx.font         = "14px 'Arial'";
      ctx.fillStyle    = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle    = "#069";
      ctx.fillText("RankShield \u00a9 \u2665 \u03a9", 2, 15);
      ctx.fillStyle    = "rgba(102,204,0,0.7)";
      ctx.fillText("RankShield \u00a9 \u2665 \u03a9", 4, 17);

      const gradient = ctx.createLinearGradient(0, 0, 256, 0);
      gradient.addColorStop(0,   "red");
      gradient.addColorStop(0.5, "green");
      gradient.addColorStop(1,   "blue");
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 40, 256, 20);

      ctx.beginPath();
      ctx.arc(50, 80, 30, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.stroke();

      return hash(c.toDataURL());
    } catch {
      return "canvas-error";
    }
  }

  // WebGL — GPU vendor + renderer string
  function webglHash() {
    try {
      const c  = document.createElement("canvas");
      const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "no-webgl";

      const ext      = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor   = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR);
      const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

      return hash(`${vendor}::${renderer}::${gl.getParameter(gl.VERSION)}`);
    } catch {
      return "webgl-error";
    }
  }

  // Audio — CPU audio processing characteristics
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

  // Font metrics — rendered font dimensions differ per OS/GPU
  function fontHash() {
    try {
      const fonts   = ["Arial", "Courier New", "Georgia", "Times New Roman", "Verdana", "Trebuchet MS", "Impact"];
      const c       = document.createElement("canvas");
      const ctx     = c.getContext("2d");
      if (!ctx) return "no-ctx";
      const results = [];
      for (const f of fonts) {
        ctx.font = `16px '${f}'`;
        results.push(`${f}:${ctx.measureText("RankShield").width.toFixed(2)}`);
      }
      return hash(results.join("|"));
    } catch {
      return "font-error";
    }
  }

  // Mouse physics — humans curve, bots move in straight lines
  function trackMouse(e) {
    if (mouse.events.length >= MAX_MOUSE) return;
    const t = performance.now();
    if (mouse.startX === -1) {
      mouse.startX    = e.clientX;
      mouse.startY    = e.clientY;
      mouse.startTime = t;
    }
    mouse.events.push([Math.round(e.clientX), Math.round(e.clientY), Math.round(t)]);
  }

  function mousePhysics() {
    const pts = mouse.events;
    if (pts.length < 5) return { samples: 0, avgVelocity: 0, jitter: 0, curveRatio: 0 };

    let totalDist    = 0;
    let totalTime    = 0;
    let jitterSum    = 0;
    let prevAngle    = null;
    let angleChanges = 0;

    for (let i = 1; i < pts.length; i++) {
      const dx   = pts[i][0] - pts[i-1][0];
      const dy   = pts[i][1] - pts[i-1][1];
      const dt   = pts[i][2] - pts[i-1][2];
      const dist = Math.sqrt(dx*dx + dy*dy);
      totalDist += dist;
      totalTime += dt;

      if (dist < 2 && dt < 20) jitterSum++;

      const angle = Math.atan2(dy, dx);
      if (prevAngle !== null && Math.abs(angle - prevAngle) > 0.1) angleChanges++;
      prevAngle = angle;
    }

    const startPt  = pts[0];
    const endPt    = pts[pts.length - 1];
    const straight = Math.sqrt(
      Math.pow(endPt[0] - startPt[0], 2) + Math.pow(endPt[1] - startPt[1], 2)
    );

    return {
      samples:      pts.length,
      avgVelocity:  totalTime > 0 ? (totalDist / totalTime * 1000).toFixed(1) : 0,
      jitter:       jitterSum,
      curveRatio:   straight > 0 ? parseFloat((totalDist / straight).toFixed(2)) : 0,
      angleChanges,
    };
  }

  // Scroll behavior — bots scroll at constant speed, humans decelerate
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
    if (!evts.length) return { samples: 0, avgDelta: 0, variance: 0, linear: true };
    const deltas   = evts.map((e) => e[0]);
    const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    const variance = deltas.reduce((sum, d) => sum + Math.pow(d - avgDelta, 2), 0) / deltas.length;
    return {
      samples:  evts.length,
      avgDelta: avgDelta.toFixed(1),
      variance: variance.toFixed(1),
      linear:   variance < 5,
    };
  }

  // Environment — headless/automation detection
  function collectEnvironment() {
    const nav = navigator;
    const isHeadless =
      nav.webdriver === true ||
      !nav.languages?.length ||
      window.callPhantom !== undefined ||
      window._phantom   !== undefined;

    const isAutomated =
      /HeadlessChrome|PhantomJS|Puppeteer/i.test(nav.userAgent) ||
      document.documentElement.getAttribute("webdriver") !== null;

    return {
      ua:           nav.userAgent,
      lang:         nav.language,
      langs:        (nav.languages ?? []).join(","),
      platform:     nav.platform,
      cores:        nav.hardwareConcurrency ?? 0,
      memory:       nav.deviceMemory ?? 0,
      tz:           Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen:       `${screen.width}x${screen.height}x${screen.colorDepth}`,
      viewport:     `${window.innerWidth}x${window.innerHeight}`,
      plugins:      nav.plugins?.length ?? 0,
      touchPoints:  nav.maxTouchPoints ?? 0,
      isHeadless,
      isAutomated,
      url:          window.location.href,
      referrer:     document.referrer,
    };
  }

  // Collect everything and send
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

    const payload = {
      canvas,
      webgl,
      audio,
      fonts,
      hw_hash: hash(`${canvas}::${webgl}::${audio}::${fonts}`),
      mouse:   mousePhysics(),
      scroll:  scrollPhysics(),
      env,
      ts:      Date.now(),
      url:     window.location.href,
      ua:      navigator.userAgent,
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
      // Silent fail — never break the page
    }
  }

  document.addEventListener("mousemove",  trackMouse,  { passive: true });
  document.addEventListener("scroll",     trackScroll, { passive: true });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(collect, SEND_DELAY));
  } else {
    setTimeout(collect, SEND_DELAY);
  }

  window.addEventListener("pagehide", collect, { passive: true });

})();
