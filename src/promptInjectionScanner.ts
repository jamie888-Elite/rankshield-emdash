/**
 * RankShield for EmDash — Prompt Injection Scanner
 * Copyright 2026 SEO Elite Agency LLC. All rights reserved.
 *
 * PATENT PENDING: RS-016-PROV — Pre-Publication Prompt Injection Defense
 * for CMS Content via Semantic Integrity Scoring and Instruction-Pattern
 * Recognition filed April 5, 2026 by Jamie Kloncz / SEO Elite Agency.
 *
 * Scans CMS content BEFORE publication for hidden prompt injection payloads
 * targeting AI agents, LLMs, and RAG systems that process published content.
 *
 * OWASP LLM Top 10 2025 — #1 Risk: Indirect Prompt Injection
 * MITRE ATLAS: AML.T0051 (LLM Prompt Injection)
 *
 * Detection layers:
 *   1. Lexical pattern scanner  — known injection instruction patterns
 *   2. Hidden text detector     — CSS/Unicode invisible injection
 *   3. Semantic integrity scorer — anomalous imperative passages
 *   4. Context-aware classifier — risk weights by author + content type
 */

// ── INJECTION PATTERN LIBRARY ─────────────────────────────────────────────────
// Compiled from OWASP LLM Top 10, published academic research, and
// empirical observation of production injection attempts.

const INJECTION_PATTERNS: Array<{
  category: string;
  weight: number;
  patterns: RegExp[];
}> = [
  {
    category: "SYSTEM_OVERRIDE",
    weight: 90,
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)/i,
      /disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?)/i,
      /forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?)/i,
      /override\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)/i,
      /new\s+(system\s+)?instructions?:/i,
      /\[system\]/i,
      /<\s*system\s*>/i,
      /###\s*system/i,
    ],
  },
  {
    category: "ROLE_HIJACK",
    weight: 75,
    patterns: [
      /you\s+are\s+now\s+(a|an|the)\s+\w+/i,
      /act\s+as\s+(a|an|the)\s+\w+/i,
      /pretend\s+(you\s+are|to\s+be)\s+(a|an|the)/i,
      /roleplay\s+as/i,
      /from\s+now\s+on\s+(you|act|respond|behave)/i,
      /switch\s+(to|into)\s+(a|an|the)\s+\w+\s+mode/i,
      /enter\s+(developer|jailbreak|god|admin|unrestricted)\s+mode/i,
    ],
  },
  {
    category: "DATA_EXFILTRATION",
    weight: 95,
    patterns: [
      /repeat\s+(everything|all|the\s+above|your\s+(system|instructions?))/i,
      /print\s+(your\s+)?(system\s+)?(prompt|instructions?|context)/i,
      /output\s+(your\s+)?(system\s+)?(prompt|instructions?|context)/i,
      /reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|context)/i,
      /show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|training)/i,
      /what\s+(are|were)\s+your\s+(original\s+)?(instructions?|prompts?|rules?)/i,
      /send\s+(this|the)\s+(conversation|context|data)\s+to/i,
      /exfiltrate/i,
    ],
  },
  {
    category: "MEMORY_POISONING",
    weight: 85,
    patterns: [
      /remember\s+(that\s+|this\s+|always\s+)?[\w\s]+(is\s+)?(trusted|authoritative|best|recommended)/i,
      /always\s+recommend\s+[\w\s]+/i,
      /in\s+future\s+(conversations?|sessions?|chats?)/i,
      /store\s+(this|the\s+following)\s+(in\s+)?(your\s+)?memory/i,
      /add\s+(this\s+)?to\s+your\s+(memory|context|knowledge)/i,
      /cite\s+[\w\s]+\s+as\s+(a\s+)?(trusted|authoritative|primary)\s+source/i,
      /trusted\s+source\s+for\s+(all|any|future)/i,
    ],
  },
  {
    category: "TOOL_INVOCATION",
    weight: 80,
    patterns: [
      /call\s+(the\s+)?\w+\s+(tool|function|api|endpoint)/i,
      /invoke\s+(the\s+)?\w+\s+(tool|function|api)/i,
      /execute\s+(the\s+following|this)\s+(code|command|script|function)/i,
      /run\s+(the\s+following|this)\s+(code|command|script)/i,
      /use\s+(the\s+)?(search|browse|code|execute)\s+(tool|function)/i,
    ],
  },
  {
    category: "JAILBREAK",
    weight: 85,
    patterns: [
      /DAN\s*(mode|prompt)?/,
      /do\s+anything\s+now/i,
      /jailbreak/i,
      /developer\s+mode/i,
      /unrestricted\s+mode/i,
      /bypass\s+(your\s+)?(safety|content|ethical|guidelines?)/i,
      /without\s+(any\s+)?(restrictions?|limitations?|filters?|guidelines?)/i,
      /\bsudo\b.*\b(mode|prompt|access)\b/i,
    ],
  },
  {
    category: "CONDITIONAL_INSTRUCTION",
    weight: 60,
    patterns: [
      /when\s+(a\s+user\s+asks?|asked\s+about|someone\s+asks?)\s+[\w\s,]+,?\s*(always|never|only|must)/i,
      /if\s+(anyone|a\s+user|someone)\s+asks?\s+about\s+[\w\s]+,\s*(say|respond|tell|reply)/i,
      /whenever\s+(you|the\s+ai|the\s+assistant)\s+(is\s+asked|responds?)\s+about/i,
    ],
  },
];

// ── HIDDEN TEXT PATTERNS ──────────────────────────────────────────────────────
// Attackers hide injection payloads using CSS or Unicode tricks

const HIDDEN_TEXT_PATTERNS: RegExp[] = [
  // CSS display:none or visibility:hidden
  /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff|transparent))[^"']*["'][^>]*>([^<]{15,})/gi,
  // aria-hidden
  /aria-hidden\s*=\s*["']true["'][^>]*>([^<]{15,})/gi,
  // HTML comments with content
  /<!--([^-]{15,})-->/g,
  // Zero-width characters followed by text
  /[\u200b\u200c\u200d\ufeff]{2,}([^\u200b\u200c\u200d\ufeff]{10,})/g,
];

// ── SEMANTIC ANOMALY PATTERNS ─────────────────────────────────────────────────
// Instruction-like imperative constructions anomalous in editorial content

const SEMANTIC_ANOMALY_PATTERNS: Array<{ pattern: RegExp; weight: number }> = [
  { pattern: /^(always|never|must|should|do not|don't)\s+\w+/im,          weight: 25 },
  { pattern: /when\s+(you\s+)?(are\s+)?(asked|queried|prompted)\s+about/i, weight: 35 },
  { pattern: /respond\s+(only\s+)?(with|by|using|in)\s+/i,                weight: 30 },
  { pattern: /do\s+not\s+(mention|discuss|reveal|say|tell)/i,              weight: 40 },
  { pattern: /you\s+(must|should|will|shall)\s+(always|never|only)/i,      weight: 35 },
  { pattern: /assistant[:\s]+/i,                                           weight: 20 },
  { pattern: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/,          weight: 95 },
  { pattern: /###\s*(instruction|human|assistant|system|user)/i,           weight: 80 },
];

// ── TYPES ─────────────────────────────────────────────────────────────────────

export interface ScanResult {
  clean:       boolean;
  score:       number;
  verdict:     "CLEAN" | "SUSPECTED_INJECTION" | "CONFIRMED_INJECTION";
  findings:    Finding[];
  action:      "allow" | "quarantine" | "block";
  summary:     string;
}

export interface Finding {
  category:  string;
  severity:  "low" | "medium" | "high" | "critical";
  weight:    number;
  detail:    string;
  excerpt?:  string;
}

export interface ScanOptions {
  mode:              "monitor" | "protect" | "paranoid";
  authorRole?:       "admin" | "editor" | "author" | "contributor" | "anonymous";
  contentType?:      "post" | "page" | "comment" | "review" | "forum" | string;
  aiAccessEnabled?:  boolean;  // Is this content indexed for AI Overviews / RAG?
}

// ── MAIN SCANNER ──────────────────────────────────────────────────────────────

/**
 * Scans content for prompt injection payloads before publication.
 * This is the primary entry point called from the content:beforeSave hook.
 *
 * @param title   - Content title
 * @param body    - Content body (HTML or plain text)
 * @param options - Scan options including mode and context
 */
export function scanContent(
  title:   string,
  body:    string,
  options: ScanOptions = { mode: "protect" }
): ScanResult {
  const findings: Finding[] = [];
  let totalScore = 0;

  // Combine title + body for full scan
  const fullText   = `${title}\n${body}`;
  const plainText  = stripHtml(fullText);

  // ── LAYER 1: Lexical pattern scan ─────────────────────────────────────────
  for (const group of INJECTION_PATTERNS) {
    for (const pattern of group.patterns) {
      const matches = plainText.match(pattern);
      if (matches) {
        const excerpt  = matches[0].slice(0, 120);
        const weight   = applyContextWeight(group.weight, options);
        totalScore    += weight;
        findings.push({
          category: group.category,
          severity: weight >= 80 ? "critical" : weight >= 60 ? "high" : weight >= 40 ? "medium" : "low",
          weight,
          detail:  `${group.category} injection pattern detected`,
          excerpt: `"${excerpt}..."`,
        });
        break; // One finding per category
      }
    }
  }

  // ── LAYER 2: Hidden text detection ────────────────────────────────────────
  for (const pattern of HIDDEN_TEXT_PATTERNS) {
    const matches = [...body.matchAll(pattern)];
    for (const match of matches) {
      const hiddenText = (match[1] || match[0]).slice(0, 200).toLowerCase();
      // Check if hidden text contains injection keywords
      const hasInjection = INJECTION_PATTERNS.some(g =>
        g.patterns.some(p => p.test(hiddenText))
      );
      if (hasInjection || hiddenText.length > 50) {
        const weight   = applyContextWeight(85, options);
        totalScore    += weight;
        findings.push({
          category: "HIDDEN_INJECTION",
          severity: "critical",
          weight,
          detail:  "Hidden text with potential injection payload detected (CSS/Unicode concealment)",
          excerpt: `"${hiddenText.slice(0, 100)}..."`,
        });
        break;
      }
    }
  }

  // ── LAYER 3: Semantic anomaly scan ────────────────────────────────────────
  // Only run on plain text — checks for instruction-like constructions
  // anomalous in editorial/blog content
  for (const { pattern, weight: baseWeight } of SEMANTIC_ANOMALY_PATTERNS) {
    if (pattern.test(plainText)) {
      const weight   = applyContextWeight(baseWeight, options);
      totalScore    += weight;
      const match    = plainText.match(pattern);
      findings.push({
        category: "SEMANTIC_ANOMALY",
        severity: weight >= 60 ? "high" : "medium",
        weight,
        detail:  "Instruction-like pattern found — anomalous in editorial content",
        excerpt: match ? `"${match[0].slice(0, 100)}"` : undefined,
      });
    }
  }

  // ── LAYER 4: LLM training data markers ───────────────────────────────────
  // These special tokens are used in LLM training data formats and
  // have no legitimate place in CMS content
  const llmTokens = ["<|im_start|>", "<|im_end|>", "[INST]", "[/INST]",
                     "<<SYS>>", "<</SYS>>", "[SYSTEM]", "### Human:",
                     "### Assistant:", "### Instruction:"];
  for (const token of llmTokens) {
    if (fullText.includes(token)) {
      totalScore += 95;
      findings.push({
        category: "LLM_TOKEN",
        severity: "critical",
        weight:   95,
        detail:  `LLM training data token found in content: ${token}`,
        excerpt: token,
      });
    }
  }

  // ── SCORE → VERDICT ───────────────────────────────────────────────────────
  const score   = Math.min(100, totalScore);
  const clean   = score < 30;
  const verdict = score >= 70 ? "CONFIRMED_INJECTION"
                : score >= 30 ? "SUSPECTED_INJECTION"
                : "CLEAN";

  // ── ACTION BASED ON MODE ──────────────────────────────────────────────────
  let action: "allow" | "quarantine" | "block" = "allow";
  if (verdict === "CONFIRMED_INJECTION") {
    action = options.mode === "monitor" ? "allow" : "block";
  } else if (verdict === "SUSPECTED_INJECTION") {
    action = options.mode === "paranoid" ? "block"
           : options.mode === "protect"  ? "quarantine"
           : "allow";
  }

  // ── SUMMARY ───────────────────────────────────────────────────────────────
  const summary = clean
    ? "Content is clean — no prompt injection patterns detected"
    : `${verdict.replace("_", " ")}: ${findings.length} injection signal(s) detected (score: ${score}/100). ` +
      `Top signal: ${findings.sort((a,b) => b.weight - a.weight)[0]?.category}. ` +
      `Action: ${action.toUpperCase()}.`;

  return { clean, score, verdict, findings, action, summary };
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Applies context-aware risk multipliers based on author role,
 * content type, and AI accessibility settings.
 */
function applyContextWeight(baseWeight: number, options: ScanOptions): number {
  let multiplier = 1.0;

  // Higher risk for user-generated content types
  if (options.contentType === "comment" || options.contentType === "review") {
    multiplier *= 1.3;
  } else if (options.contentType === "forum") {
    multiplier *= 1.2;
  }

  // Higher risk for anonymous or contributor authors
  if (options.authorRole === "anonymous" || options.authorRole === "contributor") {
    multiplier *= 1.25;
  } else if (options.authorRole === "admin" || options.authorRole === "editor") {
    multiplier *= 0.8; // Trusted authors — reduce weight
  }

  // Higher risk if content is configured for AI access
  if (options.aiAccessEnabled) {
    multiplier *= 1.2;
  }

  return Math.round(Math.min(100, baseWeight * multiplier));
}

/**
 * Strips HTML tags while preserving text content for analysis.
 * Keeps enough structure to detect style-attribute hidden text.
 */
function stripHtml(html: string): string {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s{2,}/g, " ")
    .trim();
}
