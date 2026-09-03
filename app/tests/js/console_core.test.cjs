/*
 * console_core.test.cjs — Node unit tests for the shared console logic.
 *
 * No browser, no dependencies: uses the built-in node:test + node:assert so
 * the rendering / state-machine helpers can be verified in CI without a
 * headless browser stack. Mirrors the same file the browser loads
 * (app/console/console-core.js).
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const Core = require("../../console/console-core.js");

const XSS = '<img src=x onerror=alert(1)>"><script>alert(2)</script>';

test("escapeHtml neutralizes every HTML-significant character", () => {
  const out = Core.escapeHtml(XSS);
  assert.ok(!out.includes("<"), "no raw < left");
  assert.ok(!out.includes(">"), "no raw > left");
  assert.ok(out.includes("&lt;"));
  assert.ok(out.includes("&gt;"));
  assert.ok(out.includes("&quot;"));
  // XSS has no single quote; verify quote escaping separately.
  assert.ok(Core.escapeHtml("a'b").includes("&#39;"));
});

test("escapeHtml handles null/undefined/numbers", () => {
  assert.strictEqual(Core.escapeHtml(null), "");
  assert.strictEqual(Core.escapeHtml(undefined), "");
  assert.strictEqual(Core.escapeHtml(73), "73");
  assert.strictEqual(Core.escapeHtml("a & b"), "a &amp; b");
});

test("legalTransitions mirrors the backend state machine", () => {
  assert.deepStrictEqual(
    Core.legalTransitions("open").sort(),
    ["acknowledged", "escalated", "false_positive", "investigating"].sort()
  );
  assert.deepStrictEqual(Core.legalTransitions("investigating").sort(), [
    "acknowledged",
    "escalated",
    "false_positive",
    "resolved",
  ]);
  // Terminal states allow nothing.
  assert.deepStrictEqual(Core.legalTransitions("resolved"), []);
  assert.deepStrictEqual(Core.legalTransitions("false_positive"), []);
  // Unknown status yields no transitions (UI shows no buttons).
  assert.deepStrictEqual(Core.legalTransitions("nope"), []);
});

test("isTerminal matches the terminal states", () => {
  assert.strictEqual(Core.isTerminal("resolved"), true);
  assert.strictEqual(Core.isTerminal("false_positive"), true);
  assert.strictEqual(Core.isTerminal("open"), false);
  assert.strictEqual(Core.isTerminal("escalated"), false);
});

test("groupIncidentsByStatus creates every board column", () => {
  const groups = Core.groupIncidentsByStatus([
    { status: "open" },
    { status: "open" },
    { status: "resolved" },
    { status: "weird_unknown_status" },
  ]);
  // All six board columns are always present (empty or not).
  assert.ok(Core.INCIDENT_BOARD_COLUMNS.every((c) => c in groups));
  assert.strictEqual(groups.open.length, 2);
  assert.strictEqual(groups.resolved.length, 1);
  // Unknown statuses still land in their own bucket.
  assert.strictEqual(groups.weird_unknown_status.length, 1);
});

test("buildScoreFactors projects server factors without recomputation", () => {
  const risk = {
    score: 73,
    tier: "high",
    factors: [
      { name: "rule severity", points: 40, max: 40, detail: "level 12" },
      { name: "MITRE groups", points: 11, max: 15, detail: "" },
      { name: "IOC evidence", points: 12, max: 15, detail: "vt hit" },
    ],
  };
  const factors = Core.buildScoreFactors(risk);
  assert.strictEqual(factors.length, 3);
  assert.strictEqual(factors[0].name, "rule severity");
  assert.strictEqual(factors[0].points, 40);
  assert.strictEqual(factors[0].max, 40);
  assert.strictEqual(factors[0].pct, 100);
  assert.strictEqual(factors[1].pct, Math.round((11 / 15) * 100));
  assert.strictEqual(factors[0].detail, "level 12");
  // No score is recomputed client-side — server numbers pass through.
  assert.strictEqual(Core.totalScore(risk).score, 73);
});

test("buildScoreFactors tolerates missing risk", () => {
  assert.deepStrictEqual(Core.buildScoreFactors(null), []);
  assert.deepStrictEqual(Core.buildScoreFactors({}), []);
});

test("buildQueryString drops empty params and preserves real ones", () => {
  const qs = Core.buildQueryString({
    limit: 50,
    offset: 0,
    tier: "high",
    severity: "",
    source: null,
    duplicate: "true",
  });
  assert.strictEqual(qs, "?limit=50&offset=0&tier=high&duplicate=true");
  assert.strictEqual(Core.buildQueryString({}), "");
});

test("parsePagination provides sane defaults and reads real values", () => {
  const def = Core.parsePagination(null);
  assert.deepStrictEqual(def, { limit: 50, offset: 0, total: 0, has_more: false });
  const real = Core.parsePagination({ limit: 10, offset: 20, total: 100, has_more: true });
  assert.strictEqual(real.limit, 10);
  assert.strictEqual(real.total, 100);
  assert.strictEqual(real.has_more, true);
});

test("hasNextPage / hasPrevPage reflect pagination", () => {
  const p = { limit: 10, offset: 0, total: 100, has_more: true };
  assert.strictEqual(Core.hasNextPage(p), true);
  assert.strictEqual(Core.hasPrevPage(p), false);
  const last = { limit: 10, offset: 90, total: 100, has_more: false };
  assert.strictEqual(Core.hasNextPage(last), false);
  assert.strictEqual(Core.hasPrevPage(last), true);
});

test("formatDateTime renders UTC and tolerates bad input", () => {
  assert.strictEqual(Core.formatDateTime(null), "");
  const out = Core.formatDateTime("2026-09-03T12:00:00+00:00");
  assert.strictEqual(out, "2026-09-03 12:00:00 UTC");
  assert.strictEqual(Core.formatDateTime("not-a-date"), "not-a-date");
});

test("formatErrorMessage extracts a concise message from structured errors", () => {
  assert.strictEqual(
    Core.formatErrorMessage({ status: 409, data: { error: { message: "illegal transition" } } }),
    "illegal transition"
  );
  assert.strictEqual(
    Core.formatErrorMessage({ status: 422, data: { error: { code: "validation_error" } } }),
    "validation_error"
  );
  assert.strictEqual(Core.formatErrorMessage({ status: 500 }), "HTTP 500");
  assert.strictEqual(Core.formatErrorMessage(null), "Unknown error");
});

test("severity / risk / status classes are deterministic and css-safe", () => {
  assert.strictEqual(Core.severityClass("SEV1"), "sev sev-1");
  assert.strictEqual(Core.severityClass("SEV2"), "sev sev-2");
  assert.strictEqual(Core.riskTierClass("critical"), "tier tier-critical");
  assert.strictEqual(Core.statusClass("false_positive"), "status-false-positive");
  assert.strictEqual(Core.statusClass("acknowledged"), "status-acknowledged");
});
