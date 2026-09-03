/*
 * console-core.js — pure, dependency-free helpers for the SOC console.
 *
 * This file deliberately contains NO DOM access and NO secrets. It is the
 * shared logic layer for the browser app (console.js) and is mirrored 1:1 by
 * the Node unit tests (app/tests/js/console_core.test.cjs) so the rendering /
 * state-machine helpers can be verified without a browser stack.
 *
 * The incident status machine below is a *read-only copy* of the backend's
 * VALID_TRANSITIONS table (soc_triage/models/incident.py). The UI uses it
 * only to decide which transition buttons to show; the backend remains the
 * single source of truth and still rejects anything illegal with a 409.
 */
(function (global, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    global.ConsoleCore = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // --- Incident lifecycle state machine (mirror of backend) -----------------
  // Terminal states (resolved, false_positive) have no outgoing transitions.
  var VALID_TRANSITIONS = {
    open: ["investigating", "acknowledged", "false_positive", "escalated"],
    investigating: ["acknowledged", "resolved", "escalated", "false_positive"],
    acknowledged: ["investigating", "resolved", "escalated"],
    escalated: ["investigating", "acknowledged", "resolved", "false_positive"],
    resolved: [],
    false_positive: [],
  };

  // Board columns, in the order the analyst reads an incident board.
  var INCIDENT_BOARD_COLUMNS = [
    "open",
    "investigating",
    "acknowledged",
    "escalated",
    "resolved",
    "false_positive",
  ];

  function legalTransitions(current) {
    var list = VALID_TRANSITIONS[current];
    return list ? list.slice() : [];
  }

  function isTerminal(status) {
    var list = VALID_TRANSITIONS[status];
    return list !== undefined && list.length === 0;
  }

  // --- Safe HTML escaping ----------------------------------------------------
  // Every value that originates from an alert/incident/timeline (i.e. attacker-
  // or analyst-influenced text) must pass through this before it can be placed
  // into the DOM. The browser app prefers textContent / createElement, but any
  // string interpolation uses escapeHtml as a defense-in-depth guarantee.
  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // --- Severity / risk / status visual classes ------------------------------
  function severityClass(sev) {
    if (sev === "SEV1") return "sev sev-1";
    if (sev === "SEV2") return "sev sev-2";
    return "sev sev-other";
  }

  function riskTierClass(tier) {
    if (tier === "critical") return "tier tier-critical";
    if (tier === "high") return "tier tier-high";
    if (tier === "medium") return "tier tier-medium";
    if (tier === "low") return "tier tier-low";
    return "tier tier-unknown";
  }

  function statusClass(status) {
    return "status-" + String(status || "unknown").replace(/[ _]/g, "-");
  }

  // --- Score factor projection ----------------------------------------------
  // Turn the server-provided risk object into render rows. The server is the
  // source of the numbers; we never recompute a score in the browser.
  function buildScoreFactors(risk) {
    if (!risk || !Array.isArray(risk.factors)) {
      return [];
    }
    return risk.factors.map(function (factor) {
      var points = Number(factor.points) || 0;
      var max = Number(factor.max) || 0;
      var pct = max > 0 ? Math.round((points / max) * 100) : 0;
      return {
        name: factor.name,
        points: points,
        max: max,
        pct: pct,
        detail: factor.detail || "",
      };
    });
  }

  function totalScore(risk) {
    if (!risk) return null;
    return { score: Number(risk.score) || 0, tier: risk.tier || "unknown" };
  }

  // --- Incident board grouping ----------------------------------------------
  function groupIncidentsByStatus(incidents) {
    var groups = {};
    INCIDENT_BOARD_COLUMNS.forEach(function (col) {
      groups[col] = [];
    });
    (incidents || []).forEach(function (inc) {
      var key = inc.status;
      if (!groups[key]) groups[key] = [];
      groups[key].push(inc);
    });
    return groups;
  }

  // --- Query-string builder (preserves only meaningful params) --------------
  function buildQueryString(params) {
    var usp = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      var value = params[key];
      if (value === null || value === undefined || value === "") return;
      usp.set(key, String(value));
    });
    var s = usp.toString();
    return s ? "?" + s : "";
  }

  // --- Pagination helper -----------------------------------------------------
  function parsePagination(pagination) {
    if (!pagination) {
      return { limit: 50, offset: 0, total: 0, has_more: false };
    }
    return {
      limit: Number(pagination.limit) || 50,
      offset: Number(pagination.offset) || 0,
      total: Number(pagination.total) || 0,
      has_more: Boolean(pagination.has_more),
    };
  }

  function hasNextPage(pagination) {
    var p = parsePagination(pagination);
    return p.offset + p.limit < p.total;
  }

  function hasPrevPage(pagination) {
    return parsePagination(pagination).offset > 0;
  }

  // --- Timestamp formatting --------------------------------------------------
  function formatDateTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return (
      d.toISOString().slice(0, 19).replace("T", " ") + " UTC"
    );
  }

  // --- Error message extraction ---------------------------------------------
  // Pull a concise, analyst-friendly message out of a structured error
  // response without leaking raw server internals.
  function formatErrorMessage(result) {
    if (!result) return "Unknown error";
    if (result.data && result.data.error) {
      var err = result.data.error;
      if (err.message) return err.message;
      if (err.code) return err.code;
    }
    if (typeof result.status === "number") {
      return "HTTP " + result.status;
    }
    return "Request failed";
  }

  return {
    VALID_TRANSITIONS: VALID_TRANSITIONS,
    INCIDENT_BOARD_COLUMNS: INCIDENT_BOARD_COLUMNS,
    legalTransitions: legalTransitions,
    isTerminal: isTerminal,
    escapeHtml: escapeHtml,
    severityClass: severityClass,
    riskTierClass: riskTierClass,
    statusClass: statusClass,
    buildScoreFactors: buildScoreFactors,
    totalScore: totalScore,
    groupIncidentsByStatus: groupIncidentsByStatus,
    buildQueryString: buildQueryString,
    parsePagination: parsePagination,
    hasNextPage: hasNextPage,
    hasPrevPage: hasPrevPage,
    formatDateTime: formatDateTime,
    formatErrorMessage: formatErrorMessage,
  };
});
