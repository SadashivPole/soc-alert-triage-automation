/*
 * console.js — SOC static console application logic.
 *
 * Design notes (see ARCHITECTURE.md §19 and the console README):
 *  * Plain HTML/CSS/JS, no framework. The only shared logic (escaping, the
 *    status machine mirror, score-factor projection) lives in console-core.js
 *    so it can be unit-tested in Node without a browser.
 *  * The analyst token is entered by the user and kept ONLY in this module's
 *    memory — it is never persisted to browser storage, never hardcoded, and
 *    never embedded in the served files. It is sent as the X-N8N-Token header,
 *    exactly like the existing n8n callback channel.
 *  * Every value that comes from an alert/incident/timeline is rendered with
 *    DOM nodes + textContent (or escapeHtml). No untrusted string is ever
 *    injected via innerHTML.
 *  * The console is read + lifecycle only. GET endpoints never mutate; the
 *    only write is PATCH /incidents/{id}/status using the backend state
 *    machine. The sweeper is never triggered from the UI.
 */
(function () {
  "use strict";

  var Core = window.ConsoleCore;
  var API_BASE = "/api/v1";

  // In-memory session: the token lives here and nowhere else.
  var session = {
    token: "",
    analyst: "soc-console",
  };

  // -------------------------------------------------------------------------
  // Tiny DOM helper (safe by construction: text is always textContent).
  // -------------------------------------------------------------------------
  function el(tag, opts) {
    opts = opts || {};
    var node = document.createElement(tag);
    if (opts.class) node.className = opts.class;
    if (opts.text !== undefined && opts.text !== null) {
      node.textContent = opts.text;
    }
    if (opts.attrs) {
      Object.keys(opts.attrs).forEach(function (k) {
        node.setAttribute(k, String(opts.attrs[k]));
      });
    }
    if (opts.children) {
      opts.children.forEach(function (c) {
        if (c) node.appendChild(c);
      });
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function $(id) {
    return document.getElementById(id);
  }

  // -------------------------------------------------------------------------
  // API client — attaches the analyst token, normalizes errors.
  // -------------------------------------------------------------------------
  function api(method, path, body) {
    var headers = { Accept: "application/json" };
    if (session.token) {
      headers["X-N8N-Token"] = session.token;
    }
    var init = { method: method, headers: headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(API_BASE + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (e) {
            data = null;
          }
        }
        return { status: res.status, ok: res.ok, data: data };
      });
    });
  }

  function setConnection(status, detail) {
    var dot = $("conn-dot");
    var label = $("conn-label");
    if (!dot || !label) return;
    dot.className = "conn-dot conn-" + status;
    label.textContent =
      status === "ok"
        ? "API connected"
        : status === "auth"
          ? "Auth required"
          : status === "error"
            ? "API error"
            : "Idle";
    if (detail) label.title = detail;
  }

  // -------------------------------------------------------------------------
  // Toast / banner messages.
  // -------------------------------------------------------------------------
  function toast(message, kind) {
    var area = $("toast-area");
    if (!area) return;
    var t = el("div", { class: "toast toast-" + (kind || "info"), text: message });
    area.appendChild(t);
    setTimeout(function () {
      t.classList.add("toast-hide");
      setTimeout(function () {
        if (t.parentNode) t.parentNode.removeChild(t);
      }, 400);
    }, 5000);
  }

  // -------------------------------------------------------------------------
  // Router (hash based: no framework, no server config needed).
  // -------------------------------------------------------------------------
  var routes = {
    queue: renderQueue,
    alert: renderAlert,
    incidents: renderIncidents,
    incident: renderIncident,
  };

  function currentRoute() {
    var hash = window.location.hash.replace(/^#/, "") || "queue";
    var parts = hash.split("/");
    return { name: parts[0] || "queue", id: parts[1] || null };
  }

  function navigate(hash) {
    if (window.location.hash === "#" + hash) {
      render();
    } else {
      window.location.hash = hash;
    }
  }

  function setActiveNav(name) {
    ["nav-queue", "nav-incidents"].forEach(function (id) {
      var node = $(id);
      if (!node) return;
      node.classList.toggle("active", id === "nav-" + name);
    });
  }

  function render() {
    var route = currentRoute();
    setActiveNav(route.name === "alert" ? "queue" : route.name);
    if (!session.token && !bootstrapTokenFromPrompt()) {
      // No token yet: show the auth panel but still render the shell.
    }
    var content = $("content");
    clear(content);
    var fn = routes[route.name] || renderQueue;
    fn(content, route);
  }

  // -------------------------------------------------------------------------
  // Auth UX — token entry (memory only).
  // -------------------------------------------------------------------------
  function bootstrapTokenFromPrompt() {
    var input = $("token-input");
    if (input && input.value.trim()) {
      session.token = input.value.trim();
      reflectToken();
      return true;
    }
    return false;
  }

  function reflectToken() {
    var wrap = $("token-wrap");
    var masked = $("token-masked");
    if (!wrap) return;
    if (session.token) {
      wrap.classList.add("has-token");
      if (masked) {
        masked.textContent =
          "••••••••" + session.token.slice(-4);
      }
    } else {
      wrap.classList.remove("has-token");
      if (masked) masked.textContent = "no token";
    }
  }

  function applyToken() {
    var input = $("token-input");
    if (!input) return;
    var value = input.value.trim();
    if (!value) {
      toast("Enter the shared analyst token (N8N callback token).", "warn");
      return;
    }
    session.token = value;
    reflectToken();
    input.value = "";
    toast("Token set for this session (kept in memory only).", "info");
    setConnection("idle");
    render();
  }

  function clearToken() {
    session.token = "";
    reflectToken();
    toast("Token cleared from memory.", "info");
    render();
  }

  // -------------------------------------------------------------------------
  // Shared state for list views (so pagination/filter survive re-renders).
  // -------------------------------------------------------------------------
  var queueState = {
    limit: 50,
    offset: 0,
    filters: { tier: "", severity: "", source: "", duplicate: "" },
    loading: false,
  };
  var incidentState = {
    limit: 50,
    offset: 0,
    filters: { status: "", severity: "" },
    loading: false,
  };

  // =========================================================================
  // VIEW 1 — ALERT QUEUE
  // =========================================================================
  function renderQueue(content) {
    var wrap = el("section", { class: "view" });
    wrap.appendChild(
      el("div", {
        class: "view-head",
        children: [
          el("h2", { text: "Alert Queue" }),
          el("button", {
            class: "btn btn-sm",
            text: "Refresh",
            attrs: { type: "button", onclick: "SOC.refreshQueue()" },
          }),
        ],
      })
    );

    // Filter bar.
    var filterRow = el("div", { class: "filter-row" });
    filterRow.appendChild(
      selectControl("queue-filter-tier", "Tier", [
        ["", "All tiers"],
        ["critical", "Critical"],
        ["high", "High"],
        ["medium", "Medium"],
        ["low", "Low"],
      ], queueState.filters.tier, function (v) {
        queueState.filters.tier = v;
      })
    );
    filterRow.appendChild(
      selectControl("queue-filter-severity", "Decision", [
        ["", "All"],
        ["SEV1", "SEV1"],
        ["SEV2", "SEV2"],
      ], queueState.filters.severity, function (v) {
        queueState.filters.severity = v;
      })
    );
    filterRow.appendChild(
      selectControl("queue-filter-source", "Source", [
        ["", "All sources"],
        ["wazuh", "wazuh"],
      ], queueState.filters.source, function (v) {
        queueState.filters.source = v;
      })
    );
    filterRow.appendChild(
      checkboxControl("queue-filter-dup", "Duplicates only", queueState.filters.duplicate === "true", function (checked) {
        queueState.filters.duplicate = checked ? "true" : "";
      })
    );
    filterRow.appendChild(
      el("button", {
        class: "btn btn-sm",
        text: "Apply",
        attrs: { type: "button", onclick: "SOC.applyQueueFilters()" },
      })
    );
    wrap.appendChild(filterRow);

    var tableHost = el("div", { class: "table-host", attrs: { id: "queue-table-host" } });
    wrap.appendChild(tableHost);
    content.appendChild(wrap);

    loadQueue(tableHost);
  }

  function selectControl(id, label, options, value, onChange) {
    var wrap = el("label", { class: "field" });
    wrap.appendChild(el("span", { class: "field-label", text: label }));
    var sel = el("select", { attrs: { id: id } });
    options.forEach(function (opt) {
      var o = el("option", { text: opt[1], attrs: { value: opt[0] } });
      if (opt[0] === value) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("change", function () {
      onChange(sel.value);
    });
    wrap.appendChild(sel);
    return wrap;
  }

  function checkboxControl(id, label, checked, onChange) {
    var wrap = el("label", { class: "field field-inline" });
    var box = el("input", { attrs: { id: id, type: "checkbox" } });
    box.checked = !!checked;
    box.addEventListener("change", function () {
      onChange(box.checked);
    });
    wrap.appendChild(box);
    wrap.appendChild(el("span", { class: "field-label", text: label }));
    return wrap;
  }

  function applyQueueFilters() {
    queueState.offset = 0;
    SOC.refreshQueue();
  }

  function refreshQueue() {
    var host = $("queue-table-host");
    if (host) loadQueue(host);
  }

  function loadQueue(host) {
    if (!host) return;
    if (!ensureToken(host)) return;
    queueState.loading = true;
    clear(host);
    host.appendChild(el("div", { class: "state state-loading", text: "Loading alerts…" }));

    var params = {
      limit: queueState.limit,
      offset: queueState.offset,
      tier: queueState.filters.tier,
      severity: queueState.filters.severity,
      source: queueState.filters.source,
      duplicate: queueState.filters.duplicate,
    };
    var qs = Core.buildQueryString(params);

    api("GET", "/alerts" + qs)
      .then(function (res) {
        queueState.loading = false;
        clear(host);
        if (res.status === 401) {
          setConnection("auth");
          host.appendChild(
            authNeeded("Alert queue requires the analyst token.")
          );
          return;
        }
        if (!res.ok) {
          setConnection("error");
          host.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        setConnection("ok");
        renderAlertTable(host, res.data);
      })
      .catch(function (err) {
        queueState.loading = false;
        clear(host);
        setConnection("error");
        host.appendChild(errorState("Network error: " + err.message));
      });
  }

  function renderAlertTable(host, data) {
    var items = (data && data.items) || [];
    if (items.length === 0) {
      host.appendChild(
        emptyState("No alerts match the current filters.")
      );
      renderQueuePager(host, data && data.pagination);
      return;
    }

    var table = el("table", { class: "soc-table" });
    var thead = el("thead");
    var headRow = el("tr");
    [
      "alert_id",
      "received_at",
      "source",
      "rule",
      "agent",
      "risk",
      "tier",
      "decision",
      "severity",
      "incident",
      "occ",
    ].forEach(function (h) {
      headRow.appendChild(el("th", { text: h }));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el("tbody");
    items.forEach(function (a) {
      var row = el("tr", {
        attrs: { onclick: "SOC.openAlert('" + a.alert_id + "')" },
      });
      row.appendChild(el("td", { class: "mono", text: shortId(a.alert_id) }));
      row.appendChild(el("td", { class: "nowrap", text: Core.formatDateTime(a.received_at) }));
      row.appendChild(el("td", { text: a.source || "" }));
      row.appendChild(
        el("td", {
          children: [
            el("div", { class: "mono", text: a.rule ? a.rule.id : "" }),
            el("div", { class: "muted small", text: a.rule ? a.rule.description : "" }),
          ],
        })
      );
      row.appendChild(
        el("td", {
          children: [
            el("div", { class: "mono", text: a.agent ? a.agent.id : "" }),
            el("div", { class: "muted small", text: a.agent ? a.agent.name : "" }),
          ],
        })
      );
      var riskCell = el("td", { class: "num" });
      if (a.risk) {
        riskCell.appendChild(el("span", { class: "risk-score", text: String(a.risk.score) }));
      } else {
        riskCell.textContent = "—";
      }
      row.appendChild(riskCell);
      var tierCell = el("td");
      if (a.risk) {
        tierCell.appendChild(
          el("span", { class: Core.riskTierClass(a.risk.tier), text: a.risk.tier })
        );
      } else {
        tierCell.textContent = "—";
      }
      row.appendChild(tierCell);
      var decCell = el("td");
      if (a.decision) {
        decCell.appendChild(el("span", { class: "decision", text: a.decision.action }));
        if (a.decision.severity) {
          decCell.appendChild(
            el("span", { class: " " + Core.severityClass(a.decision.severity), text: " " + a.decision.severity })
          );
        }
      } else {
        decCell.textContent = "—";
      }
      row.appendChild(decCell);
      row.appendChild(
        el("td", {
          children: [
            a.decision && a.decision.severity
              ? el("span", { class: Core.severityClass(a.decision.severity), text: a.decision.severity })
              : el("span", { text: "—" }),
          ],
        })
      );
      var incCell = el("td", { class: "mono" });
      if (a.incident_id) {
        incCell.appendChild(
          el("a", {
            text: a.incident_id,
            attrs: {
              href: "#incident/" + a.incident_id,
              onclick: "SOC.openIncident('" + a.incident_id + "')",
            },
          })
        );
      } else {
        incCell.textContent = "—";
      }
      row.appendChild(incCell);
      var occ = a.dedupe ? a.dedupe.occurrences : 1;
      row.appendChild(el("td", { class: "num", text: String(occ) }));
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    host.appendChild(table);
    renderQueuePager(host, data.pagination);
  }

  function renderQueuePager(host, pagination) {
    var p = Core.parsePagination(pagination);
    var bar = el("div", { class: "pager" });
    bar.appendChild(
      el("span", {
        class: "muted",
        text:
          "Showing " +
          (p.total === 0 ? 0 : p.offset + 1) +
          "–" +
          Math.min(p.offset + p.limit, p.total) +
          " of " +
          p.total,
      })
    );
    var prev = el("button", {
      class: "btn btn-sm",
      text: "← Prev",
      attrs: { type: "button", disabled: !Core.hasPrevPage(pagination) ? "disabled" : null },
    });
    prev.addEventListener("click", function () {
      if (Core.hasPrevPage(pagination)) {
        queueState.offset = Math.max(0, p.offset - p.limit);
        refreshQueue();
      }
    });
    var next = el("button", {
      class: "btn btn-sm",
      text: "Next →",
      attrs: { type: "button", disabled: !Core.hasNextPage(pagination) ? "disabled" : null },
    });
    next.addEventListener("click", function () {
      if (Core.hasNextPage(pagination)) {
        queueState.offset = p.offset + p.limit;
        refreshQueue();
      }
    });
    bar.appendChild(prev);
    bar.appendChild(next);
    host.appendChild(bar);
  }

  // =========================================================================
  // VIEW 2 — ALERT DETAIL / SCORE DRILL-DOWN
  // =========================================================================
  function renderAlert(content, route) {
    var wrap = el("section", { class: "view" });
    wrap.appendChild(
      el("div", {
        class: "view-head",
        children: [
          el("h2", { text: "Alert Detail" }),
          el("button", {
            class: "btn btn-sm",
            text: "← Back to queue",
            attrs: { type: "button", onclick: "SOC.navigate('queue')" },
          }),
        ],
      })
    );
    var host = el("div", { attrs: { id: "alert-detail-host" } });
    wrap.appendChild(host);
    content.appendChild(wrap);
    if (!route.id) {
      host.appendChild(errorState("No alert id in the URL."));
      return;
    }
    if (!ensureToken(host)) return;
    host.appendChild(el("div", { class: "state state-loading", text: "Loading alert…" }));
    api("GET", "/alerts/" + encodeURIComponent(route.id))
      .then(function (res) {
        clear(host);
        if (res.status === 401) {
          setConnection("auth");
          host.appendChild(authNeeded("Alert detail requires the analyst token."));
          return;
        }
        if (res.status === 404) {
          host.appendChild(errorState("Alert not found (404)."));
          return;
        }
        if (!res.ok) {
          setConnection("error");
          host.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        setConnection("ok");
        renderAlertDetail(host, res.data);
      })
      .catch(function (err) {
        clear(host);
        setConnection("error");
        host.appendChild(errorState("Network error: " + err.message));
      });
  }

  function renderAlertDetail(host, a) {
    // Metadata header.
    var head = el("div", { class: "detail-head" });
    head.appendChild(el("div", { class: "mono detail-id", text: a.alert_id }));
    head.appendChild(
      el("div", {
        children: [
          a.incident_id
            ? el("a", {
                class: "pill pill-incident",
                text: "incident " + a.incident_id,
                attrs: { href: "#incident/" + a.incident_id, onclick: "SOC.openIncident('" + a.incident_id + "')" },
              })
            : el("span", { class: "pill pill-muted", text: "no incident" }),
        ],
      })
    );
    host.appendChild(head);

    var grid = el("div", { class: "detail-grid" });

    // --- Identity / source / rule / agent / asset / location ---
    grid.appendChild(
      kvCard("Identity & source", [
        ["source", a.source],
        ["received_at", Core.formatDateTime(a.received_at)],
        ["rule id", a.rule ? a.rule.id : ""],
        ["rule level", a.rule ? String(a.rule.level) : ""],
        ["rule description", a.rule ? a.rule.description : ""],
        ["rule groups", a.rule && a.rule.groups ? a.rule.groups.join(", ") : ""],
        ["agent id", a.agent ? a.agent.id : ""],
        ["agent name", a.agent ? a.agent.name : ""],
        ["agent ip", a.agent && a.agent.ip ? a.agent.ip : ""],
        ["location", a.location || ""],
        ["asset", a.asset ? [a.asset.name, a.asset.tier, a.asset.owner].filter(Boolean).join(" · ") : ""],
        ["enrichment", a.enrichment_status || ""],
      ])
    );

    // --- Risk score + factor breakdown ---
    var riskCard = el("div", { class: "card card-risk" });
    riskCard.appendChild(el("h3", { text: "Risk score & factors" }));
    if (a.risk) {
      var total = Core.totalScore(a.risk);
      var scoreLine = el("div", { class: "score-line" });
      scoreLine.appendChild(
        el("span", { class: "score-big " + Core.riskTierClass(total.tier), text: String(total.score) })
      );
      scoreLine.appendChild(
        el("span", { class: "score-tier " + Core.riskTierClass(total.tier), text: total.tier })
      );
      if (a.risk.degraded) {
        scoreLine.appendChild(el("span", { class: "pill pill-warn", text: "degraded" }));
      }
      riskCard.appendChild(scoreLine);
      if (a.risk.summary) {
        riskCard.appendChild(el("p", { class: "muted", text: a.risk.summary }));
      }
      riskCard.appendChild(el("div", { class: "muted small", text: "engine " + (a.risk.engine_version || "?") }));

      var factors = Core.buildScoreFactors(a.risk);
      if (factors.length) {
        var fl = el("ul", { class: "factor-list" });
        factors.forEach(function (f) {
          var li = el("li", { class: "factor" });
          li.appendChild(
            el("div", {
              class: "factor-row",
              children: [
                el("span", { class: "factor-name", text: f.name }),
                el("span", { class: "factor-pts", text: f.points + " / " + f.max }),
              ],
            })
          );
          var bar = el("div", { class: "factor-bar" });
          bar.appendChild(el("div", { class: "factor-fill", attrs: { style: "width:" + f.pct + "%" } }));
          li.appendChild(bar);
          if (f.detail) {
            li.appendChild(el("div", { class: "factor-detail muted small", text: f.detail }));
          }
          fl.appendChild(li);
        });
        riskCard.appendChild(fl);
      } else {
        riskCard.appendChild(emptyState("No factor breakdown provided."));
      }
    } else {
      riskCard.appendChild(emptyState("No risk assessment for this alert."));
    }
    grid.appendChild(riskCard);

    // --- Decision & reasons ---
    grid.appendChild(
      kvCard("Decision", a.decision ? [
        ["action", a.decision.action],
        ["severity", a.decision.severity || ""],
        ["decided_at", Core.formatDateTime(a.decision.decided_at)],
        ["reasons", a.decision.reasons ? a.decision.reasons.join(" · ") : ""],
        ["runbook", a.decision.runbook || ""],
      ] : [["action", "—"]])
    );

    // --- IOC summary ---
    var iocCard = el("div", { class: "card" });
    iocCard.appendChild(el("h3", { text: "IOC summary (" + (a.iocs ? a.iocs.length : 0) + ")" }));
    if (a.iocs && a.iocs.length) {
      var iocList = el("ul", { class: "ioc-list" });
      a.iocs.forEach(function (ioc) {
        var li = el("li", { class: "ioc" });
        li.appendChild(el("span", { class: "ioc-type", text: ioc.type }));
        li.appendChild(el("span", { class: "ioc-value mono", text: ioc.value }));
        iocList.appendChild(li);
      });
      iocCard.appendChild(iocList);
    } else {
      iocCard.appendChild(emptyState("No IOCs extracted."));
    }
    grid.appendChild(iocCard);

    // --- Dedupe ---
    grid.appendChild(
      kvCard("Deduplication", a.dedupe ? [
        ["group_key", a.dedupe.group_key],
        ["occurrences", String(a.dedupe.occurrences)],
        ["generation", String(a.dedupe.generation)],
        ["duplicate_deliveries", String(a.dedupe.duplicate_deliveries)],
        ["first_seen", Core.formatDateTime(a.dedupe.first_seen)],
        ["last_seen", Core.formatDateTime(a.dedupe.last_seen)],
        ["event_identity", a.dedupe.event_identity || ""],
      ] : [["status", "single event"]])
    );

    host.appendChild(grid);
  }

  // =========================================================================
  // VIEW 3a — INCIDENT BOARD
  // =========================================================================
  function renderIncidents(content) {
    var wrap = el("section", { class: "view" });
    wrap.appendChild(
      el("div", {
        class: "view-head",
        children: [
          el("h2", { text: "Incident Board" }),
          el("button", {
            class: "btn btn-sm",
            text: "Refresh",
            attrs: { type: "button", onclick: "SOC.refreshIncidents()" },
          }),
        ],
      })
    );

    var filterRow = el("div", { class: "filter-row" });
    filterRow.appendChild(
      selectControl("inc-filter-status", "Status", [
        ["", "All statuses"],
        ["open", "Open"],
        ["investigating", "Investigating"],
        ["acknowledged", "Acknowledged"],
        ["escalated", "Escalated"],
        ["resolved", "Resolved"],
        ["false_positive", "False positive"],
      ], incidentState.filters.status, function (v) {
        incidentState.filters.status = v;
      })
    );
    filterRow.appendChild(
      selectControl("inc-filter-severity", "Severity", [
        ["", "All severities"],
        ["SEV1", "SEV1"],
        ["SEV2", "SEV2"],
      ], incidentState.filters.severity, function (v) {
        incidentState.filters.severity = v;
      })
    );
    filterRow.appendChild(
      el("button", {
        class: "btn btn-sm",
        text: "Apply",
        attrs: { type: "button", onclick: "SOC.applyIncidentFilters()" },
      })
    );
    wrap.appendChild(filterRow);

    var host = el("div", { attrs: { id: "incident-board-host" } });
    wrap.appendChild(host);
    content.appendChild(wrap);
    loadIncidentBoard(host);
  }

  function applyIncidentFilters() {
    incidentState.offset = 0;
    SOC.refreshIncidents();
  }

  function refreshIncidents() {
    var host = $("incident-board-host");
    if (host) loadIncidentBoard(host);
  }

  function loadIncidentBoard(host) {
    if (!host) return;
    if (!ensureToken(host)) return;
    clear(host);
    host.appendChild(el("div", { class: "state state-loading", text: "Loading incidents…" }));

    var params = {
      limit: incidentState.limit,
      offset: incidentState.offset,
      status: incidentState.filters.status,
      severity: incidentState.filters.severity,
    };
    var qs = Core.buildQueryString(params);

    api("GET", "/incidents" + qs)
      .then(function (res) {
        clear(host);
        if (res.status === 401) {
          setConnection("auth");
          host.appendChild(authNeeded("Incident board requires the analyst token."));
          return;
        }
        if (!res.ok) {
          setConnection("error");
          host.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        setConnection("ok");
        renderIncidentBoard(host, res.data);
      })
      .catch(function (err) {
        clear(host);
        setConnection("error");
        host.appendChild(errorState("Network error: " + err.message));
      });
  }

  function renderIncidentBoard(host, data) {
    var items = (data && data.items) || [];
    if (items.length === 0 && !(data && data.pagination && data.pagination.total > 0)) {
      // Empty board: still show the column scaffolding so the layout reads
      // like a SOC board, with an empty notice.
    }
    var groups = Core.groupIncidentsByStatus(items);
    var board = el("div", { class: "board" });
    Core.INCIDENT_BOARD_COLUMNS.forEach(function (col) {
      var colEl = el("div", { class: "board-col " + Core.statusClass(col) });
      colEl.appendChild(
        el("div", {
          class: "board-col-head",
          children: [
            el("span", { class: "board-col-title", text: prettyStatus(col) }),
            el("span", { class: "board-col-count", text: String(groups[col].length) }),
          ],
        })
      );
      var list = el("div", { class: "board-col-body" });
      if (groups[col].length === 0) {
        list.appendChild(el("div", { class: "board-empty muted", text: "—" }));
      }
      groups[col].forEach(function (inc) {
        list.appendChild(incidentCard(inc));
      });
      colEl.appendChild(list);
      board.appendChild(colEl);
    });
    host.appendChild(board);

    var p = Core.parsePagination(data && data.pagination);
    var total = (data && data.pagination && data.pagination.total) || items.length;
    host.appendChild(
      el("div", {
        class: "pager",
        children: [
          el("span", { class: "muted", text: "Total incidents: " + total }),
          el("span", {
            class: "muted",
            text:
              incidentState.filters.status || incidentState.filters.severity
                ? "(filtered)"
                : "",
          }),
        ],
      })
    );
  }

  function incidentCard(inc) {
    var card = el("div", {
      class: "inc-card " + Core.statusClass(inc.status),
      attrs: { onclick: "SOC.openIncident('" + inc.incident_id + "')" },
    });
    card.appendChild(
      el("div", {
        class: "inc-card-top",
        children: [
          el("span", { class: "mono inc-id", text: inc.incident_id }),
          el("span", { class: Core.severityClass(inc.severity), text: inc.severity }),
        ],
      })
    );
    card.appendChild(
      el("div", {
        class: "inc-card-meta muted small",
        text:
          "primary " +
          shortId(inc.primary_alert_id) +
          " · " +
          inc.linked_alert_count +
          " alerts",
      })
    );
    card.appendChild(
      el("div", {
        class: "inc-card-times muted small",
        text:
          "created " +
          Core.formatDateTime(inc.created_at) +
          (inc.resolved_at ? " · resolved " + Core.formatDateTime(inc.resolved_at) : ""),
      })
    );
    return card;
  }

  // =========================================================================
  // VIEW 3b — INCIDENT DETAIL
  // =========================================================================
  function renderIncident(content, route) {
    var wrap = el("section", { class: "view" });
    wrap.appendChild(
      el("div", {
        class: "view-head",
        children: [
          el("h2", { text: "Incident Detail" }),
          el("button", {
            class: "btn btn-sm",
            text: "← Back to board",
            attrs: { type: "button", onclick: "SOC.navigate('incidents')" },
          }),
        ],
      })
    );
    var host = el("div", { attrs: { id: "incident-detail-host" } });
    wrap.appendChild(host);
    content.appendChild(wrap);
    if (!route.id) {
      host.appendChild(errorState("No incident id in the URL."));
      return;
    }
    if (!ensureToken(host)) return;
    host.appendChild(el("div", { class: "state state-loading", text: "Loading incident…" }));

    api("GET", "/incidents/" + encodeURIComponent(route.id))
      .then(function (res) {
        clear(host);
        if (res.status === 401) {
          setConnection("auth");
          host.appendChild(authNeeded("Incident detail requires the analyst token."));
          return;
        }
        if (res.status === 404) {
          host.appendChild(errorState("Incident not found (404)."));
          return;
        }
        if (!res.ok) {
          setConnection("error");
          host.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        setConnection("ok");
        renderIncidentDetail(host, res.data, route.id);
      })
      .catch(function (err) {
        clear(host);
        setConnection("error");
        host.appendChild(errorState("Network error: " + err.message));
      });
  }

  function renderIncidentDetail(host, inc, incidentId) {
    var head = el("div", { class: "detail-head" });
    head.appendChild(el("div", { class: "mono detail-id", text: inc.incident_id }));
    head.appendChild(
      el("div", {
        children: [
          el("span", { class: Core.severityClass(inc.severity) + " pill", text: inc.severity }),
          el("span", { class: "pill " + Core.statusClass(inc.status), text: prettyStatus(inc.status) }),
        ],
      })
    );
    host.appendChild(head);

    var grid = el("div", { class: "detail-grid" });
    grid.appendChild(
      kvCard("Lifecycle", [
        ["status", inc.status],
        ["severity", inc.severity],
        ["created_at", Core.formatDateTime(inc.created_at)],
        ["updated_at", Core.formatDateTime(inc.updated_at)],
        ["acknowledged_at", Core.formatDateTime(inc.acknowledged_at)],
        ["resolved_at", Core.formatDateTime(inc.resolved_at)],
        ["dedupe_group", inc.dedupe_group_key],
      ])
    );
    grid.appendChild(
      kvCard("Primary alert", [
        ["primary_alert_id", inc.primary_alert_id],
        ["linked_alert_count", String(inc.linked_alert_count)],
      ])
    );
    host.appendChild(grid);

    // Linked alerts.
    var linkedCard = el("div", { class: "card" });
    linkedCard.appendChild(
      el("h3", { text: "Linked alerts (" + (inc.linked_alerts ? inc.linked_alerts.length : 0) + ")" })
    );
    if (inc.linked_alerts && inc.linked_alerts.length) {
      var tbl = el("table", { class: "soc-table soc-table-sm" });
      var thr = el("tr");
      ["alert", "received", "rule", "agent", "risk", "decision", "primary"].forEach(function (h) {
        thr.appendChild(el("th", { text: h }));
      });
      tbl.appendChild(el("thead", {}, [thr]));
      var tb = el("tbody");
      inc.linked_alerts.forEach(function (la) {
        var tr = el("tr", { attrs: { onclick: "SOC.openAlert('" + la.alert_id + "')" } });
        tr.appendChild(el("td", { class: "mono", text: shortId(la.alert_id) }));
        tr.appendChild(el("td", { class: "nowrap", text: Core.formatDateTime(la.received_at) }));
        tr.appendChild(el("td", { class: "mono", text: la.rule_id }));
        tr.appendChild(el("td", { text: la.agent_name }));
        tr.appendChild(el("td", { class: "num", text: la.risk_score != null ? String(la.risk_score) : "—" }));
        tr.appendChild(el("td", { text: la.decision_action || "—" }));
        tr.appendChild(el("td", { text: la.is_primary ? "★" : "" }));
        tb.appendChild(tr);
      });
      tbl.appendChild(tb);
      linkedCard.appendChild(tbl);
    } else {
      linkedCard.appendChild(emptyState("No linked alerts."));
    }
    host.appendChild(linkedCard);

    // Lifecycle actions (legal transitions only).
    host.appendChild(buildLifecyclePanel(inc, incidentId));

    // Timeline.
    var tlCard = el("div", { class: "card" });
    tlCard.appendChild(el("h3", { text: "Timeline" }));
    var tlHost = el("div", { attrs: { id: "timeline-host" } });
    tlHost.appendChild(el("div", { class: "state state-loading", text: "Loading timeline…" }));
    tlCard.appendChild(tlHost);
    host.appendChild(tlCard);
    loadTimeline(tlHost, incidentId);
  }

  function buildLifecyclePanel(inc, incidentId) {
    var card = el("div", { class: "card card-lifecycle" });
    card.appendChild(el("h3", { text: "Lifecycle actions" }));
    card.appendChild(
      el("p", {
        class: "muted small",
        text:
          "Current status: " +
          prettyStatus(inc.status) +
          (Core.isTerminal(inc.status) ? " (terminal — no further transitions)" : ""),
      })
    );
    var transitions = Core.legalTransitions(inc.status);
    var btnRow = el("div", { class: "lifecycle-actions" });
    if (transitions.length === 0) {
      btnRow.appendChild(el("span", { class: "pill pill-muted", text: "no actions available" }));
    }
    transitions.forEach(function (target) {
      var btn = el("button", {
        class: "btn btn-transition " + Core.statusClass(target),
        text: "→ " + prettyStatus(target),
        attrs: { type: "button", "data-target": target },
      });
      btn.addEventListener("click", function () {
        performTransition(incidentId, target, card);
      });
      btnRow.appendChild(btn);
    });
    card.appendChild(btnRow);
    card.appendChild(el("div", { attrs: { id: "lifecycle-msg" } }));
    return card;
  }

  function performTransition(incidentId, target, card) {
    var msg = $("lifecycle-msg");
    if (msg) clear(msg);
    var body = { status: target, actor: session.analyst };
    api("PATCH", "/incidents/" + encodeURIComponent(incidentId) + "/status", body)
      .then(function (res) {
        if (res.status === 401) {
          setConnection("auth");
          if (msg) msg.appendChild(authNeeded("Transition requires the analyst token."));
          return;
        }
        if (res.status === 409) {
          var allowed = (res.data && res.data.details && res.data.details.allowed_transitions) || [];
          toast(
            "Transition blocked: " + Core.formatErrorMessage(res) +
              (allowed.length ? " (allowed: " + allowed.join(", ") + ")" : ""),
            "error"
          );
          if (msg) {
            msg.appendChild(
              el("div", {
                class: "state state-error",
                text:
                  "Illegal transition. Allowed from " +
                  (res.data && res.data.details ? res.data.details.current_status : "?") +
                  ": " +
                  (allowed.join(", ") || "none"),
              })
            );
          }
          return;
        }
        if (!res.ok) {
          toast("Transition failed: " + Core.formatErrorMessage(res), "error");
          if (msg) msg.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        // Success: refresh incident + timeline to reflect server truth.
        toast("Incident moved to " + prettyStatus(target) + ".", "ok");
        var host = $("incident-detail-host");
        if (host) renderIncident($("content"), { name: "incident", id: incidentId });
      })
      .catch(function (err) {
        toast("Network error during transition: " + err.message, "error");
        if (msg) msg.appendChild(errorState("Network error: " + err.message));
      });
  }

  function loadTimeline(host, incidentId) {
    api("GET", "/incidents/" + encodeURIComponent(incidentId) + "/timeline")
      .then(function (res) {
        clear(host);
        if (res.status === 401) {
          host.appendChild(authNeeded("Timeline requires the analyst token."));
          return;
        }
        if (res.status === 404) {
          host.appendChild(errorState("Timeline not found (404)."));
          return;
        }
        if (!res.ok) {
          host.appendChild(errorState(Core.formatErrorMessage(res)));
          return;
        }
        var events = (res.data && res.data.events) || [];
        if (events.length === 0) {
          host.appendChild(emptyState("No timeline events yet."));
          return;
        }
        var tl = el("ol", { class: "timeline" });
        events.forEach(function (ev) {
          tl.appendChild(timelineEvent(ev));
        });
        host.appendChild(tl);
      })
      .catch(function (err) {
        clear(host);
        host.appendChild(errorState("Network error: " + err.message));
      });
  }

  function timelineEvent(ev) {
    var li = el("li", { class: "tl-event" });
    li.appendChild(
      el("div", {
        class: "tl-time muted small",
        text: Core.formatDateTime(ev.timestamp),
      })
    );
    li.appendChild(el("div", { class: "tl-action", text: ev.action }));
    var meta = el("div", { class: "tl-meta muted small" });
    var bits = [];
    if (ev.actor) bits.push("actor: " + ev.actor);
    if (ev.entity_type) bits.push("entity: " + ev.entity_type + "/" + shortId(ev.entity_id));
    if (ev.metadata && ev.metadata.before_status && ev.metadata.after_status) {
      bits.push("status: " + ev.metadata.before_status + " → " + ev.metadata.after_status);
    } else if (ev.metadata && ev.metadata.after_status) {
      bits.push("status: " + ev.metadata.after_status);
    }
    if (ev.metadata && ev.metadata.verdict) bits.push("verdict: " + ev.metadata.verdict);
    meta.textContent = bits.join(" · ");
    li.appendChild(meta);
    // before/after (safe metadata only — backend redacts secrets).
    if (ev.after || ev.before) {
      var diff = el("div", { class: "tl-diff" });
      if (ev.before) diff.appendChild(kvMini("before", ev.before));
      if (ev.after) diff.appendChild(kvMini("after", ev.after));
      li.appendChild(diff);
    }
    return li;
  }

  function kvMini(label, obj) {
    var wrap = el("div", { class: "kv-mini" });
    wrap.appendChild(el("span", { class: "kv-mini-label", text: label }));
    var json = "";
    try {
      json = JSON.stringify(obj);
    } catch (e) {
      json = String(obj);
    }
    wrap.appendChild(el("span", { class: "kv-mini-val mono", text: json }));
    return wrap;
  }

  // =========================================================================
  // Shared UI building blocks.
  // =========================================================================
  function kvCard(title, pairs) {
    var card = el("div", { class: "card" });
    card.appendChild(el("h3", { text: title }));
    var dl = el("dl", { class: "kv" });
    pairs.forEach(function (pair) {
      var val = pair[1];
      if (val === null || val === undefined || val === "") val = "—";
      dl.appendChild(el("dt", { text: pair[0] }));
      dl.appendChild(el("dd", { text: String(val) }));
    });
    card.appendChild(dl);
    return card;
  }

  function shortId(id) {
    if (!id) return "—";
    var s = String(id);
    return s.length > 12 ? s.slice(0, 8) + "…" + s.slice(-4) : s;
  }

  function prettyStatus(status) {
    if (status === "false_positive") return "False positive";
    return String(status || "").replace(/_/g, " ");
  }

  function emptyState(text) {
    return el("div", { class: "state state-empty", text: text });
  }

  function errorState(text) {
    return el("div", { class: "state state-error", text: text });
  }

  function authNeeded(text) {
    var box = el("div", { class: "state state-auth" });
    box.appendChild(el("p", { text: text }));
    box.appendChild(
      el("p", {
        class: "muted small",
        text: "Enter the shared analyst token (N8N callback token) in the top bar, then refresh.",
      })
    );
    return box;
  }

  function ensureToken(host) {
    if (session.token) return true;
    setConnection("auth");
    clear(host);
    host.appendChild(authNeeded("This view requires the analyst token."));
    return false;
  }

  // -------------------------------------------------------------------------
  // Navigation helpers, exposed for inline onclick handlers.
  // -------------------------------------------------------------------------
  window.SOC = {
    navigate: navigate,
    refreshQueue: refreshQueue,
    applyQueueFilters: applyQueueFilters,
    refreshIncidents: refreshIncidents,
    applyIncidentFilters: applyIncidentFilters,
    openAlert: function (id) {
      navigate("alert/" + id);
    },
    openIncident: function (id) {
      navigate("incident/" + id);
    },
  };

  // -------------------------------------------------------------------------
  // Boot.
  // -------------------------------------------------------------------------
  window.addEventListener("hashchange", render);
  window.addEventListener("DOMContentLoaded", function () {
    // Token bar wiring.
    var applyBtn = $("token-apply");
    if (applyBtn) applyBtn.addEventListener("click", applyToken);
    var clearBtn = $("token-clear");
    if (clearBtn) clearBtn.addEventListener("click", clearToken);
    reflectToken();
    render();
  });
})();
