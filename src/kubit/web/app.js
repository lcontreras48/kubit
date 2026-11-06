(() => {
  "use strict";

  const severity = { supported: 0, unknown: 1, stale: 2, unsupported: 3, incompatible: 4 };
  const attentionStates = new Set(["unsupported", "incompatible"]);
  const sourceOverrideStorageKey = "kubit.inventory-source-overrides.v1";
  const themeStorageKey = "kubit.theme.v1";
  const kubernetesReleaseSource = "https://kubernetes.io/releases/";
  const pageSizes = new Set([25, 50, 100]);
  let report = null;
  let componentRows = [];
  let currentUser = null;
  let csrfToken = "";
  let sourceValidationToken = "";
  let sourceOverrides = loadSourceOverrides();
  let securitySeverityFilter = "all";
  let securityTypeBeforeSeverity = "all";
  const pagination = { inventory: { page: 1, size: 25 }, security: { page: 1, size: 25 } };
  const collapsedApplications = new Set();
  let toastTimer;

  const byId = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
  const normalizeVersion = (value) => String(value || "").replace(/^v/, "");
  const statusGroup = (status) => attentionStates.has(status) ? "attention" : status === "supported" ? "supported" : "unknown";
  const statusLabel = (status) => ({ incompatible: "Incompatible", unsupported: "Unsupported", stale: "Stale evidence", unknown: "Unverified", supported: "Supported" })[status] || "Unverified";

  function paginate(items, kind) {
    const state = pagination[kind];
    const pageCount = Math.max(1, Math.ceil(items.length / state.size));
    state.page = Math.min(Math.max(state.page, 1), pageCount);
    const start = (state.page - 1) * state.size;
    const end = Math.min(start + state.size, items.length);
    byId(`${kind}-page-info`).textContent = items.length ? `${start + 1}–${end} of ${items.length} items · Page ${state.page} of ${pageCount}` : "0 items";
    byId(`${kind}-page-prev`).disabled = state.page <= 1;
    byId(`${kind}-page-next`).disabled = state.page >= pageCount;
    return items.slice(start, end);
  }

  function resetPage(kind) {
    pagination[kind].page = 1;
  }

  function applicationRuntimeState(row) {
    if (!row.metadata?.application_group) return "";
    const health = String(row.metadata.health_status || "").toLowerCase();
    const sync = String(row.metadata.sync_status || "").toLowerCase();
    const podTotal = Number(row.metadata.pod_total || 0);
    const podReady = Number(row.metadata.pod_ready || 0);
    const podsReady = !podTotal || podReady === podTotal;
    if (health === "healthy" && sync === "synced" && podsReady) return "healthy";
    if (["degraded", "missing"].includes(health) || sync === "outofsync" || (podTotal && podReady < podTotal)) return "attention";
    return "unknown";
  }

  function loadTheme() {
    try {
      const stored = localStorage.getItem(themeStorageKey);
      return ["dark", "light"].includes(stored) ? stored : "dark";
    } catch (_error) {
      return "dark";
    }
  }

  function applyTheme(theme, persist = false) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    const next = selected === "dark" ? "light" : "dark";
    const label = byId("theme-label");
    const toggle = byId("theme-toggle");
    label.textContent = next === "light" ? "Light" : "Dark";
    toggle.setAttribute("aria-label", `Switch to ${next} theme`);
    toggle.title = `Switch to ${next} theme`;
    document.querySelector('meta[name="theme-color"]').content = selected === "light" ? "#ffffff" : "#091524";
    if (persist) {
      try {
        localStorage.setItem(themeStorageKey, selected);
      } catch (_error) {
        showToast("The theme preference could not be saved in this browser.");
      }
    }
  }

  function sourceName(value, providerName = "") {
    const knownProviders = {
      "kubernetes-version-skew": "Kubernetes version skew policy",
      "cloudnativepg-supported-releases": "CloudNativePG supported releases",
      "containerd-kubernetes-recommendations": "containerd Kubernetes support",
      "kube-state-metrics-compatibility": "kube-state-metrics compatibility",
      "kube-rbac-proxy-project-status": "kube-rbac-proxy project status",
      "kubernetes-csi-sidecar-support": "Kubernetes CSI sidecar support",
      "ceph-csi-support": "Ceph CSI support matrix",
      "argocd-tested-kubernetes-versions": "Argo CD tested versions",
      "prometheus-operator-kubernetes-requirements": "Prometheus Operator compatibility",
      "talos-kubernetes-releases": "Talos release metadata",
      "metallb-official-helm-chart": "MetalLB official Helm chart",
      "opentelemetry-operator-compatibility": "OpenTelemetry Operator compatibility",
      "clickhouse-operator-kubernetes-requirements": "ClickHouse Operator requirements",
      "mend-renovate-ce-official-chart": "Mend Renovate CE official chart",
      "opentelemetry-collector-official-releases": "OpenTelemetry Collector releases",
      "compatibility-fyi": "compatibility.fyi catalog"
    };
    if (knownProviders[providerName]) return knownProviders[providerName];
    try {
      const url = new URL(value);
      const host = url.hostname.replace(/^www\./, "");
      const knownHosts = {
        "raw.githubusercontent.com": "GitHub upstream source",
        "github.com": "GitHub upstream source",
        "kubernetes.io": "Kubernetes documentation",
        "cloudnative-pg.io": "CloudNativePG documentation",
        "prometheus-operator.dev": "Prometheus Operator documentation"
      };
      return knownHosts[host] || host;
    } catch (_error) {
      return providerName ? providerName.replaceAll("-", " ") : "Source unavailable";
    }
  }

  function sourceLink(value, label, className = "") {
    if (!value) return '<span class="no-evidence">No official source</span>';
    try {
      const url = new URL(value);
      if (url.protocol !== "https:") return '<span class="no-evidence">Source URL unavailable</span>';
      return `<a class="${escapeHtml(className)}" href="${escapeHtml(url.href)}" target="_blank" rel="noreferrer">${escapeHtml(label || sourceName(value))} ↗</a>`;
    } catch (_error) {
      return '<span class="no-evidence">Source URL unavailable</span>';
    }
  }

  function evidenceLink(value) {
    return sourceLink(value, "Official evidence");
  }

  function loadSourceOverrides() {
    try {
      const stored = JSON.parse(localStorage.getItem(sourceOverrideStorageKey) || "{}");
      if (!stored || Array.isArray(stored) || typeof stored !== "object") return {};
      return Object.fromEntries(Object.entries(stored).filter(([, value]) => typeof value === "string" && value.startsWith("https://")));
    } catch (_error) {
      return {};
    }
  }

  function saveSourceOverrides() {
    try {
      localStorage.setItem(sourceOverrideStorageKey, JSON.stringify(sourceOverrides));
      return true;
    } catch (_error) {
      return false;
    }
  }

  function sourceOverrideKey(row) {
    return encodeURIComponent(JSON.stringify([row.name, row.version, row.instance, row.source]));
  }

  function componentNamespace(row) {
    if (row.metadata?.namespace) return row.metadata.namespace;
    const parts = String(row.source || "").split("/");
    return ["pod", "deployment", "daemonset", "statefulset"].includes(parts[0]) && parts[1] ? parts[1] : "—";
  }

  function applicationKey(row) {
    if (row.metadata?.application_id) return row.metadata.application_id;
    return JSON.stringify([row.metadata?.application || "—", row.metadata?.namespace || ""]);
  }

  function sourceCatalog(data) {
    const catalog = new Map([[kubernetesReleaseSource, "Kubernetes releases"]]);
    (data?.providers || []).forEach((provider) => {
      if (provider.source_url) catalog.set(provider.source_url, sourceName(provider.source_url, provider.name));
    });
    (data?.results || []).forEach((result) => {
      if (!result.evidence) return;
      catalog.set(result.evidence, result.evidence_title || sourceName(result.evidence, result.evidence_provider));
    });
    return catalog;
  }

  function sourceEditor(row, evidenceSources) {
    const key = sourceOverrideKey(row);
    const override = sourceOverrides[key] || "";
    const catalog = sourceCatalog(report);
    if (override && !catalog.has(override)) catalog.set(override, sourceName(override));
    const automaticTitle = row.primaryCheck?.evidence
      ? row.primaryCheck.evidence_title || sourceName(row.primaryCheck.evidence, row.primaryCheck.evidence_provider)
      : evidenceSources.size ? [...evidenceSources.values()][0] : "No official source";
    const options = [...catalog.entries()].sort((left, right) => left[1].localeCompare(right[1])).map(([url, title]) =>
      `<option value="${escapeHtml(url)}"${url === override ? " selected" : ""}>${escapeHtml(title)}</option>`
    ).join("");
    const displayedSources = override
      ? sourceLink(override, catalog.get(override), "inventory-source-link")
      : evidenceSources.size
        ? [...evidenceSources].map(([url, title]) => sourceLink(url, title, "inventory-source-link")).join("")
        : '<span class="no-evidence">No official source</span>';
    return `<div class="source-editor">
      <select class="source-truth-select" data-source-key="${escapeHtml(key)}" aria-label="Source of truth for ${escapeHtml(row.name)} ${escapeHtml(row.version)}">
        <option value=""${override ? "" : " selected"}>Automatic — ${escapeHtml(automaticTitle)}</option>
        ${options}
      </select>
      <div class="source-links">${displayedSources}</div>
      ${override ? '<small class="source-override-state">Local override · choose Automatic to reset</small>' : '<small class="source-automatic-state">Selected from live evidence</small>'}
    </div>`;
  }

  function showToast(message) {
    const toast = byId("toast");
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
  }

  function chooseWorst(statuses) {
    return statuses.reduce((worst, current) => (severity[current] ?? 1) > (severity[worst] ?? 1) ? current : worst, "supported");
  }

  function rowsFromReport(data) {
    const results = data.results || [];
    return (data.components || []).map((component) => {
      let matches = results.filter((result) => result.component === component.name && result.version === component.version && (result.instance === component.instance || result.instance === "cluster"));
      if (component.name === "kubernetes" && !matches.length) matches = [{
        component: "kubernetes",
        version: component.version,
        dependency: "compatibility baseline",
        dependency_version: component.version,
        status: "supported",
        reason: "Observed directly from the Kubernetes API and used as the central compatibility baseline.",
        rule: "kubernetes-observed-baseline",
        evidence: kubernetesReleaseSource,
        evidence_provider: "kubernetes-release-baseline",
        evidence_title: "Kubernetes releases",
        instance: component.instance
      }];
      const status = matches.length ? chooseWorst(matches.map((item) => item.status)) : "unknown";
      const primaryCheck = matches.reduce((worst, item) => !worst || (severity[item.status] ?? 1) > (severity[worst.status] ?? 1) ? item : worst, null);
      return { ...component, status, checks: matches, primaryCheck };
    });
  }

  function componentSummary(rows) {
    const grouped = new Map();
    rows.forEach((row) => {
      const current = grouped.get(row.name);
      grouped.set(row.name, current ? chooseWorst([current, row.status]) : row.status);
    });
    return [...grouped.entries()].map(([name, status]) => ({ name, status }));
  }

  function renderSourceComponentOptions(data) {
    const select = byId("source-component");
    const previous = select.value;
    const discovered = new Map();
    (data.components || []).forEach((component) => {
      if (!component.name) return;
      const entry = discovered.get(component.name) || { versions: new Set(), instances: 0 };
      if (component.version) entry.versions.add(component.version);
      entry.instances += 1;
      discovered.set(component.name, entry);
    });
    const choices = [...discovered.entries()].sort(([left], [right]) => left.localeCompare(right));
    select.innerHTML = '<option value="">Select a discovered component</option>' + choices.map(([name, entry]) => {
      const versions = [...entry.versions].sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));
      const versionLabel = versions.length ? ` — ${versions.join(", ")}` : "";
      const instanceLabel = entry.instances > 1 ? ` (${entry.instances} instances)` : "";
      return `<option value="${escapeHtml(name)}">${escapeHtml(name + versionLabel + instanceLabel)}</option>`;
    }).join("");
    select.disabled = choices.length === 0;
    if (discovered.has(previous)) select.value = previous;
    else if (previous) resetSourceValidation();
    byId("verify-source").disabled = choices.length === 0;
  }

  function renderProviderState(data) {
    const badge = byId("live-badge");
    const providers = data.providers || [];
    badge.classList.remove("degraded", "offline");
    if (!data.ready) {
      badge.classList.add("offline");
      badge.querySelector("span").textContent = data.error ? "Scan failed" : "Scanning";
      return;
    }
    const degraded = providers.some((provider) => !["fresh", "cached"].includes(provider.status));
    if (degraded) badge.classList.add("degraded");
    badge.querySelector("span").textContent = degraded ? "Evidence degraded" : "Live";
  }

  function renderOverview(data) {
    renderBaseline(data);
    renderRelationships(data);
    const security = data.security || {};
    const securitySummary = security.summary || {};
    const securityAvailable = Boolean(security.available);
    const eligibleContainers = securitySummary.eligible_containers || 0;
    const coveredContainers = securitySummary.covered_containers || 0;
    byId("overview-security-critical").textContent = securityAvailable ? securitySummary.critical || 0 : "—";
    byId("overview-security-high").textContent = securityAvailable ? securitySummary.high || 0 : "—";
    byId("overview-security-detail").textContent = !securityAvailable
      ? "Trivy reports unavailable · security state is unknown"
      : eligibleContainers
        ? `${coveredContainers} of ${eligibleContainers} containers covered · ${security.status || "unknown"} reports`
        : `${security.status || "unknown"} reports · coverage unavailable`;
    const summary = componentSummary(componentRows.filter((row) => !row.metadata?.application_group));
    const counts = { supported: 0, attention: 0, unknown: 0 };
    summary.forEach(({ status }) => { counts[statusGroup(status)] += 1; });
    const total = summary.length;
    const percent = total ? Math.round((counts.supported / total) * 100) : 0;
    byId("health-percent").textContent = `${percent}%`;
    byId("health-progress").style.width = `${percent}%`;
    byId("health-detail").textContent = `${counts.supported} of ${total} components supported`;
    byId("attention-count").textContent = String(counts.attention).padStart(2, "0");
    byId("attention-label").textContent = counts.attention === 1 ? "1 component requires review" : `${counts.attention} components require review`;
    byId("supported-count").textContent = String(counts.supported).padStart(2, "0");
    byId("unknown-count").textContent = String(counts.unknown).padStart(2, "0");
    byId("component-total").textContent = `${total} component${total === 1 ? "" : "s"}`;
    byId("legend-supported").textContent = counts.supported;
    byId("legend-danger").textContent = counts.attention;
    byId("legend-unknown").textContent = counts.unknown;
    byId("bar-supported").style.width = `${total ? counts.supported / total * 100 : 0}%`;
    byId("bar-danger").style.width = `${total ? counts.attention / total * 100 : 0}%`;
    byId("bar-unknown").style.width = `${total ? counts.unknown / total * 100 : 0}%`;

    const findings = (data.results || []).filter((item) => attentionStates.has(item.status));
    byId("finding-badge").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    byId("findings-list").innerHTML = findings.length ? findings.map(findingMarkup).join("") : '<p class="empty-state">No critical compatibility findings in the latest scan.</p>';
  }

  function renderBaseline(data) {
    const kubernetes = (data.components || []).find((item) => item.name === "kubernetes");
    const providers = data.providers || [];
    const usable = providers.filter((provider) => ["fresh", "cached"].includes(provider.status));
    const fresh = providers.filter((provider) => provider.status === "fresh").length;
    const cached = providers.filter((provider) => provider.status === "cached").length;
    const degraded = providers.length - usable.length;
    byId("baseline-kubernetes").textContent = kubernetes?.version || "Not detected";
    byId("baseline-axis").textContent = kubernetes ? `Kubernetes ${kubernetes.version}` : "Kubernetes not detected";
    byId("baseline-providers").textContent = `${usable.length} of ${providers.length} usable`;
    byId("baseline-provider-detail").textContent = `${fresh} fresh${cached ? `, ${cached} cached` : ""}${degraded ? `, ${degraded} need attention` : ""}`;
    const badge = byId("baseline-status");
    const group = data.ready && !degraded ? "supported" : data.ready ? "attention" : "unknown";
    badge.className = `status-pill ${group}`;
    badge.textContent = data.ready && !degraded ? "Evidence ready" : data.ready ? "Evidence degraded" : "Scanning";
  }

  function relationshipGroups(data) {
    const grouped = new Map();
    (data.results || []).filter((item) => item.rule !== "no-rule" && item.dependency !== "none").forEach((item) => {
      const key = [item.component, item.version, item.dependency, item.dependency_version, item.status, item.reason, item.rule, item.evidence].join("\u0000");
      const current = grouped.get(key);
      if (current) current.instances.add(item.instance);
      else grouped.set(key, { ...item, instances: new Set([item.instance]) });
    });
    const priority = { talos: 0, "kube-apiserver": 1, kubelet: 2, "kube-proxy": 3 };
    return [...grouped.values()].sort((left, right) => {
      const statusDifference = (severity[right.status] ?? 1) - (severity[left.status] ?? 1);
      if (statusDifference) return statusDifference;
      return (priority[left.component] ?? 20) - (priority[right.component] ?? 20) || left.component.localeCompare(right.component);
    });
  }

  function renderRelationships(data) {
    const relationships = relationshipGroups(data);
    byId("relationship-total").textContent = `${relationships.length} relationship${relationships.length === 1 ? "" : "s"}`;
    byId("relationship-list").innerHTML = relationships.length ? relationships.map((item) => {
      const group = statusGroup(item.status);
      const count = item.instances.size;
      return `<div class="relationship ${group}">
        <span class="relationship-mark" aria-hidden="true">${group === "supported" ? "✓" : group === "attention" ? "!" : "?"}</span>
        <div class="relationship-content">
          <div class="relationship-header">
            <div class="relationship-path"><span><small>Deployed</small><strong>${escapeHtml(item.component)} ${escapeHtml(item.version)}</strong></span><b>→</b><span><small>Verified against</small><strong>${escapeHtml(item.dependency)} ${escapeHtml(item.dependency_version)}</strong></span></div>
            <span class="status-pill ${group}">${escapeHtml(statusLabel(item.status))}</span>
          </div>
          <p>${escapeHtml(item.reason)}</p>
          <div class="relationship-meta"><span>${count} instance${count === 1 ? "" : "s"}</span><span>Rule: ${escapeHtml(item.rule)}</span>${evidenceLink(item.evidence)}</div>
        </div>
      </div>`;
    }).join("") : '<p class="empty-state">No verified compatibility relationships are available yet.</p>';
  }

  function findingMarkup(item) {
    const evidence = evidenceLink(item.evidence);
    return `<div class="finding"><span class="finding-mark">!</span><div><strong>${escapeHtml(item.component)} ${escapeHtml(item.version)} requires attention</strong><p>${escapeHtml(item.reason)}</p><div class="finding-meta"><span>${escapeHtml(item.dependency)} ${escapeHtml(item.dependency_version)}</span><span>${escapeHtml(statusLabel(item.status))}</span>${evidence}</div></div></div>`;
  }

  function renderInventory() {
    const query = byId("inventory-search").value.trim().toLowerCase();
    const wanted = byId("inventory-status").value;
    const visible = componentRows.filter((row) => {
      const checkText = row.checks.flatMap((check) => [check.dependency, check.dependency_version, check.reason, check.rule, check.evidence, check.evidence_title, check.evidence_basis, check.evidence_confidence, sourceName(check.evidence)]).join(" ");
      const matchesText = [row.name, row.version, row.instance, row.source, row.metadata?.namespace, row.metadata?.application, row.metadata?.application_role, checkText].join(" ").toLowerCase().includes(query);
      return matchesText && (wanted === "all" || statusGroup(row.status) === wanted);
    }).sort((left, right) => {
      const leftApplication = left.metadata?.application_id || left.metadata?.application || "~";
      const rightApplication = right.metadata?.application_id || right.metadata?.application || "~";
      return leftApplication.localeCompare(rightApplication)
        || Number(Boolean(right.metadata?.application_group)) - Number(Boolean(left.metadata?.application_group))
        || left.name.localeCompare(right.name);
    });
    byId("inventory-total").textContent = `${componentRows.length} instance${componentRows.length === 1 ? "" : "s"}`;
    const groupedApplications = new Set(
      componentRows
        .filter((row) => row.metadata?.application_group)
        .map(applicationKey)
    );
    const inventoryItems = [];
    const itemIndexes = new Map();
    visible.forEach((row) => {
      const key = applicationKey(row);
      const itemKey = groupedApplications.has(key) ? `application:${key}` : `component:${sourceOverrideKey(row)}`;
      if (!itemIndexes.has(itemKey)) {
        itemIndexes.set(itemKey, inventoryItems.length);
        inventoryItems.push([]);
      }
      inventoryItems[itemIndexes.get(itemKey)].push(row);
    });
    const pageRows = paginate(inventoryItems, "inventory").flat();
    const renderedRows = pageRows.filter((row) => {
      const key = applicationKey(row);
      const isChild = !row.metadata?.application_group && groupedApplications.has(key);
      return !(isChild && collapsedApplications.has(key) && !query);
    });
    byId("inventory-body").innerHTML = renderedRows.length ? renderedRows.map((row, index) => {
      const group = statusGroup(row.status);
      const verifiedChecks = row.checks.filter((check) => check.dependency !== "none");
      const dependencies = [...new Set(verifiedChecks.map((check) => `${check.dependency} ${check.dependency_version}`))];
      const verifiedAgainst = dependencies.length ? dependencies.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : '<span class="no-evidence">No verified relationship</span>';
      const reason = row.primaryCheck?.reason || "No compatibility result is available for this component.";
      const namespace = componentNamespace(row);
      const instance = namespace !== "—" && row.instance === namespace ? "—" : row.instance;
      const evidenceSources = new Map();
      row.checks.forEach((check) => {
        if (!check.evidence) return;
        const provider = (report?.providers || []).find((item) => item.name === check.evidence_provider);
        evidenceSources.set(check.evidence, check.evidence_title || sourceName(check.evidence, provider?.name));
      });
      const application = row.metadata?.application || "—";
      const role = row.metadata?.application_role;
      const currentApplicationKey = applicationKey(row);
      const isApplication = Boolean(row.metadata?.application_group);
      const isChild = !isApplication && groupedApplications.has(currentApplicationKey);
      const nextRow = renderedRows[index + 1];
      const nextApplicationKey = nextRow ? applicationKey(nextRow) : "";
      const closesApplicationGroup = (isApplication || isChild) && nextApplicationKey !== currentApplicationKey;
      const runtimeState = isApplication ? applicationRuntimeState(row) : "";
      const relationship = row.metadata?.application_group
        ? `${row.metadata?.version_mode || "unknown"} · ${row.metadata?.member_count || 0} components`
        : role ? `${role} · ${row.metadata?.grouping_evidence || "discovered"}` : "";
      const podTotal = row.metadata?.pod_total || 0;
      const podReady = row.metadata?.pod_ready || 0;
      const imageIds = row.metadata?.running_image_ids || [];
      const runtime = row.metadata?.application_group
        ? `${row.metadata?.health_status || "unknown"} · ${row.metadata?.sync_status || "unknown"}${podTotal ? ` · ${podReady}/${podTotal} ready` : ""}`
        : podTotal
          ? `${podReady}/${podTotal} ready${imageIds.length ? ` · ${imageIds[0].split("@sha256:").pop().slice(0, 12)}` : ""}`
          : "Not observed";
      const collapsed = collapsedApplications.has(currentApplicationKey);
      const applicationCell = isApplication
        ? `<button type="button" class="application-toggle" data-application-key="${escapeHtml(currentApplicationKey)}" aria-expanded="${collapsed ? "false" : "true"}"><span>${collapsed ? "▸" : "▾"}</span><strong>${escapeHtml(application)}</strong></button><small>${escapeHtml(relationship)}</small>`
        : isChild
          ? `<span class="application-branch">↳ ${escapeHtml(role || "component")}</span><small>${escapeHtml(row.metadata?.grouping_evidence || "discovered")}</small>`
          : `${escapeHtml(application)}${relationship ? `<small>${escapeHtml(relationship)}</small>` : ""}`;
      const applicationClasses = isApplication
        ? ` application-summary-row application-runtime-${runtimeState}`
        : isChild ? " application-child-row" : "";
      const groupEndClass = closesApplicationGroup ? " application-group-end" : "";
      return `<tr class="inventory-row ${group}${applicationClasses}${groupEndClass}"><td class="component-name">${applicationCell}</td><td class="component-name">${escapeHtml(row.name)}<small>${escapeHtml(row.source)}</small></td><td class="deployed-version">${escapeHtml(row.version)}</td><td class="muted">${escapeHtml(runtime)}</td><td>${sourceEditor(row, evidenceSources)}</td><td class="muted">${escapeHtml(namespace)}</td><td><div class="dependency-list">${verifiedAgainst}</div></td><td><div class="why-cell"><span>${escapeHtml(reason)}</span></div></td><td class="muted">${escapeHtml(instance)}</td><td><span class="status-pill ${group}">${escapeHtml(row.name === "kubernetes" ? "Baseline" : statusLabel(row.status))}</span></td></tr>`;
    }).join("") : '<tr><td colspan="10" class="empty-state">No components match this filter.</td></tr>';
  }

  function formatTimestamp(value) {
    if (!value) return "Not available";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }

  function securityReportLabel(value) {
    return ({ vulnerability: "Vulnerabilities", config_audit: "Configuration", exposed_secret: "Exposed secrets", sbom: "SBOM" })[value] || value || "Unknown"; // pragma: allowlist secret -- Trivy report kind
  }

  function securityObservedMeaning(value) {
    return ({
      fresh: "Generated within the configured freshness window.",
      stale: "Older than the allowed window; findings may no longer describe the running workload.",
      unknown: "Age or collection state cannot be verified. This never means the report is clean."
    })[value] || "The report observation state is not recognized and must be treated as unknown.";
  }

  function securityFindingMarkup(finding) {
    const identifier = finding.url
      ? `<a href="${escapeHtml(finding.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(finding.id || "Finding")}</a>`
      : `<strong>${escapeHtml(finding.id || "Finding")}</strong>`;
    const versions = finding.package
      ? `${finding.package} ${finding.installed_version || ""}${finding.fixed_version ? ` → ${finding.fixed_version}` : " · no fix reported"}`
      : finding.title || "Configuration finding";
    return `<li><span class="security-severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity || "unknown")}</span><span>${identifier}<small>${escapeHtml(versions)}</small></span></li>`;
  }

  function sbomPackageMarkup(item) {
    const name = [item.group, item.name].filter(Boolean).join("/") || "Unnamed component";
    const metadata = [item.purl, ...(item.licenses || []).map((license) => `License: ${license}`)].filter(Boolean).join(" · ");
    return `<li><span class="security-package-type">${escapeHtml(item.type || "package")}</span><span><strong>${escapeHtml(name)}</strong>${item.version ? ` <code>${escapeHtml(item.version)}</code>` : ""}${metadata ? `<small>${escapeHtml(metadata)}</small>` : ""}</span></li>`;
  }

  function renderSecurity(data) {
    const security = data.security || {};
    const summary = security.summary || {};
    const reports = security.reports || [];
    const state = byId("security-state");
    const stateGroup = security.status === "fresh" ? "supported" : "unknown";
    state.className = `status-pill ${stateGroup}`;
    state.textContent = !security.available ? "Trivy unavailable" : security.status === "fresh" ? "Reports fresh" : security.status === "stale" ? "Stale reports" : "Unknown";
    byId("security-critical").textContent = security.available ? summary.critical || 0 : "—";
    byId("security-high").textContent = security.available ? summary.high || 0 : "—";
    byId("security-fixable").textContent = security.available ? summary.fixable || 0 : "—";
    const eligible = summary.eligible_containers || 0;
    const covered = summary.covered_containers || 0;
    byId("security-coverage").textContent = eligible ? `${Math.round(covered / eligible * 100)}%` : "Unknown";
    byId("security-coverage-detail").textContent = eligible ? `${covered} of ${eligible} discovered containers have a VulnerabilityReport` : "No eligible inventory is available";
    document.querySelectorAll("[data-security-severity]").forEach((button) => {
      const active = securitySeverityFilter === button.dataset.securitySeverity;
      const label = button.dataset.securitySeverity === "critical" ? "Critical" : "High";
      button.classList.toggle("active", active);
      button.closest(".security-stat").classList.toggle("filter-active", active);
      button.setAttribute("aria-pressed", String(active));
      button.setAttribute("aria-label", active ? `Clear ${label} CVE filter` : `Filter list to ${label} CVEs`);
    });

    const query = byId("security-search").value.trim().toLowerCase();
    const wanted = byId("security-type").value;
    const visible = reports.filter((item) => {
      const findingText = (item.findings || []).flatMap((finding) => [finding.id, finding.package, finding.title]).join(" ");
      const packageText = (item.sbom_packages || []).flatMap((pkg) => [pkg.group, pkg.name, pkg.version, pkg.type, pkg.purl, ...(pkg.licenses || [])]).join(" ");
      const text = [item.namespace, item.workload_kind, item.workload_name, item.container, item.component, item.application, item.image, item.image_digest, findingText, packageText].join(" ").toLowerCase();
      const matchesSeverity = securitySeverityFilter === "all"
        || (item.report_type === "vulnerability" && Number(item.summary?.[securitySeverityFilter] || 0) > 0);
      return (wanted === "all" || item.report_type === wanted) && matchesSeverity && text.includes(query);
    });
    const activeFilter = byId("security-active-filter");
    const securityTable = document.querySelector(".security-table");
    securityTable.classList.toggle("severity-filter-critical", securitySeverityFilter === "critical");
    securityTable.classList.toggle("severity-filter-high", securitySeverityFilter === "high");
    activeFilter.hidden = securitySeverityFilter === "all";
    if (securitySeverityFilter !== "all") {
      const label = securitySeverityFilter === "critical" ? "Critical" : "High";
      const severityReports = reports.filter((item) => item.report_type === "vulnerability" && Number(item.summary?.[securitySeverityFilter] || 0) > 0).length;
      byId("security-active-filter-label").textContent = `${label} CVEs`;
      byId("security-active-filter-detail").textContent = query
        ? `${visible.length} of ${severityReports} matching reports also match the search.`
        : `${severityReports} vulnerability reports contain at least one ${label} finding.`;
    }
    const pageReports = paginate(visible, "security");
    byId("security-body").innerHTML = pageReports.length ? pageReports.map((item) => {
      const counts = item.summary || {};
      const total = Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0);
      const group = item.status !== "fresh" ? "unknown" : (counts.critical || counts.high) ? "attention" : "supported";
      const additional = item.report_type === "vulnerability"
        ? `${item.fixable || 0} fixable`
        : item.report_type === "config_audit"
          ? `${total} failed checks`
          : item.report_type === "exposed_secret"
            ? `${total} findings · values suppressed`
            : `${item.sbom_components || 0} components`;
      const findings = item.findings || [];
      const displayedSeverities = ["critical", "high", "medium", "low", "unknown"]
        .map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length])
        .filter(([, count]) => count)
        .map(([severity, count]) => `${count} ${severity[0].toUpperCase()}${severity.slice(1)}`)
        .join(" · ");
      const displayedFindingCount = item.findings_truncated ? `${findings.length} of ${total}` : String(findings.length);
      const details = findings.length ? `<details class="security-findings"><summary>View ${displayedFindingCount} prioritized finding${total === 1 ? "" : "s"}${displayedSeverities ? ` · ${displayedSeverities}` : ""}</summary><ul>${findings.map(securityFindingMarkup).join("")}</ul></details>` : "";
      const sbomPackages = item.sbom_packages || [];
      const sbomDetails = item.report_type === "sbom" && sbomPackages.length
        ? `<details class="security-findings sbom-packages"><summary>View ${sbomPackages.length}${item.sbom_packages_truncated ? ` of ${item.sbom_components || sbomPackages.length}` : ""} SBOM components</summary><ul>${sbomPackages.map(sbomPackageMarkup).join("")}</ul></details>`
        : "";
      const digest = item.image_digest ? item.image_digest.replace(/^sha256:/, "").slice(0, 12) : "";
      const observedStatus = item.status || "unknown";
      const observedMeaning = securityObservedMeaning(observedStatus);
      return `<tr class="security-row ${group}"><td><strong>${escapeHtml(item.workload_kind)} / ${escapeHtml(item.workload_name)}</strong><small>${escapeHtml([item.namespace, item.container, item.component || "unmatched inventory"].filter(Boolean).join(" · "))}</small>${details}${sbomDetails}</td><td>${escapeHtml(securityReportLabel(item.report_type))}<small>${escapeHtml(`${item.scanner?.name || "scanner unknown"} ${item.scanner?.version || ""}`)}</small></td><td class="security-image">${escapeHtml(item.image || "Not applicable")}<small>${escapeHtml(digest ? `sha256:${digest}` : "No digest reported")}</small></td><td class="security-count critical">${counts.critical || 0}</td><td class="security-count high">${counts.high || 0}</td><td>${counts.medium || 0}</td><td>${counts.low || 0}</td><td>${escapeHtml(additional)}</td><td><span class="status-pill ${group}" title="${escapeHtml(observedMeaning)}" aria-label="${escapeHtml(`${observedStatus}: ${observedMeaning}`)}">${escapeHtml(observedStatus)}</span><small>${escapeHtml(formatTimestamp(item.generated_at))}</small></td></tr>`;
    }).join("") : `<tr><td colspan="9" class="empty-state">${security.available ? "No Trivy reports match this filter." : "Trivy report APIs are unavailable; security state is unknown."}</td></tr>`;
  }

  function renderSources(data) {
    const providers = data.providers || [];
    const usage = new Map();
    (data.results || []).forEach((result) => {
      if (!result.evidence_provider) return;
      if (!usage.has(result.evidence_provider)) usage.set(result.evidence_provider, { relationships: new Set(), sources: new Map() });
      const providerUsage = usage.get(result.evidence_provider);
      providerUsage.relationships.add(`${result.component} → ${result.dependency}`);
      if (result.evidence) providerUsage.sources.set(result.evidence, {
        title: result.evidence_title || sourceName(result.evidence),
        basis: result.evidence_basis,
        confidence: result.evidence_confidence,
        verifiedAt: result.evidence_verified_at
      });
    });
    byId("sources-total").textContent = `${providers.length} source${providers.length === 1 ? "" : "s"}`;
    byId("sources-list").innerHTML = providers.length ? providers.map((provider) => {
      const usable = ["fresh", "cached"].includes(provider.status);
      const stateClass = usable ? "supported" : provider.status === "stale" ? "unknown" : "attention";
      const providerUsage = usage.get(provider.name);
      const relationships = [...(providerUsage?.relationships || [])];
      const primarySources = [...(providerUsage?.sources || new Map())];
      const checksum = provider.checksum ? provider.checksum.slice(0, 12) : "Not available";
      return `<article class="card source-card">
        <div class="source-card-header"><div><span class="source-origin">${escapeHtml(sourceName(provider.source_url, provider.name))}</span>${sourceLink(provider.source_url, provider.source_url, "source-url")}</div><span class="status-pill ${stateClass}">${escapeHtml(provider.status)}</span></div>
        <div class="source-facts"><span><small>Provider</small><strong>${escapeHtml(provider.name)}</strong></span><span><small>Retrieved</small><strong>${escapeHtml(formatTimestamp(provider.retrieved_at))}</strong></span><span><small>Evidence checksum</small><strong title="${escapeHtml(provider.checksum)}">${escapeHtml(checksum)}</strong></span></div>
        <div class="source-coverage"><small>Used to verify</small><p>${relationships.length ? relationships.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : '<span>No active relationship matched this scan</span>'}</p></div>
        ${primarySources.length ? `<div class="source-primary"><small>Primary evidence</small>${primarySources.map(([url, source]) => `<div>${sourceLink(url, source.title, "source-primary-link")}${source.basis || source.confidence || source.verifiedAt ? `<span>${escapeHtml([source.basis, source.confidence && `${source.confidence} confidence`, source.verifiedAt && `verified ${source.verifiedAt}`].filter(Boolean).join(" · "))}</span>` : ""}</div>`).join("")}</div>` : ""}
        ${provider.error ? `<p class="source-error">${escapeHtml(provider.error)}</p>` : ""}
      </article>`;
    }).join("") : '<article class="card empty-upgrade"><strong>No evidence providers available</strong><p>The current report does not contain any upstream sources.</p></article>';
  }

  function openFilteredInventory(status) {
    byId("inventory-status").value = status;
    byId("inventory-search").value = "";
    resetPage("inventory");
    renderInventory();
    switchView("inventory");
    byId("inventory-status").focus();
  }

  function setTargetSuggestion(data) {
    const kubernetes = (data.components || []).find((item) => item.name === "kubernetes");
    if (!kubernetes) return;
    const match = normalizeVersion(kubernetes.version).match(/^(\d+)\.(\d+)/);
    if (!match) return;
    byId("target-version").value = `v${match[1]}.${Number(match[2]) + 1}.0`;
    byId("current-kubernetes-version").textContent = `Current Kubernetes: ${kubernetes.version}. Installed component versions remain unchanged in the simulation.`;
  }

  function rolePermits(required) {
    const level = { viewer: 1, operator: 2, admin: 3 };
    return (level[currentUser?.role] || 0) >= level[required];
  }

  function renderAuth() {
    const button = byId("auth-button");
    const label = byId("auth-label");
    const authenticated = Boolean(currentUser);
    button.classList.toggle("authenticated", authenticated);
    button.title = authenticated ? "Open privileged workspace" : "Login for privileged actions";
    label.textContent = authenticated ? `${currentUser.username} · ${currentUser.role}` : "Login";
    byId("logout-button").hidden = !authenticated;
    byId("admin-tab").hidden = !rolePermits("admin");
    byId("source-proposal-card").hidden = !rolePermits("operator");
    byId("admin-current-user").textContent = authenticated ? `${currentUser.username} · ${currentUser.role}` : "Administrator";
    if (!rolePermits("admin") && byId("admin-view").classList.contains("active")) switchView("overview");
    if (rolePermits("admin")) loadUsers();
  }

  function renderUsers(users) {
    const list = byId("user-list");
    list.innerHTML = users.length ? users.map((user) => `<div class="user-row">
      <span class="user-avatar" aria-hidden="true">${escapeHtml(user.username.slice(0, 1).toUpperCase())}</span>
      <span class="user-identity"><strong>${escapeHtml(user.username)}</strong><small>Created ${escapeHtml(formatTimestamp(user.created_at))}</small></span>
      <span class="role-badge">${escapeHtml(user.role)}</span>
      <span class="account-state ${user.enabled ? "enabled" : "disabled"}">${user.enabled ? "Enabled" : "Disabled"}</span>
    </div>`).join("") : '<p class="empty-state">No local users found.</p>';
  }

  async function loadUsers() {
    if (!rolePermits("admin")) return;
    try {
      const response = await fetch("/api/v1/admin/users", { headers: { Accept: "application/json" }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `request returned ${response.status}`);
      renderUsers(data.users || []);
    } catch (error) {
      byId("user-list").innerHTML = `<p class="form-error">Unable to load users: ${escapeHtml(error.message)}</p>`;
    }
  }

  async function loadAuth() {
    try {
      const response = await fetch("/api/v1/auth/me", { headers: { Accept: "application/json" }, cache: "no-store" });
      if (response.status === 401) {
        currentUser = null;
        csrfToken = "";
      } else {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || `request returned ${response.status}`);
        currentUser = { id: data.id, username: data.username, role: data.role };
        csrfToken = data.csrf_token || "";
      }
    } catch (error) {
      currentUser = null;
      csrfToken = "";
      showToast(`Authentication status unavailable: ${error.message}`);
    }
    renderAuth();
  }

  async function apiMutation(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {})
      },
      body: JSON.stringify(body || {})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `request returned ${response.status}`);
    return data;
  }

  async function login(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type=submit]");
    const errorBox = byId("login-error");
    button.disabled = true;
    errorBox.textContent = "";
    try {
      const values = new FormData(form);
      const response = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ username: values.get("username"), password: values.get("password") })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `request returned ${response.status}`);
      currentUser = data.user;
      csrfToken = data.csrf_token;
      form.reset();
      byId("auth-dialog").close();
      renderAuth();
      showToast(`Logged in as ${currentUser.username} (${currentUser.role}).`);
    } catch (error) {
      errorBox.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function logout() {
    try {
      await apiMutation("/api/v1/auth/logout", {});
    } catch (error) {
      return showToast(`Logout failed: ${error.message}`);
    }
    currentUser = null;
    csrfToken = "";
    resetSourceValidation();
    renderAuth();
    showToast("Logged out. Read-only access remains available.");
  }

  function resetSourceValidation() {
    sourceValidationToken = "";
    byId("submit-source").disabled = true;
    const result = byId("source-validation");
    result.hidden = true;
    result.innerHTML = "";
  }

  function renderSourceValidation(validation) {
    const result = byId("source-validation");
    const eligible = Boolean(validation.eligible);
    const checks = (validation.checks || []).map((check) => {
      const symbol = check.status === "passed" ? "✓" : check.status === "review" ? "!" : "×";
      return `<li class="${escapeHtml(check.status)}"><b>${symbol}</b><span>${escapeHtml(check.detail)}</span></li>`;
    }).join("");
    result.className = `source-validation form-wide ${eligible ? "eligible" : "invalid"}`;
    result.innerHTML = `<div class="source-validation-heading"><strong>${eligible ? "Eligible for proposal" : "Not eligible"}</strong><span>${escapeHtml(validation.reason)}</span></div><ul>${checks}</ul>${validation.content_sha256 ? `<small>SHA-256 ${escapeHtml(validation.content_sha256.slice(0, 16))}… · ${escapeHtml(String(validation.content_bytes || 0))} bytes · ${escapeHtml(String((validation.versions_detected || []).length))} version tokens</small>` : ""}`;
    result.hidden = false;
  }

  async function verifySource() {
    const form = byId("source-proposal-form");
    if (!form.reportValidity()) return;
    const values = new FormData(form);
    const button = byId("verify-source");
    resetSourceValidation();
    button.disabled = true;
    button.textContent = "Verifying…";
    try {
      const data = await apiMutation("/api/v1/source-validations", {
        component: values.get("component"),
        source_url: values.get("source_url")
      });
      const validation = data.validation;
      renderSourceValidation(validation);
      if (validation.eligible) {
        sourceValidationToken = validation.validation_token;
        form.elements.source_url.value = validation.source_url;
        byId("submit-source").disabled = false;
        showToast("Source is eligible. You can now submit it for administrator review.");
      } else {
        showToast(`Source is not eligible: ${validation.reason}`);
      }
    } catch (error) {
      renderSourceValidation({ eligible: false, reason: error.message, checks: [] });
      showToast(`Source validation failed: ${error.message}`);
    } finally {
      button.disabled = false;
      button.textContent = "Verify URL";
    }
  }

  async function submitSourceProposal(event) {
    event.preventDefault();
    if (!sourceValidationToken) return showToast("Verify the source URL before submitting it.");
    const form = event.currentTarget;
    const values = new FormData(form);
    try {
      await apiMutation("/api/v1/source-proposals", {
        component: values.get("component"),
        source_url: values.get("source_url"),
        notes: values.get("notes"),
        validation_token: sourceValidationToken
      });
      form.reset();
      resetSourceValidation();
      showToast("Source candidate stored. It remains inactive until validation and approval.");
    } catch (error) {
      showToast(`Unable to submit source: ${error.message}`);
    }
  }

  async function createUser(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    try {
      const data = await apiMutation("/api/v1/admin/users", {
        username: values.get("username"),
        password: values.get("password"),
        role: values.get("role")
      });
      form.reset();
      showToast(`Created ${data.user.username} with ${data.user.role} access.`);
      await loadUsers();
    } catch (error) {
      showToast(`Unable to create user: ${error.message}`);
    }
  }

  async function loadReport(notify = false) {
    const button = byId("refresh-button");
    button.classList.add("loading");
    try {
      const response = await fetch("/api/v1/report", { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error(`report request returned ${response.status}`);
      report = await response.json();
      componentRows = rowsFromReport(report);
      byId("footer-version").textContent = `Version ${report.kubit_version || "unknown"}`;
      renderSourceComponentOptions(report);
      byId("cluster-name").textContent = report.cluster || "cluster";
      renderProviderState(report);
      renderOverview(report);
      renderInventory();
      renderSecurity(report);
      renderSources(report);
      if (!byId("target-version").value) setTargetSuggestion(report);
      if (notify) showToast("Latest cluster assessment loaded.");
    } catch (error) {
      const badge = byId("live-badge");
      badge.classList.add("offline");
      badge.querySelector("span").textContent = "Unavailable";
      showToast(`Unable to load Kubit report: ${error.message}`);
    } finally {
      button.classList.remove("loading");
    }
  }

  function switchView(view) {
    if (view === "admin" && !rolePermits("admin")) view = "overview";
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === view));
    document.querySelectorAll(".view").forEach((panel) => panel.classList.toggle("active", panel.id === `${view}-view`));
    history.replaceState(null, "", `#${view}`);
  }

  async function analyzeUpgrade() {
    const target = byId("target-version").value.trim();
    const button = byId("analyze-upgrade");
    if (!target) return showToast("Enter a target Kubernetes version.");
    button.disabled = true;
    button.textContent = "Analyzing…";
    try {
      const response = await fetch(`/api/v1/upgrade-readiness?kubernetes=${encodeURIComponent(target)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `request returned ${response.status}`);
      renderUpgrade(data);
    } catch (error) {
      showToast(`Upgrade analysis failed: ${error.message}`);
    } finally {
      button.disabled = false;
      button.innerHTML = "Analyze upgrade <span>→</span>";
    }
  }

  function renderUpgrade(data) {
    const counts = { supported: 0, attention: 0, unknown: 0 };
    Object.entries(data.summary || {}).forEach(([status, count]) => { counts[statusGroup(status)] += count; });
    const findings = (data.results || []).filter((item) => attentionStates.has(item.status));
    const findingsHtml = findings.length ? `<article class="card findings-card"><div class="card-title"><strong>Upgrade findings</strong><span class="finding-badge">${findings.length} finding${findings.length === 1 ? "" : "s"}</span></div><div class="findings-list">${findings.map(findingMarkup).join("")}</div></article>` : '<article class="card empty-upgrade"><strong>No critical findings for this target</strong><p>Unverified components still require vendor evidence before the upgrade can be considered fully supported.</p></article>';
    byId("upgrade-results").innerHTML = `<div class="upgrade-summary"><article class="card upgrade-stat"><span>Target Kubernetes</span><strong>${escapeHtml(data.target_kubernetes)}</strong></article><article class="card upgrade-stat"><span>Supported checks</span><strong class="supported">${counts.supported}</strong></article><article class="card upgrade-stat"><span>Attention / unverified</span><strong class="unknown">${counts.attention} / ${counts.unknown}</strong></article></div>${findingsHtml}`;
  }

  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
    switchView(tab.dataset.view);
    if (tab.dataset.view === "admin") loadUsers();
  }));
  document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.go)));
  document.querySelectorAll("[data-inventory-filter]").forEach((button) => button.addEventListener("click", () => openFilteredInventory(button.dataset.inventoryFilter)));
  applyTheme(loadTheme());
  byId("theme-toggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light", true));
  byId("auth-button").addEventListener("click", () => {
    if (!currentUser) return byId("auth-dialog").showModal();
    switchView(rolePermits("admin") ? "admin" : rolePermits("operator") ? "sources" : "overview");
  });
  byId("logout-button").addEventListener("click", logout);
  byId("admin-logout-button").addEventListener("click", logout);
  byId("users-refresh").addEventListener("click", loadUsers);
  byId("auth-dialog-close").addEventListener("click", () => byId("auth-dialog").close());
  byId("auth-dialog").addEventListener("click", (event) => { if (event.target === byId("auth-dialog")) byId("auth-dialog").close(); });
  byId("login-form").addEventListener("submit", login);
  byId("verify-source").addEventListener("click", verifySource);
  byId("source-proposal-form").addEventListener("submit", submitSourceProposal);
  byId("source-proposal-form").elements.component.addEventListener("input", resetSourceValidation);
  byId("source-proposal-form").elements.source_url.addEventListener("input", resetSourceValidation);
  byId("user-admin-form").addEventListener("submit", createUser);
  byId("refresh-button").addEventListener("click", () => loadReport(true));
  byId("inventory-search").addEventListener("input", () => { resetPage("inventory"); renderInventory(); });
  byId("inventory-status").addEventListener("change", () => { resetPage("inventory"); renderInventory(); });
  byId("security-search").addEventListener("input", () => { resetPage("security"); if (report) renderSecurity(report); });
  byId("security-type").addEventListener("change", () => {
    if (byId("security-type").value !== "vulnerability") {
      securitySeverityFilter = "all";
      securityTypeBeforeSeverity = byId("security-type").value;
    }
    resetPage("security");
    if (report) renderSecurity(report);
  });
  ["inventory", "security"].forEach((kind) => {
    const render = () => kind === "inventory" ? renderInventory() : report && renderSecurity(report);
    byId(`${kind}-page-size`).addEventListener("change", (event) => {
      const size = Number(event.target.value);
      pagination[kind].size = pageSizes.has(size) ? size : 25;
      resetPage(kind);
      render();
    });
    byId(`${kind}-page-prev`).addEventListener("click", () => { pagination[kind].page -= 1; render(); });
    byId(`${kind}-page-next`).addEventListener("click", () => { pagination[kind].page += 1; render(); });
  });
  document.querySelectorAll("[data-security-severity]").forEach((button) => button.addEventListener("click", () => {
    const selected = button.dataset.securitySeverity;
    if (securitySeverityFilter === selected) {
      securitySeverityFilter = "all";
      byId("security-type").value = securityTypeBeforeSeverity;
    } else {
      if (securitySeverityFilter === "all") securityTypeBeforeSeverity = byId("security-type").value;
      securitySeverityFilter = selected;
      byId("security-type").value = "vulnerability";
    }
    resetPage("security");
    if (report) renderSecurity(report);
  }));
  byId("security-active-filter-clear").addEventListener("click", () => {
    const activeButton = document.querySelector(`[data-security-severity="${securitySeverityFilter}"]`);
    if (activeButton) activeButton.click();
  });
  byId("inventory-body").addEventListener("change", (event) => {
    const select = event.target.closest(".source-truth-select");
    if (!select) return;
    if (select.value) sourceOverrides[select.dataset.sourceKey] = select.value;
    else delete sourceOverrides[select.dataset.sourceKey];
    if (!saveSourceOverrides()) showToast("The source preference could not be saved in this browser.");
    else showToast(select.value ? "Source preference saved locally. Compatibility results are unchanged." : "Automatic source selection restored.");
    renderInventory();
  });
  byId("inventory-body").addEventListener("click", (event) => {
    const toggle = event.target.closest(".application-toggle");
    if (!toggle) return;
    const key = toggle.dataset.applicationKey;
    if (collapsedApplications.has(key)) collapsedApplications.delete(key);
    else collapsedApplications.add(key);
    renderInventory();
  });
  byId("analyze-upgrade").addEventListener("click", analyzeUpgrade);
  byId("target-version").addEventListener("keydown", (event) => { if (event.key === "Enter") analyzeUpgrade(); });
  switchView(["overview", "inventory", "security", "upgrade", "sources"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "overview");
  renderAuth();
  loadAuth();
  loadReport();
})();
