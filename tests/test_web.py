import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from kubit.app import (
    State,
    WEB_ASSETS,
    WEB_ROOT,
    current_report,
    require_discovered_component,
)
from kubit.models import Component
from kubit.source_validation import SourceValidationError


class WebInterfaceTest(unittest.TestCase):
    def test_release_version_matches_deployment_artifacts(self):
        root = Path(__file__).parents[1]
        version_match = re.search(
            r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$',
            (root / "pyproject.toml").read_text(),
            re.MULTILINE,
        )
        self.assertIsNotNone(version_match)
        version = version_match.group(1)
        self.assertRegex(version, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        chart = (root / "charts" / "kubit" / "Chart.yaml").read_text()
        self.assertIn(f'appVersion: "{version}"', chart)
        values = (root / "charts" / "kubit" / "values.yaml").read_text()
        self.assertIn("repository: ghcr.io/lcontreras48/kubit", values)
        deployment = (root / "base" / "deployment.yaml").read_text()
        self.assertIn(f"image: ghcr.io/lcontreras48/kubit:{version}", deployment)
        config = (root / "base" / "configmap.yaml").read_text()
        self.assertIn("CLUSTER_NAME: cluster", config)
        self.assertNotIn("sandbox", config.lower())
        workflow = (root / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("python3 -m unittest discover -s tests -v", workflow)

    def test_grafana_dashboard_exposes_reasons_sources_and_filters(self):
        root = Path(__file__).parents[1]
        dashboard_source = (root / "components" / "monitoring" / "dashboard.json").read_text()
        dashboard = json.loads(dashboard_source)
        self.assertEqual(
            dashboard_source,
            (root / "charts" / "kubit" / "files" / "dashboards" / "kubit-compatibility.json").read_text(),
        )
        panels = {panel["title"]: panel for panel in dashboard["panels"]}
        self.assertIn("Action required", panels)
        self.assertIn("Unverified components", panels)
        self.assertIn("Sources of truth", panels)
        self.assertIn("reason", panels["Action required"]["targets"][0]["expr"])
        self.assertIn("evidence_url", panels["Compatibility matrix"]["targets"][0]["expr"])
        self.assertIn("component_namespace", panels["Compatibility matrix"]["targets"][0]["expr"])
        self.assertIn("component_instance", panels["Discovered inventory"]["targets"][0]["expr"])
        matrix_renames = panels["Compatibility matrix"]["transformations"][0]["options"]["renameByName"]
        self.assertEqual(matrix_renames["component_namespace"], "Namespace")
        self.assertEqual(matrix_renames["component_instance"], "Node / instance")
        self.assertEqual({item["name"] for item in dashboard["templating"]["list"]}, {"component", "status"})

    def test_dashboard_assets_are_explicit_and_present(self):
        self.assertEqual(set(WEB_ASSETS), {"/", "/assets/styles.css", "/assets/app.js", "/assets/favicon.svg"})
        for filename, content_type in WEB_ASSETS.values():
            with self.subTest(filename=filename):
                asset = WEB_ROOT / filename
                self.assertTrue(asset.is_file())
                self.assertGreater(asset.stat().st_size, 100)
                self.assertTrue(content_type)
        self.assertIn("Kubernetes Unified Baseline &amp; Interoperability Tracker", (WEB_ROOT / "index.html").read_text())
        self.assertIn("Evidence-based compatibility intelligence for your Kubernetes stack", (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-inventory-filter="attention"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="baseline-kubernetes"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="relationship-list"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("inventory-row", (WEB_ROOT / "app.js").read_text())
        self.assertIn("application-toggle", (WEB_ROOT / "app.js").read_text())
        self.assertIn("application-summary-row", (WEB_ROOT / "styles.css").read_text())
        self.assertIn('id="theme-toggle"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("kubit.theme.v1", (WEB_ROOT / "app.js").read_text())
        self.assertIn('data-theme="light"', (WEB_ROOT / "styles.css").read_text())
        self.assertIn("--application-summary: #142f4b", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("--application-summary: #e5eeff", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("--application-healthy-summary: #def5e8", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("applicationRuntimeState", (WEB_ROOT / "app.js").read_text())
        self.assertIn("application-runtime-${runtimeState}", (WEB_ROOT / "app.js").read_text())
        self.assertIn("application-group-end", (WEB_ROOT / "app.js").read_text())
        self.assertIn("--red: #b00020", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("Blue frame: application group", (WEB_ROOT / "index.html").read_text())
        self.assertIn("renderRelationships", (WEB_ROOT / "app.js").read_text())
        self.assertIn('id="footer-version">Version loading…', (WEB_ROOT / "index.html").read_text())
        self.assertIn('`Version ${report.kubit_version || "unknown"}`', (WEB_ROOT / "app.js").read_text())
        self.assertIn("Verified against", (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-view="sources"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-view="security"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="security-view"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="security-body"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="overview-security-critical"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="overview-security-high"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-go="security"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-security-severity="critical"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('data-security-severity="high"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('byId("overview-security-detail")', (WEB_ROOT / "app.js").read_text())
        self.assertIn(".overview-security-card", (WEB_ROOT / "styles.css").read_text())
        self.assertIn('item.report_type === "vulnerability" && Number(item.summary?.[securitySeverityFilter] || 0) > 0', (WEB_ROOT / "app.js").read_text())
        self.assertIn(".security-stat-filter", (WEB_ROOT / "styles.css").read_text())
        self.assertNotIn('class="security-filter-clear"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('active ? `Clear ${label} CVE filter`', (WEB_ROOT / "app.js").read_text())
        self.assertIn('byId("security-type").value = securityTypeBeforeSeverity', (WEB_ROOT / "app.js").read_text())
        self.assertIn('id="security-active-filter"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('class="security-filter-caption">Applied filter', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="security-active-filter-clear"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("vulnerability reports contain at least one", (WEB_ROOT / "app.js").read_text())
        self.assertIn('item.findings_truncated ? `${findings.length} of ${total}`', (WEB_ROOT / "app.js").read_text())
        self.assertIn('`${count} ${severity[0].toUpperCase()}${severity.slice(1)}`', (WEB_ROOT / "app.js").read_text())
        self.assertIn("severity-filter-high", (WEB_ROOT / "styles.css").read_text())
        self.assertIn(".security-stat.filter-active", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("renderSecurity", (WEB_ROOT / "app.js").read_text())
        self.assertIn("values suppressed", (WEB_ROOT / "app.js").read_text())
        self.assertIn("sbomPackageMarkup", (WEB_ROOT / "app.js").read_text())
        self.assertIn("View ${sbomPackages.length}", (WEB_ROOT / "app.js").read_text())
        self.assertIn(".sbom-packages", (WEB_ROOT / "styles.css").read_text())
        self.assertIn('id="inventory-page-size"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="security-page-size"', (WEB_ROOT / "index.html").read_text())
        self.assertEqual((WEB_ROOT / "index.html").read_text().count('<option value="25">25</option><option value="50">50</option><option value="100">100</option>'), 2)
        self.assertIn('const pagination = { inventory:', (WEB_ROOT / "app.js").read_text())
        self.assertIn('const pageRows = paginate(inventoryItems, "inventory").flat()', (WEB_ROOT / "app.js").read_text())
        self.assertIn('const pageReports = paginate(visible, "security")', (WEB_ROOT / "app.js").read_text())
        self.assertIn(".pagination-actions", (WEB_ROOT / "styles.css").read_text())
        self.assertIn('aria-label="Observed status definitions"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("securityObservedMeaning", (WEB_ROOT / "app.js").read_text())
        self.assertIn("This never means the report is clean", (WEB_ROOT / "app.js").read_text())
        self.assertIn(".observed-tooltip", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("Sources of Truth", (WEB_ROOT / "index.html").read_text())
        self.assertIn("<th>Source of truth</th>", (WEB_ROOT / "index.html").read_text())
        self.assertIn("<th>Application</th>", (WEB_ROOT / "index.html").read_text())
        self.assertIn("<th>Runtime</th>", (WEB_ROOT / "index.html").read_text())
        self.assertIn("<th>Namespace</th>", (WEB_ROOT / "index.html").read_text())
        self.assertIn("<th>Node / instance</th>", (WEB_ROOT / "index.html").read_text())
        self.assertIn("componentNamespace", (WEB_ROOT / "app.js").read_text())
        header = (WEB_ROOT / "index.html").read_text().split("<thead><tr>", 1)[1].split("</tr></thead>", 1)[0]
        self.assertLess(header.index("Source of truth"), header.index("Verified against"))
        self.assertIn("renderSources", (WEB_ROOT / "app.js").read_text())
        self.assertIn("Primary evidence", (WEB_ROOT / "app.js").read_text())
        self.assertIn("sourceOverrideStorageKey", (WEB_ROOT / "app.js").read_text())
        self.assertIn("source-truth-select", (WEB_ROOT / "app.js").read_text())
        self.assertIn("Source of truth", (WEB_ROOT / "index.html").read_text())
        self.assertIn("Overrides are stored only in this browser", (WEB_ROOT / "index.html").read_text())
        self.assertIn("inventory-row.attention", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("--inventory-green: #7cf7b2", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("inventory-row.supported { background", (WEB_ROOT / "styles.css").read_text())
        self.assertIn(".source-truth-select", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("width: min(1480px", (WEB_ROOT / "styles.css").read_text())
        self.assertNotIn("min-width: 1520px", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("table-layout: fixed", (WEB_ROOT / "styles.css").read_text())
        self.assertIn("@media (max-width: 900px)", (WEB_ROOT / "styles.css").read_text())
        self.assertIn('class="inventory-table"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="auth-button"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="auth-dialog"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="source-proposal-form"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="source-component"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("renderSourceComponentOptions", (WEB_ROOT / "app.js").read_text())
        self.assertIn('id="verify-source"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="source-validation"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("sourceValidationToken", (WEB_ROOT / "app.js").read_text())
        self.assertIn('apiMutation("/api/v1/source-validations"', (WEB_ROOT / "app.js").read_text())
        self.assertIn('id="user-admin-form"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="admin-tab"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="admin-view"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="user-list"', (WEB_ROOT / "index.html").read_text())
        self.assertIn('id="logout-button"', (WEB_ROOT / "index.html").read_text())
        self.assertIn("loadAuth", (WEB_ROOT / "app.js").read_text())
        self.assertIn("loadUsers", (WEB_ROOT / "app.js").read_text())
        self.assertIn('fetch("/api/v1/admin/users"', (WEB_ROOT / "app.js").read_text())
        self.assertIn("X-CSRF-Token", (WEB_ROOT / "app.js").read_text())
        self.assertIn("rolePermits", (WEB_ROOT / "app.js").read_text())
        self.assertIn(".auth-dialog", (WEB_ROOT / "styles.css").read_text())

    def test_report_exposes_deployment_cluster_name(self):
        state = State()
        state.cluster_name = "sandbox-test"
        with patch("kubit.app.application_version", return_value="1.0.0"):
            report = current_report(state)
        self.assertEqual(report["kubit_version"], "1.0.0")
        self.assertEqual(report["cluster"], "sandbox-test")
        self.assertFalse(report["ready"])
        self.assertEqual(report["security"]["status"], "unknown")

    def test_source_proposals_are_limited_to_discovered_components(self):
        state = State()
        state.components = [Component("cloudnative-pg", "1.30.1", "workload")]
        self.assertEqual(
            require_discovered_component(state, " cloudnative-pg "),
            "cloudnative-pg",
        )
        with self.assertRaisesRegex(SourceValidationError, "not present"):
            require_discovered_component(state, "invented-component")

    def test_arbitrary_files_are_not_in_asset_allowlist(self):
        self.assertNotIn("/assets/../app.py", WEB_ASSETS)
        self.assertNotIn("/app.py", WEB_ASSETS)


if __name__ == "__main__":
    unittest.main()
