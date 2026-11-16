# File formats and APIs

This is the register of every file format and API that Stenwatch reads or plans to read. An import is built only against a format someone has seen. A format stays "From documentation only" until a real export has been read by the person who runs Stenwatch. Real exports go in the git-ignored `samples/` folder in the repository root. They are never committed, never copied into `examples/` and never sent to an LLM or to the web. The fictional files in `examples/` are written by hand with the real column names and the Example Organisation's values.

Status values:

- **Verified against a real export**: Stenwatch reads this format today and has tests for it.
- **From documentation only**: the field names come from the vendor's reference page or a public sample file, and no real export has been read yet.
- **Not yet researched**: no public page with the fields was found. Nothing is assumed.

Date checked is the day the reference page or sample was read. Pages and portals change; check again before building.

## Register

| Product | What Stenwatch reads from it | How to export it | Where the format knowledge comes from | Date checked | Status |
|---|---|---|---|---|---|
| Microsoft Defender Vulnerability Management: vulnerabilities export | One row per CVE with severity, CVSS, EPSS, age, exploit flags, related software and exposed machines (Morning triage) | Defender portal, Vulnerability management, Vulnerabilities, Export (CSV or Excel) | `DefenderTriage.Load` and its tests; fictional copy `examples/defender-export.example.csv`; API reference for the per-device fields: [Export software vulnerabilities assessment per device](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities) | 2026-11-16 | Verified against a real export |
| CycloneDX SBOM | Components by name and version, or by CPE, converted to assets | Produced by the build of the software (for example the customer portal), as JSON | `Inventory.ReadRows` and its tests; `examples/sbom.example.json`; [CycloneDX specification overview](https://cyclonedx.org/specification/overview/) | 2026-11-16 | Verified against a real export |
| Inventory CSV or Excel (own format and host exports) | One row per host with columns such as hostname, vendor, product, version, os, os_build | Any inventory tool that lists hosts and software (Intune, SCCM, Defender and others) | `Inventory.ReadRows` and its tests; `examples/inventory.example.csv` | 2026-11-16 | Verified against a real export |
| Intune discovered apps CSV | One row per program and version with a device count, semicolon- or comma-separated | Intune admin center, discovered apps, export (see the checklist) | `Inventory.ReadRows` and its tests; `examples/apps.example.csv`; resource reference: [detectedApp](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-detectedapp) | 2026-11-16 | Verified against a real export |
| RSS 2.0 and Atom feeds | Advisory title, link, date, text and the CVE ids in the text | The feed URL of the publisher (NCSC-FI, CERT-EU, CISA, Chrome Releases, your own) | `Advisories.ParseRss`, `Sources.ParseAtom` and their tests; [RSS 2.0 specification](https://www.rssboard.org/rss-specification), [RFC 4287 (Atom)](https://www.rfc-editor.org/rfc/rfc4287) | 2026-11-16 | Verified against a real export |
| Microsoft MSRC CVRF (JSON) | CVEs that Microsoft marks "Exploited:Yes" in the newest monthly document | Public API, no export: `https://api.msrc.microsoft.com/cvrf/v3.0/updates` lists the months and their `CvrfUrl` | `Sources.ParseCvrf` and its test; the live `updates` response was read on the check date | 2026-11-16 | Verified against a real export |
| Microsoft Defender Vulnerability Management: security recommendations | One row per recommendation: product, recommended version, category, severity score, weaknesses, exposed machines | Defender portal, Vulnerability management, Recommendations, Export (menu path not confirmed on a public page) | [List all recommendations](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations) (API; the portal CSV column names were not found) | 2026-11-16 | From documentation only |
| Microsoft Secure Score | Overall score and one row per control: title, category, max score, implementation cost, user impact, tier | Defender portal, Secure score, Recommended actions, export (menu path not confirmed on a public page); or Microsoft Graph | [secureScore](https://learn.microsoft.com/en-us/graph/api/resources/securescore), [secureScoreControlProfile](https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile) | 2026-11-16 | From documentation only |
| Intune managed devices | One row per device: name, operating system, OS version, compliance state, encryption, user | Intune admin center, Devices, All devices, Export (menu path not confirmed on a public page); or Graph | [managedDevice](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice) (API; the portal CSV column names were not found) | 2026-11-16 | From documentation only |
| Intune update compliance report | Windows update state per device | Intune admin center, Reports, Windows updates; reports can also be pulled with the export jobs API | [Use Graph APIs to export Intune reports](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis). Column names of the update reports were not found | 2026-11-16 | Not yet researched |
| Microsoft Entra ID: risky users | One row per risky user: user principal name, risk level, risk state, risk detail, last updated | Entra admin center, Protection, Identity Protection, Risky users, Download (menu path not confirmed on a public page); needs Entra ID P2 | [riskyUser](https://learn.microsoft.com/en-us/graph/api/resources/riskyuser) (API; the portal CSV column names were not found) | 2026-11-16 | From documentation only |
| Microsoft Entra ID: sign-in logs | Sign-ins with app, client, result, risk level and conditional access status | Entra admin center, Monitoring and health, Sign-in logs, Download (CSV or JSON, up to 100,000 records per file) | [signIn](https://learn.microsoft.com/en-us/graph/api/resources/signin); [How to download logs in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs) | 2026-11-16 | From documentation only |
| Microsoft Entra ID: role assignments | Stale privileged accounts | Entra admin center, Roles and administrators (export option not found on a public page) | Not found on a public page | 2026-11-16 | Not yet researched |
| Defender for Cloud: recommendations export (CSV) | Recommendations per cloud resource | Azure portal, Defender for Cloud, Recommendations, download the CSV report (menu path not confirmed on a public page) | The CSV column names were not found on a public page. The recommendations page is described in [Review security recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations) | 2026-11-16 | Not yet researched |
| Defender for Cloud: Azure Resource Graph security assessments | Assessments and sub-assessments per resource | Azure portal, Defender for Cloud, Recommendations, a recommendation, Open query; or Resource Graph Explorer, table `securityresources` | [Azure Resource Graph sample queries for Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/resource-graph-samples) | 2026-11-16 | From documentation only |
| Microsoft Security Exposure Management: attack paths and critical assets | Nodes and edges of the exposure graph, including critical asset criticality | Defender portal, Hunting, Advanced hunting, query `ExposureGraphNodes` and `ExposureGraphEdges`, then export the results | [Query the enterprise exposure graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph) | 2026-11-16 | From documentation only |
| Microsoft Defender External Attack Surface Management (EASM) asset export | Discovered internet-facing assets | Azure portal, Defender EASM, Inventory, export (menu path not confirmed on a public page) | Not found on a public page. The inventory page is [Understanding inventory assets](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-inventory-assets); it names no export columns | 2026-11-16 | Not yet researched |
| OWASP ZAP JSON report | Alerts per site with risk, confidence, CWE and the affected URLs | In ZAP: Report, Generate Report, template "Traditional JSON Report" (or the automation framework report job) | [Traditional JSON Report](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/) with a sample | 2026-11-16 | From documentation only |
| SARIF 2.1.0 | Static analysis results: rule, level, message, locations | Written by the analysis tool (for example GitHub code scanning, CodeQL, Semgrep, ZAP's SARIF report) | [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), JSON schema in [oasis-tcs/sarif-spec](https://github.com/oasis-tcs/sarif-spec) | 2026-11-16 | From documentation only |
| Defender for Cloud Apps: discovered apps | Apps seen in cloud discovery, filtered to the generative-AI category | Defender portal, Cloud apps, Cloud discovery, Discovered apps, export (menu path not confirmed on a public page) | Not found on a public page. Concept page: [Cloud discovery tutorial](https://learn.microsoft.com/en-us/defender-cloud-apps/tutorial-shadow-it) | 2026-11-16 | Not yet researched |
| Defender for IoT: device inventory export | OT and IoT devices with vendor, model and firmware | Defender portal or Azure portal, Defender for IoT, Device inventory, export (menu path not confirmed on a public page) | Not found on a public page. The Defender for IoT inventory page was not found at the address tried | 2026-11-16 | Not yet researched |
| endoflife.date API (v1) | Per product and release: end-of-life date and whether it is still maintained | Public API, no export: `https://endoflife.date/api/v1/products/{product}/` and `.../releases/{release}` | [API v1 documentation](https://endoflife.date/docs/api/v1/) and its OpenAPI file `https://endoflife.date/docs/api/v1/openapi.yml`; live responses for every slug in the table below were read on the check date | 2026-11-16 | From documentation only |
| MITRE ATLAS data | Tactics, techniques, mitigations, case studies and relationships for attacks on AI systems | Public download: `dist/ATLAS-latest.yaml` in the data repository | [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data); the 2026.10 file (format 6.1.0) was read | 2026-11-16 | From documentation only |
| MITRE ATT&CK for ICS (STIX 2.1) | Techniques, tactics, groups, mitigations and relationships for industrial control systems | Public download: `ics-attack/ics-attack.json` in the STIX data repository | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data); the current file was read | 2026-11-16 | From documentation only |
| Microsoft Teams incoming webhook (Workflows) | Not read: Stenwatch posts the briefing or a ticket card to it | In Teams, the Workflows app, the trigger "When a Teams webhook request is received" gives the URL (steps in Fields) | [Create an Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) (page dated 2026-10-26; states that Office 365 connector webhooks were retired in May 2026), [Create incoming webhooks with Workflows](https://support.microsoft.com/en-US/teams/apps-service/create-incoming-webhooks-with-workflows-for-microsoft-teams), [Microsoft Teams connector: webhook trigger](https://learn.microsoft.com/en-us/connectors/teams/) | 2026-11-16 | From documentation only |
| Jira Cloud Automation: incoming webhook trigger | Not read: Stenwatch posts a ticket as JSON to a URL the customer creates | In Jira, a project or global automation rule with the trigger "Incoming webhook"; the rule shows the URL and a secret | [Configure the incoming webhook trigger](https://support.atlassian.com/cloud-automation/docs/configure-the-incoming-webhook-trigger-in-atlassian-automation/), [Use incoming webhooks with smart values](https://support.atlassian.com/jira/kb/use-incoming-webhooks-with-smart-values-in-automation-for-jira/) | 2026-11-16 | From documentation only |
| ServiceNow: Table API and Scripted REST API | Not read: Stenwatch posts a ticket as JSON to an endpoint on the customer's instance | Customer creates a Scripted REST API resource, or uses the Table API | [Create an incident with the Table API](https://www.servicenow.com/docs/bundle/yokohama-api-reference/page/integrate/inbound-rest/task/t_GetStartedCreateInt.html), [Scripted REST API example script samples](https://www.servicenow.com/docs/r/MVRCUFVyKWd7vUoUukbW6g/3LBPBV8ftJn4eB9hZJy8Cg). Flow Designer inbound: not found on a public page | 2026-11-16 | From documentation only |
| Azure DevOps: create a work item | Not read: Stenwatch cannot post to it directly (see Fields) | Customer creates a flow with an HTTP request trigger (Power Automate or Azure Logic Apps), or calls the REST API with a JSON Patch body | [Work Items - Create](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create), [Webhooks with Azure DevOps](https://learn.microsoft.com/en-us/azure/devops/service-hooks/services/webhooks) (outgoing only), [Create callable or nestable workflows](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-http-endpoint) | 2026-11-16 | From documentation only |
| Defender advanced hunting: `DeviceTvmSoftwareVulnerabilities` and `DeviceTvmSoftwareVulnerabilitiesKB` | Not read: Stenwatch writes a KQL query per urgent finding for the customer to run | Defender portal, Hunting, Advanced hunting | [DeviceTvmSoftwareVulnerabilities](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table), [DeviceTvmSoftwareVulnerabilitiesKB](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table) | 2026-11-16 | From documentation only |
| Windows Task Scheduler (`schtasks /Create`) and MSIX app execution aliases | Not read: Stenwatch registers a daily task that runs the command-line mode | Command line `schtasks`; for the Store edition an alias declared in the package manifest | [schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create), [uap5:AppExecutionAlias](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap5-appexecutionalias), [Packaging extensions](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-extensions). Scheduling a packaged app: the documentation is silent (see Fields) | 2026-11-16 | From documentation only |
| Tenable CSV export | Findings with plugin, asset, severity and CVE | Tenable Vulnerability Management, Explore, Findings, Export (CSV or JSON) | The export page is [Export Findings](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/ExportFindings.htm); the CSV keys were not found on a page that could be read | 2026-11-16 | Not yet researched |
| Qualys CSV export | Detections with QID, asset, severity and CVE | Qualys, Vulnerability Management, reports, CSV (menu path not found) | Not found on a public page | 2026-11-16 | Not yet researched |

The "Verified" rows mean the reader exists in `src/Stenwatch.Core` and tests cover it. The tests use small hand-written files in the real column layout, not committed real exports.

## Fields

Field names are copied from the page named in each section. Where an item is an API field, the portal CSV may use different headings. Compare with the real export header before building (the Defender export is the example: the portal CSV uses "Name", "CVSS v3", "Epss score", while the API uses `cveId`, `cvssScore`).

### Defender vulnerabilities export (portal CSV or Excel)

Header of the file Stenwatch reads today, from `examples/defender-export.example.csv` (a fictional copy of the layout, line 1 is a title line with the export date): Name, Severity, CVSS v3, Epss score, Age (days), Published, First detected, Updated, Has Exploit, Has Known Threats, Has Associated Alerts, Related Software, Exposed Machines, Description, Status. This list is from the repository, not from a public page.

API, per device, from the page above: id, deviceId, rbacGroupName, deviceName, osPlatform, osVersion, osArchitecture, softwareVendor, softwareName, softwareVersion, cveId, vulnerabilitySeverityLevel, cvssScore, recommendedSecurityUpdate, recommendedSecurityUpdateId, recommendedSecurityUpdateUrl, diskPaths, registryPaths, lastSeenTimestamp, firstSeenTimestamp, exploitabilityLevel (NoExploit, ExploitIsPublic, ExploitIsVerified, ExploitIsInKit), recommendationReference, securityUpdateAvailable. The page also states that the portal export from the weaknesses page is limited to 6,000 records and 64 KB ([Vulnerabilities in my organization](https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-weaknesses)).

### CycloneDX, inventory, Intune discovered apps, RSS, Atom

The columns and elements Stenwatch recognises are in `Inventory.cs` (alias lists such as product, version, vendor, os, os_build, device count) and `Sources.cs` / `Advisories.cs`. The Intune `detectedApp` resource lists: id, displayName, version, sizeInByte, deviceCount, publisher, platform ([page](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-detectedapp)). The portal CSV headings are read by the alias list ("Application name", "Application version", "Publisher", "Device count" in `examples/apps.example.csv`).

### MSRC CVRF

From the `updates` response read on 2026-11-16: `value[]` with ID, Alias, DocumentTitle, Severity, InitialReleaseDate, CurrentReleaseDate, CvrfUrl. Stenwatch reads from the CVRF document: DocumentTracking.InitialReleaseDate, Vulnerability[].CVE, Vulnerability[].Title.Value, Vulnerability[].Threats[].Description.Value (the text "Exploited:Yes").

### Defender security recommendations (API)

From [List all recommendations](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations): id, productName, recommendationName, weaknesses, vendor, recommendedVersion, recommendedVendor, recommendedProgram, recommendationCategory, subCategory, severityScore, publicExploit, activeAlert, associatedThreats, remediationType, status, configScoreImpact, exposureImpact, totalMachineCount, exposedMachinesCount, nonProductivityImpactedAssets, relatedComponent, hasUnpatchableCve, tags, exposedCriticalDevices. Portal CSV column names: Not found on a public page.

### Secure Score (Microsoft Graph)

secureScore, from [the page](https://learn.microsoft.com/en-us/graph/api/resources/securescore): id, azureTenantId, activeUserCount, createdDateTime, currentScore, enabledServices, licensedUserCount, maxScore, averageComparativeScores, controlScores, vendorInformation.

secureScoreControlProfile, from [the page](https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile): id, azureTenantId, actionType, actionUrl, controlCategory, controlStateUpdates, deprecated, implementationCost, lastModifiedDateTime, maxScore, rank, remediation, remediationImpact, service, threats, tier, title, userImpact, vendorInformation (complianceInformation is documented as not implemented).

### Intune managed devices (Microsoft Graph)

From [managedDevice](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice), the properties that matter for Stenwatch: id, deviceName, operatingSystem, osVersion, complianceState, enrolledDateTime, lastSyncDateTime, isEncrypted, userPrincipalName, model, manufacturer, serialNumber, azureADDeviceId, managementAgent, managedDeviceOwnerType. The page lists many more. Portal CSV column names: Not found on a public page.

### Intune update compliance report

Not found on a public page. The export jobs endpoint is `https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs` ([page](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis)); the report names and columns for update reports were not read.

### Entra risky users and sign-ins (Microsoft Graph)

riskyUser, from [the page](https://learn.microsoft.com/en-us/graph/api/resources/riskyuser): id, isDeleted, isProcessing, riskLastUpdatedDateTime, riskLevel (low, medium, high, hidden, none), riskState (none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised), riskDetail, userDisplayName, userPrincipalName.

signIn, from [the page](https://learn.microsoft.com/en-us/graph/api/resources/signin): id, createdDateTime, appDisplayName, appId, ipAddress, clientAppUsed, correlationId, conditionalAccessStatus, appliedConditionalAccessPolicies, isInteractive, deviceDetail, location, riskDetail, riskLevelAggregated, riskLevelDuringSignIn, riskState, riskEventTypes_v2, resourceDisplayName, resourceId, status, userDisplayName, userId, userPrincipalName.

Role assignments: Not found on a public page.

### Defender for Cloud recommendations export (CSV)

Not found on a public page.

### Azure Resource Graph security assessments

From [the sample queries](https://learn.microsoft.com/en-us/azure/defender-for-cloud/resource-graph-samples) (table `securityresources`, types `microsoft.security/assessments` and `microsoft.security/assessments/subassessments`): properties.displayName, properties.status.code, properties.status.severity, properties.resourceDetails.id, properties.resourceDetails.source, properties.category, properties.description, properties.remediation, properties.impact, properties.timeGenerated, properties.additionalData, properties.metadata.severity, properties.metadata.categories, properties.metadata.threats, properties.metadata.userImpact, properties.metadata.implementationEffort, properties.metadata.assessmentType, properties.metadata.policyDefinitionId, properties.links.azurePortal. The page shows the sub-assessment form; the plain assessment form should be checked against a real result. The Defender for Cloud page also names `properties.status.firstEvaluationDate`.

### Exposure Management attack paths and critical assets

From [the page](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph), tables in advanced hunting: ExposureGraphNodes with NodeId, NodeLabel, NodeName, NodeProperties (rawData holds items such as exposedToInternet, vulnerableToRCE, criticalityLevel.criticalityLevel), Categories, EntityIds; ExposureGraphEdges with SourceNodeId, SourceNodeLabel, TargetNodeId, TargetNodeLabel, EdgeLabel. The page uses `Id` in one example and `NodeId` in the others, so the node key must be checked against a real result.

### EASM asset export

Not found on a public page.

### OWASP ZAP traditional JSON report

From [the page](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/): top level `@version`, `@generated`, `created`, `insights`, `site[]`. Each site: `@name`, `@host`, `@port`, `@ssl`, `alerts[]`. Each alert: pluginid, alertRef, alert, name, riskcode, confidence, riskdesc, desc, instances[], count, systemic, solution, otherinfo, reference, cweid, wascid, sourceid. Each instance: uri, nodeName, method, param, attack, evidence, otherinfo. Values are strings, including the numbers.

### SARIF 2.1.0

From the JSON schema in [oasis-tcs/sarif-spec](https://github.com/oasis-tcs/sarif-spec) (`sarif-schema-2.1.0.json`): top level $schema, version, runs, inlineExternalProperties, properties. Run: tool, invocations, artifacts, results, taxonomies, automationDetails, and others. Result: ruleId, ruleIndex, rule, kind, level, message, locations, partialFingerprints, fingerprints, codeFlows, relatedLocations, suppressions, baselineState, rank, fixes, taxa, properties, and others. Rule (reportingDescriptor): id, name, shortDescription, fullDescription, helpUri, help, defaultConfiguration, properties. Real tools fill these differently; a real file from each tool is needed.

### Defender for Cloud Apps discovered apps

Not found on a public page.

### Defender for IoT device inventory export

Not found on a public page.

### endoflife.date API v1

Checked on 2026-11-16 against `https://endoflife.date/api/v1/` (`schema_version` 1.2.1, data generated 2026-11-14) and the OpenAPI file `https://endoflife.date/docs/api/v1/openapi.yml`. The Swagger page at https://endoflife.date/docs/api/v1/ only loads that file in a browser, so the file was read instead.

Endpoints in the OpenAPI file: `/`, `/products`, `/products/full`, `/products/{product}`, `/products/{product}/releases/{release}`, `/products/{product}/releases/latest`, `/categories`, `/categories/{category}`, `/tags`, `/tags/{tag}`, `/identifiers`, `/identifiers/{identifier_type}`. The first four product calls and `releases/latest` were fetched and answered with HTTP 200 and JSON. `/products/` listed 489 products on the check date.

`GET .../products/{product}/` returns `result` with name, aliases, label, category, tags, versionCommand, identifiers (purl and cpe entries, for example `cpe:2.3:o:microsoft:windows` for `windows` and `cpe:2.3:a:microsoft:exchange_server` for `msexchange`) and `releases`. Each release has: name, codename, label, releaseDate, isLts, ltsFrom, isEoas, eoasFrom, isEol, eolFrom, isMaintained, latest (name, date, link) and custom. Some products also carry isEoes and eoesFrom (seen on the Windows release `10-22h2`: `eolFrom` 2025-10-14, `eoesFrom` 2028-10-10). The file describes `isMaintained` as "Whether this release cycle still have some level of support. This can be any level of support, even extended support." The two flags can disagree: `windows` release `10-22h2` returned `isEol` true and `isMaintained` true on the check date. Stenwatch should read `isEol` and `eolFrom` and show `isMaintained` separately. `eolFrom` is null for some releases that are not yet end of life (Apache HTTP Server 2.4, WordPress 6.2).

Slugs: an alias answers with HTTP 301 and a `Location` header to the canonical slug (checked: `google-chrome` to `chrome`, `vmware-esxi` to `esxi`, `jira` to `jira-software`, `apache` to `apache-http-server`). An unknown slug answers HTTP 404 with an HTML page, not JSON. Use the canonical slug from the table below so no redirect is needed.

| Product | Slug | Answered on 2026-11-16 | Release key tried, and what it returned |
|---|---|---|---|
| Windows 10 | `windows` | 200 | `10-22h2`: EOL 2025-10-14, isEol true. `windows-10` returns 404 |
| Windows 11 | `windows` | 200 | Keys carry an edition suffix: `11-23h2-w` (Home and Pro) EOL 2025-11-11, `11-23h2-e` (Enterprise and Education) EOL 2026-11-10, `11-24h2-w` EOL 2026-10-13. `windows-11` returns 404 |
| Windows Server | `windows-server` | 200 | `2019` EOL 2029-01-09, `2022` EOL 2031-10-14, `2016` EOL 2027-01-12 |
| SQL Server | `mssqlserver` | 200 | Keys are engine versions: `15.0` (2019) EOL 2030-01-08, `16.0` (2022) EOL 2033-01-11. `sql-server` returns 404 |
| Exchange Server | `msexchange` | 200 | `2019` EOL 2025-10-14, `2016` EOL 2025-10-14, `subscription` no EOL date. `exchange` returns 404 |
| Office | `office` | 200 | `2019` EOL 2025-10-14, `2021` EOL 2026-10-13 |
| .NET | `dotnet` | 200 | `8` EOL 2026-11-10 (isEol true), `9` EOL 2026-11-10, `10` EOL 2028-11-14. .NET Framework is the separate slug `dotnetfx` (200) |
| Edge | none | not applicable | No product with Edge in its name, alias or label in the product list. Not found on a public page |
| Chrome | `chrome` | 200 | Key is the major version: `157` EOL 2026-11-17, `156` EOL 2026-11-03 (isEol true) |
| Firefox | `firefox` | 200 | Key is the major version: `160` EOL 2026-11-24, `159` EOL 2026-11-10 |
| PHP | `php` | 200 | `8.1` EOL 2025-12-31 (isEol true), `8.2` EOL 2026-12-31 |
| OpenSSL | `openssl` | 200 | `3.0` EOL 2026-09-07, `1.1.1` EOL 2023-09-11 |
| Apache HTTP Server | `apache-http-server` | 200 | `2.4` no EOL date |
| nginx | `nginx` | 200 | `1.24` EOL 2024-04-23, `1.28` EOL 2026-04-14 |
| VMware vCenter Server | `vcenter` | 200 | `7.0` EOL 2025-10-02, `8.0` EOL 2027-10-11. `vmware-vcenter` is an alias and redirects |
| VMware ESXi | `esxi` | 200 | `7.0` EOL 2025-10-02, `8.0` EOL 2027-10-11 |
| Ubuntu | `ubuntu` | 200 | `22.04` EOL 2027-06-01, `24.04` EOL 2029-05-31 |
| Red Hat Enterprise Linux | `rhel` | 200 | `8` EOL 2029-05-31, `9` EOL 2032-05-31. `red-hat-enterprise-linux` returns 404 |

Products in `examples/assets.example.csv` that have a page (slug, release key from the file's version, result on 2026-11-16):

| Asset row (version in the file) | Slug | Release | EOL date returned | isEol |
|---|---|---|---|---|
| Exchange 2019 (`2019`) | `msexchange` | `2019` | 2025-10-14 | true |
| FortiOS (`7.2.4`) | `fortios` | `7.2` | 2026-09-30 | true |
| nginx (`1.24.0`) | `nginx` | `1.24` | 2024-04-23 | true |
| Apache HTTP Server (`2.4.57`) | `apache-http-server` | `2.4` | none | false |
| PHP (`8.1.12`) | `php` | `8.1` | 2025-12-31 | true |
| WordPress (`6.2.2`) | `wordpress` | `6.2` | none returned | false |
| OpenSSL (`3.0.8`) | `openssl` | `3.0` | 2026-09-07 | true |
| MySQL (`8.0.33`) | `mysql` | `8.0` | 2026-04-30 | true |
| Windows Server 2019 and 2022 | `windows-server` | `2019`, `2022` | 2029-01-09, 2031-10-14 | false |
| Veeam Backup & Replication (`12.1.2.172`) | `veeam-backup-and-replication` | `12` | 2027-02-28 | false |
| VMware ESXi (`7.0`) | `esxi` | `7.0` | 2025-10-02 | true |
| VMware vCenter (`7.0`) | `vcenter` | `7.0` | 2025-10-02 | true |
| SQL Server (`2019`) | `mssqlserver` | `15.0` | 2030-01-08 | false |
| SharePoint Server (`2019`) | `sharepoint` | `2019` | 2026-07-14 | true |
| Jira Data Center (`9.4.0`) | `jira-software` | `9.4` | 2025-01-31 | true |
| Confluence Data Center (`8.5.3`) | `confluence` | `8.5` | 2025-12-15 | true |
| GitLab (`16.5.0`) | `gitlab` | `16.5` | 2024-01-18 | true |
| Apache Tomcat (`9.0.80`) | `tomcat` | `9.0` | 2027-03-31 | false |
| Cisco IOS XE (`17.9.4`) | `cisco-ios-xe` | `17.9` | 2026-09-30 | true |
| Windows 11 23H2 | `windows` | `11-23h2-w` or `11-23h2-e` | 2025-11-11 or 2026-11-10 | true |
| Windows 10 22H2 | `windows` | `10-22h2` | 2025-10-14 | true |
| Chrome (`128.0.6613.120`) | `chrome` | `128` | not fetched for this release | |
| macOS 13 | `macos` | `13` | 2025-09-15 | true |
| iOS 17 | `ios` | `17` | 2025-05-13 | true |
| Android 13 | `android` | `13` | 2026-03-02 | true |

Jenkins (`2.426.1`) has the slug `jenkins` (200), but its releases are the current LTS lines (for example `2.555`, `2.568`) and the file's version matches none of them, so no answer can be given for it.

Products in the example asset file with no endoflife.date page (not in the product list on the check date, and the guessed slugs returned 404): Synology DiskStation Manager, SAP NetWeaver AS ABAP, Ivanti Endpoint Manager, Flexera FlexNet Publisher, ArubaOS, FortiClient, Autodesk AutoCAD, Autodesk Revit, Microsoft Edge, Adobe Acrobat Reader DC, 7-Zip, Zoom Meetings. Oracle JRE 8 has no page of its own; the page `oracle-jdk` (a different product) lists release `8` with EOL 2022-03-31, and it should not be treated as the answer for the JRE without a decision.

For these products, and for any asset with no version, Stenwatch must say "not checked", not "supported".


### MITRE ATLAS data

From `dist/v6/ATLAS-2026.10.yaml` (format-version 6.1.0), top-level keys: format-version, collection, matrix, tactics, techniques, mitigations, case-studies, entities, software, relationships. Techniques are keyed by id (for example AML.T0000) with name, description, references, created-date and further fields. The release list is in `dist/manifest.yaml`. The README says the latest file is `dist/ATLAS-latest.yaml`; that path returned only a pointer line to `v6/ATLAS-latest.yaml` on the check date, which in turn pointed to the dated file, so read the file named in `manifest.yaml`.

### ATT&CK for ICS (STIX 2.1)

From `ics-attack/ics-attack.json` in [attack-stix-data](https://github.com/mitre-attack/attack-stix-data): a STIX bundle (`type`, `id`, `objects`). Object types found: x-mitre-collection, campaign, course-of-action, intrusion-set, malware, attack-pattern (127), x-mitre-asset, x-mitre-matrix, x-mitre-tactic (12), x-mitre-analytic, x-mitre-data-component, x-mitre-data-source, x-mitre-detection-strategy, relationship, identity, marking-definition. An attack-pattern has: type, spec_version, id, created, created_by_ref, revoked, external_references, object_marking_refs, modified, name, description, kill_chain_phases, x_mitre_attack_spec_version, x_mitre_deprecated, x_mitre_domains, x_mitre_is_subtechnique, x_mitre_modified_by_ref, x_mitre_platforms, x_mitre_version.

### Teams incoming webhook (Workflows)

Checked on 2026-11-16 on these pages: [Create an Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) (`ms.date` 2026-10-26), [Create incoming webhooks with Workflows](https://support.microsoft.com/en-US/teams/apps-service/create-incoming-webhooks-with-workflows-for-microsoft-teams) and [Microsoft Teams connector](https://learn.microsoft.com/en-us/connectors/teams/).

- **Body for an Adaptive Card message.** The first page gives this payload as the C# sample: `type` "message", `attachments[]` with `contentType` "application/vnd.microsoft.card.adaptive" and `content`, which holds `type` "AdaptiveCard", `$schema` "http://adaptivecards.io/schemas/adaptive-card.json", `version` and `body` (for example one `TextBlock` with `text`). The JavaScript sample on the same page adds `contentUrl` null and uses `version` "1.2". A plain `{"text": "Hello from a webhook workflow!"}` body is also shown on that page as a request the workflow turns into a message. The page says Workflows webhooks support Adaptive Card and MessageCard payloads, that MessageCard "doesn't support interactive HTTP POST action buttons", that all text fields support basic Markdown and that HTML "is ignored and treated as plain text". The request header in the sample is `Content-Type: application/json`.
- **Size limit.** "The message size limit is 28 KB. When the size exceeds 28 KB, you receive an error." The error text and code are not given.
- **Rate.** "If more than four requests are made in a second, the client connection is throttled until the window refreshes for the duration of the fixed rate." The page points to HTTP 429 handling and retry with exponential backoff.
- **Reply.** Not found on a public page. None of the three pages gives the HTTP status code or body the webhook returns on success. The Teams connector page says of the trigger's outputs only that "Output is identical to request body sent to trigger". (A different trigger, the Azure Logic Apps Request trigger, is documented to answer "202 Accepted" when the flow has no Response action; that page does not mention the Teams trigger, so it is not evidence for it.)
- **Authentication choice.** The trigger has the parameter `triggerAuthenticationType`: the flow can be triggered by anyone, any user in the tenant, or only specific users in the tenant. The page says: "Do not pass an authentication token header if you selected the "Anyone" authentication option, or POST requests to the trigger will fail." and for the other two options "you will need to pass an authentication token". The support page says "Each template has a different authentication type". Stenwatch sends no token, so the template must be one with the "Anyone" option; which template names map to which option is not stated beyond the three channel templates below.
- **Steps in Teams (from the Learn page).** In Teams, go to the team and channel. Select More options (...) next to the channel. Select Workflows. Search for and select a template such as "Send webhook alerts to a channel". Configure the parameters. Select Save. Copy the webhook link from the workflow that is then shown. The support page names three channel templates ("Send webhook alerts to a channel", "Send webhook alerts from specific people to a channel", "Send webhook alerts from people in an org to a channel") and the same three for a chat, and says Workflows can be opened "from any entry point" and that the details page of the new workflow shows the URL. Neither page says whether the URL can be shown again later. Neither page says that the URL is a secret, but it works as a credential for posting to the channel, so Stenwatch keeps it in Windows Credential Manager.
- **Ownership.** "Workflows are linked only to specific users (referred to as owners of the workflow) and not to a Teams team or channel." A workflow can stop working if its owner leaves and no co-owner exists. Workflows can be turned off or deleted from the Workflows app, Home, "Your workflows". The Learn page says Workflows webhooks support private channels. The support page says the templates and the webhook trigger need no premium licence.
- **Office 365 connectors.** The Learn page: "Office 365 Connectors in Teams, including connector-based Incoming Webhooks, were retired in May 2026." Old `outlook.office.com/webhook` URLs are not supported by Stenwatch.

### Ticket systems (Jira, ServiceNow, Azure DevOps)

Stenwatch sends one plain JSON object with `Content-Type: application/json` (the fields are in `examples/ticket.example.json`). What each system needs on the customer's side, from the pages named, checked on 2026-11-16:

- **Jira Cloud: a plain JSON POST is enough once the customer has built one automation rule.** The rule uses the trigger "Incoming webhook" and a "Create work item" action. The trigger page says that a unique URL and secret are created, that the flow runs on an HTTP POST, and that the secret goes in the header `X-Automation-Webhook-Token` (or, if the sender cannot set headers, after a slash at the end of the URL; the page recommends the header as more secure). The cURL example uses `Content-type: application/json`. The Regenerate button invalidates the old token. A request that works returns 200 in Postman; the cURL example prints `null`, and the page says to check the audit log to see that the rule ran. Inside the rule, `{{webhookData}}` stands for the POST payload and a property is read by path, for example `{{webhookData.fields.summary}}` ([Atlassian KB](https://support.atlassian.com/jira/kb/use-incoming-webhooks-with-smart-values-in-automation-for-jira/)). Not found on a public page: a payload size limit, the plan or permission needed, and a complete example of a rule that creates a work item from the webhook. The older page [Jira automation triggers](https://support.atlassian.com/cloud-automation/docs/jira-automation-triggers/) describes `{{webhookData}}` as "custom XML data", which does not match the JSON examples on the other two pages; this was not resolved.
- **ServiceNow: a plain JSON POST is enough only if the customer writes a Scripted REST API resource; the Table API needs the field names of the table.** The Table API page says: "Use a POST request to create a new record." (example: the incident table) and "Role required: admin, web_service_admin, or rest_api_explorer"; it does not describe an authentication method, and its request body is the table's own column names, so Stenwatch's fields would have to be named like the table's. A Scripted REST API resource script reads the body with `var body = request.body.data;` ([script samples](https://www.servicenow.com/docs/r/MVRCUFVyKWd7vUoUukbW6g/3LBPBV8ftJn4eB9hZJy8Cg)), so the customer's script can accept any JSON object and create the record. A Flow Designer inbound trigger: not found on a public page that could be read. The authentication needed to call the endpoint, and the response, are not described on the pages read.
- **Azure DevOps: a plain JSON POST is not enough.** Service hooks send events out of Azure DevOps ("send a JSON representation of an Azure DevOps event to any service that has a public endpoint"); the page describes no incoming side. The REST call [Work Items - Create](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create) is `POST https://dev.azure.com/{organization}/{project}/_apis/wit/workitems/${type}?api-version=7.1`, takes the media type `application/json-patch+json`, a body that is an array of operations such as `{"op": "add", "path": "/fields/System.Title", "value": "Sample task"}`, needs the OAuth scope `vso.work_write` and answers 200 with the work item. Stenwatch's object is not that shape. The route that accepts a plain object is a flow that the customer builds with an HTTP request trigger followed by a "create work item" step. The [Azure Logic Apps page](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-http-endpoint) documents the Request trigger: the callback URL carries a shared access signature, an optional JSON schema describes the body, and with no Response action the endpoint "responds immediately with the 202 Accepted status". The Power Automate version of the trigger and its "create a work item" action were not read, so they are not confirmed here.

### Defender advanced hunting tables

From [DeviceTvmSoftwareVulnerabilities](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table) (`ms.date` 2026-06-14), "the Microsoft Defender Vulnerability Management list of vulnerabilities in installed software products". Columns exactly as listed: DeviceId (string), DeviceName (string, "Fully qualified domain name (FQDN) of the device"), OSPlatform (string), OSVersion (string), OSArchitecture (string), SoftwareVendor (string), SoftwareName (string), SoftwareVersion (string), CveId (string), VulnerabilitySeverityLevel (string), RecommendedSecurityUpdate (string), RecommendedSecurityUpdateId (string), CveTags (dynamic, "Array of tags relevant to the CVE; example: ZeroDay, NoSecurityUpdate"). The table has no timestamp column. The page says it is populated from Microsoft Defender for Endpoint, and that the table "isn't ingested into Microsoft Sentinel" (queries there return no results; use Defender advanced hunting). It also says `DeviceTvmSoftwareInventory` and `DeviceTvmSoftwareVulnerabilities` replaced the table `DeviceTvmSoftwareInventoryVulnerabilities`.

From [DeviceTvmSoftwareVulnerabilitiesKB](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table) (`ms.date` 2026-06-14), "the list of vulnerabilities Microsoft Defender Vulnerability Management assesses devices for": CveId (string), CvssScore (string), IsExploitAvailable (boolean), VulnerabilitySeverityLevel (string), LastModifiedTime (datetime), PublishedDate (datetime), VulnerabilityDescription (string), AffectedSoftware (dynamic). Same Sentinel limit.

For "which devices still have this CVE", the first table answers it directly: one row per device, software and CVE, filtered on `CveId`. The second table describes the CVE, not the devices, and joins on `CveId`. Neither page gives an example query. Whether a CVE that has been fixed disappears from the first table on the next assessment is not stated on these pages.

### Windows Task Scheduler and packaged apps

[schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create) (updated 2025-10-22) and the older [Schtasks.exe](https://learn.microsoft.com/en-us/windows/win32/taskschd/schtasks) page:

- `/sc daily` with an optional `/mo` interval (default 1), `/st HH:mm` start time, `/tn` task name ("not exceeding 238 characters"; a folder can be given as `folder name\task name`), `/tr` the program ("The path name must not exceed 262 characters"), `/f` to create and suppress the warning if the task exists. Documented daily example: `schtasks /create /tn MyApp /tr c:\apps\myapp.exe /sc daily /st 08:00`.
- `/ru`: "By default, the task runs with the permissions of the current user of the local computer". `/rl`: LIMITED ("scheduled tasks will be ran with the least level of privileges, such as Standard User accounts") or HIGHEST; "The default value is Limited". `/it`: run "only when the run as user ... is logged on to the computer"; by default the run as user is the current user. `/np`: "No password is stored. The task runs non-interactively as the given user. Only local resources are available."
- The remarks say: "Schtasks always prompts for a password unless you provide one, even when you schedule a task on the local computer using the current user account. This is normal behavior for schtasks." Whether `/it` avoids that prompt is not stated. The page says only Administrators can schedule tasks in the system-account example; it does not say that a standard user cannot create a task for themselves. Not found on these pages: whether creating a task for the current user needs elevation.
- "Schtasks doesn't verify program file locations or user account passwords", so a task with a wrong path is created and fails later.

Packaged (MSIX) apps:

- [uap5:AppExecutionAlias](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap5-appexecutionalias) is "the executable of a UWP app to be activated from a command prompt"; minimum OS Windows 10 version 1709 (build 16299). The `desktop4:Subsystem` attribute is "console" or "windows". Its child `uap5:ExecutionAlias` has `Alias`: "A required string between 1 and 256 characters in length that must end with `.exe`".
- [Packaging extensions](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-extensions), section "Start your application by using an alias": "Users and other processes can use an alias to start your application without having to specify the full path to your app." The XML is a `uap3:Extension` with `Category="windows.appExecutionAlias"`, `Executable` (relative path), `EntryPoint="Windows.FullTrustApplication"` and a `desktop:ExecutionAlias Alias="Contoso.exe"`. "You can only specify a single app execution alias for each application in the package." "If multiple apps register for the same alias, the system will invoke the last one that was registered." Also: "The user can disable the AppExecutionAlias entry for your packaged app in the App execution aliases page in Settings."
- [Package Support Framework shortcut guide](https://learn.microsoft.com/en-us/windows/msix/psf/create-shortcut-with-script-package-support-framework): "the MSIX application path can change, once it has the version number specified in the installation folder", with the example `C:\Program Files\WindowsApps\ContosoExpenses_1.0.0.0_x86__3z09h3y28h0qg`, and "To avoid having to change the application shortcut every time the application is updated, create the shortcut by pointing to the AppExecutionAlias." It points a shortcut at `%localappdata%\Microsoft\WindowsApps\contosoexpenses.exe`.
- Not found on a public Microsoft page: any statement on running an MSIX app, or its alias, from Task Scheduler. The documentation is silent on it. The only material found is a community thread on Microsoft Tech Community ([thread](https://techcommunity.microsoft.com/discussions/msix-discussions/msix-app-execution-alias-from-cannot-be-selected-from-task-scheduler/3805369), no Microsoft employee replied): the poster reports that the alias "cannot be selected" as the task action, with the error "The file cannot be accessed by the system", while it still runs from Explorer and the command line, and that the full `WindowsApps` path gave the same error. The poster's workaround was `cmd` with the task set to "Run only when user is logged on". A community MVP suggested, without testing, that the Task Scheduler service does not see the user's packaged app. These are community reports, not documentation.
- `installer/msix/AppxManifest.template.xml` in this repository declares no execution alias today (searched for `ExecutionAlias`: no match).


### Tenable and Qualys CSV exports

Not found on a public page that could be read. Both products let a customer choose the columns, so the header of a real export decides.

## Exports to pull

For the user. Menu paths below are the best known and are marked where a public page did not confirm them. Portals move menus often; if a path differs, note the real one here. If a file leaves your machine, redact names (user names, device names, tenant and domain names) first. Put the files in `samples/` in the repository root. That folder is git-ignored.

### Phase 2

None beyond the Defender vulnerabilities export you already pull (Defender portal, Vulnerability management, Vulnerabilities, Export). The endoflife.date check and the hunting queries need no export from you. For the Teams post, create the workflow webhook URL when the phase is ready to try: in Teams, the channel's More options (...), Workflows, the template "Send webhook alerts to a channel", then copy the URL (steps and the authentication choice are under Fields, "Teams incoming webhook"). For a ticket push, the Jira, ServiceNow or Azure DevOps side has to be set up by whoever runs that system (see Fields, "Ticket systems").

### Phase 3

- **Intune devices**: Intune admin center, Devices, All devices, Export. Path not confirmed on a public page.
- **Intune discovered apps**: Intune admin center, Apps, Monitor, Discovered apps, Export. Path not confirmed on a public page.
- **Intune update compliance**: Intune admin center, Reports, Windows updates; export the report you use. Path not confirmed on a public page.
- **Entra risky users**: Entra admin center, Protection, Identity Protection, Risky users, Download. Needs Entra ID P2. Path not confirmed on a public page.
- **Entra sign-ins**: Entra admin center, Monitoring and health, Sign-in logs, set a filter and a short date range, Download (CSV). The download option is documented.
- **Entra role assignments** (stale privileged accounts): Entra admin center, Roles and administrators, the role, assignments, Download if offered. Path not found on a public page.
- **Defender for Cloud recommendations**: Azure portal, Defender for Cloud, Recommendations, download the CSV report. Path not confirmed on a public page. Also, for Azure Resource Graph: open a recommendation, Open query, run it in Resource Graph Explorer and download the result as CSV. That path is documented.
- **Defender security recommendations**: Defender portal, Vulnerability management, Recommendations, Export. Path not confirmed on a public page.
- **Secure Score**: Defender portal, Secure score, Recommended actions, Export. Path not confirmed on a public page.
- **Exposure Management**: Defender portal, Hunting, Advanced hunting. Run `ExposureGraphNodes | take 100` and `ExposureGraphEdges | take 100` and export the results to CSV. The query path is documented; the export button is not confirmed on a public page. Also note the attack paths and critical assets pages under Exposure management, in case a direct export exists there.

### Phase 4

- **Defender EASM**: Azure portal, Defender EASM resource, Inventory, filter to the asset types you want, Export. Path not confirmed on a public page.
- **OWASP ZAP and SARIF**: from your own scans. In ZAP, Report, Generate Report, "Traditional JSON Report" and "SARIF JSON Report". For SARIF from other tools, use the tool's own export.

### Phase 5

- **Defender for Cloud Apps discovered apps**: Defender portal, Cloud apps, Cloud discovery, Discovered apps, filter to the generative-AI category, Export. Path not confirmed on a public page.
- **Defender for IoT device inventory**: Defender for IoT, Device inventory, Export. Path not confirmed on a public page.

Tenable and Qualys exports are not scheduled in any phase. Pull one only if you want that import to be considered.

## File imports built in 0.6 (phases 3 to 5)

Checked 2026-11-16. No real export from a tenant was available, so these readers were built from public material and from fictional files, and the rule at the top of this page ("built only against a format someone has seen") is relaxed for them by the user's decision. Each file in `examples/imports/` is fictional (Example Organisation values, `example-org.invalid` names, documentation IP ranges) and is the test input in `ImportTests.cs`. One button on Integrations (Import) and one CLI flag (`--import FILE`) read all of them; the format is recognised from the file's own keys or headings. Names are compared with case, spaces and punctuation removed, so the Graph property `riskLevel` and a portal heading "Risk level" are the same column.

| Format | Component | Shape the reader was built from | Example file | Status |
|---|---|---|---|---|
| OWASP ZAP traditional JSON report | Web apps | The sample on the ZAP documentation page | `zap-report.example.json` | From documentation only (public sample) |
| SARIF 2.1.0 | Web apps | The schema, and `simple-example.sarif` from microsoft/sarif-tutorials, which was downloaded and imported | `code-scan.example.sarif` | Read one real public file |
| Entra risky users | Identity | Graph `riskyUser` list response (`value[]`) | `entra-risky-users.example.json` | From documentation only |
| Intune devices | Misconfiguration | Graph `managedDevice` list response | `intune-devices.example.json` | From documentation only |
| Defender security recommendations | Misconfiguration | Defender API "List all recommendations" response | `defender-recommendations.example.json` | From documentation only |
| Defender for Cloud assessments | Cloud workloads | Azure Resource Graph `securityresources`, type `microsoft.security/assessments`, as `az graph query` writes it (`data[]`) | `defender-for-cloud.example.json` | From documentation only |
| Exposure Management graph nodes | Attack surface | Advanced hunting table `ExposureGraphNodes` exported as CSV, `NodeProperties` as a JSON cell | `exposure-graph-nodes.example.csv` | From documentation only |
| Defender EASM assets | Attack surface | EASM data-plane API "List asset resource" response | `easm-assets.example.json` | From documentation only |
| Defender for Cloud Apps discovered apps | AI discovery | No public column list. Headings assumed: Name, Category, Risk score, Users, Last seen, Tags | `cloud-apps-discovered.example.csv` | Columns assumed |
| Defender for IoT device inventory | OT and IoT | No public column list. Headings assumed: Name, Type, Vendor, Model, Firmware version, Purdue level, Site, Authorization, Last activity | `iot-device-inventory.example.csv` | Columns assumed |

The two "columns assumed" formats are marked so on Integrations and in the import's own note. A real export with other headings will be refused as "not a format Stenwatch knows" rather than read wrongly; send the header line and the reader gets the real names.

What each reader keeps as a finding: risky users in state atRisk or confirmedCompromised; devices that are noncompliant or not encrypted; active recommendations of type ConfigurationChange with exposed devices (software updates stay with the CVE findings); unhealthy assessments; graph nodes that carry `exposedToInternet` or `IsInternetFacing`; confirmed EASM assets (High when a CVE id is on a web component, else Low); ZAP alerts above Informational; SARIF results that are not suppressed, one per rule and file; discovered apps in the Generative AI category (the 0 to 10 risk score is turned round, 10 being the lowest risk); OT devices that are unauthorised or have no firmware version.

Not built: live Graph, Defender and Azure API pulls (no tenant to test against), Secure Score, Intune update compliance, Entra role assignments, Exposure Management edges on the Attack paths page, the EASM result feeding the internet-facing flag of the asset list, MITRE ATLAS and ATT&CK for ICS context.
