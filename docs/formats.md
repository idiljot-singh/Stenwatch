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
| endoflife.date API (v1) | Per product and release: end-of-life date and whether it is still maintained | Public API, no export: `https://endoflife.date/api/v1/products/{product}/` and `.../releases/{release}` | [API v1 documentation](https://endoflife.date/docs/api/v1/); a live `releases` response was read on the check date | 2026-11-16 | From documentation only |
| MITRE ATLAS data | Tactics, techniques, mitigations, case studies and relationships for attacks on AI systems | Public download: `dist/ATLAS-latest.yaml` in the data repository | [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data); the 2026.10 file (format 6.1.0) was read | 2026-11-16 | From documentation only |
| MITRE ATT&CK for ICS (STIX 2.1) | Techniques, tactics, groups, mitigations and relationships for industrial control systems | Public download: `ics-attack/ics-attack.json` in the STIX data repository | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data); the current file was read | 2026-11-16 | From documentation only |
| Microsoft Teams incoming webhook (Workflows) | Not read: Stenwatch posts the briefing or a ticket card to it | In Teams, the Workflows app, the trigger "When a Teams webhook request is received" gives the URL | [Create incoming webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook). The page states that Office 365 connector webhooks were retired in May 2026 | 2026-11-16 | From documentation only |
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

Read live on 2026-11-16: `GET https://endoflife.date/api/v1/products/python/releases/3.9` returns `schema_version`, `generated_at`, `result` with name, codename, label, releaseDate, isLts, ltsFrom, isEoas, eoasFrom, isEol, eolFrom, isMaintained, latest (name, date, link) and custom. `GET https://endoflife.date/api/v1/products/python/` returns `result` with name, aliases, label, category, tags, versionCommand, identifiers (purl entries) and the releases. The Swagger page at https://endoflife.date/docs/api/v1/ could not be read as text.

### MITRE ATLAS data

From `dist/v6/ATLAS-2026.10.yaml` (format-version 6.1.0), top-level keys: format-version, collection, matrix, tactics, techniques, mitigations, case-studies, entities, software, relationships. Techniques are keyed by id (for example AML.T0000) with name, description, references, created-date and further fields. The release list is in `dist/manifest.yaml`. The README says the latest file is `dist/ATLAS-latest.yaml`; that path returned only a pointer line to `v6/ATLAS-latest.yaml` on the check date, which in turn pointed to the dated file, so read the file named in `manifest.yaml`.

### ATT&CK for ICS (STIX 2.1)

From `ics-attack/ics-attack.json` in [attack-stix-data](https://github.com/mitre-attack/attack-stix-data): a STIX bundle (`type`, `id`, `objects`). Object types found: x-mitre-collection, campaign, course-of-action, intrusion-set, malware, attack-pattern (127), x-mitre-asset, x-mitre-matrix, x-mitre-tactic (12), x-mitre-analytic, x-mitre-data-component, x-mitre-data-source, x-mitre-detection-strategy, relationship, identity, marking-definition. An attack-pattern has: type, spec_version, id, created, created_by_ref, revoked, external_references, object_marking_refs, modified, name, description, kill_chain_phases, x_mitre_attack_spec_version, x_mitre_deprecated, x_mitre_domains, x_mitre_is_subtechnique, x_mitre_modified_by_ref, x_mitre_platforms, x_mitre_version.

### Teams incoming webhook (Workflows)

From [the page](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook), the payload posted to the workflow URL is JSON: `type` "message", `attachments[]` with `contentType` "application/vnd.microsoft.card.adaptive", `contentUrl` null and `content` (an Adaptive Card with `$schema`, `type` "AdaptiveCard", `version` and `body`). The page says Workflows webhooks accept Adaptive Card and MessageCard payloads and that MessageCard does not support interactive action buttons.

### Tenable and Qualys CSV exports

Not found on a public page that could be read. Both products let a customer choose the columns, so the header of a real export decides.

## Exports to pull

For the user. Menu paths below are the best known and are marked where a public page did not confirm them. Portals move menus often; if a path differs, note the real one here. If a file leaves your machine, redact names (user names, device names, tenant and domain names) first. Put the files in `samples/` in the repository root. That folder is git-ignored.

### Phase 2

None beyond the Defender vulnerabilities export you already pull (Defender portal, Vulnerability management, Vulnerabilities, Export). The endoflife.date check, the Teams post and the hunting queries need no export from you. For the Teams post, create the workflow webhook URL in Teams (Workflows app, "When a Teams webhook request is received") when the phase is ready to try.

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
