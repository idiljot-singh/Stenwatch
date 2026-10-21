# 1. Hybrid cloud SaaS on Azure: the pipeline stays local, only ranked Findings go up

Status: accepted (demo and learning project, not a certified service)

## Decision
Stenwatch keeps running locally. A small agent (`saas/upload.py`) sends the ranked **Findings** to a hosted **Dashboard** on Azure App Service (`saas/app.py`). **Organisation data** (profile, assets, suppliers, exceptions) never leaves the organisation. Asset names are replaced by keyed pseudonyms (`asset-3fa9c1b27d04`) before upload, using a secret that stays on the customer machine and is never sent (the server knows the tenant key, so that key cannot be the alias key), so even the hosted copy cannot be read as a map of the estate.

[Data-flow diagram](../diagrams/hybrid-saas.html): customer network, trust boundary, Azure EU region.

## Why hybrid
`SECURITY.md` says Stenwatch holds "a map of which vulnerable software an organisation runs". In a full SaaS that map would sit with the provider for every customer, which makes the provider the most attractive breach target. Hybrid removes that map from the cloud. What is left (CVE id, tier, risk, a short reason, a pseudonymous label) is useful for a shared view and low-value to an attacker.

## Rejected
- **Full SaaS (upload assets):** simplest for users, but holds every customer's vulnerable-software map. Larger breach impact, harder GDPR and NIS2 story.
- **Single-tenant deployment per customer:** strong isolation, but cost and operations per customer are too high for a one-person project.

## Threat model (STRIDE)
| Threat | Example | Control |
|---|---|---|
| Spoofing | Someone posts as another tenant | 256-bit random tenant key, stored only as SHA-256, constant-time compare |
| Spoofing | Forged sign-in header | `X-MS-CLIENT-PRINCIPAL-NAME` trusted only when `STENWATCH_TRUST_EASYAUTH=1` **and** App Service reports Easy Auth enabled (`WEBSITE_AUTH_ENABLED`), otherwise the app refuses; the dev user is never honoured on App Service; the Entra app registration must be single-tenant |
| Tampering | Malformed or oversized upload | Exact field set, per-field validators, 1 MB and 2000-row caps; unknown fields rejected; `why` limited to a plain-text vocabulary with no IP addresses; the agent only sends over HTTPS |
| Repudiation | "I never uploaded that" | Audit log of upload, view, erase and auth failures with tenant id, never payloads |
| Information disclosure | Cross-tenant read | Every query filters by the tenant resolved from the key or the signed-in user; tested |
| Information disclosure | Asset names reaching the cloud | Agent pseudonymises; server accepts `asset-xxxxxx` only, so a real name is rejected |
| Denial of service | Flooding uploads | Request size cap, 30 uploads/min per tenant (per process) |
| Elevation / injection | Hostile text in `why` rendered in the page | HTML-escaped on output, strict CSP (`default-src 'none'`), `nosniff`, no inline script |

## Azure concepts used (for the learner)
- **Resource group:** a folder for everything in this project; delete it to remove everything.
- **App Service plan and Web App:** the plan is the rented machine, the Web App is your code on it. Free (F1) or the student B1 tier is enough.
- **Easy Auth (Entra ID):** the platform signs users in before your code runs and passes the identity in a header. You write no login code.
- **Managed identity and Key Vault:** the app gets its own identity, so secrets are not pasted into settings. Not needed for the demo (the only secret is per-tenant keys, held as hashes), needed once the app holds a real secret.
- **Budget alert:** Cost Management email when spend passes a small amount. Set before anything else.
- **Region:** an EU region only (Sweden Central or West Europe).

## EU compliance: what the design does, what a real launch would still need
| Area | Already in the design | Still needed for a real service |
|---|---|---|
| GDPR data minimisation | No personal data in Findings, no asset names; only the viewer's Entra identity | Records of processing, lawful-basis note per customer |
| GDPR rights | `DELETE /api/tenant` erases all tenant data | A process for access and deletion requests by viewers |
| Data location | EU region only | Check logs and backups stay in region |
| Processor terms | Microsoft's DPA covers Azure as sub-processor | DPA between the service and each customer, DPIA |
| NIS2 (supplier risk) | Small attack surface, audit log, no customer asset map | Incident reporting process, supplier due-diligence pack |
| Cyber Resilience Act | Dependency audit (`pip-audit`), static analysis (`bandit`), security policy | Vulnerability handling process, SBOM, support period |
| Certification | None | ISO 27001 or SOC 2 path |

This is a demo. It is not certified, and no real organisation data should be uploaded.

## Known ceilings
- SQLite on App Service `/home`: single instance only. Upgrade to Azure Database for PostgreSQL when scaling out.
- Rate limit is per process. Use the gateway's limiter if scaled out.
- Auth failures are logged but not rate-limited (keys are 256-bit, so guessing is infeasible); add an IP limit at the gateway if that changes.
- Alias collisions: 48-bit aliases make a clash among a few thousand assets negligible, not impossible.
- The viewer is matched on the (lower-cased) name claim; match the immutable object id for real use.
- One tenant maps to one viewer email. Real use needs a users table and roles.

## Future work
Billing, accounts and invitations, multi-region, hosted feed collection, per-tenant encryption keys, AI-written explanations (tried as a local beta and dropped: it only reworded the rules' own summary).
