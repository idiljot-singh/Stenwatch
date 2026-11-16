# Daily operation

Run the morning triage on a schedule, post the briefing to Teams, push fix actions to your ticket system, flag software that is past end of life, and get a Defender hunting query for each urgent finding. This guide describes what the plan for version 0.3 contains. Each part works only once that version has it; the app says so where a part is missing.

## Set it up once
1. **Watched folder and time.** Integrations (the plug icon in the toolbar), the schedule row: pick the folder where you save the Defender export (`export-tvm-vulnerabilities*.xlsx`, as in [MORNING-TRIAGE.md](MORNING-TRIAGE.md)) and a daily time. Each morning the scheduled run takes the **newest export in that folder** and does what **Run triage** does. Output goes to `out/triage/` in the data folder.
2. **Windows Task Scheduler** does the starting. The task is meant to run as you, without administrator rights. Whether it also runs when you are signed out is not settled in this version.
3. **Store edition.** Microsoft's pages describe an alias that starts a packaged app's program by name, and recommend it because the package folder name changes with every update. They say nothing about starting a packaged app from Task Scheduler, and a community report says it failed for one developer ([details](../formats.md)). So the schedule is tried on a real Store install first. If it does not work there, the schedule is offered in the Setup edition only, and the app says so.
4. **Teams.** In Teams, open the channel's **More options (...)**, **Workflows**, choose the template **Send webhook alerts to a channel**, set where it posts, **Save**, and copy the URL it shows. Choose a template whose authentication is "Anyone": Stenwatch sends no sign-in token, and Microsoft says a request with a token header fails on "Anyone" and a request without one fails on the other options. The workflow belongs to the person who made it; if they leave and nobody else owns it, it stops. Teams accepts at most 28 KB per message and about four requests a second.
5. **Paste the URL** on the Integrations page, in the Teams row. It is stored in **Windows Credential Manager**, never in a file in the data folder. Treat the URL like a password: anyone who has it can post to that channel. Old Office 365 connector URLs (retired by Microsoft in May 2026) do not work.
6. **Ticket webhook.** One URL, the same way, in the ticketing row of Integrations. You choose the format there: a Teams card, or a plain JSON object for Jira, ServiceNow or Azure DevOps.

## What a ticket push sends
- **Push to ticket** on a task in Remediation posts **one task**: task id, item (the CVE), asset, tier, deadline, owner, the reason the rule gave, and a link. See [`examples/ticket.example.json`](../../examples/ticket.example.json) (fictional).
- It does not send anything else about your estate. Nothing is read back except a ticket reference, if the reply has one. The task shows its state (Not sent, Sent, Failed) and the **Tickets** page lists the pushed ones.
- **Your ticket system has to be ready for it.** Stenwatch cannot create the rule for you:
  - **Jira Cloud**: an automation rule with the trigger "Incoming webhook" and a "Create work item" action that reads the fields, for example `{{webhookData.asset}}`. The secret goes in the header `X-Automation-Webhook-Token` or at the end of the URL.
  - **ServiceNow**: a Scripted REST API resource you write that reads the JSON body and creates the record. The built-in Table API wants your table's own column names, not these fields.
  - **Azure DevOps**: it does not accept a plain JSON object. Build a flow (Power Automate or Azure Logic Apps) with an HTTP request trigger that creates the work item, and use its URL.
  - Sources and what was not found: [formats.md](../formats.md).
- Try the format with `examples/ticket.example.json` only against a test project. It is fictional and the example URL does not exist.

## End-of-life software
- The asset list (name, product, version) is checked against [endoflife.date](https://endoflife.date). Software past its end-of-life date becomes a finding in **Findings** and fills the **End-of-life** tile on Coverage.
- **A fixed product map** links a product to its endoflife.date page. A product outside the map is **not checked**. In the Example Organisation, Microsoft Edge, Synology DSM, SAP NetWeaver and 7-Zip have no endoflife.date page at all.
- **An asset with no version is "not checked", never "supported".** The same for a version that matches none of the page's release lines.
- The tier comes from a fixed rule, not from a model, and the rule is not validated against outcomes.
- Limits you will meet: Windows releases are listed per edition (Home and Pro end earlier than Enterprise and Education), and a file with only "Windows 11 23H2" does not say which; support for some products is still running through extended updates after the end-of-life date.
- To try it: **Example Organisation** includes Exchange 2019, Windows 10 22H2, PHP 8.1, nginx 1.24, ESXi 7.0 and others past their dates.

## Hunting queries (KQL)
- Each **Act** finding gets a **Hunting query (KQL)** button. The query asks Microsoft Defender advanced hunting which devices still have that CVE, using the table `DeviceTvmSoftwareVulnerabilities`. Queries are saved with the reports.
- They are **templates**. Stenwatch fills in the CVE id and **does not run them against your tenant**; it has no access to it. Open Defender, Hunting, Advanced hunting, paste the query and run it yourself.
- The table needs Defender for Endpoint, and it does not return data in Microsoft Sentinel. The columns are the ones Microsoft documents; the queries were not run against a live tenant.

## Limits, stated plainly
- Briefing delivery is a Teams post or a ready-to-send email file. Sending mail directly needs a mail server and is not part of this.
- A webhook reply is not read except for a reference. Whether a Teams post reached the channel is whatever the HTTP answer says; Microsoft does not document that reply.
- Nothing here has been run against a real Teams, Jira, ServiceNow or Azure DevOps. These are tested against the documented shapes.
