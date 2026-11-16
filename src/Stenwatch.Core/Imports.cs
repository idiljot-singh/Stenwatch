using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Stenwatch.Core;

/// <summary>What one import did: the format it was read as, the component it feeds, records read and findings kept.</summary>
public record ImportResult(string Format, string Component, int Read, int Findings, string Note);

/// <summary>One file format Stenwatch can import as exposure rows. Basis says where the field names come from: a public sample or the vendor's API reference
/// ("documented"), or nothing public ("assumed": the column names are a guess until a real export has been read, see docs/formats.md).</summary>
public record ImportFormat(string Name, string Component, string Kind, string Basis);

/// <summary>File imports for the components that are not CVEs on an asset (phases 3 to 5). One entry point, <see cref="Run"/>: the format is recognised from the
/// file's own keys or column headings, never from its name. Keys are compared with case, spaces and punctuation removed, so the Graph property "riskLevel" and a
/// portal heading "Risk level" are the same column. Every reader produces <see cref="Exposure"/> rows; the tier comes from Exposure.Rank only.
/// ponytail: one tolerant reader per format, no live Graph or Azure calls; add the API pulls when there is a tenant to test them against.</summary>
public static class Imports
{
    public const string Documented = "documented", Assumed = "assumed";

    public static readonly ImportFormat[] Formats =
    {
        new("OWASP ZAP report", "Web apps", "JSON", Documented),
        new("SARIF file", "Web apps", "JSON", Documented),
        new("Entra risky users", "Identity", "JSON or CSV", Documented),
        new("Intune devices", "Misconfiguration", "JSON or CSV", Documented),
        new("Defender security recommendations", "Misconfiguration", "JSON or CSV", Documented),
        new("Defender for Cloud", "Cloud workloads", "JSON or CSV", Documented),
        new("Exposure Management", "Attack surface", "CSV or JSON", Documented),
        new("Defender EASM", "Attack surface", "JSON", Documented),
        new("Defender for Cloud Apps", "AI discovery", "CSV", Assumed),
        new("Defender for IoT", "OT and IoT", "CSV", Assumed),
    };

    /// <summary>The day a format was last imported into this data folder, or null.</summary>
    public static DateTime? Last(string data, ImportFormat f) => File.Exists(Exposure.FileFor(data, f.Component, f.Name)) ? File.GetLastWriteTime(Exposure.FileFor(data, f.Component, f.Name)) : null;

    static string K(string s) => new(s.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
    /// <summary>First non-empty value among alternatives: G(r, "compliancestate|compliance").</summary>
    static string G(Dictionary<string, string> r, string keys) => keys.Split('|').Select(k => r.GetValueOrDefault(k, "").Trim()).FirstOrDefault(v => v != "") ?? "";
    static bool Has(Dictionary<string, string> r, params string[] keys) => keys.All(alt => alt.Split('|').Any(r.ContainsKey));
    static bool Yes(string v) => K(v) is "true" or "yes" or "y" or "1";
    static bool No(string v) => K(v) is "false" or "no" or "n" or "0";
    static string Day(string v) => v.Length >= 10 && DateTime.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d.ToString("yyyy-MM-dd") : "";
    static string Cut(string s, int n) => s.Length <= n ? s : s[..n].TrimEnd() + "...";
    static double Num(string v) => double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : 0;
    static string Str(JsonNode? n) => n is null ? "" : n is JsonValue ? n.ToString() : n.ToJsonString();

    /// <summary>A JSON object as one flat row: nested names are joined ("properties.status.code" is "propertiesstatuscode"); an array becomes its items joined by ", ".</summary>
    static void Flat(JsonNode? n, string prefix, Dictionary<string, string> d)
    {
        if (n is JsonObject o) foreach (var (k, v) in o) Flat(v, prefix + K(k), d);
        else if (n is JsonArray a) d[prefix] = string.Join(", ", a.Select(Str));
        else d[prefix] = Str(n);
    }

    static List<Dictionary<string, string>> Table(string text, JsonNode? json)
    {
        if (json is null)
        {
            var first = text.Split('\n')[0];
            var rows = Csv.Parse(text, first.Count(c => c == ';') > first.Count(c => c == ',') ? ';' : ',');
            if (rows.Count == 0) return new();
            var head = rows[0].Select(K).ToList();
            return rows.Skip(1).Select(r => { var d = new Dictionary<string, string>(); for (var i = 0; i < head.Count; i++) if (head[i] != "") d[head[i]] = i < r.Count ? r[i] : ""; return d; }).ToList();
        }
        var list = json as JsonArray ?? (json is JsonObject o ? new[] { "value", "data", "Results", "results" }.Select(k => o[k]).OfType<JsonArray>().FirstOrDefault() : null) ?? new JsonArray(json.DeepClone());
        return list.Select(x => { var d = new Dictionary<string, string>(); Flat(x, "", d); return d; }).ToList();
    }

    /// <summary>Read one file, recognise its format, replace that format's rows for its component in <paramref name="saveTo"/> and say what happened.
    /// Throws InvalidDataException with a plain sentence when the file is not one of the known formats or cannot be read as CSV or JSON.</summary>
    public static ImportResult Run(string path, string saveTo)
    {
        var text = File.ReadAllText(path);
        JsonNode? json = null;
        if (text.TrimStart().StartsWith('{') || text.TrimStart().StartsWith('['))
            try { json = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }); }
            catch (JsonException e) { throw new InvalidDataException($"{Path.GetFileName(path)} looks like JSON but cannot be read: {e.Message}"); }

        string name; int read; List<Exposure> rows;
        if (json is JsonObject zo && zo["site"] is JsonArray sites) { name = "OWASP ZAP report"; rows = Zap(zo, sites, out read); }
        else if (json is JsonObject so && so["runs"] is JsonArray runs) { name = "SARIF file"; rows = Sarif(runs, out read); }
        else
        {
            var table = Table(text, json); read = table.Count;
            var r0 = table.FirstOrDefault() ?? new();
            var known = new (string Name, bool Is, Func<Dictionary<string, string>, IEnumerable<Exposure>> Map)[]
            {
                ("Entra risky users", Has(r0, "userprincipalname", "risklevel"), RiskyUser),
                ("Intune devices", Has(r0, "devicename", "compliancestate|compliance"), IntuneDevice),
                ("Defender security recommendations", Has(r0, "recommendationname", "exposedmachinescount|exposeddevices"), Recommendation),
                ("Defender for Cloud", Has(r0, "propertiesdisplayname|recommendationname", "propertiesstatuscode|recommendationstate"), CloudAssessment),
                ("Exposure Management", Has(r0, "nodename", "nodelabel"), GraphNode),
                ("Defender EASM", Has(r0, "kind", "uuid"), EasmAsset),
                ("Defender for Cloud Apps", Has(r0, "name|appname|app", "category", "riskscore|score"), CloudApp),
                ("Defender for IoT", Has(r0, "purduelevel") || Has(r0, "firmwareversion|firmware", "vendor"), IotDevice),
            };
            var hit = known.FirstOrDefault(k => k.Is);
            if (hit.Name is null) throw new InvalidDataException($"{Path.GetFileName(path)} is not a format Stenwatch knows. It reads: {string.Join(", ", Formats.Select(f => f.Name))}. The list of columns for each is in docs/formats.md.");
            name = hit.Name; rows = table.SelectMany(hit.Map).ToList();
        }
        var f = Formats.First(x => x.Name == name);
        // one row per item and asset: Remediation and History key on that pair
        rows = rows.GroupBy(e => (e.ItemId, e.Asset)).Select(g => g.First()).ToList();
        Exposure.Save(saveTo, f.Component, rows, f.Name);
        return new(f.Name, f.Component, read, rows.Count, $"{f.Name}: {read:N0} records read, {rows.Count:N0} findings for {f.Component}"
            + (f.Basis == Assumed ? ". The column names for this format are assumed, not confirmed against a real export: check the rows." : ""));
    }

    // ---------- public sample formats ----------
    /// <summary>ZAP traditional JSON report: one row per site and alert above "Informational". The URL is left out of the evidence on purpose (the ladder reads evidence words).</summary>
    static List<Exposure> Zap(JsonObject root, JsonArray sites, out int read)
    {
        var rows = new List<Exposure>(); read = 0; var day = Day(Str(root["created"]));
        foreach (var site in sites.OfType<JsonObject>())
            foreach (var a in (site["alerts"] as JsonArray ?? new()).OfType<JsonObject>())
            {
                read++;
                var risk = (int)Num(Str(a["riskcode"])); if (risk < 1) continue;
                var first = (a["instances"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault();
                var where = first is null ? "" : $"; first: {Str(first["method"])} parameter \"{Cut(Str(first["param"]), 40)}\"";
                rows.Add(new("", Str(site["@name"]), "zap:" + Str(a["pluginid"]), Str(a["name"]) is { Length: > 0 } n ? n : Str(a["alert"]), new[] { "", "Low", "Medium", "High" }[Math.Min(risk, 3)],
                    $"{Str(a["count"])} instance(s), CWE-{Str(a["cweid"])}, confidence {Str(a["confidence"])} of 4{where}", "OWASP ZAP", day));
            }
        return rows;
    }

    /// <summary>SARIF 2.1.0: one row per rule and file. Severity is the rule's "security-severity" (0 to 10) when the tool gives one; without it an error is Medium and anything else Low.</summary>
    static List<Exposure> Sarif(JsonArray runs, out int read)
    {
        var rows = new List<Exposure>(); read = 0;
        foreach (var run in runs.OfType<JsonObject>())
        {
            var driver = run["tool"]?["driver"] as JsonObject; var tool = Str(driver?["name"]);
            var rules = (driver?["rules"] as JsonArray ?? new()).OfType<JsonObject>().ToList();
            var hits = new List<(string Rule, string Uri, string Line, string Text, string Sev)>();
            foreach (var x in (run["results"] as JsonArray ?? new()).OfType<JsonObject>())
            {
                read++;
                if (Str(x["kind"]) is "pass" or "notApplicable" or "informational" || x["suppressions"] is JsonArray { Count: > 0 }) continue;
                var id = Str(x["ruleId"]) is { Length: > 0 } rid ? rid : Str(x["rule"]?["id"]);
                var rule = rules.FirstOrDefault(r => Str(r["id"]) == id) ?? (x["ruleIndex"] is JsonValue ix && ix.TryGetValue<int>(out var i) && i >= 0 && i < rules.Count ? rules[i] : null);
                var level = Str(x["level"]) is { Length: > 0 } l ? l : Str(rule?["defaultConfiguration"]?["level"]) is { Length: > 0 } dl ? dl : "warning";
                var score = Str(rule?["properties"]?["security-severity"]);
                var loc = (x["locations"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()?["physicalLocation"];
                hits.Add((id, Str(loc?["artifactLocation"]?["uri"]), Str(loc?["region"]?["startLine"]), Str(x["message"]?["text"]),
                    score != "" ? score : level == "error" ? "Medium" : "Low")); // no security score: a linter's "error" is not a high-severity weakness
            }
            rows.AddRange(hits.GroupBy(h => (h.Rule, h.Uri)).Select(g => new Exposure("", g.Key.Uri == "" ? tool : g.Key.Uri, "sarif:" + g.Key.Rule, Cut(g.First().Text, 160), g.First().Sev,
                $"{tool}, rule {g.Key.Rule}, {g.Count()} result(s)" + (g.First().Line != "" ? $", first at line {g.First().Line}" : ""), "SARIF", "")));
        }
        return rows;
    }

    // ---------- documented Microsoft API shapes ----------
    /// <summary>Graph riskyUser: users at risk or confirmed compromised. Dismissed, remediated and confirmed-safe users are not findings.</summary>
    static IEnumerable<Exposure> RiskyUser(Dictionary<string, string> r)
    {
        var state = K(G(r, "riskstate")); if (state is not ("atrisk" or "confirmedcompromised")) yield break;
        var level = G(r, "risklevel"); var detail = G(r, "riskdetail");
        yield return new("", G(r, "userprincipalname"), "entra:risky-user", $"Risky user ({level} risk)", level,
            (state == "atrisk" ? "at risk" : "confirmed compromised") + (K(detail) is "" or "none" ? "" : $"; {detail}"), "Entra risky users", Day(G(r, "risklastupdateddatetime|risklastupdated")));
    }

    /// <summary>Graph managedDevice: a device that is not compliant, and a device whose storage is not encrypted.</summary>
    static IEnumerable<Exposure> IntuneDevice(Dictionary<string, string> r)
    {
        var name = G(r, "devicename"); var what = $"{G(r, "operatingsystem|os")} {G(r, "osversion")}".Trim(); var day = Day(G(r, "lastsyncdatetime|lastcheckin"));
        if (K(G(r, "compliancestate|compliance")) == "noncompliant") yield return new("", name, "intune:noncompliant", "Device not compliant with Intune policy", "High", $"{what}; state noncompliant", "Intune", day);
        if (No(G(r, "isencrypted|encrypted"))) yield return new("", name, "intune:not-encrypted", "Device storage not encrypted", "Medium", $"{what}; isEncrypted false", "Intune", day);
    }

    /// <summary>Defender Vulnerability Management recommendations: active configuration changes with exposed devices. Software updates are left to the CVE findings.</summary>
    static IEnumerable<Exposure> Recommendation(Dictionary<string, string> r)
    {
        var exposed = (int)Num(G(r, "exposedmachinescount|exposeddevices"));
        if (exposed == 0 || G(r, "status") is { Length: > 0 } st && K(st) != "active" || G(r, "remediationtype") is { Length: > 0 } t && K(t) != "configurationchange") yield break;
        var score = Num(G(r, "severityscore")); var exploit = Yes(G(r, "publicexploit"));
        // worded so that only the internet-facing tag meets the ladder's "reachable from the internet" words
        var ev = $"{exposed} of {G(r, "totalmachinecount")} devices affected" + (exploit ? "; exploit code is available" : "") + (Yes(G(r, "activealert")) ? "; active alert" : "")
            + (K(G(r, "tags")).Contains("internetfacing") ? "; internet-facing devices among them" : "");
        var name = G(r, "recommendationname");
        yield return new("", G(r, "relatedcomponent|productname") is { Length: > 0 } c ? c : name, G(r, "id") is { Length: > 0 } id ? id : "rec:" + K(name), name,
            score > 0 ? score.ToString(CultureInfo.InvariantCulture) : exploit ? "High" : "Medium", ev, "Defender recommendations", "");
    }

    /// <summary>Defender for Cloud assessments from Azure Resource Graph (type microsoft.security/assessments): the unhealthy ones, one per resource.</summary>
    static IEnumerable<Exposure> CloudAssessment(Dictionary<string, string> r)
    {
        if (K(G(r, "propertiesstatuscode|recommendationstate")) != "unhealthy") yield break;
        var res = G(r, "propertiesresourcedetailsid|resourceid|id");
        var cut = res.IndexOf("/providers/Microsoft.Security/", StringComparison.OrdinalIgnoreCase); if (cut > 0) res = res[..cut];
        var title = G(r, "propertiesdisplayname|recommendationname");
        yield return new("", res.TrimEnd('/').Split('/').Last(), G(r, "name|recommendationid") is { Length: > 0 } id ? "mdc:" + id : "mdc:" + K(title), title,
            G(r, "propertiesmetadataseverity|propertiesstatusseverity|recommendationseverity|severity"),
            "unhealthy" + (G(r, "propertiesmetadatacategories|category") is { Length: > 0 } c ? $"; category {c}" : ""), "Defender for Cloud",
            Day(G(r, "propertiesstatusfirstevaluationdate|propertiestimegenerated")));
    }

    /// <summary>Exposure Management ExposureGraphNodes: nodes that carry exposedToInternet (or IsInternetFacing); vulnerableToRCE raises the severity.
    /// The property is read as present or absent, as the documented queries do (isnotnull).</summary>
    static IEnumerable<Exposure> GraphNode(Dictionary<string, string> r)
    {
        var blob = string.Concat(r.Select(kv => kv.Key + " " + K(kv.Value) + " "));
        if (!blob.Contains("exposedtointernet") && !blob.Contains("isinternetfacing")) yield break;
        var rce = blob.Contains("vulnerabletorce"); var esc = blob.Contains("vulnerabletoprivilegeescalation");
        yield return new("", G(r, "nodename"), "xm:internet-exposed", $"Internet-exposed {G(r, "nodelabel")}" + (rce ? ", vulnerable to remote code execution" : esc ? ", vulnerable to privilege escalation" : ""),
            rce || esc ? "High" : "Medium", "exposed to the internet" + (rce ? "; vulnerable to remote code execution" : "") + (esc ? "; vulnerable to privilege escalation" : ""), "Exposure Management", "");
    }

    /// <summary>Defender EASM asset list (data-plane API): every confirmed asset is internet-facing by definition; CVE ids seen on its web components raise it to High.</summary>
    static IEnumerable<Exposure> EasmAsset(Dictionary<string, string> r)
    {
        if (G(r, "state") is { Length: > 0 } s && K(s) != "confirmed") yield break;
        var cves = r.Values.SelectMany(v => Regex.Matches(v, @"CVE-\d{4}-\d+").Select(m => m.Value)).Distinct().Take(8).ToList();
        var kind = G(r, "kind"); var name = G(r, "name|displayname");
        yield return new("", name, "easm:" + K(kind), $"Internet-facing {kind}" + (cves.Count > 0 ? " with known-vulnerable web components" : ""), cves.Count > 0 ? "High" : "Low",
            $"internet-facing {kind}" + (cves.Count > 0 ? "; CVE ids on its web components: " + string.Join(", ", cves) : ""), "Defender EASM", Day(G(r, "updateddate|createddate")));
    }

    // ---------- no public column list: assumed headings ----------
    /// <summary>Defender for Cloud Apps discovered apps, generative-AI category only. Its risk score runs from 0 to 10 where 10 is the lowest risk, so it is turned round.</summary>
    static IEnumerable<Exposure> CloudApp(Dictionary<string, string> r)
    {
        if (!K(G(r, "category")).Contains("generativeai")) yield break;
        var score = Num(G(r, "riskscore|score")); var name = G(r, "name|appname|app");
        yield return new("", name, "ai:discovered-app", $"Generative AI app in use: {name}", score <= 3 ? "High" : score <= 6 ? "Medium" : "Low",
            $"{G(r, "users|usercount")} users; risk score {G(r, "riskscore|score")} of 10 (10 is the lowest risk)" + (G(r, "tags|tag") is { Length: > 0 } t ? $"; {t}" : ""), "Defender for Cloud Apps", Day(G(r, "lastseen|lastused")));
    }

    /// <summary>Defender for IoT device inventory: an unauthorised device, and a device whose firmware version is not known (it cannot be checked for vulnerabilities).</summary>
    static IEnumerable<Exposure> IotDevice(Dictionary<string, string> r)
    {
        var name = G(r, "name|devicename"); var day = Day(G(r, "lastactivity|lastseen"));
        var what = $"{G(r, "type|devicetype")}, {G(r, "vendor")} {G(r, "model")}".Trim(' ', ',') + (G(r, "purduelevel") is { Length: > 0 } p ? $", Purdue level {p}" : "") + (G(r, "site") is { Length: > 0 } s ? $", site {s}" : "");
        var auth = K(G(r, "authorization|authorized|isauthorized"));
        if (auth is "unauthorized" or "false" or "no") yield return new("", name, "iot:unauthorized", "Unauthorised device on the OT network", "High", what, "Defender for IoT", day);
        if (G(r, "firmwareversion|firmware") == "") yield return new("", name, "iot:no-firmware", "Firmware version not known: cannot be checked for vulnerabilities", "Medium", what, "Defender for IoT", day);
    }
}
