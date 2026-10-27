using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Stenwatch.Core;

/// <summary>CTI stage 5 - Dissemination: CSV (tools), Markdown (people), STIX 2.1 (sharing), HTML dashboard.</summary>
public static class Disseminate
{
    public const string Banner = "**TLP:AMBER**: limited disclosure, organisation and clients on a need-to-know basis only.";
    public static readonly string[] Tiers = { "Act", "Attend", "Track", "Ignore" };

    static List<string> Table(List<Ranked> rows, int top)
    {
        if (rows.Count == 0) return new() { "None." };
        var md = new List<string> { "| # | Tier | Risk | CVE | Asset | Why |", "|---|---|---|---|---|---|" };
        md.AddRange(rows.Take(top).Select((r, i) =>
            $"| {i + 1} | {r.Tier} | {Py.Repr(r.Risk)} | [{r.Cve}](https://nvd.nist.gov/vuln/detail/{r.Cve}) | {r.Asset.Name} | {r.Why} |"));
        return md;
    }

    static Dictionary<string, int> Count<T>(IEnumerable<T> xs, Func<T, string> key)
    {
        var d = new Dictionary<string, int>();
        foreach (var x in xs) d[key(x)] = d.GetValueOrDefault(key(x)) + 1;
        return d;
    }

    /// <summary>report.csv, report.md and report.html.</summary>
    public static void WriteReports(List<Ranked> ranked, string outDir, Profile profile, int top = 50,
                                    List<Ranked>? suppressed = null, List<Decision>? expired = null, DateOnly? today = null)
    {
        suppressed ??= new(); expired ??= new();
        var date = (today ?? DateOnly.FromDateTime(DateTime.Today)).ToString("yyyy-MM-dd");
        Directory.CreateDirectory(outDir);
        Pipeline.WriteCsv(Path.Combine(outDir, "report.csv"), ranked);

        var owned = ranked.Where(r => !r.Asset.ThirdParty).ToList();
        var third = ranked.Where(r => r.Asset.ThirdParty).ToList();
        var tiers = Count(ranked, r => r.Tier);
        int T(string t) => tiers.GetValueOrDefault(t);
        var urgent = ranked.Where(r => r.Tier is "Act" or "Attend").ToList();

        var perAsset = new Dictionary<string, Dictionary<string, int>>(); // insertion order = first appearance
        foreach (var r in ranked)
        {
            if (!perAsset.TryGetValue(r.Asset.Name, out var c)) perAsset[r.Asset.Name] = c = new();
            c[r.Tier] = c.GetValueOrDefault(r.Tier) + 1;
        }

        // ATT&CK view: what an attacker achieves through our urgent CVEs
        var tactics = new SortedDictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var r in urgent)
            foreach (var t in r.Techniques)
                foreach (var tac in t.Tactics.Split(',').Where(x => x != ""))
                {
                    if (!tactics.TryGetValue(tac, out var s)) tactics[tac] = s = new(StringComparer.Ordinal);
                    s.Add($"{t.Id} {t.Name}");
                }
        var cited = Count(ranked.SelectMany(r => r.CitedBy), g => g);

        var org = profile.Organisation;
        var md = new List<string> {
            $"# CVE Priority Report: {org.Name}, {date}", "", Banner, "",
            $"Threat profile: {org.Sector}, {org.Country}; {profile.ThreatGroups.Count} tracked threat groups.", "",
            "## Decision summary", "", "| Tier | Findings | Action |", "|---|---|---|" };
        md.AddRange(Tiers.Select(t => $"| **{t}** | {T(t)} | {Analyse.Action[t]} |"));
        md.AddRange(new[] { "",
            $"- **Owned assets:** {owned.Count} CVEs, and {owned.Count(r => r.F.Kev)} of them are known-exploited (KEV).",
            $"- **Third parties:** {third.Count} recent CVEs in supplier products, and {third.Count(r => r.F.Kev)} of them are known-exploited.",
            "", "## Per asset", "", "| Asset | " + string.Join(" | ", Tiers) + " |", "|---|---|---|---|---|" });
        md.AddRange(perAsset.OrderBy(x => -x.Value.GetValueOrDefault("Act")).ThenBy(x => -x.Value.GetValueOrDefault("Attend"))
            .Select(x => $"| {x.Key} | " + string.Join(" | ", Tiers.Select(t => x.Value.GetValueOrDefault(t))) + " |"));
        md.AddRange(new[] { "", "## Threat profile hits", "", "Profiled groups known (per MITRE ATT&CK) to exploit CVEs present in our estate:", "" });
        md.AddRange(cited.Count > 0 ? cited.OrderByDescending(x => x.Value).Select(x => $"- **{x.Key}**: {x.Value} finding(s)") : new[] { "- None." });
        md.AddRange(new[] { "", "## ATT&CK view of Act + Attend findings", "",
            "What an attacker could achieve through our urgent vulnerabilities (CTID KEV→ATT&CK mappings):", "", "| Tactic | Techniques |", "|---|---|" });
        md.AddRange(tactics.Count > 0 ? tactics.Select(x => $"| {x.Key} | {string.Join(", ", x.Value)} |") : new[] { "| n/a | no mapped techniques |" });
        md.AddRange(new[] { "", $"## Owned assets: top {top} by risk", "" }); md.AddRange(Table(owned, top));
        md.AddRange(new[] { "", "## Third-party risk", "",
            "CVEs in products our suppliers run for us. We can't patch these ourselves. " +
            "**Action:** ask the supplier to confirm the patch status, and restrict their access until they do.", "" });
        md.AddRange(Table(third, top));
        md.AddRange(new[] { "", "## Finding details: Act and Attend", "", "What each urgent finding is, how likely it is to be used, by whom, and what to do.", "" });
        int n = 0;
        foreach (var r in urgent.Take(top))
        {
            n++;
            md.AddRange(new[] { $"### {n}. {r.Cve} · {r.Asset.Name} · {r.Tier} (risk {Py.Repr(r.Risk)})", "", r.Summary.Replace("|", "/"), "",
                "**Diamond Model** (projected intrusion, not an observed event)", "", "| Vertex | |", "|---|---|" });
            var d = r.Diamond;
            md.AddRange(new[] { ("Adversary", d.Adversary), ("Capability", d.Capability), ("Infrastructure", d.Infrastructure), ("Victim", d.Victim), ("Phase", d.Phase) }
                .Select(k => $"| {k.Item1} | {k.Item2.Replace("|", "/")} |"));
            md.AddRange(new[] { "", "**Defend (MITRE D3FEND):** " + string.Join("; ", r.Defend.Select(x =>
                $"{x.Tactic}: [{x.Name}](https://d3fend.mitre.org/technique/d3f:{x.Name.Replace(" ", "")}/) ({x.Id})")), "" });
            if (r.Mitigations.Count > 0)
                md.AddRange(new[] { "**ATT&CK mitigations:** " + string.Join("; ", r.Mitigations.Select(m => $"[{m.Name}](https://attack.mitre.org/mitigations/{m.Id}/) ({m.Id})")), "" });
            md.AddRange(new[] { $"[NVD](https://nvd.nist.gov/vuln/detail/{r.Cve}) · score terms: {r.Why}", "" });
        }
        if (urgent.Count == 0) md.Add("None.");
        md.AddRange(new[] { "", "## Feedback: exceptions", "", $"{suppressed.Count} findings suppressed by analyst decisions in `exceptions.csv`.", "" });
        if (suppressed.Count > 0)
        {
            md.AddRange(new[] { "| CVE | Asset | Status | Until | Note |", "|---|---|---|---|---|" });
            md.AddRange(suppressed.Select(r => $"| {r.Cve} | {r.Asset.Name} | {r.Decision!.Status} | {(r.Decision.Until != "" ? r.Decision.Until : "no expiry")} | {r.Decision.Note} |"));
        }
        if (expired.Count > 0)
            md.AddRange(new[] { "", $"**{expired.Count} exception(s) expired; those findings are back in the ranking for review:** "
                + string.Join(", ", expired.Select(e => $"{e.Cve} ({e.Asset}, until {e.Until})")) });
        var text = string.Join("\n", md);
        File.WriteAllText(Path.Combine(outDir, "report.md"), text + "\n", new UTF8Encoding(false));
        Render.WritePage(text, Path.Combine(outDir, "report.html"), "Intelligence report", org.Name, date,
            Tiers.Select(t => (t, T(t), Analyse.Action[t])));
    }

    /// <summary>Management brief. LLM output is display-only: it is labelled as such and nothing reads it back.</summary>
    public static void WriteBrief(string text, string source, string outDir, Profile profile, DateOnly? today = null)
    {
        var date = (today ?? DateOnly.FromDateTime(DateTime.Today)).ToString("yyyy-MM-dd");
        var label = source.StartsWith("template") ? "Generated from a fixed template (no AI)."
            : $"**AI-generated draft ({source}). Verify against report.md before sending.**";
        var md = string.Join("\n", new[] { $"# Weekly CVE Brief: {profile.Organisation.Name}, {date}", "", Banner, "", label, "", text, "" });
        File.WriteAllText(Path.Combine(outDir, "brief.md"), md, new UTF8Encoding(false));
        Render.WritePage(text, Path.Combine(outDir, "brief.html"), "Weekly management brief", profile.Organisation.Name, date, note: label);
    }

    // ---------- STIX 2.1 ----------
    // fixed namespace -> same object, same id every run
    const string TlpAmber = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";

    /// <summary>RFC 4122 UUID v5, as Python's uuid.uuid5.</summary>
    public static string Uuid5(string name)
    {
        var ns = Guid.Parse("6f0c2b43-2a55-4c1e-9d3e-5b1c1a7e2f10").ToString("N");
        var nsBytes = Convert.FromHexString(ns);
        var data = nsBytes.Concat(Encoding.UTF8.GetBytes(name)).ToArray();
        var h = SHA1.HashData(data)[..16];
        h[6] = (byte)((h[6] & 0x0F) | 0x50); h[8] = (byte)((h[8] & 0x3F) | 0x80);
        var x = Convert.ToHexString(h).ToLowerInvariant();
        return $"{x[..8]}-{x[8..12]}-{x[12..16]}-{x[16..20]}-{x[20..]}";
    }

    /// <summary>Deterministic STIX id, so re-importing into MISP/OpenCTI updates objects instead of duplicating them.</summary>
    public static string Sid(string kind, string key) => $"{kind}--{Uuid5(key)}";

    public static int WriteStix(List<Ranked> ranked, string outDir, Profile profile, string[]? tiers = null)
    {
        tiers ??= new[] { "Act", "Attend" };
        var org = profile.Organisation;
        var now = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
        var meId = Sid("identity", org.Name);
        var objs = new Dictionary<string, JsonObject>(); var rels = new Dictionary<string, JsonObject>();

        JsonObject Obj(string id, string type, params (string, JsonNode?)[] props)
        {
            var o = new JsonObject { ["type"] = type, ["spec_version"] = "2.1", ["id"] = id, ["created"] = now, ["modified"] = now };
            foreach (var (k, v) in props) if (v is not null) o[k] = v;
            return o;
        }
        JsonObject Common(string id, string type, params (string, JsonNode?)[] props)
        {
            var o = Obj(id, type, props);
            o["created_by_ref"] = meId; o["object_marking_refs"] = new JsonArray(TlpAmber);
            return o;
        }
        JsonArray Ext(string source, string id) => new(new JsonObject { ["source_name"] = source, ["external_id"] = id });
        string Add(JsonObject o) { objs.TryAdd(o["id"]!.GetValue<string>(), o); return o["id"]!.GetValue<string>(); }
        void Rel(string src, string kind, string dst, string? description = null)
        {
            var id = Sid("relationship", $"{src}|{kind}|{dst}");
            rels.TryAdd(id, Common(id, "relationship", ("relationship_type", kind), ("description", description), ("source_ref", src), ("target_ref", dst)));
        }

        var me = Obj(meId, "identity", ("name", org.Name), ("identity_class", "organization"));
        me["object_marking_refs"] = new JsonArray(TlpAmber);
        objs[meId] = me;
        var groupIds = profile.ThreatGroups.ToDictionary(kv => kv.Value, kv => kv.Key);

        foreach (var r in ranked.Where(r => tiers.Contains(r.Tier)))
        {
            var d = r.F.Description; if (d.Length > 1000) d = d[..1000];
            var vuln = Add(Common(Sid("vulnerability", r.Cve), "vulnerability", ("name", r.Cve), ("description", d),
                ("external_references", Ext("cve", r.Cve))));
            var a = r.Asset;
            var owner = a.ThirdParty ? $"Supplier-operated ({a.Type})" : "Owned";
            var infra = Add(Common(Sid("infrastructure", a.Name), "infrastructure", ("name", a.Name), ("description", $"{owner}: {a.Cpe} {a.Version}".Trim())));
            Rel(infra, "has", vuln, $"{r.Tier} | risk {Py.Repr(r.Risk)} | {r.Summary}");
            foreach (var g in r.CitedBy)
                Rel(Add(Common(Sid("intrusion-set", g), "intrusion-set", ("name", g),
                    ("external_references", groupIds.TryGetValue(g, out var gid) ? Ext("mitre-attack", gid) : null))), "targets", vuln);
            foreach (var x in r.Defend) // D3FEND countermeasure mitigates the vulnerability
                Rel(Add(Common(Sid("course-of-action", x.Id), "course-of-action", ("name", $"{x.Name} ({x.Id})"),
                    ("description", $"MITRE D3FEND {x.Tactic}"), ("external_references", Ext("mitre-d3fend", x.Id)))), "mitigates", vuln);
            foreach (var t in r.Techniques)
                Rel(Add(Common(Sid("attack-pattern", t.Id), "attack-pattern", ("name", t.Name), ("external_references", Ext("mitre-attack", t.Id)))), "targets", vuln);
        }

        var tlp = new JsonObject { ["type"] = "marking-definition", ["spec_version"] = "2.1", ["id"] = TlpAmber, ["created"] = "2017-01-20T00:00:00.000Z",
            ["definition_type"] = "tlp", ["name"] = "TLP:AMBER", ["definition"] = new JsonObject { ["tlp"] = "amber" } };
        var bundle = new JsonObject { ["type"] = "bundle", ["id"] = "bundle--" + Guid.NewGuid(),
            ["objects"] = new JsonArray(new[] { tlp }.Concat(objs.Values).Concat(rels.Values).Select(o => (JsonNode)o).ToArray()) };
        File.WriteAllText(Path.Combine(outDir, "bundle.json"), bundle.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        return objs.Count + rels.Count;
    }

    // ---------- HTML dashboard ----------
    public static void WriteDashboard(List<Ranked> ranked, string outDir, Profile profile, DateOnly? today = null)
    {
        var rows = new JsonArray(ranked.Select(r => (JsonNode)new JsonObject
        {
            ["tier"] = r.Tier, ["risk"] = r.Risk, ["cve"] = r.Cve, ["asset"] = r.Asset.Name, ["source"] = r.Asset.ThirdParty ? "third-party" : "owned",
            ["kev"] = r.F.Kev, ["epss"] = Py.Round3(r.F.Epss), ["cvss"] = r.F.Cvss, ["groups"] = string.Join(", ", r.CitedBy), ["why"] = r.Why,
            ["summary"] = r.Summary, ["cwe"] = Analyse.Cwes(r.F), ["published"] = r.F.Published[..Math.Min(10, r.F.Published.Length)],
            ["techniques"] = new JsonArray(r.Techniques.Select(t => (JsonNode)$"{t.Id} {t.Name}").ToArray()),
            ["diamond"] = new JsonObject { ["adversary"] = r.Diamond.Adversary, ["capability"] = r.Diamond.Capability, ["infrastructure"] = r.Diamond.Infrastructure,
                ["victim"] = r.Diamond.Victim, ["phase"] = r.Diamond.Phase },
            ["defend"] = new JsonArray(r.Defend.Select(d => (JsonNode)new JsonArray(d.Id, d.Name, d.Tactic)).ToArray()),
            ["mitigations"] = new JsonArray(r.Mitigations.Select(m => (JsonNode)new JsonArray(m.Id, m.Name)).ToArray()),
        }).ToArray());
        // data goes into a <script> block: escape "</" so hostile feed text can't close the tag
        var data = rows.ToJsonString().Replace("</", "<\\/");
        var date = (today ?? DateOnly.FromDateTime(DateTime.Today)).ToString("yyyy-MM-dd");
        var page = Render.Resource("dashboard.html").Replace("__ORG__", Render.Esc(profile.Organisation.Name)).Replace("__DATE__", date).Replace("__DATA__", data);
        File.WriteAllText(Path.Combine(outDir, "dashboard.html"), page, new UTF8Encoding(false));
    }

    // ---------- ATT&CK Navigator layer ----------
    /// <summary>A layer file for the ATT&amp;CK Navigator: one cell per technique, scored by the number of Act and Attend findings that enable it.</summary>
    public static void WriteNavigator(List<Ranked> ranked, string outDir, Profile profile)
    {
        var urgent = ranked.Where(r => r.Tier is "Act" or "Attend").ToList();
        var counts = urgent.SelectMany(r => r.Techniques.Select(t => (t.Id, r.Cve))).GroupBy(x => x.Id).ToDictionary(g => g.Key, g => g.Select(x => x.Cve).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList());
        var max = Math.Max(1, counts.Values.Select(v => v.Count).DefaultIfEmpty(1).Max());
        var layer = new JsonObject
        {
            ["name"] = $"Stenwatch: {profile.Organisation.Name}", ["versions"] = new JsonObject { ["navigator"] = "5.1.0", ["layer"] = "4.5" },
            ["domain"] = "enterprise-attack", ["description"] = "Techniques enabled by Act and Attend findings (CTID KEV mappings). TLP:AMBER.",
            ["gradient"] = new JsonObject { ["colors"] = new JsonArray("#ffe9b0", "#ff4d5e"), ["minValue"] = 0, ["maxValue"] = max },
            ["techniques"] = new JsonArray(counts.OrderBy(x => x.Key, StringComparer.Ordinal).Select(kv => (JsonNode)new JsonObject
                { ["techniqueID"] = kv.Key, ["score"] = kv.Value.Count, ["comment"] = string.Join(", ", kv.Value.Take(10)) }).ToArray()),
        };
        File.WriteAllText(Path.Combine(outDir, "attack-layer.json"), layer.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
    }

    // ---------- attack paths ----------
    public static void WritePaths(PathResult paths, string outDir, Profile profile, DateOnly? today = null)
    {
        var date = (today ?? DateOnly.FromDateTime(DateTime.Today)).ToString("yyyy-MM-dd");
        var md = new List<string> { $"# Possible attack paths: {profile.Organisation.Name}, {date}", "", Banner, "",
            "Each path is **possible, not proven**. Reachability comes from the link table you maintain; exploit feasibility is assumed from the vulnerability's capability class (CVSS vector or ATT&CK tactic). The likelihood is the product of each step's exploitation likelihood and is a ranking aid, not a probability of attack.", "" };
        if (paths.Paths.Count == 0) md.Add("No path from the internet to a crown-jewel asset was found with the current links and evidence.");
        foreach (var p in paths.Paths)
        {
            md.AddRange(new[] { $"## To {p.Target}: likelihood {Py.Repr(Math.Round(p.Likelihood, 4))}, {p.Length} step(s)", "", p.Describe(), "", "| Step | Asset | Vulnerability | Allows | Basis |", "|---|---|---|---|---|" });
            md.AddRange(p.Hops.Select((h, i) => $"| {i + 1} | {h.Asset} | [{h.Cve}](https://nvd.nist.gov/vuln/detail/{h.Cve}) | {h.Cap} | {h.Basis} |"));
            md.Add("");
        }
        var text = string.Join("\n", md);
        File.WriteAllText(Path.Combine(outDir, "paths.md"), text + "\n", new UTF8Encoding(false));
        Render.WritePage(text, Path.Combine(outDir, "paths.html"), "Possible attack paths", profile.Organisation.Name, date);
    }
}
