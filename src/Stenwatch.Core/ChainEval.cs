using System.Globalization;
using System.Text;

namespace Stenwatch.Core;

/// <summary>Test 2 of docs/evaluation.md: does ATT&amp;CK improve attack-path interpretation?
/// Input is chains.csv: documented intrusions with a source URL per chain. Columns:
/// chain_id, source_url, kind (step|distractor), order, asset, cve, internet_facing, tactics (ATT&amp;CK tactics separated by ';'), vector, linked_from.
/// A step row is one host the report says the attacker took over, in order; steps are linked in sequence. Distractor rows are extra hosts with
/// extra vulnerabilities and links the report does not use; a path through one is a false path.</summary>
public static class ChainEval
{
    public record Variant(string Name, PathOptions Options);
    public record ChainResult(string Chain, string Variant, double Precision, double Recall, bool FalsePath, bool Found);

    public static readonly Variant[] Variants =
    {
        new("vector only", new PathOptions(UseAttack: false, UseVector: true)),
        new("ATT&CK only", new PathOptions(UseAttack: true, UseVector: false)),
        new("vector + ATT&CK", new PathOptions(UseAttack: true, UseVector: true)),
        new("assume network-exploitable", new PathOptions(UseAttack: false, UseVector: false, UnknownAs: Cap.Network)),
    };

    public static List<ChainResult> Run(string chainsCsv, Profile p)
    {
        var rows = Csv.ReadDict(chainsCsv);
        var res = new List<ChainResult>();
        foreach (var chain in rows.GroupBy(r => r["chain_id"]))
        {
            if (chain.Any(r => r.GetValueOrDefault("source_url", "").Trim() == ""))
                throw new InvalidDataException($"chain {chain.Key}: every row needs a source_url; unsourced chains are not evidence");
            var steps = chain.Where(r => r["kind"] == "step").OrderBy(r => int.Parse(r["order"], CultureInfo.InvariantCulture)).ToList();
            var ctx = new OrgContext(); var findings = new List<Finding>(); var threat = new Threat();
            foreach (var r in chain)
            {
                var a = new Asset(r["asset"], "cpe:2.3:a:x:" + r["asset"], "1", 1, IsYes(r["internet_facing"]), false);
                var f = new Finding(a, r["cve"], 9.0, "", "", 0.5, true, false, "", null, "", r.GetValueOrDefault("vector", ""));
                findings.Add(f);
                var tactics = r.GetValueOrDefault("tactics", "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (tactics.Length > 0) threat.Techniques[r["cve"]] = new() { new Technique("T-" + r["cve"], "mapped", string.Join(",", tactics)) };
                if (r.GetValueOrDefault("linked_from", "") != "") ctx.Links.Add(new Link(r["linked_from"], r["asset"]));
            }
            for (int i = 1; i < steps.Count; i++) ctx.Links.Add(new Link(steps[i - 1]["asset"], steps[i]["asset"]));
            var target = steps[^1]["asset"]; ctx.Assets[target] = new AssetContext(target, CrownJewel: true);
            var documented = steps.Select(s => s["asset"]).ToList(); var distractors = chain.Where(r => r["kind"] == "distractor").Select(r => r["asset"]).ToHashSet();

            foreach (var v in Variants)
            {
                var (ranked, paths) = Analyse.RankWithPaths(findings, p, threat, ctx, v.Options);
                var path = paths!.Paths.FirstOrDefault(x => x.Target == target);
                var hops = path?.Hops.Select(h => h.Asset).ToList() ?? new();
                int hit = hops.Count(documented.Contains);
                res.Add(new(chain.Key, v.Name, hops.Count == 0 ? 0 : (double)hit / hops.Count, (double)hit / documented.Count, hops.Any(distractors.Contains), path != null));
            }
        }
        return res;
    }

    static bool IsYes(string s) => new[] { "y", "yes", "true", "1" }.Contains(s.Trim().ToLowerInvariant());

    /// <summary>Per variant: mean hop precision and recall, false paths, and the pre-registered label.
    /// Validated: ATT&amp;CK (alone or with vectors) has higher recall than vector-only at no worse precision on at least 4 chains.</summary>
    public static string Report(List<ChainResult> r)
    {
        var chains = r.Select(x => x.Chain).Distinct().ToList();
        var sb = new StringBuilder("# Test 2: attack-path interpretation\n\n");
        if (chains.Count < 5) { sb.AppendLine($"**Not run.** {chains.Count} sourced chain(s) supplied; the pre-registered test needs at least 5."); return sb.ToString(); }
        sb.AppendLine("| Variant | Chains with a path | Mean hop precision | Mean hop recall | Chains with a false path |\n|---|---|---|---|---|");
        foreach (var g in r.GroupBy(x => x.Variant))
            sb.AppendLine($"| {g.Key} | {g.Count(x => x.Found)} of {chains.Count} | {g.Average(x => x.Precision):0.00} | {g.Average(x => x.Recall):0.00} | {g.Count(x => x.FalsePath)} |");
        int better = chains.Count(c =>
        {
            var vec = r.First(x => x.Chain == c && x.Variant == "vector only");
            return new[] { "ATT&CK only", "vector + ATT&CK" }.Any(n => { var a = r.First(x => x.Chain == c && x.Variant == n); return a.Recall > vec.Recall && a.Precision >= vec.Precision; });
        });
        sb.AppendLine($"\nATT&CK beat vector-only on recall at no worse precision on {better} of {chains.Count} chains. Result: **{(better >= 4 ? "Validated" : "Not shown")}**.");
        return sb.ToString();
    }
}

/// <summary>Test 3 of docs/evaluation.md: are technique-specific recommendations rated better than a generic baseline? Blind rating sheet.</summary>
public static class RatingSheet
{
    /// <summary>The five mitigations seen most often across all findings: the "generic advice" baseline.</summary>
    public static List<string> Generic(IEnumerable<Ranked> all) =>
        all.SelectMany(r => r.Mitigations).GroupBy(m => $"{m.Name} ({m.Id})").OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(5).Select(g => g.Key).ToList();

    /// <summary>Writes a sheet (list_1, list_2 in random order, blank ratings) and a separate key. -> number of findings sampled.</summary>
    public static int Export(IReadOnlyList<Ranked> all, string sheetPath, string keyPath, int n = 30, int seed = 11)
    {
        var rnd = new Random(seed); var generic = "Software Update (D3-SU); " + string.Join("; ", Generic(all));
        var pool = all.Where(r => r.Techniques.Count > 0 && r.Tier != "Ignore").OrderBy(r => r.Cve, StringComparer.Ordinal).ThenBy(r => r.Asset.Name, StringComparer.Ordinal).OrderBy(_ => rnd.Next()).Take(n).ToList();
        var sheet = new List<string[]> { new[] { "id", "cve", "asset_type", "list_1", "list_2", "rating_1", "rating_2" } }; var key = new List<string[]> { new[] { "id", "list_1_is" } };
        for (int i = 0; i < pool.Count; i++)
        {
            var r = pool[i]; var specific = string.Join("; ", r.Defend.Take(6).Select(d => $"{d.Name} ({d.Id})").Concat(r.Mitigations.Take(3).Select(m => $"{m.Name} ({m.Id})")));
            bool first = rnd.Next(2) == 0;
            sheet.Add(new[] { (i + 1).ToString(), r.Cve, r.Asset.ThirdParty ? "supplier" : "owned", first ? specific : generic, first ? generic : specific, "", "" });
            key.Add(new[] { (i + 1).ToString(), first ? "specific" : "generic" });
        }
        Csv.Write(sheetPath, sheet); Csv.Write(keyPath, key);
        return pool.Count;
    }

    /// <summary>Mean rating of specific vs generic, with a paired-bootstrap 95% interval. Validated needs the interval's lower bound above 0.5 points.</summary>
    public static (int Rated, double Specific, double Generic, double Low, double High, string Label) Import(string sheetPath, string keyPath)
    {
        var key = Csv.ReadDict(keyPath).ToDictionary(r => r["id"], r => r["list_1_is"]);
        var diffs = new List<double>(); double s = 0, g = 0;
        foreach (var r in Csv.ReadDict(sheetPath))
        {
            if (!double.TryParse(r["rating_1"], NumberStyles.Float, CultureInfo.InvariantCulture, out var a) || !double.TryParse(r["rating_2"], NumberStyles.Float, CultureInfo.InvariantCulture, out var b)) continue;
            var (spec, gen) = key[r["id"]] == "specific" ? (a, b) : (b, a);
            diffs.Add(spec - gen); s += spec; g += gen;
        }
        if (diffs.Count < 30) return (diffs.Count, 0, 0, 0, 0, "Not run");
        var rnd = new Random(5); var means = Enumerable.Range(0, 1000).Select(_ => Enumerable.Range(0, diffs.Count).Average(_ => diffs[rnd.Next(diffs.Count)])).Order().ToList();
        double lo = means[25], hi = means[974];
        return (diffs.Count, s / diffs.Count, g / diffs.Count, lo, hi, lo > 0.5 ? "Validated" : "Proposed");
    }
}
