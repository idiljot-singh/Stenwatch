namespace Stenwatch.Core;

/// <summary>How a vulnerability can be used to move through the estate. Network = exploitable remotely with no foothold,
/// Pivot = exploitable over the network from a host the attacker already controls, Local = needs to be on the host already.</summary>
public enum Cap { Network, Pivot, Local, Unknown }

/// <summary>Which evidence the path engine may use to decide what a vulnerability allows. The switches exist so the value of
/// ATT&amp;CK mappings can be tested by ablation (see docs/evaluation.md): same graph, with and without them.</summary>
public record PathOptions(bool UseAttack = true, bool UseVector = true, Cap UnknownAs = Cap.Local, int MaxHops = 6);

/// <summary>One step of a possible path: the asset the attacker takes over and the vulnerability they would use.</summary>
public record Hop(string Asset, string Cve, Cap Cap, double Likelihood, string Basis);

/// <summary>A possible path from the internet to a target. "Possible" because link reachability comes from the link table,
/// and exploit feasibility is assumed from the capability class; neither is verified.</summary>
public record AttackPath(string Target, List<Hop> Hops, double Likelihood)
{
    public int Length => Hops.Count;
    public string Describe() => "Internet > " + string.Join(" > ", Hops.Select(h => $"{h.Asset} ({h.Cve})"));
}

/// <summary>Result of path analysis for an estate.</summary>
public class PathResult
{
    public List<AttackPath> Paths = new();                                   // best path to each target
    public Dictionary<string, int> Hops = new();                             // asset -> shortest hop count from the internet (1 = directly exposed)
    public Dictionary<string, AttackPath> BestTo = new();                    // asset -> its best path (every reachable asset)
    public Dictionary<string, int> OnPaths = new();                          // cve|asset -> number of target paths using it
    public bool Reachable(string asset) => Hops.ContainsKey(asset);
}

public static class AttackPaths
{
    /// <summary>Capability of one finding under the given options, with the evidence it was based on.</summary>
    public static (Cap Cap, string Basis) Capability(Ranked r, PathOptions o)
    {
        if (o.UseVector && r.F.Vector != "")
        {
            var av = r.F.Vector.Split('/').FirstOrDefault(p => p.StartsWith("AV:"))?[3..];
            var pr = r.F.Vector.Split('/').FirstOrDefault(p => p.StartsWith("PR:"))?[3..];
            switch (av)
            {
                case "N": return (pr == "N" ? Cap.Network : Cap.Pivot, $"CVSS vector {r.F.Vector.Split('/').FirstOrDefault(p => p.StartsWith("AV:"))}/PR:{pr}");
                case "A": return (Cap.Pivot, "CVSS vector AV:A (adjacent network)");
                case "L" or "P": return (Cap.Local, $"CVSS vector AV:{av} (local or physical)");
            }
        }
        if (o.UseAttack && r.Techniques.Count > 0)
        {
            var tactics = r.Techniques.SelectMany(t => t.Tactics.Split(',')).ToHashSet();
            if (tactics.Contains("initial-access")) return (Cap.Network, "ATT&CK initial access (" + string.Join(", ", r.Techniques.Where(t => t.Tactics.Contains("initial-access")).Select(t => t.Id)) + ")");
            if (tactics.Contains("lateral-movement")) return (Cap.Pivot, "ATT&CK lateral movement (" + string.Join(", ", r.Techniques.Where(t => t.Tactics.Contains("lateral-movement")).Select(t => t.Id)) + ")");
            return (Cap.Local, "ATT&CK mapping shows only post-exploitation tactics");
        }
        return (o.UnknownAs, "no capability evidence; assumed " + o.UnknownAs);
    }

    /// <summary>Dijkstra over assets, where taking over asset N costs -ln(likelihood of its best usable vulnerability).
    /// The best path is the one with the highest product of per-hop likelihoods.</summary>
    public static PathResult Build(OrgContext ctx, IReadOnlyList<Ranked> findings, PathOptions? opt = null)
    {
        opt ??= new PathOptions();
        var res = new PathResult();
        var byAsset = findings.GroupBy(r => r.Asset.Name).ToDictionary(g => g.Key, g => g.ToList());
        var assets = findings.Select(r => r.Asset).GroupBy(a => a.Name).ToDictionary(g => g.Key, g => g.First());

        // best usable vulnerability on an asset for a given kind of access
        Hop? Best(string asset, bool fromInternet)
        {
            if (!byAsset.TryGetValue(asset, out var fs)) return null;
            Hop? best = null;
            foreach (var r in fs)
            {
                var (cap, basis) = Capability(r, opt);
                if (!(cap == Cap.Network || (!fromInternet && cap == Cap.Pivot))) continue;
                if (best is null || r.Likelihood > best.Likelihood) best = new Hop(asset, r.Cve, cap, r.Likelihood, basis);
            }
            return best is { Likelihood: > 0 } ? best : null;
        }

        var adj = ctx.Links.GroupBy(l => l.Src).ToDictionary(g => g.Key, g => g.Select(l => l.Dst).Distinct().ToList());
        var dist = new Dictionary<string, double>(); var prev = new Dictionary<string, (string? From, Hop Hop)>(); var hops = new Dictionary<string, int>();
        var queue = new PriorityQueue<string, double>();
        foreach (var (name, a) in assets.Where(x => x.Value.InternetFacing))
            if (Best(name, true) is { } h) { dist[name] = -Math.Log(h.Likelihood); prev[name] = (null, h); hops[name] = 1; queue.Enqueue(name, dist[name]); }

        while (queue.TryDequeue(out var u, out var du))
        {
            if (du > dist[u] + 1e-12 || hops[u] >= opt.MaxHops) continue;
            foreach (var v in adj.GetValueOrDefault(u) ?? new())
            {
                if (Best(v, false) is not { } h) continue;
                var dv = du - Math.Log(h.Likelihood);
                if (!dist.TryGetValue(v, out var old) || dv < old - 1e-12) { dist[v] = dv; prev[v] = (u, h); hops[v] = hops[u] + 1; queue.Enqueue(v, dv); }
            }
        }

        AttackPath PathTo(string t)
        {
            var list = new List<Hop>();
            for (string? n = t; n != null; n = prev[n].From) list.Add(prev[n].Hop);
            list.Reverse();
            return new AttackPath(t, list, list.Aggregate(1.0, (p, h) => p * h.Likelihood));
        }

        foreach (var n in dist.Keys) { res.Hops[n] = hops[n]; res.BestTo[n] = PathTo(n); }
        var targets = ctx.Assets.Values.Where(a => a.CrownJewel).Select(a => a.Asset)
            .Concat(ctx.Services.Where(s => s.Criticality >= 3).SelectMany(s => ctx.ServiceAssets.GetValueOrDefault(s.Name) ?? new())).Distinct();
        foreach (var t in targets.Where(res.BestTo.ContainsKey).Order(StringComparer.Ordinal))
        {
            var p = res.BestTo[t]; res.Paths.Add(p);
            foreach (var h in p.Hops) res.OnPaths[$"{h.Cve}|{h.Asset}"] = res.OnPaths.GetValueOrDefault($"{h.Cve}|{h.Asset}") + 1;
        }
        res.Paths = res.Paths.OrderByDescending(p => p.Likelihood).ThenBy(p => p.Target, StringComparer.Ordinal).ToList();
        return res;
    }
}
