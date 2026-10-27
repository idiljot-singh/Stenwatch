using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

public record KNode(string Type, string Id, string Label)
{
    public string Key => $"{Type}:{Id}";
}

/// <summary>A typed relationship. Source says where it came from and Basis how strong the claim is
/// (documented = stated by the source for this exact relationship, inferred = derived by us from other relationships).</summary>
public record KEdge(string Src, string Type, string Dst, string Source, string Basis = "documented");

/// <summary>Pillar 13: vulnerabilities, weaknesses, techniques, adversaries, mitigations, assets, services and controls as one queryable graph.
/// Built in memory from the relational tables and the current findings, so it can never disagree with them.
/// A relational model would hold the same facts; the graph is for questions that cross several of them.</summary>
public class Knowledge
{
    public Dictionary<string, KNode> Nodes = new();
    public List<KEdge> Edges = new();
    Dictionary<string, List<KEdge>> outE = new(), inE = new();

    KNode N(string type, string id, string label = "")
    {
        var n = new KNode(type, id, label == "" ? id : label);
        return Nodes.TryAdd(n.Key, n) ? n : Nodes[n.Key];
    }

    void E(KNode a, string type, KNode b, string source, string basis = "documented")
    {
        var e = new KEdge(a.Key, type, b.Key, source, basis);
        Edges.Add(e);
        if (!outE.TryGetValue(a.Key, out var o)) outE[a.Key] = o = new(); o.Add(e);
        if (!inE.TryGetValue(b.Key, out var i)) inE[b.Key] = i = new(); i.Add(e);
    }

    public static Knowledge Build(SqliteConnection? db, IEnumerable<Ranked> findings, OrgContext? ctx = null)
    {
        var k = new Knowledge();
        var list = findings.ToList();
        var cves = list.Select(r => r.Cve).ToHashSet();

        if (db != null)
        {
            string Q(string sql, Action<SqliteDataReader> row) { using var c = db.CreateCommand(); c.CommandText = sql; using var r = c.ExecuteReader(); while (r.Read()) row(r); return ""; }
            Q("SELECT id, name FROM technique", r => k.N("technique", r.GetString(0), $"{r.GetString(0)} {r.GetString(1)}"));
            Q("SELECT id, name FROM actor", r => k.N("actor", r.GetString(0), r.GetString(1)));
            Q("SELECT actor, technique FROM actor_technique", r => { if (k.Has("actor", r.GetString(0)) && k.Has("technique", r.GetString(1))) k.E(k.Nodes["actor:" + r.GetString(0)], "uses", k.Nodes["technique:" + r.GetString(1)], "MITRE ATT&CK"); });
            // the CVE appears in the group's or campaign's ATT&CK text: a report, so documented-by-text
            Q("SELECT actor, cve FROM actor_cve", r => { if (k.Has("actor", r.GetString(0))) k.E(k.Nodes["actor:" + r.GetString(0)], "exploits", k.N("cve", r.GetString(1)), "MITRE ATT&CK text", "reported"); });
            Q("SELECT cve, technique, mapping_type FROM cve_technique", r => { if (k.Has("technique", r.GetString(1))) k.E(k.N("cve", r.GetString(0)), "enables", k.Nodes["technique:" + r.GetString(1)], "CTID " + r.GetString(2), "mapped"); });
            try
            {
                Q("SELECT technique, id, name FROM mitigation", r => { if (k.Has("technique", r.GetString(0))) k.E(k.Nodes["technique:" + r.GetString(0)], "mitigated_by", k.N("mitigation", r.GetString(1), $"{r.GetString(2)} ({r.GetString(1)})"), "MITRE ATT&CK"); });
                Q("SELECT technique, id, name FROM defend", r => { if (k.Has("technique", r.GetString(0))) k.E(k.Nodes["technique:" + r.GetString(0)], "countered_by", k.N("d3fend", r.GetString(1), $"{r.GetString(2)} ({r.GetString(1)})"), "MITRE D3FEND"); });
            }
            catch (SqliteException) { }
        }

        foreach (var r in list)
        {
            var cve = k.N("cve", r.Cve); var asset = k.N("asset", r.Asset.Name);
            k.E(asset, "vulnerable_to", cve, "Stenwatch matching", "inferred");
            foreach (var cwe in Analyse.Cwes(r.F).Split(", ", StringSplitOptions.RemoveEmptyEntries)) k.E(cve, "has_weakness", k.N("cwe", cwe), "NIST NVD");
            if (r.F.Kev) k.E(cve, "flagged_by", k.N("feed", "KEV", "CISA KEV"), "CISA KEV");
        }
        if (ctx != null)
        {
            foreach (var s in ctx.Services) foreach (var a in ctx.ServiceAssets.GetValueOrDefault(s.Name) ?? new()) k.E(k.N("service", s.Name), "depends_on", k.N("asset", a), "organisation");
            foreach (var l in ctx.Links) k.E(k.N("asset", l.Src), "reaches", k.N("asset", l.Dst), "organisation");
            foreach (var c in ctx.Controls)
            {
                var cn = k.N("control", c.Id, c.Name);
                foreach (var t in c.Counters.Split(',').Select(x => x.Trim()).Where(x => x != ""))
                    if (k.Has("technique", t)) k.E(cn, "counters", k.Nodes["technique:" + t], "organisation");
                    else if (k.Has("d3fend", t)) k.E(cn, "counters", k.Nodes["d3fend:" + t], "organisation");
            }
        }
        return k;
    }

    public bool Has(string type, string id) => Nodes.ContainsKey($"{type}:{id}");
    public IEnumerable<KEdge> Out(string key, params string[] types) => (outE.GetValueOrDefault(key) ?? new()).Where(e => types.Length == 0 || types.Contains(e.Type));
    public IEnumerable<KEdge> In(string key, params string[] types) => (inE.GetValueOrDefault(key) ?? new()).Where(e => types.Length == 0 || types.Contains(e.Type));

    /// <summary>Everything within `depth` steps of a node, in either direction, as (edge, node) pairs.</summary>
    public List<(KEdge Edge, KNode Node)> Neighbours(string key, int depth = 1)
    {
        var seen = new HashSet<string> { key }; var res = new List<(KEdge, KNode)>(); var frontier = new List<string> { key };
        for (int d = 0; d < depth; d++)
        {
            var next = new List<string>();
            foreach (var n in frontier)
                foreach (var e in Out(n).Concat(In(n)))
                {
                    var other = e.Src == n ? e.Dst : e.Src;
                    if (!seen.Add(other)) continue;
                    res.Add((e, Nodes[other])); next.Add(other);
                }
            frontier = next;
        }
        return res;
    }

    /// <summary>Which assets carry vulnerabilities tied to an adversary, and how directly. "reported" = the group's ATT&amp;CK text names the CVE;
    /// "technique" = the CVE only enables a technique the group uses (a weaker, shared-technique link).</summary>
    public List<(string Asset, string Cve, string Via)> AssetsHitBy(string actorId)
    {
        var key = "actor:" + actorId;
        if (!Nodes.ContainsKey(key)) return new();
        var direct = Out(key, "exploits").Select(e => e.Dst).ToHashSet();
        var techniques = Out(key, "uses").Select(e => e.Dst).ToHashSet();
        var res = new List<(string, string, string)>();
        foreach (var cve in Nodes.Values.Where(n => n.Type == "cve"))
        {
            string? via = direct.Contains(cve.Key) ? "reported" : Out(cve.Key, "enables").Any(e => techniques.Contains(e.Dst)) ? "technique" : null;
            if (via is null) continue;
            foreach (var e in In(cve.Key, "vulnerable_to")) res.Add((Nodes[e.Src].Id, cve.Id, via));
        }
        return res.OrderBy(x => x.Item3 == "reported" ? 0 : 1).ThenBy(x => x.Item1, StringComparer.Ordinal).ThenBy(x => x.Item2, StringComparer.Ordinal).ToList();
    }

    /// <summary>Assets that share a weakness class (CWE), e.g. to find several exposed hosts with the same flaw.</summary>
    public List<(string Asset, string Cve)> SharedWeakness(string cwe, Func<string, bool>? assetFilter = null)
    {
        var key = "cwe:" + cwe;
        return In(key, "has_weakness").SelectMany(w => In(w.Src, "vulnerable_to").Select(v => (Asset: Nodes[v.Src].Id, Cve: Nodes[w.Src].Id)))
            .Where(x => assetFilter?.Invoke(x.Asset) ?? true).OrderBy(x => x.Asset, StringComparer.Ordinal).ThenBy(x => x.Cve, StringComparer.Ordinal).ToList();
    }

    /// <summary>Fewest-step connection between two nodes, ignoring edge direction. Null if not connected.</summary>
    public List<(KNode, KEdge?)>? Connect(string from, string to, int maxDepth = 6)
    {
        if (!Nodes.ContainsKey(from) || !Nodes.ContainsKey(to)) return null;
        var prev = new Dictionary<string, (string, KEdge)>(); var q = new Queue<(string, int)>(); q.Enqueue((from, 0)); var seen = new HashSet<string> { from };
        while (q.Count > 0)
        {
            var (n, d) = q.Dequeue();
            if (n == to) break;
            if (d >= maxDepth) continue;
            foreach (var e in Out(n).Concat(In(n)))
            {
                var o = e.Src == n ? e.Dst : e.Src;
                if (seen.Add(o)) { prev[o] = (n, e); q.Enqueue((o, d + 1)); }
            }
        }
        if (!prev.ContainsKey(to)) return from == to ? new() { (Nodes[from], null) } : null;
        var path = new List<(KNode, KEdge?)>();
        for (var c = to; c != from; c = prev[c].Item1) path.Add((Nodes[c], prev[c].Item2));
        path.Add((Nodes[from], null)); path.Reverse();
        return path;
    }
}
