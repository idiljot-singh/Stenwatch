using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Turn an inventory export (one row per host: hostname, vendor, product, version, os ...) into Stenwatch assets
/// (one row per product and version, with an NVD CPE). A host's OS and its product are looked up by name among the
/// products NVD itself lists in cve.db, so a match is a lookup, not a guess. Whatever does not match is listed, not dropped silently.</summary>
public static class Inventory
{
    public record Result(int Hosts, List<string[]> Assets, List<(string What, int Hosts)> Unmatched);

    /// <summary>True when the file has rows but no cpe column, i.e. it is an inventory export rather than Stenwatch's assets.csv.</summary>
    public static bool IsInventory(string path) =>
        File.Exists(path) && File.ReadLines(path).FirstOrDefault() is { } head && !head.ToLowerInvariant().Split(',').Select(h => h.Trim(' ', '"')).Contains("cpe");

    static readonly Regex CpeRx = new(@"cpe:2\.3:([ao]):([^:""]+):([^:""]+):", RegexOptions.Compiled);
    static readonly Regex TrailingVersion = new(@"^(.*?)[\s_]+v?(\d[\w.]*)$", RegexOptions.Compiled);

    /// <summary>lower case, anything but letters, digits and dots becomes one '_' (NVD's own product spelling, minus escapes).</summary>
    public static string Norm(string s) => Regex.Replace(s.Replace("\\", "").ToLowerInvariant(), @"[^a-z0-9.]+", "_").Trim('_');

    // ponytail: names that differ between inventories and NVD; add a line when an import lists one as unmatched
    static readonly Dictionary<string, (string Vendor, string Product)> Alias = new()
    {
        ["ios"] = ("apple", "iphone_os"), ["ipados"] = ("apple", "ipados"), ["android"] = ("google", "android"), ["ubuntu"] = ("canonical", "ubuntu_linux"), ["ddos"] = ("dell", "data_domain_operating_system"),
    };

    /// <summary>normalised product -> (part, vendor, product as NVD writes it), from every CPE in cve.db.</summary>
    public static ILookup<string, (string Part, string Vendor, string Product)> Vocabulary(SqliteConnection db)
    {
        var seen = new HashSet<(string, string, string)>();
        using var c = db.CreateCommand(); c.CommandText = "SELECT cpes FROM cve WHERE cpes IS NOT NULL";
        using var r = c.ExecuteReader();
        while (r.Read()) foreach (Match m in CpeRx.Matches(r.GetString(0))) seen.Add((m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value.Replace(@"\\", @"\"))); // JSON text: \\& is NVD's \&
        return seen.ToLookup(x => Norm(x.Item3), x => x);
    }

    static (string Part, string Vendor, string Product)? Lookup(ILookup<string, (string Part, string Vendor, string Product)> vocab, string key, string vendorHint)
    {
        if (key == "") return null;
        if (Alias.TryGetValue(key, out var a)) return vocab[Norm(a.Product)].FirstOrDefault(x => x.Vendor == a.Vendor) is { Vendor: not null } hit ? hit : null;
        var hits = vocab[key].ToList();
        if (hits.Count == 0) return null;
        var v = Norm(vendorHint);
        var byVendor = hits.Where(x => v != "" && (x.Vendor == v || x.Vendor.Contains(v) || v.Contains(x.Vendor))).ToList();
        if (byVendor.Count > 0) return byVendor[0];
        return hits.Select(x => x.Vendor).Distinct().Count() == 1 ? hits[0] : null; // several vendors use the name: ambiguous, report it
    }

    /// <summary>Name plus version: the whole name first ("Windows 11 23H2" is one NVD product), then name and trailing version ("iOS 18.0").</summary>
    static (string Part, string Vendor, string Product, string Version, string Label)? Match(ILookup<string, (string, string, string)> vocab, string name, string version, string vendorHint)
    {
        name = name.Trim();
        if (name == "" || name is "n/a" or "firmware" or "os") return null;
        if (Lookup(vocab, Norm(name), vendorHint) is { } full) return (full.Item1, full.Item2, full.Item3, version, name);
        if (vendorHint != "" && Lookup(vocab, Norm(vendorHint + " " + name), vendorHint) is { } withVendor) return (withVendor.Item1, withVendor.Item2, withVendor.Item3, version, name); // NVD: veeam_backup_&_replication
        var m = TrailingVersion.Match(name);
        if (m.Success && Lookup(vocab, Norm(m.Groups[1].Value), vendorHint) is { } part) return (part.Item1, part.Item2, part.Item3, m.Groups[2].Value, name);
        return null;
    }

    /// <summary>The number in a version cell ("IOS XE 17.9" -> 17.9, "8.10" -> 8.10); empty for firmware versions such as "BIOS 2.3".</summary>
    static string VersionOf(string cell)
    {
        cell = cell.Trim();
        if (cell == "" || cell.StartsWith("BIOS", StringComparison.OrdinalIgnoreCase) || cell == "n/a") return ""; // ponytail: BIOS is not the OS version
        var m = Regex.Match(cell, @"\d[\w.]*");
        return m.Success ? m.Value : "";
    }

    public static Result Convert(string inventoryCsv, SqliteConnection db)
    {
        var rows = Csv.ReadDict(inventoryCsv);
        var vocab = Vocabulary(db);
        string Col(Dictionary<string, string> r, params string[] names) =>
            names.Select(n => r.FirstOrDefault(kv => kv.Key.Trim().Equals(n, StringComparison.OrdinalIgnoreCase)).Value).FirstOrDefault(v => v != null)?.Trim() ?? "";

        var groups = new Dictionary<(string Cpe, string Version), (string Label, int Hosts, int Crit, bool Internet)>();
        var unmatched = new Dictionary<string, int>();
        foreach (var r in rows)
        {
            var vendor = Col(r, "vendor", "manufacturer"); var product = Col(r, "product", "model", "software");
            var os = Col(r, "os", "operating_system", "operating system"); var version = VersionOf(Col(r, "version"));
            var crit = int.TryParse(Col(r, "criticality"), out var c) ? Math.Clamp(c, 1, 3) : 2;
            var exposure = Col(r, "exposure", "internet_facing", "zone").ToLowerInvariant();
            var internet = exposure is "internet" or "external" or "dmz" or "public" or "y" or "yes" or "true";

            // a host can carry two things NVD tracks: the product it runs (MOVEit) and its OS (Windows Server).
            // The version cell belongs to the product when the product matched, else to an OS whose name carries no version (ArubaOS 8.10, IOS XE 17.9).
            var app = Match(vocab, product, version, vendor);
            var sys = Match(vocab, os, "", vendor);
            if (sys is { Version: "" } s && app is null && !os.Any(char.IsDigit)) sys = s with { Version = version };
            // an OS build (10.0.22631.4317) is what lets NVD's version ranges drop CVEs that patches already fixed
            if (sys is { } sb && Col(r, "os_build", "build", "os_version") is { Length: > 0 } build) sys = sb with { Version = build };
            // both name the same thing when one product name extends the other (windows_server / windows_server_2022): keep the specific one
            if (sys is { } s1 && app is { } a1 && s1.Vendor == a1.Vendor && (s1.Product.StartsWith(a1.Product) || a1.Product.StartsWith(s1.Product)))
                if (s1.Product.Length >= a1.Product.Length) app = null; else sys = null;
            var found = new[] { sys, app }.Where(x => x != null).Select(x => x!.Value).DistinctBy(x => (x.Vendor, x.Product)).ToList();
            if (found.Count == 0) { var what = string.Join(" ", new[] { vendor, product, os }.Where(s => s != "")); unmatched[what] = unmatched.GetValueOrDefault(what) + 1; continue; }
            foreach (var f in found)
            {
                var key = ($"cpe:2.3:{f.Part}:{f.Vendor}:{f.Product}", f.Version);
                var label = f.Version != "" && !f.Label.Contains(f.Version) ? $"{f.Label} {f.Version}" : f.Label;
                var g = groups.TryGetValue(key, out var had) ? had : (Label: label, Hosts: 0, Crit: 1, Internet: false);
                groups[key] = (g.Label, g.Hosts + 1, Math.Max(g.Crit, crit), g.Internet || internet);
            }
        }
        var assets = groups.OrderByDescending(g => g.Value.Hosts)
            .Select(g => new[] { $"{g.Value.Label} ({g.Value.Hosts} host{(g.Value.Hosts == 1 ? "" : "s")})", g.Key.Cpe, g.Key.Version, g.Value.Crit.ToString(), g.Value.Internet ? "y" : "n" }).ToList();
        return new(rows.Count, assets, unmatched.OrderByDescending(u => u.Value).Select(u => (u.Key, u.Value)).ToList());
    }

    /// <summary>Convert assets.csv in place: the export is kept as assets.inventory.csv, what did not match goes to assets.unmatched.csv.</summary>
    public static Result ConvertFile(string assetsCsv, SqliteConnection db)
    {
        var dir = Path.GetDirectoryName(assetsCsv)!;
        var original = Path.Combine(dir, "assets.inventory.csv");
        File.Copy(assetsCsv, original, true);
        var res = Convert(original, db);
        Csv.Write(assetsCsv, new[] { new[] { "name", "cpe", "version", "criticality", "internet_facing" } }.Concat(res.Assets));
        Csv.Write(Path.Combine(dir, "assets.unmatched.csv"), new[] { new[] { "what", "hosts" } }.Concat(res.Unmatched.Select(u => new[] { u.What, u.Hosts.ToString() })));
        return res;
    }
}
