using System.IO.Compression;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Turn an inventory export (one row per host or per installed program: hostname, vendor, product, version, os ...) into Stenwatch assets
/// (one row per product and version, with an NVD CPE). A host's OS and its product are looked up by name among the products NVD itself lists
/// in cve.db, so a match is a lookup, not a guess. Whatever does not match is listed, not dropped silently.
/// Reads CSV with any common separator (comma, semicolon, tab), Excel .xlsx (first sheet), and CycloneDX SBOM .json.</summary>
public static class Inventory
{
    public record Result(int Hosts, List<string[]> Assets, List<(string What, int Hosts)> Unmatched);

    /// <summary>True when the file is an inventory rather than Stenwatch's assets.csv: Excel, an SBOM, or a table with no cpe column.</summary>
    public static bool IsInventory(string path) =>
        File.Exists(path) && (Path.GetExtension(path).ToLowerInvariant() is ".xlsx" or ".json"
            || ReadRows(path) is { Count: > 0 } rows && !rows[0].Keys.Any(k => k.Trim().Equals("cpe", StringComparison.OrdinalIgnoreCase)));

    /// <summary>Rows of a CSV (separator sniffed from the header), an .xlsx (first sheet) or a CycloneDX SBOM (one row per component).</summary>
    public static List<Dictionary<string, string>> ReadRows(string path)
    {
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".xlsx": return Xlsx(path);
            case ".json": return Sbom(path);
        }
        var text = File.ReadAllText(path).TrimStart('﻿');
        var head = text.Split('\n')[0];
        var sep = new[] { ',', ';', '\t', '|' }.MaxBy(c => head.Count(x => x == c));
        var rows = Csv.Parse(text, sep);
        if (rows.Count == 0) return new();
        return rows.Skip(1).Where(r => r.Any(c => c.Trim() != ""))
            .Select(r => rows[0].Select((h, i) => (h: h.Trim(), v: i < r.Count ? r[i] : "")).GroupBy(x => x.h).ToDictionary(g => g.Key, g => g.First().v)).ToList();
    }

    /// <summary>First worksheet of an .xlsx as rows (shared and inline strings, numbers as written). No Excel needed.</summary>
    static List<Dictionary<string, string>> Xlsx(string path)
    {
        var table = XlsxCells(path);
        if (table.Count == 0) return new();
        var head = table[0];
        return table.Skip(1).Select(r => head.Where(h => h.Value.Trim() != "").GroupBy(h => h.Value.Trim())
            .ToDictionary(g => g.Key, g => r.GetValueOrDefault(g.First().Key, ""))).ToList();
    }

    /// <summary>Non-empty rows of the first worksheet as column index -> text.</summary>
    public static List<SortedDictionary<int, string>> XlsxCells(string path)
    {
        using var zip = ZipFile.OpenRead(path);
        XNamespace ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        XDocument Load(string name) { using var s = zip.GetEntry(name)!.Open(); return XDocument.Load(s); }
        var shared = zip.GetEntry("xl/sharedStrings.xml") is null ? new List<string>()
            : Load("xl/sharedStrings.xml").Root!.Elements(ns + "si").Select(si => string.Concat(si.Descendants(ns + "t").Select(t => t.Value))).ToList();
        var sheet = zip.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet") && e.FullName.EndsWith(".xml")).OrderBy(e => e.FullName.Length).ThenBy(e => e.FullName).First();
        static int Col(string r) { int n = 0; foreach (var ch in r.TakeWhile(char.IsLetter)) n = n * 26 + (char.ToUpperInvariant(ch) - 'A' + 1); return n - 1; }
        var table = Load(sheet.FullName).Descendants(ns + "row").Select(row =>
        {
            var cells = new SortedDictionary<int, string>();
            foreach (var c in row.Elements(ns + "c"))
            {
                var v = c.Element(ns + "v")?.Value ?? string.Concat(c.Descendants(ns + "t").Select(t => t.Value));
                cells[Col((string?)c.Attribute("r") ?? "A")] = (string?)c.Attribute("t") == "s" && int.TryParse(v, out var i) && i < shared.Count ? shared[i] : v;
            }
            return cells;
        }).Where(r => r.Count > 0).ToList();
        return table;
    }

    /// <summary>CycloneDX SBOM: every component (nested ones too) as a row: vendor (publisher, supplier or group), product, version, sbom_cpe.</summary>
    static List<Dictionary<string, string>> Sbom(string path)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var rows = new List<Dictionary<string, string>>();
        string S(JsonElement e, string k) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString()! : "";
        var host = doc.RootElement.TryGetProperty("metadata", out var meta) && meta.TryGetProperty("component", out var mc) && S(mc, "name") is { Length: > 0 } h ? h : Path.GetFileNameWithoutExtension(path);
        void Walk(JsonElement list)
        {
            foreach (var c in list.EnumerateArray())
            {
                var supplier = c.TryGetProperty("supplier", out var sp) ? S(sp, "name") : "";
                rows.Add(new() { ["hostname"] = host,
                    ["vendor"] = new[] { S(c, "publisher"), supplier, S(c, "group") }.FirstOrDefault(x => x != "") ?? "", ["product"] = S(c, "name"), ["version"] = S(c, "version"), ["sbom_cpe"] = S(c, "cpe") });
                if (c.TryGetProperty("components", out var sub)) Walk(sub);
            }
        }
        if (doc.RootElement.TryGetProperty("components", out var comps)) Walk(comps);
        return rows;
    }

    /// <summary>Copy any supported inventory to a plain comma CSV (what the rest of Stenwatch reads).</summary>
    public static void ToCsv(string source, string dest)
    {
        var rows = ReadRows(source);
        var head = rows.SelectMany(r => r.Keys).Distinct().ToList();
        Csv.Write(dest, new[] { head }.Concat(rows.Select(r => head.Select(h => r.GetValueOrDefault(h, "")))));
    }

    static readonly Regex CpeRx = new(@"cpe:2\.3:([ao]):([^:""]+):([^:""]+):", RegexOptions.Compiled);
    static readonly Regex TrailingVersion = new(@"^(.*?)[\s_]+v?(\d[\w.]*)$", RegexOptions.Compiled);
    // edition and packaging words that NVD leaves out of product names (Windows 11 Pro 23H2 is windows_11_23h2)
    static readonly Regex Edition = new(@"\b(pro|professional|enterprise|education|home|standard|datacenter|ltsc|ltsb|business|x64|x86|64-bit|32-bit|\(x64\)|\(64-bit\))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>lower case, anything but letters, digits and dots becomes one '_' (NVD's own product spelling, minus escapes).</summary>
    public static string Norm(string s) => Regex.Replace(s.Replace("\\", "").ToLowerInvariant(), @"[^a-z0-9.]+", "_").Trim('_');

    // ponytail: names that differ between inventories and NVD; add a line when an import lists one as unmatched
    static readonly Dictionary<string, (string Vendor, string Product)> Alias = new()
    {
        ["ios"] = ("apple", "iphone_os"), ["ipados"] = ("apple", "ipados"), ["android"] = ("google", "android"), ["ubuntu"] = ("canonical", "ubuntu_linux"), ["ddos"] = ("dell", "data_domain_operating_system"),
        ["mac_os_x"] = ("apple", "mac_os_x"), ["macos"] = ("apple", "macos"), ["debian"] = ("debian", "debian_linux"), ["rhel"] = ("redhat", "enterprise_linux"), ["red_hat_enterprise_linux"] = ("redhat", "enterprise_linux"),
        ["fortigate"] = ("fortinet", "fortios"), ["esxi"] = ("vmware", "esxi"), ["vcenter"] = ("vmware", "vcenter_server"), ["office_365"] = ("microsoft", "365_apps"), ["microsoft_365_apps"] = ("microsoft", "365_apps"),
        ["acrobat_reader"] = ("adobe", "acrobat_reader_dc"), ["adobe_acrobat_reader"] = ("adobe", "acrobat_reader_dc"), ["java"] = ("oracle", "jre"), ["java_runtime_environment"] = ("oracle", "jre"),
        ["node.js"] = ("nodejs", "node.js"), ["nodejs"] = ("nodejs", "node.js"), ["edge"] = ("microsoft", "edge_chromium"), ["microsoft_edge"] = ("microsoft", "edge_chromium"), ["chrome"] = ("google", "chrome"),
        ["google_chrome"] = ("google", "chrome"), ["firefox"] = ("mozilla", "firefox"), ["netscaler"] = ("citrix", "netscaler_application_delivery_controller"), ["asa"] = ("cisco", "adaptive_security_appliance_software"),
        ["veeam_backup_replication"] = ("veeam", @"veeam_backup_\&_replication"), ["veeam_backup_and_replication"] = ("veeam", @"veeam_backup_\&_replication"), ["nginx"] = ("f5", "nginx"), ["httpd"] = ("apache", "http_server"),
        ["iis"] = ("microsoft", "internet_information_services"), ["mysql"] = ("oracle", "mysql"), ["postgres"] = ("postgresql", "postgresql"), ["zoom"] = ("zoom", "meetings"), ["teams"] = ("microsoft", "teams"),
        ["dsm"] = ("synology", "diskstation_manager"), ["netweaver_as_abap"] = ("sap", "netweaver_application_server_abap"), ["sap_netweaver_as_abap"] = ("sap", "netweaver_application_server_abap"),
    };

    /// <summary>normalised product -> (part, vendor, product as NVD writes it, how many CVEs name it), from every CPE in cve.db.</summary>
    public static ILookup<string, (string Part, string Vendor, string Product, int Cves)> Vocabulary(SqliteConnection db)
    {
        var count = new Dictionary<(string, string, string), int>();
        using var c = db.CreateCommand(); c.CommandText = "SELECT cpes FROM cve WHERE cpes IS NOT NULL";
        using var r = c.ExecuteReader();
        while (r.Read())
            foreach (var k in CpeRx.Matches(r.GetString(0)).Select(m => (m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value.Replace(@"\\", @"\"))).Distinct()) // JSON text: \\& is NVD's \&
                count[k] = count.GetValueOrDefault(k) + 1;
        return count.ToLookup(x => Norm(x.Key.Item3), x => (x.Key.Item1, x.Key.Item2, x.Key.Item3, x.Value));
    }

    /// <summary>The NVD product a name means. Several candidates (a vendor hint that fits two, or no hint at all): the one most CVEs name,
    /// when it clearly dominates; NVD's rarely used duplicates (apache_tomcat:apache_tomcat) lose to the real one (apache:tomcat).</summary>
    static (string Part, string Vendor, string Product, int Cves)? Lookup(ILookup<string, (string Part, string Vendor, string Product, int Cves)> vocab, string key, string vendorHint)
    {
        if (key == "") return null;
        if (Alias.TryGetValue(key, out var a)) return vocab[Norm(a.Product)].FirstOrDefault(x => x.Vendor == a.Vendor) is { Vendor: not null } hit ? hit : null;
        var hits = vocab[key].OrderByDescending(x => x.Cves).ToList();
        if (hits.Count == 0) return null;
        var v = Norm(vendorHint);
        var byVendor = hits.Where(x => v != "" && (x.Vendor == v || x.Vendor.Contains(v) || v.Contains(x.Vendor))).ToList();
        if (byVendor.Count > 0) return byVendor[0];
        // several vendors use the name: take the clear leader, else it is ambiguous and reported
        return hits.Count == 1 || hits[0].Cves >= 3 * hits[1].Cves ? hits[0] : null;
    }

    /// <summary>The ways an inventory may spell one product, most literal first: as written, without edition and packaging words,
    /// with the vendor in front (NVD: veeam_backup_&amp;_replication), and without a leading vendor word (Microsoft SQL Server 2019).</summary>
    static IEnumerable<(string Name, string Vendor)> Spellings(string name, string vendor)
    {
        var plain = Regex.Replace(name, @"\((x64|x86|64-bit|32-bit|[^)]*bit[^)]*)\)", " ", RegexOptions.IgnoreCase);       // 7-Zip 23.01 (x64)
        plain = Regex.Replace(plain, @"\bupdate\s+\d+\b", " ", RegexOptions.IgnoreCase);                                    // Java 8 Update 381
        plain = Regex.Replace(Edition.Replace(plain, " "), @"\b(vpn|client|agent|desktop|app)$", " ", RegexOptions.IgnoreCase); // FortiClient VPN
        plain = Regex.Replace(plain, @"\s+", " ").Trim();
        yield return (name, vendor);
        if (plain != name && plain != "") yield return (plain, vendor);
        var first = vendor.Split(' ', ',').FirstOrDefault(w => w != "") ?? ""; // "Fortinet Technologies Inc" -> Fortinet
        if (first != "") yield return (first + " " + plain, vendor);
        var words = plain.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length > 1 && (vendor == "" || Norm(words[0]).Contains(Norm(first)) || Norm(first).Contains(Norm(words[0]))))
            yield return (string.Join(" ", words.Skip(1)), vendor == "" ? words[0] : vendor);
    }

    /// <summary>Name plus version: the whole name first ("Windows 11 23H2" is one NVD product), then name and trailing version ("iOS 18.0").
    /// Among spellings that match, the product with the most CVEs wins (SQL Server 2019 is sql_server_2019, which NVD uses more than sql_server).</summary>
    static (string Part, string Vendor, string Product, string Version, string Label)? Match(ILookup<string, (string, string, string, int)> vocab, string name, string version, string vendorHint)
    {
        name = name.Trim();
        if (name == "" || name is "n/a" or "firmware" or "os") return null;
        var spellings = Spellings(name, vendorHint).ToList();
        var full = spellings.Select(s => Lookup(vocab, Norm(s.Name), s.Vendor)).Where(h => h != null).MaxBy(h => h!.Value.Cves);
        if (full is { } f) return (f.Part, f.Vendor, f.Product, version, name);
        var part = spellings.Select(s => TrailingVersion.Match(s.Name)).Where(m => m.Success)
            .Select(m => (Hit: Lookup(vocab, Norm(m.Groups[1].Value), vendorHint), Ver: m.Groups[2].Value)).Where(x => x.Hit != null).OrderByDescending(x => x.Hit!.Value.Cves).FirstOrDefault();
        return part.Hit is { } p ? (p.Part, p.Vendor, p.Product, version != "" ? version : part.Ver, name) : null;
    }

    /// <summary>The number in a version cell ("IOS XE 17.9" -> 17.9, "8.10" -> 8.10); empty for firmware versions such as "BIOS 2.3".</summary>
    static string VersionOf(string cell)
    {
        cell = cell.Trim();
        if (cell == "" || cell.StartsWith("BIOS", StringComparison.OrdinalIgnoreCase) || cell == "n/a") return ""; // ponytail: BIOS is not the OS version
        var m = Regex.Match(cell, @"\d[\w.]*");
        return m.Success ? m.Value : "";
    }

    // the column names common exports use (CMDB, Intune, SCCM/MECM, Lansweeper, Defender, Qualys, plain Excel lists)
    static readonly string[] VendorCols = { "vendor", "manufacturer", "publisher", "software vendor", "software publisher", "app publisher", "vendor name" };
    static readonly string[] ProductCols = { "product", "software", "software name", "application", "application name", "app name", "display name", "displayname", "program", "title", "model", "product name", "package" };
    static readonly string[] VersionCols = { "version", "software version", "application version", "app version", "product version", "display version", "displayversion", "package version" };
    static readonly string[] OsCols = { "os", "operating_system", "operating system", "os name", "osname", "os platform", "platform", "os family" };
    static readonly string[] BuildCols = { "os_build", "build", "os_version", "os version", "osversion", "os build", "os build number", "build number" };
    static readonly string[] CritCols = { "criticality", "asset criticality", "business criticality", "importance", "priority" };
    static readonly string[] CountCols = { "device count", "devices", "device_count", "install count", "installations", "installs", "count" };
    static readonly string[] ExposureCols = { "exposure", "internet_facing", "internet facing", "zone", "network zone", "location type", "public" };

    public static Result Convert(string inventory, SqliteConnection db)
    {
        var rows = ReadRows(inventory);
        var vocab = Vocabulary(db);
        string Col(Dictionary<string, string> r, params string[] names) =>
            names.Select(n => r.FirstOrDefault(kv => kv.Key.Trim().Replace('_', ' ').Equals(n.Replace('_', ' '), StringComparison.OrdinalIgnoreCase)).Value)
                 .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? "";

        var groups = new Dictionary<(string Cpe, string Version), (string Label, int Hosts, int Crit, bool Internet)>();
        var unmatched = new Dictionary<string, int>();
        foreach (var r in rows)
        {
            var vendor = Col(r, VendorCols); var product = Col(r, ProductCols);
            var os = Col(r, OsCols); var version = VersionOf(Col(r, VersionCols));
            var crit = Col(r, CritCols).ToLowerInvariant() switch
            {
                var cs when int.TryParse(cs, out var c) => Math.Clamp(c, 1, 3),
                "high" or "critical" or "very high" => 3, "low" or "very low" => 1, _ => 2,
            };
            var exposure = Col(r, ExposureCols).ToLowerInvariant();
            var internet = exposure is "internet" or "external" or "dmz" or "public" or "y" or "yes" or "true" or "1";
            var n = int.TryParse(Col(r, CountCols), out var cnt) && cnt > 0 ? cnt : 1; // a software report counts devices per row

            // a host can carry two things NVD tracks: the product it runs (MOVEit) and its OS (Windows Server).
            // The version cell belongs to the product when the product matched, else to an OS whose name carries no version (ArubaOS 8.10, IOS XE 17.9).
            (string Part, string Vendor, string Product, string Version, string Label)? app = null;
            if (Col(r, "sbom_cpe", "cpe23", "cpe 2.3") is { Length: > 0 } given && CpeRx.Match(given + ":") is { Success: true } gm) // an SBOM may name the CPE itself
                app = (gm.Groups[1].Value, gm.Groups[2].Value, gm.Groups[3].Value, version != "" ? version : given.Split(':').ElementAtOrDefault(5) is { } gv && gv is not ("*" or "-") ? gv : "", product != "" ? product : gm.Groups[3].Value);
            app ??= Match(vocab, product, version, vendor);
            var sys = Match(vocab, os, "", vendor);
            if (sys is { Version: "" } s && app is null && !os.Any(char.IsDigit)) sys = s with { Version = version };
            // an OS build (10.0.22631.4317) is what lets NVD's version ranges drop CVEs that patches already fixed
            if (sys is { } sb && Col(r, BuildCols) is { Length: > 0 } build && Regex.IsMatch(build, @"^\d+(\.\d+)+$")) sys = sb with { Version = build };
            // both name the same thing when one product name extends the other (windows_server / windows_server_2022): keep the specific one
            if (sys is { } s1 && app is { } a1 && s1.Vendor == a1.Vendor && (s1.Product.StartsWith(a1.Product) || a1.Product.StartsWith(s1.Product)))
                if (s1.Product.Length >= a1.Product.Length) app = null; else sys = null;
            var found = new[] { sys, app }.Where(x => x != null).Select(x => x!.Value).DistinctBy(x => (x.Vendor, x.Product)).ToList();
            if (found.Count == 0) { var what = string.Join(" ", new[] { vendor, product, os }.Where(s => s != "")); if (what != "") unmatched[what] = unmatched.GetValueOrDefault(what) + n; continue; }
            foreach (var f in found)
            {
                var key = ($"cpe:2.3:{f.Part}:{f.Vendor}:{f.Product}", f.Version);
                var label = f.Version != "" && !f.Label.Contains(f.Version) ? $"{f.Label} {f.Version}" : f.Label;
                var g = groups.TryGetValue(key, out var had) ? had : (Label: label, Hosts: 0, Crit: 1, Internet: false);
                groups[key] = (g.Label, g.Hosts + n, Math.Max(g.Crit, crit), g.Internet || internet);
            }
        }
        var assets = groups.OrderByDescending(g => g.Value.Hosts)
            .Select(g => new[] { $"{g.Value.Label} ({g.Value.Hosts} host{(g.Value.Hosts == 1 ? "" : "s")})", g.Key.Cpe, g.Key.Version, g.Value.Crit.ToString(), g.Value.Internet ? "y" : "n" }).ToList();
        return new(rows.Sum(r => int.TryParse(Col(r, CountCols), out var c) && c > 0 ? c : 1), assets, unmatched.OrderByDescending(u => u.Value).Select(u => (u.Key, u.Value)).ToList());
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
