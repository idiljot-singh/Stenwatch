using System.Text.Json;

namespace Stenwatch.Core;

/// <summary>End-of-life software: the asset list checked against endoflife.date (API v1, public, no key). Reads only name, isEol and eolFrom of each release
/// (docs/formats.md). Product cycles are cached in eol-cache.json in the data folder with the fetch date, fetched again at most once a day, and the cache is used when offline.
/// Each asset whose cycle is past end of life (high) or reaches it within 90 days (medium) becomes an Exposure row in component "End-of-life software".
/// An asset with no version, no map entry, or no matching cycle is counted as not checked, never as supported. Nothing about the organisation is sent: only product names.</summary>
public static class Eol
{
    public const string Component = "End-of-life software", Api = "https://endoflife.date/api/v1/products/";
    const int SoonDays = 90;

    public record Release(string Name, bool IsEol, string? EolFrom);
    record Cached(string Fetched, List<Release> Releases);
    public record Result(int Checked, int Past, int Soon, List<string> NotChecked, string Note);

    // ponytail: a fixed CPE vendor:product -> slug map, not fuzzy matching; extend it with eol_products.txt in the data folder ("vendor:product=slug" or "=slug@cycle").
    // "@cycle" pins the cycle for CPEs whose version is a build number (windows_server_2019 is 10.0.17763.x, the cycle is 2019).
    // "@a|b" when the asset does not say which of two cycles it is (Windows 11 Home/Pro "-w" or Enterprise/Education "-e"): the later date is used and the evidence says so.
    static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        // the Example Organisation
        ["microsoft:exchange_server"] = "msexchange", ["fortinet:fortios"] = "fortios", ["f5:nginx"] = "nginx", ["nginx:nginx"] = "nginx",
        ["apache:http_server"] = "apache-http-server", ["php:php"] = "php", ["wordpress:wordpress"] = "wordpress", ["openssl:openssl"] = "openssl", ["oracle:mysql"] = "mysql",
        ["microsoft:windows_server_2016"] = "windows-server@2016", ["microsoft:windows_server_2019"] = "windows-server@2019",
        ["microsoft:windows_server_2022"] = "windows-server@2022", ["microsoft:windows_server_2025"] = "windows-server@2025",
        ["vmware:esxi"] = "esxi", ["vmware:vcenter_server"] = "vcenter", ["veeam:veeam_backup_&_replication"] = "veeam-backup-and-replication",
        ["microsoft:sql_server"] = "mssqlserver", ["microsoft:sql_server_2017"] = "mssqlserver@14.0", ["microsoft:sql_server_2019"] = "mssqlserver@15.0", ["microsoft:sql_server_2022"] = "mssqlserver@16.0",
        ["microsoft:sharepoint_server"] = "sharepoint",
        ["atlassian:jira_data_center"] = "jira-software", ["atlassian:jira_software"] = "jira-software", ["atlassian:jira"] = "jira-software",
        ["atlassian:confluence_data_center"] = "confluence", ["atlassian:confluence_server"] = "confluence", ["atlassian:confluence"] = "confluence",
        ["gitlab:gitlab"] = "gitlab", ["jenkins:jenkins"] = "jenkins", ["apache:tomcat"] = "tomcat", ["cisco:ios_xe"] = "cisco-ios-xe",
        ["microsoft:windows_10_22h2"] = "windows@10-22h2", ["microsoft:windows_11_22h2"] = "windows@11-22h2-w|11-22h2-e", ["microsoft:windows_11_23h2"] = "windows@11-23h2-w|11-23h2-e",
        ["microsoft:windows_11_24h2"] = "windows@11-24h2-w|11-24h2-e", ["google:chrome"] = "chrome", ["mozilla:firefox"] = "firefox", ["oracle:jre"] = "oracle-jdk", ["oracle:jdk"] = "oracle-jdk",
        ["apple:macos"] = "macos", ["apple:iphone_os"] = "ios", ["google:android"] = "android",
        // common Microsoft and server products
        ["microsoft:.net"] = "dotnet", ["microsoft:.net_framework"] = "dotnetfx", ["microsoft:powershell"] = "powershell", ["microsoft:internet_explorer"] = "internet-explorer",
        ["microsoft:office"] = "office", ["microsoft:visual_studio"] = "visual-studio", ["microsoft:azure_devops_server"] = "azure-devops-server",
        ["canonical:ubuntu_linux"] = "ubuntu", ["redhat:enterprise_linux"] = "rhel", ["debian:debian_linux"] = "debian", ["nodejs:node.js"] = "nodejs",
        ["python:python"] = "python", ["postgresql:postgresql"] = "postgresql", ["mariadb:mariadb"] = "mariadb", ["redis:redis"] = "redis",
        ["mongodb:mongodb"] = "mongodb", ["kubernetes:kubernetes"] = "kubernetes",
    };

    /// <summary>CPE cpe:2.3:part:vendor:product -> "vendor:product" with CPE escapes removed (veeam_backup_\&amp;_replication).</summary>
    static string Key(string cpe) { var p = cpe.Replace("\\", "").Split(':'); return p.Length > 4 ? $"{p[3]}:{p[4]}" : ""; }

    /// <summary>The slug (and pinned cycle, or "") for a CPE: eol_products.txt first, then the built-in map. (null, "") when not mapped.</summary>
    public static (string? Slug, string Cycle) SlugFor(string cpe, string? data = null)
    {
        var key = Key(cpe);
        var extra = data is not null && File.Exists(Path.Combine(data, "eol_products.txt"))
            ? File.ReadAllLines(Path.Combine(data, "eol_products.txt")).Select(l => l.Split('=', 2)).Where(p => p.Length == 2 && p[0].Trim().Equals(key, StringComparison.OrdinalIgnoreCase)).Select(p => p[1].Trim()).LastOrDefault()
            : null;
        var v = extra ?? Map.GetValueOrDefault(key);
        if (string.IsNullOrEmpty(v)) return (null, "");
        var at = v.IndexOf('@');
        return at < 0 ? (v, "") : (v[..at], v[(at + 1)..]);
    }

    /// <summary>The release a version belongs to: the pinned cycle, else the longest release name the version equals or starts with at a dot ("8.1.12" -> "8.1"). Java's "1.8.0" reads as "8.0".
    /// Several pinned cycles ("a|b"): all must exist, and the one ending last (no date counts as last) stands for them, named "a|b". A version matching no release is null (not checked).</summary>
    public static Release? CycleOf(string version, string pinned, List<Release> releases, string slug = "")
    {
        if (pinned != "")
        {
            var names = pinned.Split('|');
            var pins = releases.Where(r => names.Contains(r.Name, StringComparer.OrdinalIgnoreCase)).ToList();
            return pins.Count < names.Length ? null : pins.MaxBy(r => r.EolFrom ?? "9999") is { } last ? last with { Name = pinned } : null;
        }
        var v = slug.Contains("jdk") && version.StartsWith("1.") ? version[2..] : version;
        return releases.Where(r => v.Equals(r.Name, StringComparison.OrdinalIgnoreCase) || v.StartsWith(r.Name + ".", StringComparison.OrdinalIgnoreCase))
            .MaxBy(r => r.Name.Length);
    }

    /// <summary>Releases from one product response (result.releases[].name, isEol, eolFrom).</summary>
    public static List<Release> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("result").GetProperty("releases").EnumerateArray().Select(r => new Release(r.GetProperty("name").GetString() ?? "",
            r.TryGetProperty("isEol", out var e) && e.ValueKind == JsonValueKind.True,
            r.TryGetProperty("eolFrom", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null)).ToList();
    }

    /// <summary>Check the assets, save the rows with Exposure.Save (in saveTo, default data) and return the counts. Network failures fall back to the cache with a note;
    /// after the first failure no further product is fetched in this run.</summary>
    public static async Task<Result> Check(string data, IEnumerable<Asset> assets, HttpClient? http = null, string? saveTo = null, DateOnly? today = null, Action<string>? log = null)
    {
        var day = today ?? DateOnly.FromDateTime(DateTime.Now); var stamp = day.ToString("yyyy-MM-dd");
        var cacheFile = Path.Combine(data, "eol-cache.json");
        var cache = new Dictionary<string, Cached>();
        try { if (File.Exists(cacheFile)) cache = JsonSerializer.Deserialize<Dictionary<string, Cached>>(File.ReadAllText(cacheFile)) ?? new(); } catch (JsonException) { }
        http ??= new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        if (http.DefaultRequestHeaders.UserAgent.Count == 0) http.DefaultRequestHeaders.UserAgent.ParseAdd("Stenwatch");
        var offline = ""; var fetched = 0; var unknown = new List<string>();

        async Task<List<Release>?> Releases(string slug)
        {
            if (cache.TryGetValue(slug, out var c) && (c.Fetched == stamp || offline != "")) return c.Releases.Count > 0 ? c.Releases : null;
            if (offline == "")
                try
                {
                    using var r = await http.GetAsync(Api + Uri.EscapeDataString(slug) + "/");
                    if (r.StatusCode == System.Net.HttpStatusCode.NotFound) { cache[slug] = new(stamp, new()); unknown.Add(slug); return null; }
                    r.EnsureSuccessStatusCode();
                    var list = Parse(await r.Content.ReadAsStringAsync()); cache[slug] = new(stamp, list); fetched++; return list;
                }
                catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException or KeyNotFoundException or InvalidOperationException) { offline = e.GetType().Name; }
            return c is { Releases.Count: > 0 } ? c.Releases : null;
        }

        var rows = new List<Exposure>(); var notChecked = new List<string>(); int checkedN = 0, past = 0, soon = 0;
        foreach (var a in assets)
        {
            var (slug, pin) = SlugFor(a.Cpe, data);
            if (slug is null) { notChecked.Add($"{a.Name}: no endoflife.date product for {Key(a.Cpe)}"); continue; }
            if (a.Version == "" && pin == "") { notChecked.Add($"{a.Name}: no version"); continue; }
            var rel = await Releases(slug);
            if (rel is null) { notChecked.Add($"{a.Name}: no endoflife.date data for {slug}"); continue; }
            var cyc = CycleOf(a.Version, pin, rel, slug);
            if (cyc is null) { notChecked.Add($"{a.Name}: version {a.Version} matches no {slug} release"); continue; }
            var eol = DateOnly.TryParse(cyc.EolFrom, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : (DateOnly?)null;
            if (eol is null && !cyc.IsEol) { notChecked.Add($"{a.Name}: endoflife.date gives no end-of-life date for {slug} {cyc.Name}"); continue; }
            checkedN++;
            // decided on isEol and eolFrom only: isMaintained can be true after end of life (extended support, Windows 10 22H2)
            var isPast = eol is { } p ? p <= day : cyc.IsEol;
            var isSoon = !isPast && eol is { } s && s <= day.AddDays(SoonDays);
            if (!isPast && !isSoon) continue;
            if (isPast) past++; else soon++;
            var when = eol is { } w ? w.ToString("yyyy-MM-dd") : "a date not given";
            rows.Add(new(Component, a.Name, $"eol:{slug}-{cyc.Name}", $"{slug} {cyc.Name} {(isPast ? "past end of life" : "reaches end of life")} {when}", isPast ? "High" : "Medium",
                $"{(isPast ? "End of life since" : "End of life on")} {when} (endoflife.date, {slug} {cyc.Name})"
                + (pin.Contains('|') ? $"; edition not known, so the later of the {pin.Replace("|", " and ")} dates" : "") + (a.InternetFacing ? "; the asset is internet-facing" : ""),
                "endoflife.date", stamp));
        }
        try { File.WriteAllText(cacheFile, JsonSerializer.Serialize(cache)); } catch (IOException) { }
        Exposure.Save(saveTo ?? data, Component, rows);
        var note = $"End of life: {checkedN} assets checked, {past} past end of life, {soon} within {SoonDays} days, {notChecked.Count} not checked"
            + (offline != "" ? $"; endoflife.date not reachable ({offline}), cached cycles used" : fetched > 0 ? $"; {fetched} products read from endoflife.date" : "; cached cycles from today")
            + (unknown.Count > 0 ? $"; unknown to endoflife.date: {string.Join(", ", unknown)}" : "");
        log?.Invoke(note);
        return new(checkedN, past, soon, notChecked, note);
    }
}
