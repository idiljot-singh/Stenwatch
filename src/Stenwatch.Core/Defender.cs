using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Stenwatch.Core;

/// <summary>CTI stage 2 - Collection: owned assets straight from Microsoft Defender for Endpoint.
/// Replaces hand-maintained assets.csv rows with the live software inventory, and uses Defender's own
/// per-device vulnerability list so already-patched CVEs drop out.
/// Setup (tenant admin): Entra app "stenwatch" with WindowsDefenderATP application permissions
/// Software.Read.All, Vulnerability.Read.All, Machine.Read.All; upload a certificate (no client secret).</summary>
public static class Defender
{
    const string Api = "https://api.securitycenter.microsoft.com/api";
    static readonly Dictionary<string, int> DeviceValue = new() { ["Low"] = 1, ["Normal"] = 2, ["High"] = 3 }; // Defender "device value" -> our criticality
    const string InternetTag = "internet-facing"; // tag internet-facing devices in Defender with this

    static async Task<string> Token(DefenderCfg cfg)
    {
        // PEM holds private key + certificate; the thumbprint comes from the certificate itself
        var cert = X509Certificate2.CreateFromPemFile(cfg.Certificate);
        var app = ConfidentialClientApplicationBuilder.Create(cfg.ClientId)
            .WithAuthority($"https://login.microsoftonline.com/{cfg.TenantId}").WithCertificate(cert).Build();
        var r = await app.AcquireTokenForClient(new[] { "https://api.securitycenter.microsoft.com/.default" }).ExecuteAsync();
        return r.AccessToken;
    }

    static async Task<List<JsonElement>> GetAll(HttpClient http, string url)
    {
        var rows = new List<JsonElement>();
        while (url != null)
        {
            using var doc = JsonDocument.Parse(await http.GetStringAsync(url));
            rows.AddRange(doc.RootElement.GetProperty("value").EnumerateArray().Select(e => e.Clone()));
            url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n) ? n.GetString()! : null!;
        }
        return rows;
    }

    static string S(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    /// <summary>Defender rows -> assets, one per (vendor, product, version) across the fleet.
    /// Defender names software in the same vocabulary as NVD CPEs, so microsoft / exchange_server maps straight to cpe:2.3:a:microsoft:exchange_server.</summary>
    public static List<Asset> ToAssets(IEnumerable<JsonElement> machines, IEnumerable<JsonElement> inventory, IEnumerable<JsonElement> vulns)
    {
        var dev = machines.ToDictionary(m => S(m, "id"));
        var cves = new Dictionary<(string, string, string), HashSet<string>>();
        foreach (var v in vulns)
        {
            var k = (S(v, "softwareVendor"), S(v, "softwareName"), S(v, "softwareVersion"));
            if (!cves.TryGetValue(k, out var set)) cves[k] = set = new();
            set.Add(S(v, "cveId"));
        }
        var groups = new SortedDictionary<(string, string, string), HashSet<string>>(Comparer<(string, string, string)>.Create((a, b) =>
            string.CompareOrdinal(string.Join("\0", a.Item1, a.Item2, a.Item3), string.Join("\0", b.Item1, b.Item2, b.Item3))));
        foreach (var row in inventory)
        {
            var k = (S(row, "softwareVendor"), S(row, "softwareName"), S(row, "softwareVersion"));
            if (!groups.TryGetValue(k, out var set)) groups[k] = set = new();
            set.Add(S(row, "deviceId"));
        }
        return groups.Select(g =>
        {
            var (vendor, name, version) = g.Key;
            var ms = g.Value.Where(dev.ContainsKey).Select(d => dev[d]).ToList();
            // ponytail: part guessed from the name ('o' for Windows OS, else 'a'); fine for Microsoft estates
            var part = name.StartsWith("windows") ? "o" : "a";
            return new Asset($"{name} {version} ({g.Value.Count} devices)", // no hostnames: they never leave Defender
                $"cpe:2.3:{part}:{vendor}:{name}", version,
                ms.Count == 0 ? 2 : ms.Max(m => DeviceValue.GetValueOrDefault(S(m, "deviceValue"), 2)),
                ms.Any(m => m.TryGetProperty("machineTags", out var t) && t.EnumerateArray().Any(x => x.GetString()!.ToLowerInvariant() == InternetTag)),
                false, OnlyCves: cves.GetValueOrDefault(g.Key) ?? new());
        }).ToList();
    }

    public static async Task<List<Asset>> FetchAssets(DefenderCfg cfg, HttpClient? http = null)
    {
        http ??= new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await Token(cfg));
        return ToAssets(await GetAll(http, $"{Api}/machines"),
            await GetAll(http, $"{Api}/machines/SoftwareInventoryByMachine?pageSize=100000"),
            await GetAll(http, $"{Api}/machines/SoftwareVulnerabilitiesByMachine?pageSize=100000"));
    }
}
