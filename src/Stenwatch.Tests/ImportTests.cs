using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Imports.Run on the Example Organisation's fictional exports (examples/imports): each is recognised from its own keys, feeds the right component,
/// keeps the right rows, and the ladder gives the tiers the file was written to show. Offline, in a temp folder.</summary>
public class ImportTests : IDisposable
{
    readonly string dir = Directory.CreateTempSubdirectory("stenwatch-imp").FullName;
    public void Dispose() => Directory.Delete(dir, true);
    static string Sample(string name) => Path.Combine(AppPaths.Repo()!, "examples", "imports", name);

    [Theory]
    [InlineData("entra-risky-users.example.json", "Entra risky users", "Identity", 5, 3, "Act")]            // confirmed compromised
    [InlineData("intune-devices.example.json", "Intune devices", "Misconfiguration", 5, 5, "Track")]        // noncompliant: high, nothing more known
    [InlineData("defender-recommendations.example.json", "Defender security recommendations", "Misconfiguration", 5, 3, "Attend")] // internet-facing tag
    [InlineData("defender-for-cloud.example.json", "Defender for Cloud", "Cloud workloads", 4, 3, "Track")]
    [InlineData("exposure-graph-nodes.example.csv", "Exposure Management", "Attack surface", 4, 2, "Attend")] // internet + RCE
    [InlineData("easm-assets.example.json", "Defender EASM", "Attack surface", 4, 3, "Attend")]              // CVE on an internet-facing host
    [InlineData("zap-report.example.json", "OWASP ZAP report", "Web apps", 5, 4, "Track")]
    [InlineData("code-scan.example.sarif", "SARIF file", "Web apps", 4, 2, "Attend")]                        // security-severity 9.8
    [InlineData("cloud-apps-discovered.example.csv", "Defender for Cloud Apps", "AI discovery", 5, 3, "Track")]
    [InlineData("iot-device-inventory.example.csv", "Defender for IoT", "OT and IoT", 5, 3, "Track")]
    public void ExampleFile_IsRecognised_AndRanked(string file, string format, string component, int read, int findings, string topTier)
    {
        var r = Imports.Run(Sample(file), dir);
        Assert.Equal((format, component, read, findings), (r.Format, r.Component, r.Read, r.Findings));
        var rows = Exposure.Load(dir, component);
        Assert.Equal(findings, rows.Count);
        Assert.Equal(topTier, rows.MinBy(x => Array.IndexOf(DefenderTriage.Tiers, x.Tier))!.Tier);
        Assert.All(rows, x => { Assert.NotEqual("", x.Asset); Assert.NotEqual("", x.ItemId); Assert.NotEqual("", x.Title); });
        Assert.Equal(Coverage.Connected, Coverage.Of(dir).Single(c => c.Component.Name == component).Status);
    }

    [Fact]
    public void TwoFormatsForOneComponent_KeepTheirOwnRows_AndAReimportReplacesOnlyItsOwn()
    {
        Imports.Run(Sample("intune-devices.example.json"), dir); Imports.Run(Sample("defender-recommendations.example.json"), dir);
        Assert.Equal(8, Exposure.Load(dir, "Misconfiguration").Count);
        Imports.Run(Sample("intune-devices.example.json"), dir);
        Assert.Equal(8, Exposure.Load(dir, "Misconfiguration").Count);
    }

    [Fact]
    public void PortalStyleHeadings_ReadLikeTheApiNames_AndAnUnknownFileSaysSo()
    {
        var csv = Path.Combine(dir, "risky.csv");
        File.WriteAllText(csv, "User principal name;Risk level;Risk state;Risk last updated\nx@example-org.invalid;High;At risk;2026-11-01T10:00:00Z\n");
        Assert.Equal(1, Imports.Run(csv, dir).Findings);
        File.WriteAllText(csv, "a,b\n1,2\n");
        Assert.Contains("not a format Stenwatch knows", Assert.Throws<InvalidDataException>(() => Imports.Run(csv, dir)).Message);
        File.WriteAllText(csv, "{ not json");
        Assert.Throws<InvalidDataException>(() => Imports.Run(csv, dir));
    }

    [Fact]
    public void ComplianceEvidence_CountsTasks_AndEscapesNames()
    {
        var tasks = new List<RemediationTask> { new(1, "CVE-2026-0001", "<b>srv</b>", TaskState.Open, "Act", "IT", "", "2026-10-01", "2026-10-03", "", ""), new(2, "CVE-2026-0002", "srv2", TaskState.Verified, "Track", "IT", "", "2026-10-01", "2026-12-01", "2026-10-20", "") };
        var html = Compliance.Html("Example & Co", new(), tasks, new(), new DateOnly(2026, 11, 16));
        Assert.Contains("Article 21(2)(e)", html); Assert.Contains("1 active (1 past their deadline)", html); Assert.Contains("1 verified", html);
        Assert.Contains("Example &amp; Co", html); Assert.DoesNotContain("<b>srv</b>", html);
    }
}
