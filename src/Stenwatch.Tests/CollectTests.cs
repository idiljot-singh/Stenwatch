using System.Text.Json;
using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Ports of test_pipeline.py's offline collection checks.</summary>
public class CollectTests
{
    static JsonElement J(string s) => JsonDocument.Parse(s).RootElement.Clone();

    [Fact]
    public void ParseNvd_PicksCvssCweAndVulnerableCpesOnly()
    {
        var item = J(@"{""cve"": {""id"": ""CVE-2021-26855"", ""published"": ""2021-03-03"", ""lastModified"": ""2025-01-01"",
            ""descriptions"": [{""lang"": ""es"", ""value"": ""x""}, {""lang"": ""en"", ""value"": ""Exchange SSRF""}],
            ""metrics"": {""cvssMetricV31"": [{""cvssData"": {""baseScore"": 9.1}}]},
            ""weaknesses"": [{""description"": [{""value"": ""CWE-918""}]}],
            ""configurations"": [{""nodes"": [{""cpeMatch"": [
              {""vulnerable"": true, ""criteria"": ""cpe:2.3:a:microsoft:exchange_server:2019:*"", ""matchCriteriaId"": ""x""},
              {""vulnerable"": false, ""criteria"": ""cpe:2.3:o:microsoft:windows:-:*"", ""matchCriteriaId"": ""y""}]}]}]}}");
        var row = Collect.ParseNvd(item);
        Assert.Equal("CVE-2021-26855", row[0]); Assert.Equal(9.1, row[3]); Assert.Equal("CWE-918", row[4]); Assert.Equal("Exchange SSRF", row[6]);
        Assert.Contains("exchange_server", (string)row[5]!); Assert.DoesNotContain("windows", (string)row[5]!);
        Assert.DoesNotContain("matchCriteriaId", (string)row[5]!);
    }

    [Fact]
    public void ParseNvd_SurvivesRecordsWithFieldsMissing()
    {
        var row = Collect.ParseNvd(J(@"{""cve"": {""id"": ""CVE-2026-1"", ""metrics"": {""cvssMetricV31"": [{}]}, ""weaknesses"": [{}], ""configurations"": [{}, {""nodes"": [{}]}]}}"));
        Assert.Equal("CVE-2026-1", row[0]); Assert.Null(row[3]); Assert.Equal("", row[6]); Assert.Equal("[]", row[5]);
    }

    [Fact]
    public void Errors_ExplainCommonFailuresInPlainWords()
    {
        Assert.StartsWith("A feed sent data in an unexpected shape", Errors.Explain(new KeyNotFoundException("The given key was not present in the dictionary.")));
        Assert.StartsWith("The feed is rate-limiting", Errors.Explain(new HttpRequestException("x", null, System.Net.HttpStatusCode.TooManyRequests)));
    }

    [Fact]
    public void TinyFeed_IsRejected() =>
        Assert.Throws<InvalidDataException>(() => Collect.CheckSize("KEV", 2, Collect.MinKev));

    [Fact]
    public void ParseAttack_GroupTechniqueCampaignAndCve()
    {
        string R(string id) => $@"[{{""source_name"": ""mitre-attack"", ""external_id"": ""{id}""}}]";
        var objs = J($@"[
          {{""type"": ""intrusion-set"", ""id"": ""is--1"", ""name"": ""APT28"", ""external_references"": {R("G0007")}}},
          {{""type"": ""attack-pattern"", ""id"": ""ap--1"", ""name"": ""Exploit Public-Facing Application"", ""external_references"": {R("T1190")},
            ""kill_chain_phases"": [{{""phase_name"": ""initial-access""}}]}},
          {{""type"": ""campaign"", ""id"": ""c--1"", ""name"": ""C1"", ""external_references"": {R("C0001")}}},
          {{""type"": ""relationship"", ""id"": ""r--1"", ""relationship_type"": ""attributed-to"", ""source_ref"": ""c--1"", ""target_ref"": ""is--1""}},
          {{""type"": ""relationship"", ""id"": ""r--2"", ""relationship_type"": ""uses"", ""source_ref"": ""c--1"", ""target_ref"": ""ap--1"",
            ""description"": ""During C1, APT28 exploited CVE-2021-26855.""}}]").EnumerateArray().ToList();
        var (techniques, _, aTech, aCve) = Collect.ParseAttack(objs);
        Assert.Equal(new[] { ("T1190", "Exploit Public-Facing Application", "initial-access") }, techniques);
        Assert.Equal(new[] { ("G0007", "T1190") }, aTech);
        Assert.Equal(new[] { ("G0007", "CVE-2021-26855") }, aCve);
    }

    [Fact]
    public void ParseMitigationsAndD3fend()
    {
        string R(string id) => $@"[{{""source_name"": ""mitre-attack"", ""external_id"": ""{id}""}}]";
        var objs = J($@"[
          {{""type"": ""attack-pattern"", ""id"": ""ap--1"", ""name"": ""X"", ""external_references"": {R("T1190")}}},
          {{""type"": ""course-of-action"", ""id"": ""coa--1"", ""name"": ""Update Software"", ""external_references"": {R("M1051")}}},
          {{""type"": ""relationship"", ""id"": ""r--3"", ""relationship_type"": ""mitigates"", ""source_ref"": ""coa--1"", ""target_ref"": ""ap--1""}}]").EnumerateArray().ToList();
        Assert.Equal(new[] { ("T1190", "M1051", "Update Software") }, Collect.ParseMitigations(objs));
        var d3 = Collect.ParseD3fend("T1190", J(@"{""off_to_def"": {""results"": {""bindings"": [
          {""def_tech_id"": {""value"": ""D3-NTF""}, ""def_tech_label"": {""value"": ""Network Traffic Filtering""}, ""def_tactic_label"": {""value"": ""Isolate""}}]}}}"));
        Assert.Equal(new[] { ("T1190", "D3-NTF", "Network Traffic Filtering", "Isolate") }, d3);
    }
}
