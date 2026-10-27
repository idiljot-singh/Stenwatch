using System.Globalization;
using Stenwatch.Core;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

// stenwatch [--example] [--data DIR]  (default data folder: data/ in a checkout, else %APPDATA%\Stenwatch) [--out DIR] [--collect [--since 2026-10-20]] [--no-pdf]
// stenwatch --evaluate-attack | --evaluate-paths chains.csv | --rating-sheet | --rating-import sheet.csv key.csv
// stenwatch --import-services|--import-links|--import-controls|--import-assets FILE
var a = args.ToList();
string Opt(string name, string dflt) { var i = a.IndexOf(name); return i >= 0 && i + 1 < a.Count ? a[i + 1] : dflt; }
var data = Opt("--data", AppPaths.Data());
var ex = a.Contains("--example") ? ".example" : "";
var src = a.Contains("--example") ? AppPaths.Examples() : data; // the Example Organisation ships with the program; your own files live in the data folder
var files = new PipelineFiles(Path.Combine(data, "cve.db"), Path.Combine(src, $"profile{ex}.yaml"),
    Path.Combine(src, $"assets{ex}.csv"), Path.Combine(src, $"third_parties{ex}.csv"), Path.Combine(src, $"exceptions{ex}.csv"));

if (a.Contains("--refresh-groups")) // pull ATT&CK again so automatic threat-group selection has group descriptions and campaign dates
{
    using var gdb = Collect.Connect(files.Db);
    var (t, g, c) = await new Collect(log: Console.WriteLine).SyncAttack(gdb);
    Console.WriteLine($"ATT&CK: {t} techniques, {g} groups, {c} group-to-CVE links");
    var (eff, picks, note) = ThreatProfileAuto.Effective(Profile.Load(files.Profile), gdb);
    Console.WriteLine(note); foreach (var p in picks) Console.WriteLine($"  {p.Id,-7} {p.Name,-22} {p.Source,-7} {string.Join("; ", p.Reasons)}");
    return;
}
if (a.Contains("--evaluate-attack")) // docs/evaluation.md, test 1: writes out/evaluation/attack-value*.md
{
    var prof = Profile.Load(files.Profile);
    var dir = Path.Combine(data, "out", "evaluation"); Directory.CreateDirectory(dir);
    foreach (var all in new[] { false, true })
    {
        var res = await new AttackValue(Path.Combine(dir, "cache"), log: Console.WriteLine).Run(files.Db, prof, allGroups: all);
        var name = all ? "attack-value-all-groups" : "attack-value";
        File.WriteAllText(Path.Combine(dir, name + ".md"), res.Markdown);
        File.WriteAllText(Path.Combine(dir, name + ".json"), System.Text.Json.JsonSerializer.Serialize(res.Inputs, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"{name}: {res.Label}. {res.Reason}");
    }
    return;
}
if (a.Contains("--evaluate-paths")) // test 2: sourced chains only
{
    var dir = Path.Combine(data, "out", "evaluation"); Directory.CreateDirectory(dir);
    var report = ChainEval.Report(ChainEval.Run(Opt("--evaluate-paths", Path.Combine(data, "docs", "evaluation", "chains.csv")), Profile.Load(files.Profile)));
    File.WriteAllText(Path.Combine(dir, "attack-paths.md"), report); Console.WriteLine(report);
    return;
}
if (a.Contains("--rating-sheet")) // test 3: blind sheet for analysts
{
    var res = await Engine.Run(files, new RunOptions(Example: a.Contains("--example"), Pdf: false, Out: Path.Combine(data, "out", "evaluation", "scratch")));
    var dir = Path.Combine(data, "out", "evaluation");
    Console.WriteLine($"{RatingSheet.Export(res.Ranked, Path.Combine(dir, "rating-sheet.csv"), Path.Combine(dir, "rating-key.csv"))} findings -> {dir}\\rating-sheet.csv (key kept in rating-key.csv: do not give it to raters)");
    return;
}
if (a.Contains("--rating-import"))
{
    var i = a.IndexOf("--rating-import");
    var r = RatingSheet.Import(a[i + 1], a[i + 2]);
    Console.WriteLine($"{r.Label}: {r.Rated} rated; specific {r.Specific:0.00} vs generic {r.Generic:0.00}; difference interval [{r.Low:0.00}, {r.High:0.00}]");
    return;
}
if (a.Contains("--convert-inventory")) // inventory export (hostname, vendor, product, os) -> assets.csv
{
    using var db = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={files.Db};Mode=ReadOnly"); db.Open();
    var file = Opt("--convert-inventory", ""); // a file given: show what it converts to, write nothing
    var r = File.Exists(file) ? Inventory.Convert(file, db) : Inventory.ConvertFile(files.Assets, db);
    Console.WriteLine($"{r.Hosts} hosts -> {r.Assets.Count} assets; {r.Unmatched.Sum(u => u.Hosts)} hosts not matched" + (File.Exists(file) ? "" : " (assets.unmatched.csv); original kept as assets.inventory.csv"));
    foreach (var x in r.Assets) Console.WriteLine($"  {x[0],-45} {x[1]} {x[2]}");
    foreach (var u in r.Unmatched) Console.WriteLine($"  not matched: {u.What} ({u.Hosts})");
    return;
}
foreach (var (flag, import) in new (string, Func<Microsoft.Data.Sqlite.SqliteConnection, string, int>)[] {
    ("--import-services", ContextStore.ImportServices), ("--import-links", ContextStore.ImportLinks),
    ("--import-controls", ContextStore.ImportControls), ("--import-assets", ContextStore.ImportAssetContext) })
    if (a.Contains(flag)) { using var db = Collect.Connect(files.Db); Console.WriteLine($"{flag[9..]}: {import(db, Opt(flag, ""))} rows imported"); return; }

var result = await Engine.Run(files, new RunOptions(Example: a.Contains("--example"), Pdf: !a.Contains("--no-pdf"), Out: Opt("--out", ""),
    Collect: a.Contains("--collect"), Since: Opt("--since", "") is { Length: > 0 } s ? DateTimeOffset.Parse(s, null, DateTimeStyles.AssumeUniversal) : null), Console.WriteLine);
foreach (var e in result.Events.Take(8)) Console.WriteLine($"  {e.Kind,-16} {e.Cve} {e.Asset}: {e.Detail}");
if (Opt("--ask", "") is { Length: > 0 } q) // stenwatch --ask G0007 | --ask CWE-79: knowledge-graph questions
{
    using var gdb = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={files.Db};Mode=ReadOnly"); gdb.Open();
    var g = Knowledge.Build(gdb, result.Ranked, result.Context);
    Console.WriteLine($"graph: {g.Nodes.Count} nodes, {g.Edges.Count} edges");
    var hits = q.StartsWith("CWE-") ? g.SharedWeakness(q).Select(x => (x.Asset, x.Cve, "")) : g.AssetsHitBy(q).Select(x => (x.Asset, x.Cve, x.Via));
    foreach (var (asset, cve, via) in hits.Take(15)) Console.WriteLine($"  {asset,-40} {cve,-16} {via}");
}
Console.WriteLine($"{result.Ranked.Count} ranked findings ({result.Suppressed.Count} suppressed) -> {result.OutDir}");
