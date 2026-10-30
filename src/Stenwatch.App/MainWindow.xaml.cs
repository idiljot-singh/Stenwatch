using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Control = Stenwatch.Core.Control;
using Line = System.Windows.Shapes.Line;
using Path = System.IO.Path;
using Process = Stenwatch.Core.Process;
using Microsoft.Data.Sqlite;
using Stenwatch.Core;

namespace Stenwatch.App;

public partial class MainWindow : Window
{
    string data = "";
    PipelineFiles files = null!;
    RunResult? last;
    bool loading = true;
    readonly ObservableCollection<ServiceRow> services = new();
    readonly ObservableCollection<AssetRow> assetRows = new();
    readonly ObservableCollection<LinkRow> links = new();
    readonly ObservableCollection<ControlRow> controls = new();
    List<FindingRow> allFindings = new();

    public MainWindow()
    {
        InitializeComponent();
        TierFilter.SelectedIndex = 0; DecStatus.SelectedIndex = 0; QKind.SelectedIndex = 0; // SelectedIndex in XAML is ignored when it precedes the items
        SinceDate.SelectedDate = DateTime.Today.AddDays(-30); SinceDate.DisplayDateEnd = DateTime.Today;
        SetupPickLists();
        ServicesGrid.ItemsSource = services; AssetsGrid.ItemsSource = assetRows; LinksGrid.ItemsSource = links; ControlsGrid.ItemsSource = controls;
        data = AppPaths.Data();
        Go(0);
        ExampleBox.IsChecked = Environment.GetEnvironmentVariable("STENWATCH_EXAMPLE") == "1" || !File.Exists(Path.Combine(data, "profile.yaml"));
        loading = false;
        Configure();
        // test hooks: STENWATCH_PAGE=n opens page n; STENWATCH_AUTORUN=1 ranks on start
        if (int.TryParse(Environment.GetEnvironmentVariable("STENWATCH_PAGE"), out var pg)) Go(pg);
        if (Environment.GetEnvironmentVariable("STENWATCH_TRIAGE") is { Length: > 0 } tx) Loaded += (_, _) => { Go(12); triExport = tx; TriLlm.IsChecked = Environment.GetEnvironmentVariable("STENWATCH_TRIAGE_LLM") == "1"; TriageRun(this, null!); }; // dev only: run the Morning triage on a file
        if (Environment.GetEnvironmentVariable("STENWATCH_SYNC") == "quick") Loaded += async (_, _) => await SyncFeeds(DateTimeOffset.UtcNow.AddDays(-2));
        if (Environment.GetEnvironmentVariable("STENWATCH_AUTORUN") == "1") Loaded += async (_, _) => { await RunEngine(false); if (pg > 0) Go(pg); if (Environment.GetEnvironmentVariable("STENWATCH_FIRST") == "1") { FindingsGrid.SelectedIndex = 0; PathsGrid.SelectedIndex = int.TryParse(Environment.GetEnvironmentVariable("STENWATCH_PATHROW"), out var pr) ? pr : 0; } };
    }

    bool Example => ExampleBox.IsChecked == true;
    string Db => Path.Combine(data, "cve.db");
    /// <summary>Where the tasks live: the real database, or the Example Organisation's throwaway one with its simulated history.</summary>
    string TaskDb => Example ? Path.Combine(last?.OutDir ?? Path.Combine(data, "out", "example-cs"), ExampleHistory.File) : Db;

    /// <summary>Point at the real organisation's files, or the bundled Example Organisation's.</summary>
    void Configure()
    {
        var ex = Example ? ".example" : "";
        var root = Example ? AppPaths.Examples() : data;
        files = new PipelineFiles(Db, Path.Combine(root, $"profile{ex}.yaml"), Path.Combine(root, $"assets{ex}.csv"),
            Path.Combine(root, $"third_parties{ex}.csv"), Path.Combine(root, $"exceptions{ex}.csv"));
        LoadSettings();
        if (!File.Exists(files.Profile)) { Status($"No profile.yaml in {data}: import one on 1 Direction, or tick the Example Organisation on Overview"); UpdateGate(); return; }
        var p = Profile.Load(files.Profile);
        OrgName.Text = p.Organisation.Name;
        ShowGroups(p);
        DirectionText.Text = $"Organisation  {p.Organisation.Name}, {p.Organisation.Sector}, {p.Organisation.Country}\n\nPriority intelligence requirements\n"
            + string.Join("\n", p.Pirs.Select(x => "  - " + x)) + "\n\nThreat groups\n" + string.Join("\n", p.ThreatGroups.Select(g => $"  {g.Key}  {g.Value}"))
            + $"\n\nLikelihood = {p.Weights.Epss}*EPSS + {p.Weights.Kev}*KEV + {p.Weights.Ransomware}*ransomware + {p.Weights.ThreatProfile}*threat overlap"
            + "\nImpact     = CVSS/10 * criticality * exposure"
            + $"\nExposure   internet {p.Exposure.Internet}, reachable from the internet {p.Exposure.Reachable} (proposed), internal {p.Exposure.Internal}"
            + $"\nControls   partial x{p.Controls.Partial}, strong x{p.Controls.Strong} (proposed)"
            + $"\nSLA        {string.Join(", ", p.Sla.Select(s => $"{s.Key} {s.Value} d"))}"
            + (p.PatchBaseline != "" ? $"\nPatched to {p.PatchBaseline} (assumption, patch_baseline): assets without a version or OS build skip CVEs published before it" : "\nPatch level exact only: assets without a version or OS build match every CVE for their product (set patch_baseline to assume a date)")
            + $"\n\nData folder: {data}";
        Status(Example ? "Example Organisation: bundled fictional data, nothing is saved" : $"data: {data}");
        var unmatched = Path.Combine(data, "assets.unmatched.csv");
        var left = !Example && File.Exists(unmatched) ? Csv.ReadDict(unmatched) : new();
        UnmatchedText.Text = left.Count == 0 ? "" : $"Not in the analysis: {left.Sum(u => int.TryParse(u.GetValueOrDefault("hosts"), out var h) ? h : 0)} host(s) whose product NVD has no entry for: "
            + string.Join(", ", left.Select(u => $"{u.GetValueOrDefault("what")} ({u.GetValueOrDefault("hosts")})"))
            + ". No NVD entry means no published CVE can be tied to them. If you know a close CPE (for example the model family), add a row to assets.csv by hand.";
        LoadFeeds(); LoadContext(); LoadTasks(null, null!); LoadEvidence(); UpdateGate();
    }

    /// <summary>Direction page: the threat groups that will be tracked, with the reason for each.</summary>
    void ShowGroups(Profile p)
    {
        List<GroupPick> picks; string note;
        if (File.Exists(Db))
        {
            using var db = new SqliteConnection($"Data Source={Db};Mode=ReadOnly"); db.Open();
            (_, picks, note) = ThreatProfileAuto.Effective(p, db);
        }
        else { picks = p.ThreatGroups.Select(g => new GroupPick(g.Key, g.Value, "pinned", 0, new() { "listed in profile.yaml threat_groups" })).ToList(); note = "no database yet"; }
        GroupsGrid.ItemsSource = picks.Select(g => new GroupRow(g)).ToList();
        GroupsNote.Text = $"targeting mode: {p.Targeting.Mode}. {note}. Automatic picks are Proposed: a keyword match against ATT&CK group text, with reasons shown. Pin a group by adding it to threat_groups, remove one with targeting.exclude.";
    }

    void Status(string s) => StatusBar.Text = s;
    void AddLog(string s) => Dispatcher.Invoke(() => { Log.AppendText(s + "\n"); Log.ScrollToEnd(); });

    void ExampleToggled(object s, RoutedEventArgs e) { if (!loading) { last = null; Configure(); } }
    void NavChanged(object s, SelectionChangedEventArgs e) { if (Pages != null && Nav.SelectedItem is ListBoxItem { Tag: string t }) Pages.SelectedIndex = int.Parse(t); UpdateGate(); }

    /// <summary>Open a page by its index in Pages; the rail item with that Tag is selected, none for pages outside the rail (Settings).</summary>
    void Go(int page)
    {
        Pages.SelectedIndex = page; // first: the switcher's Checked handler then sees the page is already in its workspace
        if (Ws(page) is var ws and >= 0) { ShowWs(ws); ((RadioButton)FindName("Ws" + ws)).IsChecked = true; } // links between pages switch workspace too
        var item = Nav.Items.OfType<ListBoxItem>().FirstOrDefault(i => i.Tag as string == page.ToString());
        if (item != null) Nav.SelectedItem = item; else Nav.SelectedIndex = -1;
        UpdateGate();
    }

    // ---------- workspaces: Start, CTI cycle, Intelligence; the rail shows one at a time ----------
    static int Ws(int page) => page is 0 or 1 or 12 ? 0 : page is >= 2 and <= 7 ? 1 : page is >= 8 and <= 10 ? 2 : -1;
    static readonly int[] WsFirst = { 0, 2, 8 };
    void ShowWs(int ws) { foreach (var i in Nav.Items.OfType<ListBoxItem>()) i.Visibility = i.Tag is string t && Ws(int.Parse(t)) == ws ? Visibility.Visible : Visibility.Collapsed; }
    void WsClick(object s, RoutedEventArgs e) { if (Pages == null) return; var ws = int.Parse((string)((RadioButton)s).Tag); if (Ws(Pages.SelectedIndex) != ws) Go(WsFirst[ws]); } // mouse, keyboard and UI Automation all raise Checked

    // ---------- toolbar ----------
    void GoSettings(object s, RoutedEventArgs e) => Go(11);
    void ToolbarUpdates(object s, RoutedEventArgs e) { Go(11); CheckUpdates(s, e); }
    void ShowInfo(object s, RoutedEventArgs e) => MessageBox.Show((Pages.SelectedItem as TabItem)?.Tag as string ?? "", "About this page", MessageBoxButton.OK, MessageBoxImage.Information);
    void ShowSources(object s, RoutedEventArgs e) => Go(11); // Settings: the Sources list, with this explanation behind its "?"
    const string SourcesText =
        "WHERE THE INTELLIGENCE COMES FROM (public, free, pulled on Sync)\n\n"
        + "NVD (NIST)  every published CVE: description, CVSS severity, affected products (CPE).\n"
        + "CISA KEV  CVEs confirmed exploited in the wild, and whether used in ransomware.\n"
        + "FIRST EPSS  daily probability that a CVE is exploited in the next 30 days.\n"
        + "MITRE ATT&CK  threat groups, the techniques they use, the sectors and countries they target.\n"
        + "CTID Mappings Explorer  which ATT&CK techniques a known-exploited CVE enables.\n"
        + "MITRE D3FEND  defensive countermeasures for those techniques.\n\n"
        + "From you (never leaves the machine): profile.yaml, assets.csv, services, links, controls, decisions.\n\n"
        + "SCANNER VS INTELLIGENCE\n\n"
        + "A scanner answers: which CVEs exist on this machine? It lists hundreds, sorted by CVSS severity, the same for every organisation.\n\n"
        + "Stenwatch answers: which of those should we fix first, and why? It adds what a scanner does not know: is it exploited now (KEV), "
        + "is it likely to be (EPSS), do the groups that target your sector use it (ATT&CK), how important is the asset to the business, "
        + "can an attacker reach it, is a control already covering it. Every priority carries its evidence, source and confidence, "
        + "goes to the right audience, and is checked again on the next scan. That direction-to-feedback cycle is what makes it intelligence.\n\n"
        + "Stenwatch does not scan. It uses your asset list (or Defender) for what you run.";

    // ---------- phase gate ----------
    static readonly Dictionary<int, (int To, string Label)> NextStep = new()
    {
        [2] = (3, "Next: 2 Collection"), [3] = (4, "Next: 3 Processing"), [4] = (5, "Rank now, then 4 Analysis"),
        [5] = (6, "Next: 5 Dissemination"), [6] = (7, "Next: 6 Feedback"), [7] = (10, "Next: Effectiveness"),
    };

    long Rows(string table)
    {
        try { using var db = new SqliteConnection($"Data Source={Db};Mode=ReadOnly"); db.Open(); using var c = db.CreateCommand(); c.CommandText = $"SELECT COUNT(*) FROM {table}"; return (long)c.ExecuteScalar()!; }
        catch { return 0; }
    }

    /// <summary>What a phase needs before moving on; all true = done.</summary>
    List<(bool Ok, string What)> Checks(int page)
    {
        var db = File.Exists(Db);
        switch (page)
        {
            case 2:
                var assets = File.Exists(files.Assets) ? File.ReadLines(files.Assets).Skip(1).Count(l => l.Trim() != "") : 0;
                var inventory = Inventory.IsInventory(files.Assets);
                return new() { (File.Exists(files.Profile), "profile.yaml"),
                    (assets > 0 && !inventory, inventory ? $"assets.csv is an inventory export ({assets} hosts): press Convert inventory" : $"assets.csv ({assets} assets)"),
                    (GroupsGrid.Items.Count > 0, $"threat groups ({GroupsGrid.Items.Count})") };
            case 3:
                return new() { (db, "database"), (db && Rows("cve") > 0, "NVD CVEs"), (db && Rows("kev") > 0, "CISA KEV"), (db && Rows("epss") > 0, "EPSS scores"), (db && Rows("technique") > 0, "ATT&CK") };
            case 4:
                return new() { (db, "database"), (true, $"optional: {services.Count} services, {assetRows.Count(a => a.CrownJewel)} crown jewels, {links.Count} links, {controls.Count} controls") };
            case 5: return new() { (last != null, last == null ? "not ranked yet" : $"ranked: {last.Ranked.Count:N0} findings") };
            case 6: return new() { (last != null && File.Exists(Path.Combine(last.OutDir, "report.html")), "reports written") };
            case 7: return new() { (true, TaskStatus.Text.Trim() is { Length: > 0 } t ? t : "no tasks (Example Organisation, or nothing to do)") };
            default: return new();
        }
    }

    void UpdateGate()
    {
        if (GateBar == null || files == null) return;
        if (!NextStep.TryGetValue(Pages.SelectedIndex, out var next)) { GateBar.Visibility = Visibility.Collapsed; return; }
        var checks = Checks(Pages.SelectedIndex); var ok = checks.All(c => c.Ok);
        GateBar.Visibility = Visibility.Visible;
        GateText.Text = string.Join("     ", checks.Select(c => (c.Ok ? "✓ " : "✗ ") + c.What));
        NextBtn.Content = (ok ? "" : "Not ready:  ") + next.Label + "  →";
        NextBtn.IsEnabled = ok;
        NextBtn.Style = ok ? (Style)FindResource("Primary") : (Style)FindResource(typeof(Button));
    }

    async void NextClick(object s, RoutedEventArgs e)
    {
        var (to, _) = NextStep[Pages.SelectedIndex];
        if (Pages.SelectedIndex == 4) { last = null; await RunEngine(false); if (last == null) return; } // failed: stay, the status bar says why
        Go(to);
    }

    // ---------- run ----------
    async void RunClick(object s, RoutedEventArgs e) => await RunEngine(false);
    /// <summary>Overview: sync, then rank.</summary>
    async void SyncClick(object s, RoutedEventArgs e) { if (await SyncFeeds(null)) await RunEngine(false); }
    async void SyncOnlyClick(object s, RoutedEventArgs e) => await SyncFeeds(null);
    async void QuickSyncClick(object s, RoutedEventArgs e)
    {
        if (SinceDate.SelectedDate is not { } d || d.Date > DateTime.Today) { Status("Pick a date in the past"); return; }
        await SyncFeeds(new DateTimeOffset(d.Date));
    }

    bool syncing;
    CancellationTokenSource? syncCancel;
    void CancelSync(object s, RoutedEventArgs e) { syncCancel?.Cancel(); CancelSyncBtn.IsEnabled = false; SyncStatus.Text = "Cancelling: finishing the current download..."; }

    /// <summary>Download the public feeds with visible progress on the Collection page. since = only CVEs changed after that date.</summary>
    async Task<bool> SyncFeeds(DateTimeOffset? since)
    {
        if (syncing) { Status("A sync is already running"); return false; }
        syncing = true; Go(3); // show the progress
        SyncNowBtn.IsEnabled = QuickSyncBtn.IsEnabled = RunBtn.IsEnabled = SyncBtn.IsEnabled = false;
        syncCancel = new CancellationTokenSource(); var token = syncCancel.Token; CancelSyncBtn.IsEnabled = true;
        SyncLog.Clear(); SyncBar.IsIndeterminate = true; SyncBar.Value = 0;
        var started = DateTime.Now; var step = "starting";
        var clock = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        clock.Tick += (_, _) => SyncStatus.Text = $"Working: {step}   (elapsed {(DateTime.Now - started):mm\\:ss})";
        clock.Start(); SyncStatus.Text = "Working: starting"; Status("syncing feeds...");
        void Line(string l) => Dispatcher.Invoke(() =>
        {
            SyncLog.AppendText($"{DateTime.Now:HH:mm:ss}  {l.Trim()}\n"); SyncLog.ScrollToEnd();
            var m = System.Text.RegularExpressions.Regex.Match(l, @"NVD\s+(\d+)/(\d+)");
            if (m.Success) { SyncBar.IsIndeterminate = false; SyncBar.Value = 100.0 * int.Parse(m.Groups[1].Value) / Math.Max(1, int.Parse(m.Groups[2].Value)); step = $"NVD {m.Groups[1].Value}/{m.Groups[2].Value} CVEs"; }
            else if (l.Contains(':')) step = l.Trim().Split(':')[0];
        });
        try
        {
            var db = Db; Directory.CreateDirectory(Path.GetDirectoryName(db)!);
            await Task.Run(() => new Collect(log: Line, ct: token).Run(db, since));
            SyncBar.IsIndeterminate = false; SyncBar.Value = 100;
            SyncStatus.Text = $"Finished in {(DateTime.Now - started):mm\\:ss}. The feeds are up to date; rank to apply them.";
            Status("feeds synced"); LoadFeeds(); Configure(); return true;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            SyncBar.IsIndeterminate = false;
            SyncLog.AppendText($"{DateTime.Now:HH:mm:ss}  CANCELLED\n");
            SyncStatus.Text = $"Cancelled after {(DateTime.Now - started):mm\\:ss}. Everything downloaded so far is saved; sync again to finish.";
            Status("sync cancelled"); LoadFeeds(); Configure(); return false;
        }
        catch (Exception ex)
        {
            SyncBar.IsIndeterminate = false; SyncBar.Value = 0;
            var why = Errors.Explain(ex);
            SyncLog.AppendText($"{DateTime.Now:HH:mm:ss}  FAILED: {why}\n");
            SyncStatus.Text = "Failed: " + why;
            Status("sync failed"); return false;
        }
        finally { clock.Stop(); syncing = false; CancelSyncBtn.IsEnabled = false; SyncNowBtn.IsEnabled = QuickSyncBtn.IsEnabled = RunBtn.IsEnabled = SyncBtn.IsEnabled = true; }
    }

    async Task RunEngine(bool collect)
    {
        if (!File.Exists(Db))
        {
            Go(3); CollectionNote.Text = "There is no database yet. Choose an existing cve.db, or sync the feeds (the first full sync of every CVE takes about 15 minutes without an NVD API key).";
            Status("No database yet: see Collection"); return;
        }
        RunBtn.IsEnabled = SyncBtn.IsEnabled = false; Status("working..."); Log.Clear();
        try
        {
            var example = Example; var f = files; // read UI state here, not on the worker thread
            last = await Task.Run(() => Engine.Run(f, new RunOptions(example, Pdf: true, Collect: collect), AddLog));
            ShowResult(last);
        }
        catch (Exception ex) { var why = Errors.Explain(ex); AddLog("FAILED: " + why); Status("failed: " + why); }
        finally { RunBtn.IsEnabled = SyncBtn.IsEnabled = true; }
    }

    void ShowResult(RunResult r)
    {
        Cards.Children.Clear();
        foreach (var (t, brush) in new[] { ("Act", "Act"), ("Attend", "Attend"), ("Track", "Track"), ("Ignore", "Ignore") })
        {
            var n = r.Ranked.Count(x => x.Tier == t);
            Cards.Children.Add(new Border { BorderThickness = new Thickness(3, 1, 1, 1), BorderBrush = (Brush)FindResource(brush), Background = (Brush)FindResource("Card"), Margin = new Thickness(0, 0, 10, 0), Padding = new Thickness(14, 10, 14, 10),
                Child = new StackPanel { Children = {
                    new TextBlock { Text = t.ToUpper(), Foreground = (Brush)FindResource(brush), FontFamily = (FontFamily)FindResource("Mono"), FontSize = 11, FontWeight = FontWeights.Bold },
                    new TextBlock { Text = r.Ranked.Where(x => x.Tier == t).Select(x => x.F.Cve).Distinct().Count().ToString("N0"), FontSize = 30, FontFamily = (FontFamily)FindResource("Mono"), FontWeight = FontWeights.Bold },
                    new TextBlock { Text = $"CVEs, on {n:N0} asset findings", Style = (Style)FindResource("Muted"), FontSize = 11 },
                    new TextBlock { Text = Analyse.Action[t], Style = (Style)FindResource("Muted"), FontSize = 12 } } } });
        }
        EventsGrid.ItemsSource = r.Events;
        allFindings = r.Ranked.Select(x => new FindingRow { R = x }).ToList();
        ApplyFilter();
        PathsGrid.ItemsSource = r.Paths?.Paths.Select(p => new PathRow { P = p }).ToList();
        ShowOutputs(r);
        LoadTasks(null, null!); LoadEvidence(); LoadFeeds();
        Status($"{r.Ranked.Count} findings ({r.Suppressed.Count} suppressed) -> {r.OutDir}"); UpdateGate();
        _ = AutoIntelligence(r);
    }

    /// <summary>After every rank, answer the standing questions on the Intelligence pages without anyone asking.</summary>
    async Task AutoIntelligence(RunResult r)
    {
        // attack paths: say what is missing when there are none
        var web = r.Ranked.Select(x => x.F.Asset).Where(a => a.InternetFacing).Select(a => a.Name).Distinct().Count();
        var jewels = r.Context.Assets.Values.Count(a => a.CrownJewel); var nLinks = r.Context.Links.Count;
        if (r.Paths?.Paths.Count > 0)
        {
            PathsNote.Text = $"Updated after this rank: {r.Paths.Paths.Count} possible route(s) to your crown jewels. The first is drawn; click another to draw it.";
        }
        else
        {
            // no route to a crown jewel yet: show where an attacker gets in, which needs no links at all
            var entries = r.Paths?.BestTo.Where(b => r.Paths.Hops.GetValueOrDefault(b.Key) == 1).Select(b => b.Value).OrderByDescending(p => p.Likelihood).ToList() ?? new();
            PathsGrid.ItemsSource = entries.Select(p => new PathRow { P = p }).ToList();
            PathsNote.Text = (entries.Count > 0 ? $"Entry points: {entries.Count} internet-facing asset(s) with a vulnerability usable from the internet, the first step of any attack. " : "")
                + $"Routes to crown jewels need links between assets (you have {nLinks}) and crown jewels ({jewels}); internet-facing assets: {web}. Add links on 3 Processing and rank again.";
        }
        if (PathsGrid.Items.Count > 0) PathsGrid.SelectedIndex = 0; // drawn without a click

        // knowledge graph: every tracked threat group against the estate
        var groups = (GroupsGrid.ItemsSource as IEnumerable<GroupRow>)?.Select(g => (g.Id, g.Name)).ToList() ?? new();
        var db = Db; GraphNote.Text = "Building the knowledge graph for this rank...";
        try
        {
            var (k, rows, map) = await Task.Run(() =>
            {
                using var c = new SqliteConnection($"Data Source={db};Mode=ReadOnly"); c.Open();
                var g = Knowledge.Build(c, r.Ranked, r.Context);
                var map = BuildMap(c, groups, r.Ranked);
                var rows = groups.Select(x =>
                {
                    var hits = g.AssetsHitBy(x.Id); var reported = hits.Where(h => h.Via == "reported").Select(h => h.Cve).Distinct().ToList();
                    return (Hits: hits.Count, Row: ($"{x.Name} ({x.Id})", $"{hits.Select(h => h.Asset).Distinct().Count()} of your assets; {reported.Count} CVE(s) the group is reported exploiting",
                        reported.Count > 0 ? "reported: " + string.Join(", ", reported.Take(4)) : hits.Count > 0 ? "technique overlap only (weaker)" : "no overlap found"));
                }).OrderByDescending(x => x.Hits).Select(x => x.Row).ToList();
                return (g, rows, map);
            });
            graph = k; graphFor = r;
            QGrid.ItemsSource = Bindable(rows);
            DrawMap(groups, map);
            GraphNote.Text = "Updated after this rank. Each threat group you track, the Act and Attend CVEs that matter to it, and your assets that have them. "
                + "Solid line: the group is documented exploiting that CVE. Dashed: the CVE gives a technique the group is known to use (weaker). Click a group or CVE to read about it (MITRE ATT&CK, NVD); click an asset to see its findings.";
        }
        catch (Exception ex) { GraphNote.Text = "Knowledge graph not built: " + ex.Message; }
    }

    /// <summary>WPF binds properties, not fields: ValueTuple.Item1 is a field, Tuple.Item1 a property.</summary>
    static List<Tuple<string, string, string>> Bindable(IEnumerable<(string, string, string)> rows) => rows.Select(r => Tuple.Create(r.Item1, r.Item2, r.Item3)).ToList();

    // ---------- collection ----------
    void LoadFeeds()
    {
        if (!File.Exists(Db)) { FeedGrid.ItemsSource = Bindable(new[] { ("no database yet", "", "use Sync feeds") }); return; }
        try
        {
            using var db = new SqliteConnection($"Data Source={Db};Mode=ReadOnly"); db.Open();
            CollectionNote.Text = $"Database: {Db}  ({new FileInfo(Db).Length / 1_000_000:N0} MB)";
            var meta = new Dictionary<string, string>();
            using (var c = db.CreateCommand()) { c.CommandText = "SELECT key, value FROM meta"; using var r = c.ExecuteReader(); while (r.Read()) meta[r.GetString(0)] = r.GetString(1); }
            long N(string t) { using var c = db.CreateCommand(); c.CommandText = $"SELECT COUNT(*) FROM {t}"; return (long)c.ExecuteScalar()!; }
            string Age(string k) => meta.TryGetValue(k, out var v) ? (EvidenceOf.IsStale(v, DateTimeOffset.UtcNow) ? v + "  (stale)" : v) : "unknown (not recorded yet)";
            FeedGrid.ItemsSource = Bindable(new[] {
                ("NVD", Age("nvd_sync"), $"{N("cve"):N0} CVEs"), ("CISA KEV", Age("kev_sync"), $"{N("kev"):N0} known-exploited"),
                ("FIRST EPSS", Age("epss_sync"), $"{N("epss"):N0} scores  {meta.GetValueOrDefault("epss_model", "")}"), ("MITRE ATT&CK", Age("attack_sync"), $"{N("technique"):N0} techniques, {N("actor"):N0} groups"),
                ("CTID mappings", Age("ctid_sync"), $"{N("cve_technique"):N0} CVE-to-technique"), ("MITRE D3FEND", Age("d3fend_sync"), $"{N("defend"):N0} countermeasure links") });
        }
        catch (Exception ex) { FeedGrid.ItemsSource = Bindable(new[] { ("database", "", ex.Message) }); }
    }

    // ---------- processing: context ----------
    void LoadContext()
    {
        services.Clear(); assetRows.Clear(); links.Clear(); controls.Clear();
        OrgContext c;
        if (Example) c = ContextStore.LoadExample(AppPaths.Examples());
        else if (File.Exists(Db)) { using var db = Collect.Connect(Db); c = ContextStore.Load(db); }
        else c = new OrgContext();
        foreach (var s in c.Services) services.Add(new() { Name = s.Name, Owner = s.Owner, Criticality = s.Criticality, DataClass = s.DataClass, Regulatory = s.Regulatory, RtoHours = s.RtoHours, Assets = string.Join(";", c.ServiceAssets.GetValueOrDefault(s.Name) ?? new()) });
        foreach (var a in c.Assets.Values) assetRows.Add(new() { Asset = a.Asset, Zone = a.Zone, Owner = a.Owner, CrownJewel = a.CrownJewel });
        foreach (var l in c.Links) links.Add(new() { From = l.Src, To = l.Dst, Kind = l.Kind, Port = l.Port, Note = l.Note });
        foreach (var k in c.Controls) controls.Add(new() { Id = k.Id, Name = k.Name, Type = k.Type, Scope = k.Scope, Counters = k.Counters, Effectiveness = k.Effectiveness, Evidence = k.Evidence, EvidenceDate = k.EvidenceDate, Expires = k.Expires });
        // every asset from the asset list gets a row, so there is something to fill in (empty rows are not saved)
        var listed = 0;
        try
        {
            if (File.Exists(files.Assets) && !Inventory.IsInventory(files.Assets))
                foreach (var r in Csv.ReadDict(files.Assets).Where(r => r.GetValueOrDefault("name", "").Trim() is { Length: > 0 } n && !c.Assets.ContainsKey(n)).DistinctBy(r => r["name"].Trim()))
                { assetRows.Add(new() { Asset = r["name"].Trim(), Zone = r.GetValueOrDefault("internet_facing", "").Trim().ToLowerInvariant() is "y" or "yes" or "true" ? "internet" : "internal" }); listed++; } // zone from the asset list, correct if needed
        }
        catch { } // a broken asset list is reported on 1 Direction
        RefreshAssetPickLists(); ServiceSelected(null!, null!);
        ContextStatus.Text = $"  {services.Count} services, {assetRows.Count} assets ({listed} new from {Path.GetFileName(files.Assets)}, zone pre-filled), {links.Count} links, {controls.Count} controls"
            + (Example ? ". Example Organisation: read-only." : "");
    }

    // ---------- knowledge graph map ----------
    record MapEdge(string Group, Ranked Finding, bool Reported, string Via);

    /// <summary>Per tracked group, the 3 Act/Attend CVEs that matter most to it: documented exploitation first, then a shared technique.</summary>
    static List<MapEdge> BuildMap(SqliteConnection db, List<(string Id, string Name)> groups, List<Ranked> ranked)
    {
        var tech = new Dictionary<string, HashSet<string>>(); var reported = new HashSet<(string, string)>();
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT actor, technique FROM actor_technique"; using var rd = c.ExecuteReader(); while (rd.Read()) { if (!tech.TryGetValue(rd.GetString(0), out var s)) tech[rd.GetString(0)] = s = new(); s.Add(rd.GetString(1)); } }
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT actor, cve FROM actor_cve"; using var rd = c.ExecuteReader(); while (rd.Read()) reported.Add((rd.GetString(0), rd.GetString(1))); }
        var urgent = ranked.Where(x => x.Tier is "Act" or "Attend").ToList();
        var edges = new List<MapEdge>();
        foreach (var (id, _) in groups)
        {
            var mine = tech.GetValueOrDefault(id) ?? new();
            edges.AddRange(urgent.Select(x => reported.Contains((id, x.Cve)) ? new MapEdge(id, x, true, "documented exploiting it")
                                                : x.Techniques.FirstOrDefault(t => mine.Contains(t.Id)) is { } t ? new MapEdge(id, x, false, $"{t.Id} {t.Name}") : null)
                .Where(m => m != null).Select(m => m!)
                .OrderByDescending(m => m.Reported).ThenByDescending(m => m.Finding.Risk).DistinctBy(m => m.Finding.Cve).Take(3));
        }
        return edges;
    }

    /// <summary>Node-link diagram: threat groups, the ATT&amp;CK techniques they use, the urgent CVEs that give them, and your assets with those CVEs.
    /// A small force-directed layout (repulsion between all nodes, springs along links) puts connected things together.</summary>
    void DrawMap(List<(string Id, string Name)> groups, List<MapEdge> edges)
    {
        KgCanvas.Children.Clear();
        Brush B(string k) => (Brush)FindResource(k);
        var nodes = new Dictionary<string, (string Type, string Label, string Tip, Action Click)>();
        var links = new HashSet<(string A, string B, bool Strong)>();
        void N(string key, string type, string label, string tip, Action click) { if (!nodes.ContainsKey(key)) nodes[key] = (type, label, tip, click); }
        foreach (var (id, name) in groups) N("g:" + id, "group", name, $"{name} ({id}). Click: who they are, what they target, how they operate (MITRE ATT&CK).", () => OpenFile($"https://attack.mitre.org/groups/{id}/"));
        foreach (var e in edges)
        {
            var r = e.Finding;
            N("c:" + r.Cve, "cve", r.Cve, $"{r.Cve}, {r.Tier}. {r.Summary}\n\nClick: the NVD entry.", () => OpenFile($"https://nvd.nist.gov/vuln/detail/{r.Cve}"));
            if (e.Reported) links.Add(("g:" + e.Group, "c:" + r.Cve, true));
            else
            {
                var tid = e.Via.Split(' ')[0]; var tname = e.Via[tid.Length..].Trim();
                N("t:" + tid, "technique", tid, $"{tid} {tname}: a technique the group is known to use, and this CVE enables. Click: MITRE ATT&CK.", () => OpenFile($"https://attack.mitre.org/techniques/{tid.Replace('.', '/')}/"));
                links.Add(("g:" + e.Group, "t:" + tid, false)); links.Add(("t:" + tid, "c:" + r.Cve, false));
            }
            foreach (var a in (lastRanked ?? new()).Where(x => x.Cve == r.Cve && x.Tier is "Act" or "Attend").Select(x => x.Asset.Name).Distinct().Take(3))
            {
                N("a:" + a, "asset", a, $"{a}: your asset. Click: its findings in Analysis.", () => { Filter.Text = a; TierFilter.SelectedIndex = 0; Go(5); });
                links.Add(("c:" + r.Cve, "a:" + a, true));
            }
        }
        var keys = nodes.Keys.ToList(); var idx = keys.Select((k, i) => (k, i)).ToDictionary(x => x.k, x => x.i);
        // layered layout: one column per type, read left to right; within a column, each node moves towards the average height
        // of its neighbours (barycentre), which untangles the lines, then the column is spaced evenly so labels never overlap
        var col = new Dictionary<string, double> { ["group"] = 0, ["technique"] = 330, ["cve"] = 620, ["asset"] = 930 };
        var layers = keys.GroupBy(x => nodes[x].Type).ToDictionary(g => g.Key, g => g.ToList());
        const double gap = 44;
        double H = gap * (layers.Values.Max(l => l.Count) + 1), W = 1200;
        var px = keys.Select(x => col[nodes[x].Type]).ToArray(); var py = new double[keys.Count];
        void Space(List<string> layer) { var off = (H - gap * (layer.Count - 1)) / 2; for (var i = 0; i < layer.Count; i++) py[idx[layer[i]]] = off + i * gap; }
        foreach (var l in layers.Values) Space(l);
        var nbrs = keys.ToDictionary(x => x, x => links.Where(l => l.A == x || l.B == x).Select(l => l.A == x ? l.B : l.A).ToList());
        for (var it = 0; it < 12; it++)
            foreach (var l in layers.Values)
            {
                l.Sort((a, b) => Bary(a).CompareTo(Bary(b))); Space(l);
                double Bary(string n) => nbrs[n].Count == 0 ? py[idx[n]] : nbrs[n].Average(m => py[idx[m]]);
            }

        var look = new Dictionary<string, (double Size, string Brush)> { ["group"] = (30, "Act"), ["technique"] = (16, "Attend"), ["cve"] = (22, "Accent"), ["asset"] = (22, "Track") };
        var lineEls = new List<(Line L, string A, string B)>(); var nodeEls = new Dictionary<string, List<UIElement>>();
        foreach (var (a, b, strong) in links)
        {
            var l = new Line { X1 = px[idx[a]], Y1 = py[idx[a]], X2 = px[idx[b]], Y2 = py[idx[b]], StrokeThickness = a.StartsWith("g:") && strong ? 2.5 : 1.3,
                Stroke = !strong ? B("Dim") : a.StartsWith("g:") ? B("Act") : new SolidColorBrush(Color.FromRgb(0x3a, 0x4a, 0x5e)) };
            if (!strong) l.StrokeDashArray = new DoubleCollection { 4, 3 };
            KgCanvas.Children.Add(l); lineEls.Add((l, a, b));
        }
        void Highlight(string? key)
        {
            var near = key is null ? null : links.Where(x => x.A == key || x.B == key).SelectMany(x => new[] { x.A, x.B }).Append(key).ToHashSet();
            foreach (var (l, a, b) in lineEls) l.Opacity = near is null || a == key || b == key ? 1 : 0.08;
            foreach (var (n, els) in nodeEls) foreach (var el in els) el.Opacity = near is null || near.Contains(n) ? 1 : 0.15;
        }
        foreach (var key in keys)
        {
            var (type, label, tip, click) = nodes[key]; var (size, brush) = look[type]; var x = px[idx[key]]; var y = py[idx[key]];
            var dot = new System.Windows.Shapes.Ellipse { Width = size, Height = size, Fill = B(brush), Stroke = B("Bg"), StrokeThickness = 2, Cursor = System.Windows.Input.Cursors.Hand, ToolTip = tip };
            var txt = new TextBlock { Text = label, FontSize = type == "group" ? 13 : 11, FontWeight = type == "group" ? FontWeights.SemiBold : FontWeights.Normal, Foreground = type == "technique" ? B("Mute") : B("Fg"), MaxWidth = 190, TextTrimming = TextTrimming.CharacterEllipsis, IsHitTestVisible = false };
            Canvas.SetLeft(dot, x - size / 2); Canvas.SetTop(dot, y - size / 2);
            Canvas.SetLeft(txt, x + size / 2 + 4); Canvas.SetTop(txt, y - 8);
            dot.MouseLeftButtonUp += (_, _) => click(); dot.MouseEnter += (_, _) => Highlight(key); dot.MouseLeave += (_, _) => Highlight(null);
            KgCanvas.Children.Add(dot); KgCanvas.Children.Add(txt); nodeEls[key] = new() { dot, txt };
        }
        var legend = new StackPanel { Orientation = Orientation.Horizontal };
        foreach (var (t, name) in new[] { ("group", "threat group"), ("technique", "ATT&CK technique"), ("cve", "urgent CVE"), ("asset", "your asset") })
        {
            legend.Children.Add(new System.Windows.Shapes.Ellipse { Width = 12, Height = 12, Fill = B(look[t].Brush), Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center });
            legend.Children.Add(new TextBlock { Text = name, Foreground = B("Mute"), FontSize = 11, Margin = new Thickness(0, 0, 18, 0) });
        }
        legend.Children.Add(new TextBlock { Text = "red line: documented exploiting it    dashed: via a technique the group uses    hover a node to isolate it", Foreground = B("Mute"), FontSize = 11 });
        Canvas.SetLeft(legend, 0); Canvas.SetTop(legend, -26); KgCanvas.Children.Add(legend);
        KgCanvas.Margin = new Thickness(10, 36, 10, 10); KgCanvas.Width = W; KgCanvas.Height = H;
    }
    List<Ranked>? lastRanked => last?.Ranked;

    // ---------- processing: pick lists and presets ----------
    static readonly string[] Zones = { "internet", "dmz", "internal", "cloud", "ot" };
    static readonly string[] LinkKinds = { "network", "remote-access", "admin", "trust" };
    static readonly string[] DataClasses = { "public", "internal", "confidential", "regulated" };
    static readonly (string Name, int Crit, string Data)[] ServicePresets =
    {
        ("Email", 2, "internal"), ("File sharing", 2, "confidential"), ("Remote access (VPN, gateway)", 3, "internal"), ("Identity (Active Directory, SSO)", 3, "confidential"),
        ("Finance and payroll", 3, "regulated"), ("Project delivery", 3, "confidential"), ("Backup and recovery", 3, "confidential"), ("Public website", 1, "public"),
    };
    // ATT&CK techniques each kind of control is commonly credited with countering (MITRE mitigations M1040, M1032, M1050, M1049, M1030, M1038, M1026)
    static readonly (string Name, string Type, string Counters)[] ControlPresets =
    {
        ("EDR on endpoints and servers", "edr", "T1059,T1068,T1203"),
        ("MFA on remote access and admin accounts", "mfa", "T1078,T1110,T1133"),
        ("Web application firewall in front of web apps", "waf", "T1190"),
        ("Email filtering and attachment sandbox", "email", "T1566,T1204"),
        ("Network segmentation between zones", "segmentation", "T1210,T1021"),
        ("Application allow-listing", "allowlist", "T1204,T1059"),
        ("Privileged access management (no standing admin)", "pam", "T1078,T1068"),
    };

    static DataGridComboBoxColumn Pick(DataGrid g, string header) => g.Columns.OfType<DataGridComboBoxColumn>().First(c => (string)c.Header == header);

    /// <summary>Fixed lists once; one click on a cell starts editing, and a list opens straight away.</summary>
    void SetupPickLists()
    {
        Pick(ServicesGrid, "CRITICALITY").ItemsSource = new[] { 1, 2, 3 };
        Pick(ServicesGrid, "DATA").ItemsSource = DataClasses;
        Pick(AssetsGrid, "ZONE").ItemsSource = Zones;
        Pick(LinksGrid, "KIND").ItemsSource = LinkKinds;
        Pick(ControlsGrid, "STRENGTH").ItemsSource = new[] { "partial", "strong" };
        ServicePreset.ItemsSource = new[] { "choose..." }.Concat(ServicePresets.Select(p => p.Name)).ToList(); ServicePreset.SelectedIndex = 0;
        ControlPreset.ItemsSource = new[] { "choose..." }.Concat(ControlPresets.Select(p => $"{p.Name}   ({p.Counters})")).ToList(); ControlPreset.SelectedIndex = 0;
        foreach (var g in new[] { ServicesGrid, AssetsGrid, LinksGrid, ControlsGrid })
        {
            g.AddHandler(DataGridCell.GotFocusEvent, new RoutedEventHandler((s, e) => { if (e.OriginalSource is DataGridCell { IsEditing: false, IsReadOnly: false }) ((DataGrid)s).BeginEdit(e); }));
            g.PreparingCellForEdit += (_, e) => { if (e.EditingElement is ComboBox cb) cb.IsDropDownOpen = true; };
        }
    }

    /// <summary>Lists that come from the assets: link ends and control scope.</summary>
    void RefreshAssetPickLists()
    {
        var names = assetRows.Select(a => a.Asset).Where(n => n != "").Distinct().ToList();
        Pick(LinksGrid, "FROM").ItemsSource = names; Pick(LinksGrid, "TO").ItemsSource = names;
        Pick(ControlsGrid, "SCOPE").ItemsSource = new[] { "*" }.Concat(Zones.Select(z => "zone:" + z)).Concat(names).ToList();
    }

    void ServiceSelected(object s, SelectionChangedEventArgs e)
    {
        ServiceAssetsPanel.Children.Clear();
        if (ServicesGrid.SelectedItem is not ServiceRow row) { ServiceAssetsPanel.Children.Add(new TextBlock { Text = "Select a service on the left, or add one with the list above.", Style = (Style)FindResource("Muted") }); return; }
        var mine = row.Assets.Split(';').Select(x => x.Trim()).Where(x => x != "").ToHashSet();
        foreach (var name in assetRows.Select(a => a.Asset).Where(n => n != "").Distinct())
        {
            var cb = new CheckBox { Content = name, IsChecked = mine.Contains(name), Margin = new Thickness(0, 3, 0, 3) };
            void Changed(object _, RoutedEventArgs __)
            {
                if (cb.IsChecked == true) mine.Add(name); else mine.Remove(name);
                row.Assets = string.Join(";", mine);
            }
            cb.Checked += Changed; cb.Unchecked += Changed;
            ServiceAssetsPanel.Children.Add(cb);
        }
    }

    void AddServicePreset(object s, SelectionChangedEventArgs e)
    {
        if (ServicePreset.SelectedIndex <= 0 || Example) { ServicePreset.SelectedIndex = 0; return; }
        var p = ServicePresets[ServicePreset.SelectedIndex - 1]; ServicePreset.SelectedIndex = 0;
        if (services.Any(r => r.Name == p.Name)) { ContextStatus.Text = $"  {p.Name} is already in the table."; return; }
        var row = new ServiceRow { Name = p.Name, Criticality = p.Crit, DataClass = p.Data };
        services.Add(row); ServicesGrid.SelectedItem = row; ServicesGrid.ScrollIntoView(row);
        ContextStatus.Text = $"  {p.Name} added: tick its assets on the right, set the owner, then Save context.";
    }

    void AddControlPreset(object s, SelectionChangedEventArgs e)
    {
        if (ControlPreset.SelectedIndex <= 0 || Example) { ControlPreset.SelectedIndex = 0; return; }
        var p = ControlPresets[ControlPreset.SelectedIndex - 1]; ControlPreset.SelectedIndex = 0;
        var next = controls.Select(c => int.TryParse(c.Id.TrimStart('C', 'c'), out var n) ? n : 0).DefaultIfEmpty().Max() + 1;
        var row = new ControlRow { Id = $"C{next}", Name = p.Name, Type = p.Type, Counters = p.Counters };
        controls.Add(row); ControlsGrid.SelectedItem = row; ControlsGrid.ScrollIntoView(row);
        ContextStatus.Text = $"  {p.Name} added. It only counts once EVIDENCE and DATED (YYYY-MM-DD) are filled in: say what proves it, e.g. a coverage report.";
    }

    void AddContextRow(object s, RoutedEventArgs e)
    {
        if (Example) { ContextStatus.Text = "  The Example Organisation is read-only."; return; }
        DataGrid grid; object row;
        switch (CtxTabs.SelectedIndex)
        {
            case 0: services.Add((ServiceRow)(row = new ServiceRow())); grid = ServicesGrid; break;
            case 1: assetRows.Add((AssetRow)(row = new AssetRow())); grid = AssetsGrid; break;
            case 2: links.Add((LinkRow)(row = new LinkRow())); grid = LinksGrid; break;
            default: controls.Add((ControlRow)(row = new ControlRow { Id = $"C{controls.Count + 1}" })); grid = ControlsGrid; break;
        }
        grid.UpdateLayout(); grid.ScrollIntoView(row); grid.UpdateLayout(); grid.SelectedItem = row; // the row must exist on screen before it can be edited grid.CurrentCell = new DataGridCellInfo(row, grid.Columns[0]); grid.Focus(); grid.BeginEdit();
    }

    void ReloadContext(object s, RoutedEventArgs e) { LoadContext(); ContextStatus.Text += $"   (reloaded {DateTime.Now:HH:mm:ss})"; }

    void SaveContext(object s, RoutedEventArgs e)
    {
        if (Example) { ContextStatus.Text = "  The Example Organisation is read-only."; return; }
        // a cell still being typed in is not in the rows until committed: clicking Save does not commit it by itself
        foreach (var g in new[] { ServicesGrid, AssetsGrid, LinksGrid, ControlsGrid }) { g.CommitEdit(DataGridEditingUnit.Cell, true); g.CommitEdit(DataGridEditingUnit.Row, true); }
        try
        {
            using var db = Collect.Connect(Db);
            ContextStore.EnsureSchema(db);
            using (var tx = db.BeginTransaction())
            {
                foreach (var t in new[] { "service", "service_asset", "asset_context", "link", "control" }) { using var c = db.CreateCommand(); c.CommandText = $"DELETE FROM {t}"; c.ExecuteNonQuery(); }
                foreach (var r in services.Where(r => r.Name.Trim() != "")) ContextStore.Save(db, new Service(r.Name.Trim(), r.Owner, r.Criticality, r.DataClass, r.Regulatory, r.RtoHours), r.Assets.Split(';').Select(x => x.Trim()).Where(x => x != ""));
                foreach (var r in assetRows.Where(r => r.Asset.Trim() != "" && (r.Zone != "" || r.Owner != "" || r.CrownJewel))) ContextStore.Save(db, new AssetContext(r.Asset.Trim(), r.Zone, r.Owner, r.CrownJewel));
                foreach (var r in links.Where(r => r.From.Trim() != "" && r.To.Trim() != "")) ContextStore.Save(db, new Link(r.From.Trim(), r.To.Trim(), r.Kind == "" ? "network" : r.Kind, r.Port, r.Note));
                foreach (var r in controls.Where(r => r.Id.Trim() != "")) ContextStore.Save(db, new Control(r.Id.Trim(), r.Name, r.Type, r.Scope == "" ? "*" : r.Scope, r.Counters, r.Effectiveness, r.Evidence, r.EvidenceDate, r.Expires));
                tx.Commit();
            }
            // names that match no asset are saved but do nothing: say so
            var known = assetRows.Select(r => r.Asset.Trim()).ToHashSet();
            var unknown = services.SelectMany(r => r.Assets.Split(';')).Concat(links.SelectMany(r => new[] { r.From, r.To }))
                .Concat(controls.SelectMany(r => r.Scope.Split(';', ',')))
                .Select(n => n.Trim()).Where(n => n != "" && n != "*" && !n.StartsWith("zone:") && !known.Contains(n)).Distinct().ToList();
            ContextStatus.Text = $"  saved at {DateTime.Now:HH:mm:ss}: {services.Count(r => r.Name.Trim() != "")} services, {links.Count} links, {controls.Count} controls. Rank again to apply."
                + (unknown.Count > 0 ? $"  Not an asset name (ignored): {string.Join(", ", unknown.Take(5))}. Copy names from Asset context." : "");
            UpdateGate();
        }
        catch (Exception ex) { ContextStatus.Text = "  not saved: " + ex.Message; }
    }

    // ---------- analysis ----------
    void FilterChanged(object s, RoutedEventArgs e) { if (IsLoaded) ApplyFilter(); }
    void ApplyFilter()
    {
        var q = Filter.Text.Trim().ToLowerInvariant(); var tier = (TierFilter.SelectedItem as ComboBoxItem)?.Content as string ?? "All";
        var rows = allFindings.Where(f => (tier == "All" || f.Tier == tier || (tier == "Act + Attend" && f.Tier is "Act" or "Attend")) && (q == "" || f.Cve.ToLowerInvariant().Contains(q) || f.Asset.ToLowerInvariant().Contains(q) || f.Why.ToLowerInvariant().Contains(q))).ToList();
        FindingsGrid.ItemsSource = rows.Take(2000).ToList();
        FindingCount.Text = $"   {rows.Select(f => f.Cve).Distinct().Count():N0} CVEs on {rows.Count:N0} asset findings (of {allFindings.Count:N0})" + (rows.Count > 2000 ? ", first 2,000 shown" : "");
    }

    void FindingSelected(object s, SelectionChangedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not FindingRow f) return;
        EvidenceGrid.ItemsSource = f.R.Evidence;
        ShowDetail(f.R);
    }

    /// <summary>One finding as separate cards, each answering one question in plain words.</summary>
    void ShowDetail(Ranked r)
    {
        Brush B(string k) => (Brush)FindResource(k);
        TextBlock Text(string s, bool muted = false) => new() { Text = s, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 2), Foreground = muted ? B("Mute") : B("Fg") };
        TextBlock Link(string s, string url)
        {
            var t = new TextBlock { Text = s + "  ↗", Foreground = B("Accent"), Cursor = System.Windows.Input.Cursors.Hand, TextDecorations = TextDecorations.Underline, Margin = new Thickness(0, 2, 14, 2), ToolTip = url };
            t.MouseLeftButtonUp += (_, _) => OpenFile(url); return t;
        }
        Border Card(string title, string brush, params UIElement[] body)
        {
            var sp = new StackPanel(); sp.Children.Add(new TextBlock { Text = title, Style = (Style)FindResource("H"), Foreground = B(brush), Margin = new Thickness(0, 0, 0, 4) });
            foreach (var b in body) sp.Children.Add(b);
            return new Border { Child = sp, Background = B("Card"), BorderBrush = B(brush), BorderThickness = new Thickness(3, 1, 1, 1), Padding = new Thickness(12, 8, 12, 10), Margin = new Thickness(0, 0, 8, 8) };
        }
        var f = r.F; var a = r.Asset; var tier = r.Tier is "Act" or "Attend" or "Track" ? r.Tier : "Ignore";
        var due = last?.Profile.Sla.TryGetValue(r.Tier, out var d) == true ? $" Deadline: {DateTime.Today.AddDays(d):yyyy-MM-dd} ({d} days)." : "";

        DetailPanel.Children.Clear();
        // headline: what, where, decision
        var head = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
        head.Children.Add(new TextBlock { Text = $"{r.Cve}  on  {a.Name}", FontSize = 18, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center });
        head.Children.Add(new Border { Background = B(tier), CornerRadius = new CornerRadius(3), Padding = new Thickness(8, 2, 8, 2), VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = r.Tier.ToUpper(), Foreground = Brushes.Black, FontWeight = FontWeights.Bold, FontFamily = (FontFamily)FindResource("Mono"), FontSize = 12 } });
        head.Children.Add(Text($"   {Analyse.Action[r.Tier]}.{due}"));
        DetailPanel.Children.Add(head);
        var links = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
        links.Children.Add(Link("NVD entry", $"https://nvd.nist.gov/vuln/detail/{r.Cve}"));
        if (f.Kev) links.Children.Add(Link("CISA KEV catalogue", $"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={r.Cve}"));
        if (f.Cwe is { Length: > 0 } cwe && cwe.Split(',')[0] is var c1 && c1.StartsWith("CWE-")) links.Children.Add(Link($"Weakness {c1}", $"https://cwe.mitre.org/data/definitions/{c1[4..]}.html"));
        DetailPanel.Children.Add(links);

        var grid = new System.Windows.Controls.Primitives.UniformGrid { Columns = 2 };
        // the vendor's own description: the generated summary repeats what the other cards say one by one
        grid.Children.Add(Card("WHAT IT IS", "Track", Text(f.Description != "" ? f.Description : r.Summary),
            Text($"Severity CVSS {(f.Cvss is { } cv ? cv.ToString("0.0", CultureInfo.InvariantCulture) : "not scored")}. Published {f.Published[..Math.Min(10, f.Published.Length)]}.", true)));
        grid.Children.Add(Card("IS IT BEING EXPLOITED?", f.Kev ? "Act" : "Attend",
            Text(r.Exploitation.Split(':')[0] switch // "observed: confirmed exploited ..." -> "observed"
            {
                "observed" => $"Yes, confirmed. CISA lists it as exploited in the wild{(f.KevAdded != "" ? " since " + f.KevAdded : "")}.{(f.Ransomware ? " Used in ransomware campaigns." : "")}",
                "reported" => "A threat group you track is documented using it.",
                "predicted" => "Not confirmed, but predicted: see the EPSS figure below.",
                _ => "No evidence of exploitation found. That is not evidence that it is safe.",
            }),
            Text($"EPSS: {f.Epss:P1} chance of exploitation in the next 30 days{(f.Percentile is { } pc ? $", more likely than {Math.Min(pc, 0.999):P1} of all CVEs" : "")}.", true)));
        grid.Children.Add(Card("WHY THIS PRIORITY", tier,
            Text($"Risk {r.Risk:0.00} = likelihood {r.Likelihood:0.00} x impact {r.Impact:0.00}."),
            Text($"On this asset: criticality {a.Criticality} of 3, {(a.InternetFacing ? "internet-facing" : "internal")}, version {(a.Version != "" ? a.Version : "unknown (assumed affected)")}.", true),
            Text(r.Why, true)));
        var who = new List<UIElement>();
        if (r.CitedBy.Count > 0) who.Add(Text("Used by groups you track: " + string.Join(", ", r.CitedBy)));
        if (r.Techniques.Count > 0)
        {
            who.Add(Text("What it lets an attacker do (MITRE ATT&CK):", r.CitedBy.Count > 0));
            var tw = new WrapPanel(); foreach (var t in r.Techniques.Take(6)) tw.Children.Add(Link($"{t.Id} {t.Name}", $"https://attack.mitre.org/techniques/{t.Id.Replace('.', '/')}/"));
            who.Add(tw);
        }
        if (who.Count == 0) who.Add(Text("No group or technique is linked to this CVE in the sources.", true));
        if (r.PathNote != "") who.Add(Text("On a possible attack path: " + r.PathNote, true));
        grid.Children.Add(Card("WHO USES IT, AND FOR WHAT", "Accent", who.ToArray()));
        var todo = new List<UIElement> { Text("First: apply the vendor's security update for this product (see the NVD entry for advisories).") };
        if (r.Mitigations.Count > 0) todo.Add(Text("If you cannot patch yet: " + string.Join("; ", r.Mitigations.Take(4).Select(m => $"{m.Name} ({m.Id})")), true));
        if (r.Defend.Count > 0) todo.Add(Text("Defences that counter it (D3FEND): " + string.Join("; ", r.Defend.Take(4).Select(x => x.Name)), true));
        grid.Children.Add(Card("WHAT TO DO", "Accent", todo.ToArray()));
        grid.Children.Add(Card("HOW SURE IS STENWATCH?", "Ignore", Text($"Confidence: {r.Confidence}."),
            Text(r.Confidence switch
            {
                "High" => "The priority rests on confirmed exploitation.",
                "Medium" => "The priority rests on predictions (EPSS) or vendor severity, not confirmed exploitation.",
                _ => "An assumption was needed: an unscored CVE, an unknown version, or a feed that is out of date. Check before acting.",
            }, true)));
        DetailPanel.Children.Add(grid);
    }

    void RecordDecision(object s, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not FindingRow f) { Status("Select a finding first"); return; }
        if (Example) { Status("The Example Organisation is read-only"); return; }
        try
        {
            Process.RecordDecision(files.Decisions!, f.Cve, f.Asset, ((ComboBoxItem)DecStatus.SelectedItem).Content!.ToString()!, DecUntil.Text.Trim(), DecNote.Text);
            Status($"Recorded for {f.Cve} on {f.Asset}. Rank again to apply it."); DecNote.Clear();
        }
        catch (Exception ex) { Status("Not recorded: " + ex.Message); }
    }

    // ---------- dissemination ----------
    void ShowOutputs(RunResult r)
    {
        ShowReport(Path.Combine(r.OutDir, "full-report.html"));
        OutputButtons.Children.Clear();
        foreach (var (label, file, pdf, who) in Outputs)
        {
            var path = Path.Combine(r.OutDir, file);
            if (!File.Exists(path)) continue;
            var open = new Button { Content = "Open", Margin = new Thickness(0, 0, 6, 0) }; open.Click += (_, _) => OpenFile(path);
            var save = new Button { Content = pdf ? "Export PDF..." : $"Export {Path.GetExtension(path)}...", Margin = new Thickness(0) };
            save.Click += (_, _) => Export(path, pdf);
            OutputButtons.Children.Add(new Border { BorderBrush = (Brush)FindResource("Line"), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 4, 0, 8),
                Child = new StackPanel { Children = {
                    new TextBlock { Text = label, FontWeight = FontWeights.SemiBold },
                    new TextBlock { Text = who, Style = (Style)FindResource("Muted"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4) },
                    new StackPanel { Orientation = Orientation.Horizontal, Children = { open, save } } } } });
        }
        OutputText.Text = $"Brief: {(r.BriefSource.StartsWith("template") ? "fixed template, no AI" : "AI draft (" + r.BriefSource + "), verify before sending")}. All outputs are in {r.OutDir}.";
    }

    /// <summary>The intelligence report inside the page (WebView2, part of Windows 10 and 11). Without the runtime, say where the report is.</summary>
    async void ShowReport(string html)
    {
        if (!File.Exists(html)) { ReportNote.Visibility = Visibility.Visible; return; }
        try
        {
            if (ReportView.CoreWebView2 is null)
                await ReportView.EnsureCoreWebView2Async(await Microsoft.Web.WebView2.Core.CoreWebView2Environment.CreateAsync(null,
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Stenwatch", "WebView2")));
            ReportView.CoreWebView2!.Navigate(new Uri(html).AbsoluteUri);
            ReportNote.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex) { ReportNote.Text = $"The report cannot be shown here ({ex.Message}). Open in browser shows it: {html}"; ReportNote.Visibility = Visibility.Visible; }
    }

    // each output once: documents are exported as PDF, data in the format the receiving tool reads
    static readonly (string Label, string File, bool Pdf, string Who)[] Outputs =
    {
        ("Findings report", "report.html", true, "IT and patch teams: Act and Attend findings with the evidence and what to do."),
        ("Management brief", "brief.html", true, "Management: one page in plain language, what is urgent and why."),
        ("Attack paths", "paths.html", true, "Architects and the security lead: possible routes to the crown jewels."),
        ("Analyst dashboard", "dashboard.html", false, "Analysts: every finding, filter and search in the browser."),
        ("Findings table", "report.csv", false, "Excel, ticketing or another tool: every finding, one row each."),
        ("STIX 2.1 bundle", "bundle.json", false, "Threat-intelligence platforms (MISP, OpenCTI, Sentinel)."),
        ("ATT&CK Navigator layer", "attack-layer.json", false, "The techniques your findings enable, for the MITRE ATT&CK Navigator."),
    };

    /// <summary>Save a copy; a document is turned into PDF first (reused while it is newer than the page).</summary>
    void Export(string path, bool pdf)
    {
        if (pdf)
        {
            var p = Path.ChangeExtension(path, ".pdf");
            if (!File.Exists(p) || File.GetLastWriteTimeUtc(p) < File.GetLastWriteTimeUtc(path)) p = Render.ToPdf(path) ?? "";
            if (p == "") { Status("No PDF: it needs Microsoft Edge or Chrome. Open it and print to PDF instead."); return; }
            path = p;
        }
        SaveCopy(path);
    }

    void OpenFullReport(object s, RoutedEventArgs e)
    {
        if (last is null) { Status("Rank first: the report is written by a rank"); return; }
        var p = Path.Combine(last.OutDir, "full-report.html");
        if (File.Exists(p)) OpenFile(p); else Status("No full report yet: rank again");
    }

    void SaveFullPdf(object s, RoutedEventArgs e)
    {
        if (last is null) { Status("Rank first: the report is written by a rank"); return; }
        Export(Path.Combine(last.OutDir, "full-report.html"), pdf: true);
    }

    void SaveCopy(string path)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { FileName = $"{Path.GetFileNameWithoutExtension(path)}-{DateTime.Today:yyyy-MM-dd}{Path.GetExtension(path)}", Filter = $"{Path.GetExtension(path)}|*{Path.GetExtension(path)}" };
        if (dlg.ShowDialog() != true) return;
        try { File.Copy(path, dlg.FileName, true); Status($"Saved {dlg.FileName}. TLP:AMBER: need-to-know only."); }
        catch (Exception ex) { Status("Not saved: " + ex.Message); }
    }

    void ExportAll(object s, RoutedEventArgs e)
    {
        if (last is null) { Status("Rank first: the outputs are written by a rank"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog { FileName = $"stenwatch-{last.Profile.Organisation.Name}-{DateTime.Today:yyyy-MM-dd}.zip", Filter = "Zip archive|*.zip" };
        if (dlg.ShowDialog() != true) return;
        try
        {
            if (File.Exists(dlg.FileName)) File.Delete(dlg.FileName);
            System.IO.Compression.ZipFile.CreateFromDirectory(last.OutDir, dlg.FileName);
            Status($"Exported every output to {dlg.FileName}. TLP:AMBER: need-to-know only.");
        }
        catch (Exception ex) { Status("Not exported: " + ex.Message); }
    }

    static void OpenFile(string path) { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true }); } catch { } }
    void GoOverview(object s, RoutedEventArgs e) => Go(1);
    void OpenDataFolder(object s, RoutedEventArgs e) => OpenFile(data);
    void OpenDocs(object s, RoutedEventArgs e)
    {
        foreach (var d in new[] { Path.Combine(AppContext.BaseDirectory, "docs"), Path.Combine(data, "docs") })
            if (Directory.Exists(d)) { OpenFile(d); return; }
        Status("Documentation folder not found: see docs/pillars.md and docs/evaluation.md in the repository");
    }

    /// <summary>Copy an existing database (for example the Python version's) into the data folder.</summary>
    async void ChooseDb(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose an existing cve.db", Filter = "Stenwatch database (*.db)|*.db|All files|*.*" };
        if (dlg.ShowDialog() != true) return;
        if (Path.GetFullPath(dlg.FileName) == Path.GetFullPath(Db)) { Status("That is already the database in use"); return; }
        if (File.Exists(Db) && MessageBox.Show("Replace the database Stenwatch already has?", "Stenwatch", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        Status("copying the database..."); var from = dlg.FileName; var to = Db;
        try { await Task.Run(() => File.Copy(from, to, true)); Status("Database copied. Rank now."); LoadFeeds(); Configure(); }
        catch (Exception ex) { Status("Could not copy: " + ex.Message); }
    }

    void OpenProfile(object s, RoutedEventArgs e) { if (File.Exists(files.Profile)) OpenFile(files.Profile); else Status("No profile.yaml yet: import one, or Settings > Start from example"); }
    void OpenAssets(object s, RoutedEventArgs e) { if (File.Exists(files.Assets)) OpenFile(files.Assets); else Status("No assets.csv yet: import one, or Settings > Start from example"); }
    void ImportProfile(object s, RoutedEventArgs e) => ImportFile("profile.yaml", Path.Combine(data, "profile.yaml"));
    void ImportAssets(object s, RoutedEventArgs e) => ImportFile("assets.csv", Path.Combine(data, "assets.csv"));

    // ---------- feedback ----------
    void LoadTasks(object? s, RoutedEventArgs e)
    {
        if (!File.Exists(TaskDb)) { TasksGrid.ItemsSource = null; TaskStatus.Text = Example ? "   Rank the Example Organisation to replay its simulated history." : ""; OpsText.Text = ""; return; }
        using var db = Collect.Connect(TaskDb);
        var tasks = Remediation.Load(db);
        TasksGrid.ItemsSource = tasks.OrderBy(t => TaskState.Active.Contains(t.State) ? 0 : 1).ThenBy(t => t.Due).ToList();
        var m = Effectiveness.Ops(tasks, DateOnly.FromDateTime(DateTime.Today));
        TaskStatus.Text = $"   {m.Active} active, {m.Overdue} overdue, {m.Verified} verified" + (Example ? "   (Example Organisation: simulated eight-week history)" : "");
        OpsText.Text = tasks.Count == 0 ? "No remediation tasks yet. Rank to create them for Act and Attend findings."
            : $"Tasks opened         {m.Opened}\nVerified by a scan    {m.Verified}\nClaimed fixed, unconfirmed  {m.Unverified}\nActive                {m.Active}   (overdue {m.Overdue})\n"
            + $"Median days to verify {(m.MedianDaysToVerify is { } d ? d.ToString("0.0", CultureInfo.InvariantCulture) : "n/a (nothing verified yet)")}\n"
            + $"Verified within SLA   {(m.SlaCompliance is { } sl ? sl.ToString("P0", CultureInfo.InvariantCulture) : "n/a")}\n"
            + $"Fixes that held       {(m.VerifiedClosureRate is { } v ? v.ToString("P0", CultureInfo.InvariantCulture) : "n/a")}   (verified / (verified + claimed but still found))";
    }

    void AssignTask(object s, RoutedEventArgs e)
    {
        if (TasksGrid.SelectedItem is not RemediationTask t) return;
        using var db = Collect.Connect(TaskDb); Remediation.Assign(db, t.Id, TaskOwner.Text.Trim(), TaskTicket.Text.Trim()); LoadTasks(null, null!);
    }
    void ClaimTask(object s, RoutedEventArgs e)
    {
        if (TasksGrid.SelectedItem is not RemediationTask t) return;
        using var db = Collect.Connect(TaskDb); Remediation.ClaimFixed(db, t.Id, "claimed fixed"); LoadTasks(null, null!);
    }

    // ---------- attack paths ----------
    void PathSelected(object s, SelectionChangedEventArgs e)
    {
        PathCanvas.Children.Clear();
        if (PathsGrid.SelectedItem is not PathRow row) return;
        double x = 10, y = 40; const double w = 190, h = 56, gap = 70;
        Border Node(string title, string sub, string brush)
        {
            var b = new Border { Width = w, Height = h, CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1), BorderBrush = (Brush)FindResource(brush), Background = (Brush)FindResource("Card"), Padding = new Thickness(8, 4, 8, 4),
                Child = new StackPanel { Children = { new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis }, new TextBlock { Text = sub, Style = (Style)FindResource("Muted"), FontSize = 11, TextTrimming = TextTrimming.CharacterEllipsis } } } };
            Canvas.SetLeft(b, x); Canvas.SetTop(b, y); PathCanvas.Children.Add(b); return b;
        }
        Node("Internet", "attacker", "Dim"); x += w + gap;
        foreach (var hop in row.P.Hops)
        {
            var arrow = new Line { X1 = x - gap + 4, X2 = x - 4, Y1 = y + h / 2, Y2 = y + h / 2, Stroke = (Brush)FindResource("Accent"), StrokeThickness = 2 };
            PathCanvas.Children.Add(arrow);
            var lab = new TextBlock { Text = hop.Cve, FontSize = 10, FontFamily = (FontFamily)FindResource("Mono"), Foreground = (Brush)FindResource("Mute") }; Canvas.SetLeft(lab, x - gap - 2); Canvas.SetTop(lab, y - 4); PathCanvas.Children.Add(lab);
            var n = Node(hop.Asset, $"{hop.Cap}, likelihood {hop.Likelihood:0.00}", hop.Asset == row.P.Target ? "Act" : "Track"); n.ToolTip = hop.Basis; x += w + gap;
        }
        var note = new TextBlock { Text = "Possible, not proven. " + string.Join("   ", row.P.Hops.Select(h => $"{h.Asset}: {h.Basis}")), Style = (Style)FindResource("Muted"), Width = 1000, FontSize = 11 };
        Canvas.SetLeft(note, 10); Canvas.SetTop(note, y + h + 22); PathCanvas.Children.Add(note);
        PathCanvas.Width = Math.Max(1000, x); PathCanvas.Height = 220;
    }

    // ---------- knowledge graph ----------
    Knowledge? graph;
    void QKey(object s, System.Windows.Input.KeyEventArgs e) { if (e.Key == System.Windows.Input.Key.Enter) AskGraph(null!, null!); }

    void AskGraph(object s, RoutedEventArgs e)
    {
        if (last is null) { Status("Rank first: the graph is built from the current findings"); return; }
        try
        {
            if (graph is null || !ReferenceEquals(graphFor, last))
            {
                using var db = new SqliteConnection($"Data Source={Db};Mode=ReadOnly"); db.Open();
                graph = Knowledge.Build(db, last.Ranked, last.Context); graphFor = last;
            }
            var q = QText.Text.Trim(); var rows = new List<(string, string, string)>();
            switch (QKind.SelectedIndex)
            {
                case 0: rows = graph.AssetsHitBy(q).Select(x => (x.Asset, x.Cve, x.Via == "reported" ? "reported: named in the group's ATT&CK text" : "technique only: a shared technique, weaker")).ToList(); break;
                case 1: rows = graph.SharedWeakness(q).Select(x => (x.Asset, x.Cve, q)).ToList(); break;
                case 2:
                    var p = q.Split(',', 2).Select(x => x.Trim()).ToArray();
                    var path = p.Length == 2 ? graph.Connect(p[0], p[1]) : null;
                    rows = path is null ? new() { ("no connection found", "", "") } : path.Select((st, i) => (st.Item1.Label, st.Item1.Type, st.Item2 is null ? "" : $"{st.Item2.Type} ({st.Item2.Source}, {st.Item2.Basis})")).ToList(); break;
                default: rows = graph.Neighbours(q).Select(n => (n.Node.Label, n.Node.Type, $"{n.Edge.Type} ({n.Edge.Source}, {n.Edge.Basis})")).ToList(); break;
            }
            QGrid.ItemsSource = Bindable(rows.Count > 0 ? rows : new List<(string, string, string)> { ("nothing found", "", "") });
            Status($"{rows.Count} result(s); graph has {graph.Nodes.Count:N0} nodes and {graph.Edges.Count:N0} edges");
        }
        catch (Exception ex) { Status("Query failed: " + ex.Message); }
    }
    RunResult? graphFor;

    // ---------- effectiveness ----------
    void LoadEvidence() => EvidenceBadges.ItemsSource = FeatureEvidence.Load(data);

    async void RunEvaluation(object s, RoutedEventArgs e)
    {
        if (!File.Exists(Db)) { EvalText.Text = "No database yet."; return; }
        EvalBtn.IsEnabled = false; EvalText.Text = "Running the pre-registered backtest (downloads EPSS, ATT&CK and CTID archives, about a minute)...";
        try
        {
            var prof = Profile.Load(files.Profile); var dir = System.IO.Path.Combine(data, "out", "evaluation"); Directory.CreateDirectory(dir);
            var res = await Task.Run(() => new AttackValue(System.IO.Path.Combine(dir, "cache")).Run(Db, prof));
            File.WriteAllText(System.IO.Path.Combine(dir, "attack-value.md"), res.Markdown);
            File.WriteAllText(System.IO.Path.Combine(dir, "attack-value.json"), System.Text.Json.JsonSerializer.Serialize(res.Inputs));
            EvalText.Text = $"{res.Label}: {res.Reason}"; LoadEvidence();
        }
        catch (Exception ex) { EvalText.Text = "Failed: " + ex.Message; }
        finally { EvalBtn.IsEnabled = true; }
    }

    // ---------- settings ----------
    static readonly HttpClient web = NewWeb();
    static HttpClient NewWeb() { var h = new HttpClient { Timeout = TimeSpan.FromSeconds(20) }; h.DefaultRequestHeaders.UserAgent.ParseAdd("Stenwatch"); return h; }
    static readonly string[] OrgFiles = { "profile.yaml", "assets.csv", "third_parties.csv", "exceptions.csv" };
    DateTime seen;
    string? releaseUrl;

    DateTime Stamp() => OrgFiles.Select(f => Path.Combine(Example ? AppPaths.Examples() : data, Example ? f.Replace(".", ".example.") : f))
        .Where(File.Exists).Select(File.GetLastWriteTimeUtc).DefaultIfEmpty().Max();

    // edits made in an editor show up when the user comes back to the window
    protected override void OnActivated(EventArgs e) { base.OnActivated(e); if (IsLoaded && !syncing && files != null && Stamp() != seen) Configure(); }
    void ReloadFiles(object s, RoutedEventArgs e) { Configure(); Status("files reloaded"); }

    Button Btn(string text, Action click) { var b = new Button { Content = text }; b.Click += (_, _) => click(); return b; }
    TextBlock Cell(string text, double width, bool muted = false) => new() { Text = text, Width = width, VerticalAlignment = VerticalAlignment.Center, Style = muted ? (Style)FindResource("Muted") : null };

    void LoadSettings()
    {
        seen = Stamp();
        FilesPanel.Children.Clear(); CtxPanel.Children.Clear(); KeysPanel.Children.Clear(); LoadSources();
        foreach (var name in OrgFiles)
        {
            var dest = Path.Combine(data, name); var sample = Path.Combine(AppPaths.Examples(), name.Replace(".", ".example."));
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            row.Children.Add(Cell(name, 170)); row.Children.Add(Cell(File.Exists(dest) ? "found" : "missing", 80, true));
            row.Children.Add(Btn("Import...", () => ImportFile(name, dest)));
            if (File.Exists(dest)) row.Children.Add(Btn("Open", () => OpenFile(dest)));
            else if (File.Exists(sample)) row.Children.Add(Btn("Start from example", () => { File.Copy(sample, dest); AfterFileChange(name); }));
            FilesPanel.Children.Add(row);
        }
        foreach (var (label, imp) in new (string, Func<SqliteConnection, string, int>)[] { ("services.csv", ContextStore.ImportServices), ("asset_context.csv", ContextStore.ImportAssetContext), ("links.csv", ContextStore.ImportLinks), ("controls.csv", ContextStore.ImportControls) })
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            row.Children.Add(Cell(label, 170)); row.Children.Add(Btn("Import...", () => ImportContext(label, imp)));
            CtxPanel.Children.Add(row);
        }
        foreach (var (key, label) in new[] { ("NVD_API_KEY", "NVD (faster sync)"), ("ANTHROPIC_API_KEY", "Anthropic (brief)"), ("AZURE_OPENAI_KEY", "Azure OpenAI (brief)"), (TriageLlm.KeyName, "OpenRouter (triage LLM)") })
        {
            var box = new PasswordBox { Width = 300, Margin = new Thickness(0, 0, 8, 0), Background = (Brush)FindResource("Card"), Foreground = (Brush)FindResource("Fg"), BorderBrush = (Brush)FindResource("Line"), Padding = new Thickness(4) };
            var state = Cell(Secrets.Get(key) is { Length: > 0 } ? "set" : "not set", 60, true);
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            row.Children.Add(Cell(label, 170));
            row.Children.Add(box); row.Children.Add(state);
            row.Children.Add(Btn("Save", () =>
            {
                if (box.Password == "") return;
                try { Secrets.Set(key, box.Password); box.Clear(); state.Text = "set"; Status(key + " saved to Credential Manager"); }
                catch (Exception ex) { Status("Not saved: " + ex.Message); }
            }));
            KeysPanel.Children.Add(row);
        }
    }

    void AfterFileChange(string name)
    {
        if (Example && File.Exists(Path.Combine(data, "profile.yaml"))) { loading = true; ExampleBox.IsChecked = false; loading = false; } // real profile now exists: use it
        Configure(); Status($"{name} updated in {data}");
    }

    void ImportFile(string name, string dest)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose " + name, Filter = name == "assets.csv"
            ? "Asset list or inventory (CSV, Excel, CycloneDX SBOM)|*.csv;*.txt;*.xlsx;*.json|All files|*.*" : name + "|*" + Path.GetExtension(name) + "|All files|*.*" };
        if (dlg.ShowDialog() != true) return;
        if (File.Exists(dest) && MessageBox.Show($"Replace the {name} Stenwatch already has?", "Stenwatch", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            if (Path.GetFullPath(dlg.FileName) == Path.GetFullPath(dest)) { }
            else if (name == "assets.csv") Inventory.ToCsv(dlg.FileName, dest); // any separator, Excel or SBOM -> the plain CSV the rest reads
            else File.Copy(dlg.FileName, dest, true);
            AfterFileChange(name);
            if (name == "assets.csv" && Inventory.IsInventory(dest)) ConvertInventory(null!, null!);
        }
        catch (Exception ex) { Status("Could not import: " + ex.Message); }
    }

    /// <summary>An inventory export (one row per host, no CPE) becomes Stenwatch's assets.csv by name lookup against NVD's product list.</summary>
    async void ConvertInventory(object s, RoutedEventArgs e)
    {
        var path = Path.Combine(data, "assets.csv");
        if (Example) { Status("Untick the Example Organisation first"); return; }
        if (!Inventory.IsInventory(path)) { Status("assets.csv is already in Stenwatch format (it has a cpe column)"); return; }
        if (!File.Exists(Db)) { Status("Converting needs the database (NVD's product names): sync or choose a cve.db on 2 Collection first"); Go(3); return; }
        Status("converting the inventory: looking up every OS and product in NVD's product list...");
        try
        {
            var db = Db;
            var r = await Task.Run(() => { using var c = new SqliteConnection($"Data Source={db};Mode=ReadOnly"); c.Open(); return Inventory.ConvertFile(path, c); });
            AfterFileChange("assets.csv");
            MessageBox.Show($"{r.Hosts:N0} hosts became {r.Assets.Count} assets (one per product and version, with the host count in the name).\n\n"
                + (r.Unmatched.Count == 0 ? "Every host matched." : $"Not matched ({r.Unmatched.Sum(u => u.Hosts)} hosts), listed in assets.unmatched.csv:\n" + string.Join("\n", r.Unmatched.Take(10).Select(u => $"  {u.What}  ({u.Hosts})"))
                    + "\nAdd these to assets.csv by hand with their CPE if they matter.")
                + "\n\nThe original export is kept as assets.inventory.csv. Open assets.csv to check the matches.",
                "Inventory converted", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { Status("Could not convert: " + ex.Message); }
    }

    void ImportContext(string label, Func<SqliteConnection, string, int> imp)
    {
        if (Example) { Status("Untick the Example Organisation first: it is read-only"); return; }
        if (!File.Exists(Db)) { Status("No database yet: sync the feeds or choose a cve.db first"); return; }
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose " + label, Filter = "CSV|*.csv|All files|*.*" };
        if (dlg.ShowDialog() != true) return;
        try { using var db = Collect.Connect(Db); ContextStore.EnsureSchema(db); var n = imp(db, dlg.FileName); LoadContext(); Status($"{n} rows imported from {Path.GetFileName(dlg.FileName)}. Rank again to apply."); }
        catch (Exception ex) { Status("Could not import: " + ex.Message); }
    }

    async void CheckUpdates(object s, RoutedEventArgs e)
    {
        if (AppPaths.PackageFamily() != null) { UpdateText.Text = "Installed from the Microsoft Store: updates arrive through the Store."; UpdateLink.Visibility = Visibility.Collapsed; return; }
        UpdateText.Text = "Checking..."; UpdateLink.Visibility = Visibility.Collapsed;
        var mine = (typeof(MainWindow).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false).FirstOrDefault() as System.Reflection.AssemblyInformationalVersionAttribute)?.InformationalVersion ?? "0";
        mine = mine.Split('+')[0];
        try
        {
            // /releases (not /releases/latest) so pre-releases count
            var list = await web.GetFromJsonAsync<System.Text.Json.JsonElement>("https://api.github.com/repos/idiljot-singh/Stenwatch/releases?per_page=1");
            if (list.GetArrayLength() == 0) { UpdateText.Text = $"Version {mine}. No release has been published yet."; return; }
            var tag = list[0].GetProperty("tag_name").GetString()!; releaseUrl = list[0].GetProperty("html_url").GetString();
            var newer = Version.TryParse(tag.TrimStart('v').Split('-')[0], out var theirs) && Version.TryParse(mine.Split('-')[0], out var ours) && theirs > ours;
            UpdateText.Text = newer ? $"Version {tag} is available (you have {mine})." : $"You have {mine}; the latest release is {tag}. Up to date.";
            if (newer) UpdateLink.Visibility = Visibility.Visible;
        }
        catch (Exception ex) { UpdateText.Text = "Could not check: " + ex.Message; }
    }
    void OpenUpdate(object s, RoutedEventArgs e) { if (releaseUrl != null) OpenFile(releaseUrl); }

    void OpenEvaluation(object s, RoutedEventArgs e) { var d = System.IO.Path.Combine(data, "out", "evaluation"); Directory.CreateDirectory(d); OpenFile(d); }
}
