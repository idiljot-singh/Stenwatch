using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Data.Sqlite;
using Path = System.IO.Path;
using Stenwatch.Core;

namespace Stenwatch.App;

/// <summary>An advisory as the Advisories grid shows it.</summary>
public class AdvisoryRow
{
    public Advisory A { get; init; } = null!;
    public string Published => A.Published; public string Source => A.Source; public string Grade => A.Grade; public string Tlp => "TLP:" + A.Tlp; public string Title => A.Title;
    public string Cves => string.Join(", ", A.Cves); public string Mark => A.ActivelyExploited ? "actively exploited" : A.ExploitExists ? "exploit exists" : "";
}

/// <summary>A task that carries a ticket reference, as the Tickets grid shows it.</summary>
public record TicketRow(string Task, string Item, string Asset, string Owner, string Ticket);

/// <summary>The pages drawn in code from the data folder: Coverage, the Dashboard's coverage line, Guided run, Advisories, Tickets and the Integrations connectors table.
/// BuildPage redraws the page that is open; it runs from UpdateGate, so on every page change and after every rank.</summary>
public partial class MainWindow
{
    static readonly FontFamily IconFont = new("Segoe Fluent Icons, Segoe MDL2 Assets");
    /// <summary>One glyph per component (seen rendered in Segoe Fluent Icons); the name always sits beside it.</summary>
    static readonly Dictionary<string, string> Icons = new()
    {
        ["Assets"] = "", ["Attack surface"] = "", ["Cloud workloads"] = "", ["OT and IoT"] = "", ["AI discovery"] = "", ["Identity"] = "",
        ["Vulnerabilities"] = "", ["Web apps"] = "", ["Misconfiguration"] = "", ["End-of-life software"] = "",
        ["Intelligence"] = "", ["Ticketing"] = "", ["Reports"] = "", ["Connectors"] = "",
    };

    void BuildPage(int page)
    {
        try
        {
            switch (page)
            {
                case 1: BuildDashCoverage(); break;
                case 13: BuildGuided(); break;
                case 14: BuildCoverage(); break;
                case 15: BuildAdvisories(); break;
                case 16: BuildTickets(); break;
                case 17: BuildConnectors(); break;
            }
        }
        catch (Exception ex) when (ex is IOException or SqliteException or System.Text.Json.JsonException or InvalidDataException) { Status("Page not drawn: " + ex.Message); }
    }

    // ---------- small parts ----------
    List<CoverageStatus> Cov() => Coverage.Of(data, files.Assets);
    static string Word(string status) => status == Coverage.Partly ? "partly connected" : status;
    TextBlock Txt(string text, string brush = "Fg", double size = 0) { var t = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center }.Res(TextBlock.ForegroundProperty, brush); if (size > 0) t.FontSize = size; return t; }
    TextBlock Head(string text) => new() { Text = text, Style = (Style)FindResource("H") };

    /// <summary>Status mark: a dot plus a word, never colour alone. Filled Accent = connected, Accent ring = partly, Dim ring = not connected, filled Warn = needs attention.</summary>
    StackPanel Mark(string status, string? word = null)
    {
        var tone = status switch { Coverage.Attention => "Warn", Coverage.NotConnected => "Dim", _ => "Accent" };
        var dot = new System.Windows.Shapes.Ellipse { Width = 9, Height = 9, StrokeThickness = 1.5, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center }.Res(System.Windows.Shapes.Shape.StrokeProperty, tone);
        if (status is Coverage.Connected or Coverage.Attention) dot.Res(System.Windows.Shapes.Shape.FillProperty, tone);
        return new StackPanel { Orientation = Orientation.Horizontal, Children = { dot, Txt(word ?? Word(status), status == Coverage.Attention ? "Warn" : status == Coverage.NotConnected ? "Dim" : "Fg") } };
    }

    TextBlock Glyph(string comp, string brush)
    {
        var t = new TextBlock { Text = Icons[comp], FontFamily = IconFont, FontSize = 16, Width = 18, TextAlignment = TextAlignment.Center, VerticalAlignment = VerticalAlignment.Center }.Res(TextBlock.ForegroundProperty, brush);
        return t;
    }
    /// <summary>Component tag: icon and name.</summary>
    StackPanel CompTag(string comp) { var p = new StackPanel { Orientation = Orientation.Horizontal }; p.Children.Add(Glyph(comp, "Mute")); p.Children.Add(new TextBlock { Text = comp, Margin = new Thickness(6, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center }); return p; }

    /// <summary>"n of 14 connected" with a thin Accent bar.</summary>
    StackPanel Counter(string text, int n, int total)
    {
        var track = new Border { Width = 180, Height = 4, CornerRadius = new CornerRadius(2), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) }.Res(Border.BackgroundProperty, "Line");
        track.Child = new Border { HorizontalAlignment = HorizontalAlignment.Left, Width = total == 0 ? 0 : 180.0 * n / total, CornerRadius = new CornerRadius(2) }.Res(Border.BackgroundProperty, "Accent");
        AutomationProperties.SetName(track, text);
        return new StackPanel { Orientation = Orientation.Horizontal, Children = { Txt(text), track } };
    }

    Button SmallBtn(string text, Action click, string? spoken = null)
    {
        var b = Btn(text, click); b.Padding = new Thickness(10, 3, 10, 3); b.FontSize = 12; b.Margin = new Thickness(0);
        if (spoken != null) AutomationProperties.SetName(b, spoken);
        return b;
    }

    /// <summary>A table of controls: a header row, then one row per entry. Widths in pixels, negative = star.</summary>
    Grid Table(string[] heads, double[] widths, List<UIElement[]> rows)
    {
        var g = new Grid();
        foreach (var w in widths) g.ColumnDefinitions.Add(new ColumnDefinition { Width = w < 0 ? new GridLength(-w, GridUnitType.Star) : new GridLength(w) });
        for (var r = 0; r <= rows.Count; r++) g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        void Put(UIElement e, int r, int c, bool head)
        {
            var cell = new Border { BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 6, 8, 6), Child = e }.Res(Border.BorderBrushProperty, "Line");
            if (head) cell.Res(Border.BackgroundProperty, "Card");
            Grid.SetRow(cell, r); Grid.SetColumn(cell, c); g.Children.Add(cell);
        }
        for (var c = 0; c < heads.Length; c++) Put(new TextBlock { Text = heads[c], FontFamily = (FontFamily)FindResource("Mono"), FontSize = 11 }.Res(TextBlock.ForegroundProperty, "Dim"), 0, c, true);
        for (var r = 0; r < rows.Count; r++) for (var c = 0; c < rows[r].Length; c++) Put(rows[r][c], r + 1, c, false);
        return g;
    }

    // ---------- Dashboard line ----------
    void BuildDashCoverage()
    {
        var all = Cov(); DashCoverage.Children.Clear();
        DashCoverage.Children.Add(Counter($"Coverage: {all.Count(c => c.Status == Coverage.Connected)} of {all.Count} connected", all.Count(c => c.Status == Coverage.Connected), all.Count));
        var open = SmallBtn("Open Coverage", () => Go(14)); open.Margin = new Thickness(12, 0, 0, 0); DashCoverage.Children.Add(open);
    }

    // ---------- Coverage ----------
    static int OpenPage(string comp) => comp switch { "Assets" => 4, "Attack surface" => 8, "Intelligence" => 15, "Ticketing" => 16, "Reports" => 6, "Connectors" => 17, _ => 5 }; // others: their rows sit in Findings

    void BuildCoverage()
    {
        var all = Cov(); var n = all.Count(c => c.Status == Coverage.Connected); CoverageHost.Children.Clear();
        var counter = Counter($"{n} of {all.Count} connected", n, all.Count); counter.Margin = new Thickness(0, 4, 0, 8); CoverageHost.Children.Add(counter);
        var legend = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) }; legend.Children.Add(Txt("Status kinds:  ", "Mute", 11));
        foreach (var s in new[] { Coverage.Connected, Coverage.Partly, Coverage.NotConnected, Coverage.Attention }) { var m = Mark(s); m.Margin = new Thickness(0, 0, 18, 0); legend.Children.Add(m); }
        CoverageHost.Children.Add(legend);
        var sections = new WrapPanel(); // sections sit side by side while they fit
        foreach (var g in Coverage.Groups)
        {
            var sec = new StackPanel(); sec.Children.Add(Head(g.ToUpperInvariant()));
            var tiles = new WrapPanel(); foreach (var c in all.Where(c => c.Component.Group == g)) tiles.Children.Add(Tile(c));
            sec.Children.Add(tiles); sections.Children.Add(sec);
        }
        CoverageHost.Children.Add(sections);
    }

    /// <summary>One component: icon and name, status mark (and the last import date), then the count with its caption and "Open", or what it still needs.</summary>
    Button Tile(CoverageStatus c)
    {
        var comp = c.Component.Name; var not = c.Status == Coverage.NotConnected;
        var name = new StackPanel { Orientation = Orientation.Horizontal };
        name.Children.Add(Glyph(comp, not ? "Dim" : "Mute"));
        name.Children.Add(new TextBlock { Text = comp, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(6, 0, 0, 0) }.Res(TextBlock.ForegroundProperty, not ? "Dim" : "Fg"));
        var status = new DockPanel { Margin = new Thickness(0, 4, 0, 0) };
        if (c.LastImport != "") { var d = Txt(c.LastImport, "Mute", 11); DockPanel.SetDock(d, Dock.Right); status.Children.Add(d); }
        status.Children.Add(Mark(c.Status));
        UIElement bottom;
        if (not) bottom = new TextBlock { Text = "Needs " + c.Component.Needs, FontSize = 11, TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.CharacterEllipsis, MaxHeight = 44, VerticalAlignment = VerticalAlignment.Bottom, ToolTip = "Needs " + c.Component.Needs }.Res(TextBlock.ForegroundProperty, "Dim");
        else
        {
            var go = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(10, 3, 10, 3), VerticalAlignment = VerticalAlignment.Bottom, Child = Txt("Open", "Fg", 12) }.Res(Border.BackgroundProperty, "Raised").Res(Border.BorderBrushProperty, "LineStrong");
            DockPanel.SetDock(go, Dock.Right);
            var left = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Bottom };
            if (c.Count > 0 || c.Caption != "") { left.Children.Add(new TextBlock { Text = c.Count.ToString("N0"), FontSize = 22, FontWeight = FontWeights.SemiBold }); left.Children.Add(new TextBlock { Text = " " + c.Caption, FontSize = 11, VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, 3) }.Res(TextBlock.ForegroundProperty, "Mute")); }
            else left.Children.Add(new TextBlock { Text = c.Note, FontSize = 11, TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.CharacterEllipsis, MaxHeight = 30, MaxWidth = 120 }.Res(TextBlock.ForegroundProperty, "Mute"));
            var row = new DockPanel { VerticalAlignment = VerticalAlignment.Bottom }; row.Children.Add(go); row.Children.Add(left); bottom = row;
        }
        var grid = new Grid(); grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); grid.RowDefinitions.Add(new RowDefinition());
        grid.Children.Add(name); Grid.SetRow(status, 1); grid.Children.Add(status); Grid.SetRow(bottom, 2); grid.Children.Add(bottom);
        var b = new Button { Style = (Style)FindResource("Tile"), Width = 220, Height = 112, Margin = new Thickness(0, 0, 6, 12), Content = grid, ToolTip = c.Note };
        AutomationProperties.SetName(b, not ? $"{comp}: not connected. Needs {c.Component.Needs}" : $"{comp}: {Word(c.Status)}. {(c.Count > 0 ? $"{c.Count:N0} {c.Caption}. " : "")}Open");
        b.Click += (_, _) => Go(not ? 17 : OpenPage(comp));
        return b;
    }

    // ---------- Guided run ----------
    static readonly (string Name, string What, int Page, string Open)[] Stages =
    {
        ("Direction", "Say who you are and which threat groups matter to you.", 2, "Threat profile"),
        ("Collection", "Pull the public feeds: NVD, KEV, EPSS, ATT&CK, CTID and D3FEND.", 3, "Feeds"),
        ("Processing", "Describe your estate so findings can be matched to it.", 4, "Estate"),
        ("Analysis", "Rank the findings and give the reason for each tier.", 5, "Findings"),
        ("Dissemination", "Send the people who must act what they need.", 6, "Reports"),
        ("Feedback", "Check that fixed things stayed fixed.", 7, "Remediation"),
    };

    /// <summary>The state of each stage is the gate bar's own checks (Checks), not new ones.</summary>
    void BuildGuided()
    {
        var checks = Stages.Select(s => Checks(s.Page)).ToArray();
        var done = checks.Select(c => c.All(x => x.Ok)).ToArray();
        done[5] &= done[3]; // Feedback's own check cannot fail (the task list may be empty), so it counts once there has been a rank
        var rows = new List<UIElement[]>();
        for (var i = 0; i < Stages.Length; i++)
        {
            var (name, what, page, open) = Stages[i];
            var state = done[i] ? Mark(Coverage.Connected, "Done") : Mark(Coverage.NotConnected, "Not done");
            state.ToolTip = string.Join("\n", checks[i].Select(c => (c.Ok ? "✓ " : "✗ ") + c.What));
            var btn = SmallBtn("Open " + open, () => Go(page), $"Open {open} ({name})");
            rows.Add(new UIElement[] { Txt((i + 1).ToString()), new TextBlock { Text = name, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center }, Txt(what, "Mute"), state, btn });
        }
        GuidedRunHost.Children.Clear();
        GuidedRunHost.Children.Add(new TextBlock { Text = "The six stages of the CTI cycle in order. Each has one sentence, its state and a button to its page. Hover a state to see what it checks.", Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 0, 0, 10) });
        GuidedRunHost.Children.Add(Table(new[] { "#", "STAGE", "WHAT HAPPENS", "STATE", "" }, new double[] { 40, 130, -1, 110, 190 }, rows));
    }

    // ---------- Advisories ----------
    void BuildAdvisories()
    {
        var host = AdvisoriesHost; host.Children.Clear();
        var all = Advisories.Load(data).OrderByDescending(a => a.Published, StringComparer.Ordinal).ToList();
        if (all.Count == 0) { host.Children.Add(new TextBlock { Text = "No advisories stored yet. They arrive when Morning triage fetches the sources (tick Feeds there and press Run triage). Add or remove sources on Integrations.", Style = (Style)FindResource("Muted") }); return; }
        var search = new TextBox { Width = 260, Margin = new Thickness(0, 0, 14, 0) }; AutomationProperties.SetName(search, "Search advisories");
        var count = Txt("", "Mute");
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8), Children = { Txt("Search ", "Mute"), search, count } };
        var grid = new DataGrid { MaxHeight = 340 }; AutomationProperties.SetName(grid, "Advisories");
        void Col(string head, string path, double w) => grid.Columns.Add(new DataGridTextColumn { Header = head, Binding = new System.Windows.Data.Binding(path), Width = w > 0 ? new DataGridLength(w) : new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = w > 0 ? 40 : 200 });
        Col("PUBLISHED", "Published", 100); Col("SOURCE", "Source", 150); Col("GRADE", "Grade", 65); Col("TLP", "Tlp", 100); Col("TITLE", "Title", 0); Col("CVES", "Cves", 190); Col("MARK", "Mark", 130);
        var detail = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        detail.Children.Add(Txt("Select an advisory to read it.", "Mute"));
        void Filter()
        {
            var q = search.Text.Trim();
            var rows = all.Where(a => q == "" || a.Title.Contains(q, StringComparison.OrdinalIgnoreCase) || a.Source.Contains(q, StringComparison.OrdinalIgnoreCase) || a.Cves.Any(c => c.Contains(q, StringComparison.OrdinalIgnoreCase))).Select(a => new AdvisoryRow { A = a }).ToList();
            grid.ItemsSource = rows; count.Text = $"   {rows.Count:N0} of {all.Count:N0} advisories";
        }
        search.TextChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) =>
        {
            detail.Children.Clear();
            if (grid.SelectedItem is not AdvisoryRow r) { detail.Children.Add(Txt("Select an advisory to read it.", "Mute")); return; }
            var a = r.A;
            detail.Children.Add(new TextBlock { Text = a.Title, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            detail.Children.Add(new TextBlock { Text = $"{a.Source}, grade {a.Grade}, {r.Tlp}, {a.Published}" + (a.Cves.Count > 0 ? ", " + r.Cves : ""), Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 2, 0, 4) });
            if (a.Link.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || a.Link.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) // never hand a file path or another scheme to the shell
            {
                var link = new TextBlock { Text = a.Link + "  ↗", Cursor = System.Windows.Input.Cursors.Hand, TextDecorations = TextDecorations.Underline, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6), Focusable = true }.Res(TextBlock.ForegroundProperty, "Accent");
                link.MouseLeftButtonUp += (_, _) => OpenFile(a.Link); detail.Children.Add(link);
            }
            else if (a.Link != "") detail.Children.Add(new TextBlock { Text = a.Link, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) }.Res(TextBlock.ForegroundProperty, "Dim"));
            detail.Children.Add(new ScrollViewer { MaxHeight = 220, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = Txt(a.Text, "Mute") });
        };
        Filter(); host.Children.Add(bar); host.Children.Add(grid); host.Children.Add(detail);
        if (grid.Items.Count > 0) grid.SelectedIndex = 0;
    }

    // ---------- Tickets ----------
    void BuildTickets()
    {
        var host = TicketsHost; host.Children.Clear();
        var rows = new List<TicketRow>();
        if (File.Exists(TaskDb)) { using var db = Collect.Connect(TaskDb); rows = Remediation.Load(db).Where(t => t.Ticket != "").Select(t => new TicketRow($"T-{t.Id}", t.Cve, t.Asset, t.Owner, t.Ticket)).ToList(); }
        host.Children.Add(new TextBlock { Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 0, 0, 8),
            Text = rows.Count == 0 ? "No task has a ticket reference yet. Pushing tasks to a ticket system arrives in the next version; until then, type a reference in the Ticket box on Remediation and it shows here."
                : "Tasks that carry a ticket reference. Pushing tasks to a ticket system arrives in the next version." });
        if (rows.Count == 0) return;
        var grid = new DataGrid { MaxHeight = 420, ItemsSource = rows }; AutomationProperties.SetName(grid, "Tickets");
        void Col(string head, string path, double w) => grid.Columns.Add(new DataGridTextColumn { Header = head, Binding = new System.Windows.Data.Binding(path), Width = w > 0 ? new DataGridLength(w) : new DataGridLength(1, DataGridLengthUnitType.Star) });
        Col("TASK", "Task", 90); Col("ITEM", "Item", 150); Col("ASSET", "Asset", 0); Col("OWNER", "Owner", 140); Col("TICKET", "Ticket", 140);
        host.Children.Add(grid);
    }

    // ---------- Integrations: the connectors table (sources and API keys sit below it, moved here from Settings) ----------
    Dictionary<string, string> DbMeta()
    {
        var m = new Dictionary<string, string>(); if (!File.Exists(Db)) return m;
        try { using var c = new SqliteConnection($"Data Source={Db};Mode=ReadOnly;Pooling=False"); c.Open(); using var q = c.CreateCommand(); q.CommandText = "SELECT key, value FROM meta"; using var r = q.ExecuteReader(); while (r.Read()) m[r.GetString(0)] = r.GetString(1); }
        catch (SqliteException) { } // feeds not synced yet
        return m;
    }

    void BuildConnectors()
    {
        var host = IntegrationsHost; host.Children.Clear();
        host.Children.Add(Head("CONNECTORS"));
        host.Children.Add(new TextBlock { Text = "Everything that goes in or out: files, APIs and webhooks. A row that names a phase is not built yet.", Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 0, 0, 8) });
        var rows = new List<UIElement[]>();
        void Row(string name, string feeds, string kind, string status, string last, string? action = null, Action? click = null, string? word = null)
            => rows.Add(new UIElement[] { Txt(name), CompTag(feeds), Txt(kind, "Mute"), Mark(status, word), Txt(last, status == Coverage.NotConnected ? "Dim" : "Mute"),
                action == null ? new TextBlock() : SmallBtn(action, click!, $"{action}: {name}") });
        void Later(string name, string feeds, string kind, int phase) => Row(name, feeds, kind, Coverage.NotConnected, $"arrives in phase {phase}");
        string Day(string v) => v[..Math.Min(10, v.Length)];

        // what works today
        Row("Asset list or inventory export", "Assets", "file", File.Exists(files.Assets) ? Coverage.Connected : Coverage.NotConnected, File.Exists(files.Assets) ? File.GetLastWriteTime(files.Assets).ToString("yyyy-MM-dd") : "never", "Open", () => Go(2));
        var hist = Path.Combine(data, "triage-history"); var newest = Directory.Exists(hist) ? Directory.GetFiles(hist, "*.json").OrderBy(f => f, StringComparer.Ordinal).LastOrDefault() : null;
        Row("Defender vulnerabilities export", "Vulnerabilities", "file", newest != null ? Coverage.Connected : Coverage.NotConnected, newest != null ? Path.GetFileNameWithoutExtension(newest) : "never", "Open", () => Go(12));
        var api = false; try { api = File.Exists(files.Profile) && Profile.Load(files.Profile).Defender.Enabled; } catch { } // a broken profile is reported on Threat profile
        Row("Defender API", "Vulnerabilities", "API", api ? Coverage.Connected : Coverage.NotConnected, api ? "not recorded" : "never", File.Exists(files.Profile) ? "Open" : null, () => OpenFile(files.Profile));
        var meta = DbMeta();
        foreach (var (name, key, feeds) in new[] { ("NVD", "nvd_sync", "Vulnerabilities"), ("CISA KEV", "kev_sync", "Intelligence"), ("FIRST EPSS", "epss_sync", "Intelligence"), ("MITRE ATT&CK", "attack_sync", "Intelligence"), ("CTID mappings", "ctid_sync", "Intelligence"), ("MITRE D3FEND", "d3fend_sync", "Intelligence") })
        {
            var has = meta.TryGetValue(key, out var v); var stale = has && EvidenceOf.IsStale(v!, DateTimeOffset.UtcNow);
            Row(name, feeds, "API", !has ? Coverage.NotConnected : stale ? Coverage.Attention : Coverage.Connected, has ? Day(v!) : "never", "Open", () => Go(3));
        }
        var on = Sources.Load(data).Count(s => s.Enabled); var advFile = Path.Combine(data, "advisories.json"); var stored = File.Exists(advFile) ? Advisories.Load(data).Count : 0;
        Row($"Advisory sources ({on} on)", "Intelligence", "API", on == 0 ? Coverage.NotConnected : stored > 0 ? Coverage.Connected : Coverage.Partly, stored > 0 ? File.GetLastWriteTime(advFile).ToString("yyyy-MM-dd") : "never", "Edit", () => SourcesPanel.BringIntoView());

        // not built yet
        Later("Scheduled morning run", "Vulnerabilities", "file", 2); Later("Ticket webhook", "Ticketing", "webhook", 2); Later("Briefing delivery (Teams, email file)", "Reports", "webhook", 2); Later("endoflife.date", "End-of-life software", "API", 2);
        Later("Intune", "Assets", "API", 3); Later("Entra", "Identity", "API", 3); Later("Defender for Cloud", "Cloud workloads", "file", 3); Later("Defender security recommendations", "Misconfiguration", "file", 3); Later("Exposure Management", "Attack surface", "file", 3);
        Later("Defender EASM", "Attack surface", "file", 4); Later("OWASP ZAP report", "Web apps", "file", 4); Later("SARIF file", "Web apps", "file", 4);
        Later("Defender for Cloud Apps", "AI discovery", "file", 5); Later("Defender for IoT", "OT and IoT", "file", 5);
        host.Children.Add(Table(new[] { "NAME", "FEEDS", "KIND", "STATUS", "LAST RUN", "" }, new double[] { -2, 190, 80, 140, 150, 100 }, rows));
    }
}
