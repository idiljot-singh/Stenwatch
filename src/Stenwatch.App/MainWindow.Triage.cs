using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Path = System.IO.Path;
using Stenwatch.Core;

namespace Stenwatch.App;

/// <summary>Morning triage page: Defender export in, fix actions out. All logic is in Core (DefenderTriage, Advisories, TriageLlm); this only collects the inputs and shows the result.</summary>
public partial class MainWindow
{
    string? triExport; readonly List<string> triMails = new(); DefenderTriage.Result? tri;
    string TriFolderFile => Path.Combine(data, "triage-folder.txt");

    static string? Newest(string folder) => Directory.Exists(folder)
        ? Directory.GetFiles(folder).Where(f => Path.GetFileName(f).StartsWith("export-tvm", StringComparison.OrdinalIgnoreCase) && Path.GetExtension(f).ToLowerInvariant() is ".xlsx" or ".csv")
            .OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault() : null;

    void TriagePick(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose the Defender vulnerabilities export", Filter = "Defender export (*.xlsx;*.csv)|*.xlsx;*.csv|All files|*.*" };
        if (dlg.ShowDialog() != true) return;
        triExport = dlg.FileName; TriSummary.Text = "Ready: " + Path.GetFileName(triExport); Status("export chosen: " + Path.GetFileName(triExport));
    }

    void TriageFolder(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Folder where the Defender exports are saved" };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(TriFolderFile, dlg.FolderName);
        if (Newest(dlg.FolderName) is { } f) { triExport = f; TriSummary.Text = "Ready: " + Path.GetFileName(f); }
        else TriSummary.Text = "No export-tvm file in that folder yet.";
    }

    void TriageMail(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose saved advisory emails", Filter = "Advisory (*.txt;*.eml)|*.txt;*.eml|All files|*.*", Multiselect = true };
        if (dlg.ShowDialog() != true) return;
        triMails.AddRange(dlg.FileNames); Status($"{triMails.Count} advisory file(s) will be read on the next run");
    }

    async void TriageRun(object s, RoutedEventArgs e)
    {
        if (triExport == null && File.Exists(TriFolderFile) && Newest(File.ReadAllText(TriFolderFile).Trim()) is { } f) triExport = f; // the morning habit: save the export, open the page, Run
        if (triExport == null || !File.Exists(triExport)) { TriSummary.Text = "Choose the export first."; return; }
        // the whole run (feed parsing, database, LLM calls) goes to a worker thread; this page only shows progress, the rest of the app stays usable
        var opts = new DefenderTriage.Options(triExport, data, Db, TriFeeds.IsChecked == true, TriLlm.IsChecked == true, triMails.ToList());
        TriRunBtn.IsEnabled = false; TriBusy.Visibility = Visibility.Visible; TriBusy.IsIndeterminate = true; TriSummary.Text = "Starting..."; Status("triage running");
        // a clock, and for counted LLM steps ("card 3/6") a real bar and time left = average time per call so far x calls left
        var started = DateTime.Now; var step = "Starting..."; var eta = ""; var phase = ""; var phaseStart = DateTime.Now;
        static string Fmt(TimeSpan t) => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} min {t.Seconds} s" : $"{t.Seconds} s";
        void Show() => TriSummary.Text = $"{step}{eta}   ({Fmt(DateTime.Now - started)} so far)";
        var clock = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        clock.Tick += (_, _) => Show(); clock.Start();
        void Progress(string m) => Dispatcher.BeginInvoke(() =>
        {
            Status(m.Trim()); if (m.StartsWith("  ")) return;
            step = m.Trim(); eta = "";
            var k = System.Text.RegularExpressions.Regex.Match(m, @"(\d+)/(\d+)");
            if (!k.Success) TriBusy.IsIndeterminate = true;
            else
            {
                var (i, n) = (int.Parse(k.Groups[1].Value), int.Parse(k.Groups[2].Value));
                if (m[..k.Index] != phase) { phase = m[..k.Index]; phaseStart = DateTime.Now; }
                TriBusy.IsIndeterminate = false; TriBusy.Value = 100.0 * (i - 1) / n;
                if (i > 1) eta = $", about {Fmt((DateTime.Now - phaseStart) / (i - 1) * (n - i + 1))} left";
            }
            Show();
        });
        try
        {
            tri = await Task.Run(() => DefenderTriage.Run(opts, log: Progress));
            triMails.Clear(); ShowTriage();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or HttpRequestException)
        { TriSummary.Text = "Could not triage: " + ex.Message; Status("triage failed"); }
        finally { clock.Stop(); TriRunBtn.IsEnabled = true; TriBusy.Visibility = Visibility.Collapsed; }
    }

    void ShowTriage()
    {
        if (tri == null) return;
        TriGrid.ItemsSource = tri.Actions.Select(a => new TriageRow { A = a }).ToList();
        var d = tri.Diff;
        TriSummary.Text = $"{DefenderTriage.CveCount(tri.Actions)} CVEs  ·  {tri.Actions.Count} fix actions  ·  " +
            (d.HasPrevious ? $"{d.New.Count} new  ·  {d.Changed.Count} changed  ·  {d.Gone.Count} gone" : "first run");
        // everything else about the run sits behind the "?": file, comparison day, feed and LLM notes, the validation caveat
        var notes = new List<string> { "File: " + Path.GetFileName(triExport), d.HasPrevious ? $"Compared with {d.PreviousDay}." : "First export kept; tomorrow shows what changed." };
        notes.AddRange(tri.Notes);
        if (!File.Exists(Db)) notes.Add("No cve.db: KEV and EPSS were not used. Sync on 2 Collection.");
        notes.Add("IT note: " + tri.NoteSource + ".");
        notes.Add("Rule-based ranking, not validated against outcomes. Each row names the rule that fired.");
        TriNotesHelp.Text = string.Join("\n", notes);
        TriNotesHelp.Warn = !File.Exists(Db) || tri.Notes.Any(n => n.Contains("not reachable") || n.Contains("not parsed") || n.Contains("failed") || n.Contains("skipped")) || tri.NoteSource.Contains("failed");
        TriMarkCol.Visibility = tri.Actions.Any(a => a.Flag != "") ? Visibility.Visible : Visibility.Collapsed;
        TriAdvTab.Header = $"Advisories ({tri.Unmatched.Count})";
        TriNote.Text = tri.ItNote;
        TriUnmatched.ItemsSource = tri.Unmatched.Select(u => $"{u.Source} {u.Published}: {u.Title}" + (u.ActivelyExploited ? "  [actively exploited]" : u.ExploitExists ? "  [exploit exists]" : "")).ToList();
        if (TriGrid.Items.Count > 0) TriGrid.SelectedIndex = 0;
        Status("triage done: " + tri.OutDir);
    }

    void TriageSelected(object s, SelectionChangedEventArgs e)
    {
        if (TriGrid.SelectedItem is not TriageRow r) return;
        var a = r.A;
        var lines = new List<string> { $"{a.Product}: {a.Tier}", a.Reason, "", "INTELLIGENCE", a.Card, "" };
        var rows = Intel.Rows(a);
        if (rows.Count > 0) { lines.Add("Sources:"); lines.AddRange(rows.Select(x => $"[{x.N}] {x.Source}, grade {x.Grade}, TLP:{x.Tlp}{(x.Date != "" ? ", " + x.Date : "")}  {x.Link}")); lines.Add(""); }
        if (a.NotInNvd > 0) lines.Add($"{a.NotInNvd} CVEs are not in the local NVD copy.");
        lines.Add("Top CVEs:"); lines.AddRange(a.Rows.Take(8).Select(c => $"- {c.Cve} {c.Severity} CVSS {c.Cvss:0.0} EPSS {c.Epss:0.0000}, {c.Age} days"));
        if (a.Rows.Count > 8) lines.Add($"... and {a.Rows.Count - 8} more (see the xlsx).");
        if (a.Flag != "") lines.Add("\nYour mark: " + a.Flag);
        TriDetail.Text = string.Join("\n", lines);
    }

    /// <summary>Saves the mark, then ranks again from the export so the mark is applied to the rule-based tier, not stacked on an earlier mark.</summary>
    void TriageFlag(object s, RoutedEventArgs e)
    {
        if (TriGrid.SelectedItem is not TriageRow r || s is not Button { Tag: string action } || tri == null || triExport == null) return;
        try { DefenderTriage.SetFlag(data, r.A.Key, action, TriReason.Text.Trim(), TriUntil.Text.Trim()); }
        catch (Exception ex) when (ex is ArgumentException or IOException) { Status("Mark not saved: " + ex.Message); return; }
        var today = DateOnly.FromDateTime(DateTime.Now); var key = r.A.Key;
        var cards = tri.Actions.ToDictionary(a => a.Key, a => a.Card); // keep the LLM's cards: the evidence did not change
        var actions = DefenderTriage.ApplyFlags(DefenderTriage.Rank(DefenderTriage.Load(triExport), Db, data, tri.Advisories, today), DefenderTriage.LoadFlags(data), today)
            .Select(a => cards.TryGetValue(a.Key, out var c) ? a with { Card = c } : a).ToList();
        tri = tri with { Actions = actions };
        File.WriteAllText(Path.Combine(tri.OutDir, "briefing.html"), DefenderTriage.Html(actions, tri.Diff, Path.GetFileName(triExport), today, tri.Unmatched));
        DefenderTriage.WriteXlsx(Path.Combine(tri.OutDir, "fix-actions.xlsx"), actions);
        ShowTriage(); TriGrid.SelectedIndex = actions.FindIndex(a => a.Key == key); Status($"{key}: marked {action}");
    }

    // ---------- Settings: intelligence sources (sources.json); every change is saved at once ----------
    void LoadSources()
    {
        if (!SourcesHelp.Text.Contains("WHERE THE INTELLIGENCE")) SourcesHelp.Text += "\n\n" + SourcesText;
        SourcesPanel.Children.Clear();
        var all = Sources.Load(data);
        void Save() { Sources.Save(data, all); Status("sources saved"); }
        ComboBox Pick(string[] items, string value, Action<string> set)
        {
            var c = new ComboBox { ItemsSource = items, SelectedItem = value, Width = 80, Margin = new Thickness(0, 0, 8, 0) };
            c.SelectionChanged += (_, _) => { set((string)c.SelectedItem); Save(); }; return c;
        }
        for (int i = 0; i < all.Count; i++)
        {
            var k = i; var src = all[k];
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            var on = new CheckBox { IsChecked = src.Enabled, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0), ToolTip = "Enabled" };
            on.Click += (_, _) => { all[k] = all[k] with { Enabled = on.IsChecked == true }; Save(); };
            row.Children.Add(on); row.Children.Add(Cell(src.Name, 150)); row.Children.Add(Cell(src.Type, 50, true));
            row.Children.Add(Pick(Sources.Grades, src.Grade, v => all[k] = all[k] with { Grade = v }));
            row.Children.Add(Pick(Sources.Tlps, src.Tlp, v => all[k] = all[k] with { Tlp = v }));
            var cve = new CheckBox { Content = "CVE posts only", IsChecked = src.RequireCve, VerticalAlignment = VerticalAlignment.Center, Foreground = (Brush)FindResource("Fg"), Margin = new Thickness(0, 0, 8, 0) };
            cve.Click += (_, _) => { all[k] = all[k] with { RequireCve = cve.IsChecked == true }; Save(); };
            row.Children.Add(cve);
            row.Children.Add(Btn("Remove", () => { all.RemoveAt(k); Save(); LoadSources(); }));
            row.ToolTip = src.Url;
            SourcesPanel.Children.Add(row);
        }
        // add a source: name, URL (http/https only), type, grade, TLP
        var add = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        var name = new TextBox { Width = 140, Margin = new Thickness(0, 0, 6, 0), ToolTip = "Name" }; var url = new TextBox { Width = 320, Margin = new Thickness(0, 0, 6, 0), ToolTip = "Feed URL (https://...)" };
        var type = new ComboBox { ItemsSource = new[] { "rss", "atom" }, SelectedIndex = 0, Width = 70, Margin = new Thickness(0, 0, 6, 0) };
        var grade = new ComboBox { ItemsSource = Sources.Grades, SelectedIndex = 1, Width = 60, Margin = new Thickness(0, 0, 6, 0), ToolTip = "Grade" };
        var tlp = new ComboBox { ItemsSource = Sources.Tlps, SelectedIndex = 0, Width = 80, Margin = new Thickness(0, 0, 6, 0), ToolTip = "TLP" };
        add.Children.Add(Cell("name", 40, true)); add.Children.Add(name); add.Children.Add(Cell("URL", 30, true)); add.Children.Add(url);
        add.Children.Add(type); add.Children.Add(grade); add.Children.Add(tlp);
        add.Children.Add(Btn("Add source", () =>
        {
            if (name.Text.Trim() == "" || !Uri.TryCreate(url.Text.Trim(), UriKind.Absolute, out var u) || u.Scheme is not ("https" or "http")) { Status("A source needs a name and an http(s) URL"); return; }
            all.Add(new Source(name.Text.Trim(), (string)type.SelectedItem, u.ToString(), (string)grade.SelectedItem, (string)tlp.SelectedItem)); Save(); LoadSources();
        }));
        SourcesPanel.Children.Add(add);
    }

    void TriageCopy(object s, RoutedEventArgs e) { try { Clipboard.SetText(TriNote.Text); Status("note copied"); } catch (System.Runtime.InteropServices.ExternalException) { Status("clipboard busy, try again"); } }
    void TriageBriefing(object s, RoutedEventArgs e) { if (tri != null) OpenFile(Path.Combine(tri.OutDir, "briefing.html")); }
    void TriageXlsx(object s, RoutedEventArgs e) { if (tri != null) OpenFile(Path.Combine(tri.OutDir, "fix-actions.xlsx")); }
    void TriageOutFolder(object s, RoutedEventArgs e) { if (tri != null) OpenFile(tri.OutDir); }
}
