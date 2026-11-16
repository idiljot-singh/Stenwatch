using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Data.Sqlite;
using Path = System.IO.Path;
using Process = Stenwatch.Core.Process;
using Stenwatch.Core;

namespace Stenwatch.App;

/// <summary>The ticket state of a task as a small pill: Not sent (Dim), Sent (Track), Failed (Warn). A word as well as a colour; follows the theme.</summary>
public class TicketPill : Border
{
    public static readonly DependencyProperty StateProperty = DependencyProperty.Register(nameof(State), typeof(string), typeof(TicketPill), new("", (d, _) => ((TicketPill)d).Draw()));
    public string State { get => (string)GetValue(StateProperty); set => SetValue(StateProperty, value); }
    readonly TextBlock word = new() { FontSize = 11 };
    public TicketPill() { CornerRadius = new CornerRadius(10); BorderThickness = new Thickness(1); Padding = new Thickness(10, 0, 10, 0); HorizontalAlignment = HorizontalAlignment.Left; VerticalAlignment = VerticalAlignment.Center; Child = word; Draw(); }
    void Draw()
    {
        var (text, tone) = State switch { Tickets.Sent => ("Sent", "Track"), Tickets.Failed => ("Failed", "Warn"), _ => ("Not sent", "Dim") };
        word.Text = text; this.Res(BorderBrushProperty, tone); word.Res(TextBlock.ForegroundProperty, tone); AutomationProperties.SetName(this, "Ticket state: " + text);
    }
}

/// <summary>Phase 2, daily operation: ticket push (Remediation, Tickets), the four working rows on Integrations (ticket webhook, briefing delivery, scheduled morning run,
/// end-of-life check), the KQL hunting query on a finding, and the briefing.eml line on Morning triage. All logic is in Core (Tickets, Morning, Eol, Kql); this only
/// collects the inputs, runs the call off the UI thread and shows the engine's own note.</summary>
public partial class MainWindow
{
    static readonly HttpClient Web = new() { Timeout = TimeSpan.FromSeconds(30) };
    bool pushBusy, pushAsk = true, dailyBusy;
    StackPanel? ticketSec, briefSec, schedSec, eolSec;
    string? kqlQuery;

    /// <summary>Where the non-CVE rows of the shown organisation are kept: the data folder, or for the Example Organisation the output folder of its last rank.</summary>
    string ExposureDir => Example ? last?.OutDir ?? Path.Combine(data, "out", "example-cs") : data;

    /// <summary>The Findings list: the last rank's CVE findings, then every component's exposure rows (end-of-life software among them), and the component filter to match.
    /// ponytail: exposures have no risk score, so they follow the ranked CVEs (by tier) instead of interleaving; interleave when they get a comparable score.</summary>
    void LoadFindings()
    {
        allFindings = (last?.Ranked.Select(x => new FindingRow { R = x }) ?? Enumerable.Empty<FindingRow>())
            .Concat(Exposure.Load(ExposureDir).OrderBy(x => Array.IndexOf(DefenderTriage.Tiers, x.Tier)).Select(x => new FindingRow { E = x })).ToList();
        var pick = ComponentFilter.SelectedItem as string;
        ComponentFilter.ItemsSource = new[] { AllComponents }.Concat(allFindings.Select(f => f.Component).Distinct()).ToList();
        ComponentFilter.SelectedItem = ComponentFilter.Items.Contains(pick ?? "") ? pick : AllComponents;
        ApplyFilter();
    }

    // ---------- Remediation and Tickets: push to ticket ----------
    async void PushTicket(object s, RoutedEventArgs e)
    {
        if (TasksGrid.SelectedItem is not RemediationTask t) { Status("Select a task first"); return; }
        await PushTask(t);
    }

    /// <summary>The reason sent: the finding's own rule and why text when it is in the last rank, else the task's note (the engine does that for an empty reason).</summary>
    string ReasonFor(RemediationTask t) => allFindings.FirstOrDefault(f => f.Cve == t.Cve && f.Asset == t.Asset)?.Why ?? t.Note;

    /// <summary>Push one task: say so when no webhook is set, show what will be sent (until "do not ask again"), post off the UI thread, show the engine's note, redraw.</summary>
    async Task PushTask(RemediationTask t)
    {
        if (pushBusy) return;
        if (Secrets.Get(Tickets.Secret) is not { Length: > 0 })
        {
            PushNote.Text = "No ticket webhook is set."; PushSetupBtn.Visibility = Visibility.Visible; Status("No ticket webhook set: add one on Integrations");
            if (Pages.SelectedIndex == 16) Go(17);
            return;
        }
        var reason = ReasonFor(t);
        if (pushAsk && !ConfirmPush(t, reason, Tickets.IsTeams(data))) return;
        pushBusy = true; PushBtn.IsEnabled = false; Status($"T-{t.Id}: pushing to the ticket webhook...");
        var taskDb = TaskDb; var d = data;
        try { Status((await Task.Run(async () => { using var db = Collect.Connect(taskDb); return await Tickets.Push(db, t.Id, reason, d); })).Note); }
        catch (Exception ex) when (ex is ArgumentException or SqliteException or IOException) { Status($"T-{t.Id}: not pushed: " + ex.Message); }
        finally { pushBusy = false; PushBtn.IsEnabled = true; }
        LoadTasks(null, null!);
        TasksGrid.SelectedItem = (TasksGrid.ItemsSource as IEnumerable<RemediationTask>)?.FirstOrDefault(x => x.Id == t.Id);
        if (Pages.SelectedIndex == 16) BuildPage(16);
    }

    /// <summary>The first push of a session shows the eight fields that leave the machine, the asset name among them.</summary>
    bool ConfirmPush(RemediationTask t, string reason, bool teams)
    {
        var fields = new[] { ("task_id", t.Id.ToString()), ("item", t.Cve), ("asset", t.Asset), ("tier", t.Tier), ("deadline", t.Due), ("owner", t.Owner), ("reason", reason == "" ? t.Note : reason), ("link", Tickets.Link(t.Cve)) };
        var grid = new Grid { Margin = new Thickness(0, 10, 0, 10) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) }); grid.ColumnDefinitions.Add(new ColumnDefinition());
        for (var i = 0; i < fields.Length; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var k = Txt(fields[i].Item1, "Dim", 12); k.FontFamily = (FontFamily)FindResource("Mono"); k.Margin = new Thickness(0, 2, 8, 2); k.VerticalAlignment = VerticalAlignment.Top;
            var v = Txt(fields[i].Item2 == "" ? "(empty)" : fields[i].Item2); v.Margin = new Thickness(0, 2, 0, 2);
            Grid.SetRow(k, i); Grid.SetRow(v, i); Grid.SetColumn(v, 1); grid.Children.Add(k); grid.Children.Add(v);
        }
        var again = new CheckBox { Content = "Do not ask again this session", Margin = new Thickness(0, 0, 0, 12) }; AutomationProperties.SetName(again, "Do not ask again this session");
        var win = new Window { Title = "Push to ticket", Owner = this, Width = 560, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner }.Res(Window.BackgroundProperty, "Bg").Res(Window.ForegroundProperty, "Fg");
        var send = new Button { Content = "Send", IsDefault = true, Style = (Style)FindResource("Primary") }; send.Click += (_, _) => win.DialogResult = true;
        var cancel = new Button { Content = "Cancel", IsCancel = true, Margin = new Thickness(0) };
        AutomationProperties.SetName(send, "Send this task to the ticket webhook"); AutomationProperties.SetName(cancel, "Cancel, send nothing");
        win.Content = new StackPanel { Margin = new Thickness(20), Children = {
            Txt($"Stenwatch will post this one task to your ticket webhook as {(teams ? "a Teams card" : "plain JSON")}. These eight fields are all that is sent. The asset name is an organisation detail: it goes to your own webhook only, never to an LLM."),
            grid, again, new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { send, cancel } } } };
        if (win.ShowDialog() != true) return false;
        if (again.IsChecked == true) pushAsk = false;
        return true;
    }

    /// <summary>Tickets page: tasks with a ticket state or a reference, the state as a pill, and Push again on a failed one.</summary>
    void BuildTickets()
    {
        var host = TicketsHost; host.Children.Clear();
        var tasks = new List<RemediationTask>();
        if (File.Exists(TaskDb)) { using var db = Collect.Connect(TaskDb); tasks = Remediation.Load(db).Where(t => t.TicketState != "" || t.Ticket != "").ToList(); }
        host.Children.Add(new TextBlock { Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 0, 0, 8),
            Text = tasks.Count == 0 ? "No task has been sent to a ticket system yet. Select a task on Remediation and press Push to ticket, once a ticket webhook is set on Integrations. A task you gave a ticket reference by hand shows here too."
                : "Tasks with a ticket state or a reference. A push sends one task and nothing else; a Failed one can be sent again here." });
        if (tasks.Count == 0) return;
        var rows = tasks.Take(300).Select(t => new UIElement[] { Txt($"T-{t.Id}"), Txt(t.Cve), Txt(t.Asset), Txt(t.Owner), new TicketPill { State = t.TicketState }, Txt(t.Ticket, "Mute"),
            t.TicketState == Tickets.Failed ? SmallBtn("Push again", () => _ = PushTask(t), $"Push again: T-{t.Id} {t.Cve}") : new TextBlock() }).ToList();
        host.Children.Add(Table(new[] { "TASK", "ITEM", "ASSET", "OWNER", "STATE", "REFERENCE", "" }, new double[] { 70, 150, -2, 120, 110, -2, 120 }, rows));
        if (tasks.Count > 300) host.Children.Add(new TextBlock { Text = $"First 300 of {tasks.Count:N0} shown.", Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 6, 0, 0) });
    }

    // ---------- Findings: the hunting query ----------
    /// <summary>The query button shows for a CVE finding only, with the box closed; Kql.For says null for anything that is not a CVE id.</summary>
    void ShowKql(FindingRow f)
    {
        kqlQuery = f.R is null ? null : Kql.For(f.R);
        KqlPanel.Visibility = kqlQuery is null ? Visibility.Collapsed : Visibility.Visible; KqlBox.Visibility = Visibility.Collapsed;
    }
    void KqlClick(object s, RoutedEventArgs e)
    {
        KqlText.Text = kqlQuery ?? ""; KqlText.MinHeight = 0; KqlBox.Visibility = KqlBox.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
    }
    void KqlCopy(object s, RoutedEventArgs e) { try { Clipboard.SetText(KqlText.Text); Status("hunting query copied"); } catch (System.Runtime.InteropServices.ExternalException) { Status("clipboard busy, try again"); } }

    // ---------- Morning triage: briefing.eml ----------
    string EmlPath => Path.Combine(tri?.OutDir ?? Path.Combine(data, "out", "triage"), "briefing.eml");
    void ShowEml()
    {
        var ok = File.Exists(EmlPath); EmlLine.Visibility = ok ? Visibility.Visible : Visibility.Collapsed;
        if (ok) EmlText.Text = $"briefing.eml was written {File.GetLastWriteTime(EmlPath):yyyy-MM-dd HH:mm}: an unsent email with the briefing in it, for your mail program.";
    }
    void OpenEml(object s, RoutedEventArgs e) => OpenFile(EmlPath);

    // ---------- Coverage: where a tile leads ----------
    /// <summary>A tile's Open goes to the page that shows the component; a component not connected goes to its settings on Integrations. End-of-life opens Findings on its own rows.</summary>
    void OpenTile(string comp, bool notConnected)
    {
        if (!notConnected && comp == Eol.Component)
        {
            LoadFindings(); Go(5);
            if (ComponentFilter.Items.Contains(Eol.Component)) { TierFilter.SelectedIndex = 1; ComponentFilter.SelectedItem = Eol.Component; }
            return;
        }
        Go(notConnected ? 17 : OpenPage(comp));
        if (notConnected && comp switch { "Ticketing" => ticketSec, Eol.Component => eolSec, _ => null } is { } sec) Dispatcher.BeginInvoke(() => sec.BringIntoView(), System.Windows.Threading.DispatcherPriority.Background);
    }

    // ---------- Integrations: connector row states ----------
    (int Sent, int Failed) TicketCounts()
    {
        try { if (!File.Exists(TaskDb)) return (0, 0); using var db = Collect.Connect(TaskDb); var all = Remediation.Load(db); return (all.Count(t => t.TicketState == Tickets.Sent), all.Count(t => t.TicketState == Tickets.Failed)); }
        catch (SqliteException) { return (0, 0); }
    }
    static bool IsSet(string secret) => Secrets.Get(secret) is { Length: > 0 };
    static string DayOf(string path) => File.Exists(path) ? File.GetLastWriteTime(path).ToString("yyyy-MM-dd") : "never";
    string TriageOut => Path.Combine(data, "out", "triage");

    (string Status, string Last, string? Word) ScheduleState()
    {
        var ran = DayOf(Path.Combine(TriageOut, "briefing.eml"));
        return Morning.Load(data).Folder == "" ? (Coverage.NotConnected, "never", null) : ran == "never" ? (Coverage.Partly, "never", "folder set, not run yet") : (Coverage.Connected, ran, "has run");
    }
    (string Status, string Last, string? Word) TicketState()
    {
        var (sent, failed) = TicketCounts();
        return !IsSet(Tickets.Secret) ? (Coverage.NotConnected, "never", null) : sent > 0 ? (Coverage.Connected, $"{sent} sent", null)
            : failed > 0 ? (Coverage.Attention, "last push failed", "needs attention") : (Coverage.Partly, "nothing sent yet", "webhook set");
    }
    (string Status, string Last, string? Word) BriefingState()
    {
        var eml = DayOf(Path.Combine(TriageOut, "briefing.eml")); var hook = IsSet(Morning.BriefingSecret);
        return hook && eml != "never" ? (Coverage.Connected, eml, null) : hook ? (Coverage.Partly, "never", "webhook set") : eml != "never" ? (Coverage.Partly, eml, "email file only") : (Coverage.NotConnected, "never", null);
    }
    (string Status, string Last, string? Word) EolState()
    {
        var day = DayOf(Exposure.FileFor(ExposureDir, Eol.Component));
        return day == "never" ? (Coverage.NotConnected, "never", null) : (Coverage.Connected, day, null);
    }

    // ---------- Integrations: the four settings areas under the connectors table ----------
    TextBlock Note(string text) => new() { Text = text, Style = (Style)FindResource("Muted"), Margin = new Thickness(0, 0, 0, 6), TextWrapping = TextWrapping.Wrap, MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Left };
    WrapPanel Bar(params UIElement[] parts) { var w = new WrapPanel { Margin = new Thickness(0, 2, 0, 2) }; foreach (var p in parts) w.Children.Add(p); return w; }

    /// <summary>A secret field like the API key rows: shown only as "set" or "not set", never the value. A webhook address must be https; the engine says why when it is not.</summary>
    WrapPanel SecretRow(string key, string label, bool address = false)
    {
        var box = new PasswordBox { Width = 300, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(4) }; AutomationProperties.SetName(box, label);
        var state = Cell(IsSet(key) ? "set" : "not set", 60, true); AutomationProperties.SetName(state, label + " state");
        return Bar(Cell(label, 210), box, state, Btn("Save", () =>
        {
            if (box.Password == "") { Status($"{label}: nothing typed"); return; }
            if (address && Tickets.UrlProblem(box.Password) is { } bad) { Status($"{label} not saved: {bad}"); return; }
            try { Secrets.Set(key, box.Password.Trim()); box.Clear(); state.Text = "set"; Status($"{label} saved to Credential Manager"); BuildPage(17); }
            catch (Exception ex) { Status($"{label} not saved: " + ex.Message); }
        }));
    }

    void BuildDaily()
    {
        if (dailyBusy) return;
        DailyHost.Children.Clear();
        StackPanel[] all = { TicketSection(), BriefingSection(), ScheduleSection(), EolSection() };
        (ticketSec, briefSec, schedSec, eolSec) = (all[0], all[1], all[2], all[3]);
        foreach (var sec in all) { sec.Margin = new Thickness(0, 0, 0, 16); DailyHost.Children.Add(sec); }
    }

    /// <summary>Ticket webhook: format, address and optional header (secrets), and a test post of one fictional task.</summary>
    StackPanel TicketSection()
    {
        var sec = new StackPanel(); sec.Children.Add(Head("TICKET WEBHOOK"));
        sec.Children.Add(Note("Push to ticket on Remediation posts one task to this webhook: task id, item, asset name, tier, deadline, owner, the reason and a link. Nothing else about your estate, and nothing is read back except a ticket reference. https only. The address and the header are secrets: they are kept in Windows Credential Manager and never shown again."));
        var format = new ComboBox { ItemsSource = new[] { "Teams card", "Plain JSON" }, SelectedIndex = Tickets.IsTeams(data) ? 0 : 1, Width = 140 }; AutomationProperties.SetName(format, "Ticket format");
        var header = new StackPanel { IsEnabled = !Tickets.IsTeams(data), Opacity = Tickets.IsTeams(data) ? 0.5 : 1 };
        header.Children.Add(SecretRow(Tickets.HeaderName, "Header name (optional)")); header.Children.Add(SecretRow(Tickets.HeaderValue, "Header value (optional)"));
        format.SelectionChanged += (_, _) =>
        {
            var teams = format.SelectedIndex == 0; header.IsEnabled = !teams; header.Opacity = teams ? 0.5 : 1;
            try { Tickets.SetFormat(data, teams); Status("Ticket format: " + (teams ? "Teams card" : "plain JSON")); } catch (IOException ex) { Status("Format not saved: " + ex.Message); }
        };
        sec.Children.Add(Bar(Cell("Format", 210, true), format, Txt("The header is sent with plain JSON only (Jira's incoming webhook wants one).", "Mute", 11)));
        sec.Children.Add(SecretRow(Tickets.Secret, "Webhook address", true)); sec.Children.Add(header);
        var result = Txt("", "Mute"); var test = Btn("Send test", () => { }); AutomationProperties.SetName(test, "Send test ticket");
        test.Click += async (_, _) =>
        {
            var url = Secrets.Get(Tickets.Secret); var teams = Tickets.IsTeams(data);
            if (Tickets.UrlProblem(url) is { } bad) { result.Text = "Not sent: " + (bad == "no webhook set" ? "no webhook set, save the address first" : bad); Status("Test ticket: " + result.Text); return; }
            (string, string)? h = !teams && Secrets.Get(Tickets.HeaderName) is { Length: > 0 } hn && Secrets.Get(Tickets.HeaderValue) is { Length: > 0 } hv ? (hn, hv) : null;
            var today = DateTime.Today.ToString("yyyy-MM-dd");
            var fake = new RemediationTask(0, "TEST-0000", "Stenwatch test, no action needed", "Open", "Track", "nobody", "", today, today, "", "");
            test.IsEnabled = false; result.Text = "Sending..."; Status("Test ticket: sending...");
            try { var (ok, _, note) = await Task.Run(() => Tickets.Post(Web, url, Tickets.Payload(fake, "Stenwatch test, no action needed", teams), h)); result.Text = (ok ? "Sent: " : "Not sent: ") + note; }
            finally { test.IsEnabled = true; }
            Status("Test ticket: " + result.Text);
        };
        sec.Children.Add(Bar(test, result)); return sec;
    }

    /// <summary>Briefing delivery: the Teams webhook (a secret) and a note that the email file is always written.</summary>
    StackPanel BriefingSection()
    {
        var sec = new StackPanel(); sec.Children.Add(Head("BRIEFING DELIVERY"));
        sec.Children.Add(Note("The scheduled morning run posts the briefing to this Teams workflow: the date, the counts, and for each fix action that needs a decision today the tier, product, version and rule. No asset names, no machine list."));
        sec.Children.Add(SecretRow(Morning.BriefingSecret, "Teams webhook address", true));
        sec.Children.Add(Note("briefing.eml is always written next to briefing.html (out/triage in the data folder): an unsent email with the briefing in it. Open it in your mail program, add the recipients and send. Stenwatch sends no mail itself."));
        return sec;
    }

    /// <summary>Scheduled morning run: watched folder, time, LLM tick, Run now (off the UI thread), and the schtasks text to copy. The app never runs schtasks.</summary>
    StackPanel ScheduleSection()
    {
        var sec = new StackPanel(); sec.Children.Add(Head("SCHEDULED MORNING RUN"));
        sec.Children.Add(Note("Each morning the newest Defender export (.csv or .xlsx) in the watched folder goes through Run triage; the output is in out/triage in the data folder. Windows Task Scheduler does the starting: Show schedule command gives the one line that registers it."));
        var s0 = Morning.Load(data);
        var folder = new TextBox { Text = s0.Folder, IsReadOnly = true, Width = 460, Margin = new Thickness(0, 0, 8, 0), ToolTip = "Watched folder" }; AutomationProperties.SetName(folder, "Watched folder");
        var pick = Btn("Folder...", () =>
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Folder where the Defender exports are saved" };
            if (dlg.ShowDialog() != true) return;
            Morning.Save(data, Morning.Load(data) with { Folder = dlg.FolderName }); folder.Text = dlg.FolderName; Status("Watched folder set"); BuildPage(17);
        }); AutomationProperties.SetName(pick, "Choose the watched folder");
        sec.Children.Add(Bar(Cell("Watched folder", 210, true), folder, pick));
        var time = new TextBox { Text = "07:30", Width = 70, Margin = new Thickness(0, 0, 12, 0), ToolTip = "Time of day, HH:mm" }; AutomationProperties.SetName(time, "Time of day (HH:mm)");
        var llm = new CheckBox { Content = "Use LLM", IsChecked = s0.Llm, VerticalAlignment = VerticalAlignment.Center, ToolTip = "Read advisories and write the note to IT with the LLM set up below (OpenRouter key) or a local model. It never sets a tier." };
        llm.Click += (_, _) => { Morning.Save(data, Morning.Load(data) with { Llm = llm.IsChecked == true }); Status("Use LLM: " + (llm.IsChecked == true ? "on" : "off")); };
        sec.Children.Add(Bar(Cell("Time of day", 210, true), time, llm));
        var result = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0), MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Left }.Res(TextBlock.ForegroundProperty, "Mute");
        var run = Btn("Run now", () => { }); AutomationProperties.SetName(run, "Run the morning run now");
        run.Click += async (_, _) =>
        {
            if (dailyBusy) return;
            var f = folder.Text == "" ? null : folder.Text; var useLlm = llm.IsChecked == true; var d = data;
            dailyBusy = true; run.IsEnabled = false; result.Text = "Running..."; Status("Morning run: starting...");
            void Progress(string m) => Dispatcher.BeginInvoke(() => Status("Morning run: " + m.Trim()));
            try
            {
                var o = await Task.Run(() => Morning.Run(d, f, useLlm, log: Progress));
                if (o.Triage != null) { tri = o.Triage; triExport = o.Export; ShowTriage(); }
                result.Text = string.Join("\n", o.Notes.Where(n => !n.StartsWith("  ")).TakeLast(6)); Status("Morning run: " + (o.Notes.LastOrDefault() ?? "done").Trim());
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or SqliteException or HttpRequestException) { result.Text = "The run failed: " + ex.Message; Status("Morning run failed"); }
            finally { dailyBusy = false; run.IsEnabled = true; }
            BuildPage(17);
        };
        var cmd = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, FontFamily = (FontFamily)FindResource("Mono"), FontSize = 12, Visibility = Visibility.Collapsed, Margin = new Thickness(0, 6, 0, 6), MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Left }; AutomationProperties.SetName(cmd, "Schedule command");
        var hint = Note(""); hint.Visibility = Visibility.Collapsed;
        var copy = Btn("Copy", () => { try { Clipboard.SetText(cmd.Text); Status("schedule command copied"); } catch (System.Runtime.InteropServices.ExternalException) { Status("clipboard busy, try again"); } }); copy.Visibility = Visibility.Collapsed; AutomationProperties.SetName(copy, "Copy the schedule command");
        var show = Btn("Show schedule command", () =>
        {
            if (!TimeOnly.TryParseExact(time.Text.Trim(), new[] { "HH:mm", "H:mm" }, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var at)) { Status("Time of day: write it as HH:mm, for example 07:30"); return; }
            var r = Morning.ScheduleCommand(at);
            cmd.Visibility = copy.Visibility = r.Command is null ? Visibility.Collapsed : Visibility.Visible; cmd.Text = r.Command ?? ""; hint.Visibility = Visibility.Visible;
            hint.Text = r.Command is null ? r.Note : "Copy it and run it once in a terminal (Command Prompt or PowerShell) as yourself. Stenwatch never runs it. The task runs while you are signed in." + (folder.Text == "" ? " Choose the watched folder first." : "");
        }); AutomationProperties.SetName(show, "Show the schedule command");
        sec.Children.Add(Bar(run, show)); sec.Children.Add(result); sec.Children.Add(cmd); sec.Children.Add(copy); sec.Children.Add(hint);
        return sec;
    }

    /// <summary>endoflife.date: Check now on the current asset list; the counts, and the products that could not be checked behind a "?".</summary>
    StackPanel EolSection()
    {
        var sec = new StackPanel(); sec.Children.Add(Head("END-OF-LIFE SOFTWARE (ENDOFLIFE.DATE)"));
        sec.Children.Add(Note("Checks the asset list against endoflife.date, a public site: only product names are sent, nothing about your organisation. Software past its end-of-life date shows in Findings as End-of-life software. A product that is not in the fixed map, or an asset with no version, is not checked: it is never counted as supported."));
        var result = Txt("Not run in this session.", "Mute"); var help = new HelpButton { Title = "Not checked", Visibility = Visibility.Collapsed };
        var check = Btn("Check now", () => { }); AutomationProperties.SetName(check, "Check the asset list against endoflife.date");
        check.Click += async (_, _) =>
        {
            if (dailyBusy) return;
            if (!File.Exists(files.Assets)) { Status("No asset list yet: import assets.csv on Threat profile"); return; }
            var d = data; var assets = files.Assets; var save = Example ? ExposureDir : null;
            dailyBusy = true; check.IsEnabled = false; result.Text = "Checking..."; Status("End of life: checking...");
            try
            {
                var r = await Task.Run(() => Eol.Check(d, Process.LoadAssets(assets), saveTo: save, log: m => Dispatcher.BeginInvoke(() => Status(m))));
                result.Text = $"{r.Checked} checked, {r.Past} past end of life, {r.Soon} within 90 days, {r.NotChecked.Count} not checked";
                help.Text = string.Join("\n", r.NotChecked.Take(40)) + (r.NotChecked.Count > 40 ? $"\nand {r.NotChecked.Count - 40} more" : ""); help.Visibility = r.NotChecked.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                Status(r.Note); LoadFindings();
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or KeyNotFoundException or FormatException) { result.Text = "The check failed: " + ex.Message; Status("End of life: check failed"); }
            finally { dailyBusy = false; check.IsEnabled = true; }
            BuildPage(17);
        };
        sec.Children.Add(Bar(check, result, help)); return sec;
    }
}
