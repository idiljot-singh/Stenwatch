using System.Text;
using System.Text.Json;

namespace Stenwatch.Core;

/// <summary>The scheduled morning run: the newest Defender vulnerabilities export in a watched folder goes through <see cref="DefenderTriage.Run"/> with feeds fetched,
/// the briefing is saved as briefing.eml next to briefing.html, and posted to Teams when a briefing webhook is set.
/// The folder and options are kept in morning.json in the data folder. Nothing here starts, changes or removes a scheduled task:
/// <see cref="ScheduleCommand"/> only returns the schtasks command line for the person (or the app) to run.
/// Briefing post, what leaves the machine (to the customer's own Teams workflow only): the date, the CVE and fix action counts, and for each fix action
/// in "Needs a decision today": tier, product name, the version to update to, and the rule that set the tier. No asset names, no machine list.</summary>
public static class Morning
{
    public const string BriefingSecret = "STENWATCH_BRIEFING_WEBHOOK", TaskName = "Stenwatch morning run";

    /// <summary>morning.json: the watched folder, whether the LLM reads advisories, and the export last run (path|last write time, UTC ticks).</summary>
    public record Settings(string Folder = "", bool Llm = false, string Last = "");
    public record Outcome(string Export, bool NewExport, DefenderTriage.Result? Triage, string Eml, List<string> Notes);
    /// <summary>Command is null when there is none to give; Note says why, or what to do with it.</summary>
    public record ScheduleResult(string? Command, string Note);

    static string File_(string data) => Path.Combine(data, "morning.json");
    public static Settings Load(string data)
    {
        try { return File.Exists(File_(data)) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(File_(data))) ?? new() : new(); }
        catch (JsonException) { return new(); }
    }
    public static void Save(string data, Settings s) => File.WriteAllText(File_(data), JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));

    /// <summary>The newest .csv or .xlsx in the folder by last write time (Excel's ~$ lock files skipped), or null.</summary>
    public static string? Newest(string folder) => !Directory.Exists(folder) ? null : new DirectoryInfo(folder).EnumerateFiles()
        .Where(f => f.Extension.ToLowerInvariant() is ".csv" or ".xlsx" && !f.Name.StartsWith("~$")).MaxBy(f => f.LastWriteTimeUtc)?.FullName;

    static string Stamp(string path) => path + "|" + File.GetLastWriteTimeUtc(path).Ticks;

    /// <summary>One morning: folder (null = the remembered one; given = remembered from now on), llm likewise. No new export since the last run: says so, refreshes the feeds, writes nothing else.
    /// Delivery and feeds fail soft with a note; an unreadable export throws as DefenderTriage.Run does.</summary>
    public static async Task<Outcome> Run(string data, string? folder = null, bool? llm = null, HttpClient? http = null, Action<string>? log = null, DateOnly? today = null, string? briefingUrl = null)
    {
        var s = Load(data); s = s with { Folder = folder ?? s.Folder, Llm = llm ?? s.Llm }; Save(data, s);
        var notes = new List<string>(); void Note(string n) { notes.Add(n); log?.Invoke(n); }
        http ??= new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        if (s.Folder == "") { Note("No watched folder: give one once (stenwatch-cli --morning FOLDER)"); return new("", false, null, "", notes); }
        var export = Newest(s.Folder);
        if (export is null || Stamp(export) == s.Last)
        {
            Note(export is null ? $"No Defender export (.csv or .xlsx) in {s.Folder}" : $"No new export since the last run ({Path.GetFileName(export)}, {File.GetLastWriteTime(export):yyyy-MM-dd HH:mm})");
            Note("Refreshing the feeds only");
            Note((await Advisories.Refresh(data, http)).Note);
            return new(export ?? "", false, null, "", notes);
        }
        var day = today ?? DateOnly.FromDateTime(DateTime.Now);
        var r = await DefenderTriage.Run(new(export, data, Path.Combine(data, "cve.db"), true, s.Llm, Today: day), http, Note);
        var eml = WriteEml(r.OutDir, File.ReadAllText(Path.Combine(r.OutDir, "briefing.html")), day);
        Note("Email file: " + eml);
        var url = briefingUrl ?? Secrets.Get(BriefingSecret);
        if (!string.IsNullOrWhiteSpace(url)) Note("Teams: " + (await Tickets.Post(http, url, TeamsCard(r, day))).Note);
        Save(data, s with { Last = Stamp(export) });
        return new(export, true, r, eml, notes);
    }

    // ---- briefing delivery --------------------------------------------------------------------------------------------------

    /// <summary>"Needs a decision today" as a Teams card: exactly the fields named in the class summary.</summary>
    public static string TeamsCard(DefenderTriage.Result r, DateOnly today)
    {
        var decide = DefenderTriage.Decide(r.Actions, r.Diff);
        var lines = decide.Select(a => (a.Tier, a.Product + (a.Fix != "" ? " to " + a.Fix : "") + ": " + a.Rule)).ToList();
        for (var keep = lines.Count; ; keep--) // Teams refuses a message over 28 KB: drop lines from the end and say how many
        {
            var card = Tickets.Card($"Stenwatch morning briefing {today.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}: needs a decision today",
                lines.Take(keep).Concat(keep < lines.Count ? new[] { ("", $"and {lines.Count - keep} more in briefing.html") } : Array.Empty<(string, string)>()),
                $"{DefenderTriage.CveCount(r.Actions)} CVEs in {r.Actions.Count} fix actions. " + (decide.Count == 0 ? "Nothing new or changed in Act or Attend." : $"{decide.Count} need a decision."));
            if (keep == 0 || Encoding.UTF8.GetByteCount(card) <= 27_000) return card;
        }
    }

    /// <summary>briefing.eml: an unsent message (X-Unsent: 1, so Outlook opens it as a draft) with the briefing as its HTML body and the date in the subject. No recipient, no SMTP.</summary>
    public static string Eml(string html, DateOnly today)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(html));
        var body = string.Join("\r\n", Enumerable.Range(0, (b64.Length + 75) / 76).Select(i => b64.Substring(i * 76, Math.Min(76, b64.Length - i * 76))));
        return $"X-Unsent: 1\r\nSubject: Stenwatch morning briefing {today.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}\r\nDate: {DateTime.UtcNow:r}\r\n"
            + "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + body + "\r\n";
    }

    public static string WriteEml(string dir, string html, DateOnly today)
    {
        var p = Path.Combine(dir, "briefing.eml"); File.WriteAllText(p, Eml(html, today), new UTF8Encoding(false)); return p;
    }

    // ---- Windows Task Scheduler ----------------------------------------------------------------------------------------------

    /// <summary>The exact command that registers a daily run at <paramref name="at"/> for this install. Not run here.
    /// exe defaults to stenwatch-cli.exe next to the program (the Setup edition installs it there); data is added as --data when STENWATCH_DATA is set.
    /// The Store edition gets no command: its program path under WindowsApps changes with every update (a command alias is planned for the release).</summary>
    public static ScheduleResult ScheduleCommand(TimeOnly at, string? exe = null, string? data = null, bool? packaged = null)
    {
        if (packaged ?? AppPaths.PackageFamily() is not null)
            return new(null, "Not available in the Store edition yet: the Store program path changes with every update. Use the Setup edition for a scheduled run, or run Morning triage by hand.");
        if (exe is null && !File.Exists(exe = Path.Combine(AppContext.BaseDirectory, "stenwatch-cli.exe")))
            return new(null, "stenwatch-cli.exe was not found next to the program: install the Setup edition, or build src/Stenwatch.Cli.");
        data ??= AppPaths.Org() != "" ? AppPaths.Data() // MSP mode: pin the open organisation's folder, org.txt may change later
            : Environment.GetEnvironmentVariable("STENWATCH_DATA") is { Length: > 0 } d ? d : null;
        var tr = $"\\\"{exe}\\\" --morning" + (data is null ? "" : $" --data \\\"{data.TrimEnd('\\')}\\\"");
        var cmd = $"schtasks /create /f /tn \"{Task()}\" /sc daily /st {at.ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture)} /tr \"{tr}\"";
        return tr.Replace("\\\"", "\"").Length > 262
            ? new(null, "The program path is too long for Task Scheduler (262 characters for the command). Install to a shorter folder.")
            : new(cmd, "Run it once in a command prompt as yourself. It runs while you are signed in; set the watched folder first (--morning FOLDER).");
    }

    /// <summary>The command that removes the daily run. Not run here.</summary>
    public static string UnscheduleCommand() => $"schtasks /delete /f /tn \"{Task()}\"";

    /// <summary>One scheduled task per organisation: the default one keeps the plain name.</summary>
    static string Task() => AppPaths.Org() is { Length: > 0 } o ? $"{TaskName} - {o}" : TaskName;
}
