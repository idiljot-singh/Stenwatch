using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>A tracked threat group and why it is tracked. Source: pinned (listed in the profile) | included | auto.</summary>
public record GroupPick(string Id, string Name, string Source, double Score, List<string> Reasons);

/// <summary>Chooses the threat groups to track from the organisation's own profile (sector and country), using what MITRE ATT&amp;CK says about
/// each group. This is a keyword heuristic over the group's description and campaign dates. It is **Proposed**: nothing has shown that groups picked
/// this way predict what attacks a given organisation, and the reasons are shown so an analyst can overrule them.
///
/// Score (documented, tunable only in code on purpose, so it cannot be nudged to taste):
///   +3 per sector the organisation is in that the description names     +3 the organisation's country is named     +1 its region is named
///   +2 ransomware or financially motivated (these groups target any sector)
///   +2 a campaign attributed to the group ended within 36 months        +1 (only when no campaign dates) MITRE edited the entry within 12 months
/// A group with no such sign of recent activity is never picked automatically, however well it matches (pin it in threat_groups to track it anyway).</summary>
public static class ThreatProfileAuto
{
    static readonly Dictionary<string, string[]> Sectors = new()
    {
        ["finance"] = new[] { "financ", "bank", "insurance", "payment", "fintech" },
        ["healthcare"] = new[] { "health", "hospital", "medical", "pharma" },
        ["government"] = new[] { "government", "ministr", "diplomat", "public sector", "municipal" },
        ["defence"] = new[] { "defense", "defence", "military", "aerospace" },
        ["energy"] = new[] { "energy", "oil", " gas ", "utilit", "power grid", "electric", "nuclear" },
        ["telecom"] = new[] { "telecom" },
        ["technology"] = new[] { "technolog", "software", "managed service", "cloud", "supply chain" },
        ["manufacturing"] = new[] { "manufactur", "industrial", "automotive", "engineering" },
        ["education"] = new[] { "educat", "universit", "academi" },
        ["transport"] = new[] { "transport", "aviation", "airline", "maritime", "shipping", "logistic" },
        ["retail"] = new[] { "retail", "hospitality", "e-commerce" },
        ["media"] = new[] { "media", "journalis" },
    };

    // country -> (words that name it, words that name its region)
    static readonly Dictionary<string, (string[] Names, string[] Regions)> Countries = new()
    {
        ["finland"] = (new[] { "finland", "finnish" }, new[] { "nordic", "scandinavia", "europe", "european" }),
        ["sweden"] = (new[] { "sweden", "swedish" }, new[] { "nordic", "scandinavia", "europe", "european" }),
        ["norway"] = (new[] { "norway", "norwegian" }, new[] { "nordic", "scandinavia", "europe", "european" }),
        ["denmark"] = (new[] { "denmark", "danish" }, new[] { "nordic", "scandinavia", "europe", "european" }),
        ["germany"] = (new[] { "germany", "german" }, new[] { "europe", "european" }),
        ["france"] = (new[] { "france", "french" }, new[] { "europe", "european" }),
        ["united kingdom"] = (new[] { "united kingdom", "uk ", "britain", "british" }, new[] { "europe", "european" }),
        ["netherlands"] = (new[] { "netherlands", "dutch" }, new[] { "europe", "european" }),
        ["italy"] = (new[] { "italy", "italian" }, new[] { "europe", "european" }),
        ["spain"] = (new[] { "spain", "spanish" }, new[] { "europe", "european" }),
        ["poland"] = (new[] { "poland", "polish" }, new[] { "europe", "european" }),
        ["estonia"] = (new[] { "estonia" }, new[] { "baltic", "europe", "european" }),
        ["ukraine"] = (new[] { "ukrain" }, new[] { "europe", "european" }),
        ["united states"] = (new[] { "united states", "u.s.", "american" }, new[] { "north america" }),
        ["canada"] = (new[] { "canada", "canadian" }, new[] { "north america" }),
        ["australia"] = (new[] { "australia" }, new[] { "asia-pacific", "apac" }),
        ["japan"] = (new[] { "japan" }, new[] { "asia" }),
        ["south korea"] = (new[] { "south korea" }, new[] { "asia" }),
        ["india"] = (new[] { "india" }, new[] { "asia" }),
        ["singapore"] = (new[] { "singapore" }, new[] { "asia" }),
        ["israel"] = (new[] { "israel" }, new[] { "middle east" }),
        ["brazil"] = (new[] { "brazil" }, new[] { "latin america", "south america" }),
    };

    static bool Has(string text, string[] words) => words.Any(w => text.Contains(w));

    /// <summary>Which canonical sectors a free-text sector (e.g. "Engineering and manufacturing") belongs to.</summary>
    public static List<string> SectorsOf(IEnumerable<string> free) =>
        Sectors.Where(kv => free.Any(f => f.ToLowerInvariant() is var t && (t.Contains(kv.Key) || Has(t, kv.Value)))).Select(kv => kv.Key).ToList();

    public static List<GroupPick> Score(Profile p, IEnumerable<(string Id, string Name, string Description, string Modified, string LastSeen)> groups, DateOnly today)
    {
        var t = p.Targeting;
        var mySectors = SectorsOf(new[] { p.Organisation.Sector }.Concat(t.Sectors));
        var myCountries = new[] { p.Organisation.Country }.Concat(t.Countries).Select(x => x.Trim().ToLowerInvariant()).Where(x => x != "").ToList();
        var picks = new List<GroupPick>();
        foreach (var g in groups)
        {
            if (t.Exclude.Contains(g.Id) || p.ThreatGroups.ContainsKey(g.Id)) continue;
            var d = (" " + g.Description + " ").ToLowerInvariant(); double score = 0; var why = new List<string>(); bool active = false;
            foreach (var s in mySectors) if (Has(d, Sectors[s])) { score += 3; why.Add($"described as targeting {s}"); }
            foreach (var c in myCountries)
            {
                var (names, regions) = Countries.TryGetValue(c, out var v) ? v : (new[] { c }, Array.Empty<string>());
                if (Has(d, names)) { score += 3; why.Add($"names {c}"); }
                else if (Has(d, regions)) { score += 1; why.Add($"names the region of {c}"); }
            }
            if (d.Contains("ransomware") || d.Contains("financially motivated") || d.Contains("financially-motivated")) { score += 2; why.Add("ransomware or financially motivated (targets any sector)"); }
            if (DateTime.TryParse(g.LastSeen, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var seen))
            { if (today.DayNumber - DateOnly.FromDateTime(seen).DayNumber <= 36 * 30) { score += 2; active = true; why.Add($"campaign activity until {seen:yyyy-MM}"); } }
            else if (DateTime.TryParse(g.Modified, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var mod)
                     && today.DayNumber - DateOnly.FromDateTime(mod).DayNumber <= 365) { score += 1; active = true; why.Add("entry updated by MITRE in the last year (weak proxy for activity)"); }
            if (score > 0 && active) picks.Add(new GroupPick(g.Id, g.Name, "auto", score, why));
        }
        return picks.OrderByDescending(x => x.Score).ThenBy(x => x.Name, StringComparer.Ordinal).ToList();
    }

    /// <summary>The profile to run with: pinned groups, plus (in auto mode) the best matches from ATT&amp;CK. Manual mode returns the profile unchanged.</summary>
    public static (Profile Profile, List<GroupPick> Picks, string Note) Effective(Profile p, SqliteConnection db, DateOnly? today = null)
    {
        var picks = p.ThreatGroups.Select(kv => new GroupPick(kv.Key, kv.Value, "pinned", 0, new() { "listed in profile.yaml threat_groups" })).ToList();
        if (p.Targeting.Mode != "auto") return (p, picks, "manual: only the groups listed in profile.yaml are tracked");

        var groups = new List<(string, string, string, string, string)>();
        try
        {
            using var c = db.CreateCommand();
            c.CommandText = "SELECT a.id, a.name, COALESCE(p.description,''), COALESCE(p.modified,''), COALESCE(p.last_seen,'') FROM actor a JOIN actor_profile p ON p.id = a.id";
            using var r = c.ExecuteReader();
            while (r.Read()) groups.Add((r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4)));
        }
        catch (SqliteException) { }
        if (groups.Count == 0) return (p, picks, "auto selection needs ATT&CK group descriptions: sync feeds (or run --refresh-groups); only pinned groups are tracked for now");

        var chosen = Score(p, groups, today ?? DateOnly.FromDateTime(DateTime.Today)).Where(x => x.Score >= p.Targeting.MinScore).Take(p.Targeting.MaxGroups).ToList();
        foreach (var id in p.Targeting.Include.Where(i => chosen.All(x => x.Id != i) && !p.ThreatGroups.ContainsKey(i)))
        {
            var g = groups.FirstOrDefault(x => x.Item1 == id);
            chosen.Add(new GroupPick(id, g.Item2 ?? id, "included", 0, new() { "added by targeting.include" }));
        }
        picks.AddRange(chosen);
        var dict = new Dictionary<string, string>(p.ThreatGroups); foreach (var c in chosen) dict[c.Id] = c.Name;
        return (p.WithThreatGroups(dict), picks, $"auto: {chosen.Count} group(s) chosen for {p.Organisation.Sector} / {p.Organisation.Country} from {groups.Count} ATT&CK groups");
    }

    public static void Store(SqliteConnection db, List<GroupPick> picks)
    {
        using var tx = db.BeginTransaction();
        using (var c = db.CreateCommand()) { c.CommandText = "DELETE FROM profile_group"; c.ExecuteNonQuery(); }
        foreach (var g in picks)
        {
            using var c = db.CreateCommand();
            c.CommandText = "INSERT INTO profile_group VALUES (@i,@n,@s,@r,@t)";
            c.Parameters.AddWithValue("@i", g.Id); c.Parameters.AddWithValue("@n", g.Name); c.Parameters.AddWithValue("@s", g.Score);
            c.Parameters.AddWithValue("@r", g.Source + ": " + string.Join("; ", g.Reasons)); c.Parameters.AddWithValue("@t", DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            c.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public static string Markdown(Profile p, List<GroupPick> picks, string note, DateOnly? today = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Tracked threat groups: {p.Organisation.Name}, {(today ?? DateOnly.FromDateTime(DateTime.Today)):yyyy-MM-dd}").AppendLine();
        sb.AppendLine("**TLP:AMBER**").AppendLine().AppendLine(note + ".").AppendLine();
        sb.AppendLine("Automatic selection is a keyword match between your sector and country and what MITRE ATT&CK says about each group, plus recent campaign activity. It is **Proposed**: it has not been shown that groups chosen this way predict what attacks an organisation like yours. Check the reasons, pin groups you know matter in `threat_groups`, and remove ones that do not with `targeting.exclude`.").AppendLine();
        sb.AppendLine("| Group | Name | How chosen | Score | Reasons |").AppendLine("|---|---|---|---|---|");
        foreach (var g in picks) sb.AppendLine($"| {g.Id} | {g.Name} | {g.Source} | {(g.Source == "auto" ? g.Score.ToString("0.#", CultureInfo.InvariantCulture) : "")} | {string.Join("; ", g.Reasons)} |");
        return sb.ToString();
    }
}
