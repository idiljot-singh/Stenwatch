using System.Globalization;
using System.Text;

namespace Stenwatch.Core;

/// <summary>Minimal RFC 4180 reader/writer, matching Python's csv module defaults.</summary>
public static class Csv
{
    public static List<Dictionary<string, string>> ReadDict(string path)
    {
        var rows = Parse(File.ReadAllText(path, Encoding.UTF8));
        if (rows.Count == 0) return new();
        var head = rows[0];
        return rows.Skip(1).Where(r => r.Count > 0)
            .Select(r => head.Select((h, i) => (h, v: i < r.Count ? r[i] : "")).ToDictionary(x => x.h, x => x.v)).ToList();
    }

    public static List<List<string>> Parse(string text, char sep = ',')
    {
        var rows = new List<List<string>>(); var row = new List<string>(); var cell = new StringBuilder();
        bool quoted = false, any = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quoted)
            {
                if (c == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { cell.Append('"'); i++; } else quoted = false; }
                else cell.Append(c);
            }
            else if (c == '"') { quoted = true; any = true; }
            else if (c == sep) { row.Add(cell.ToString()); cell.Clear(); any = true; }
            else if (c == '\r' || c == '\n')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                if (any || cell.Length > 0) { row.Add(cell.ToString()); rows.Add(row); }
                row = new(); cell.Clear(); any = false;
            }
            else { cell.Append(c); any = true; }
        }
        if (any || cell.Length > 0) { row.Add(cell.ToString()); rows.Add(row); }
        return rows;
    }

    public static void Write(string path, IEnumerable<IEnumerable<string>> rows)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(false)) { NewLine = "\r\n" };
        foreach (var r in rows) w.WriteLine(string.Join(",", r.Select(Quote)));
    }

    static string Quote(string s) => s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
}

/// <summary>Number and text formats that match Python's, so output can be compared to the original pipeline.</summary>
public static class Py
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>Python repr(float): 8.8, 9.0, 1e-05.</summary>
    public static string Repr(double d)
    {
        var s = d.ToString("R", Inv);
        if (s.Contains('E')) { var (m, e) = (s[..s.IndexOf('E')], int.Parse(s[(s.IndexOf('E') + 1)..], Inv)); return $"{m}e{(e < 0 ? '-' : '+')}{Math.Abs(e):00}"; }
        return s.Contains('.') ? s : s + ".0";
    }

    public static string Repr(double? d) => d is null ? "None" : Repr(d.Value);
    public static string F(double d, int n) => d.ToString("F" + n, Inv);
    public static string Pct(double d, int n) => (d * 100).ToString("F" + n, Inv) + "%";
    /// <summary>Python round(x, 3).</summary>
    public static double Round3(double d) => double.Parse(d.ToString("F3", Inv), Inv);
    public static string G(double d) => d.ToString("G6", Inv);
    public static string Bool(bool b) => b ? "True" : "False";
}
