namespace Stenwatch.Core;

/// <summary>Where Stenwatch finds its bundled files and keeps the organisation's files.
/// From a checkout: examples/ holds the Example Organisation, data/ holds your own files (git-ignored).
/// Installed: the Example Organisation sits next to the program, and your files live in %APPDATA%\Stenwatch.</summary>
public static class AppPaths
{
    /// <summary>The repository root when running from a checkout (found by walking up to examples/profile.example.yaml), else null.</summary>
    public static string? Repo()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return d.FullName;
        return null;
    }

    /// <summary>Folder with the *.example.* files (profile, assets, services, links, controls, ...).</summary>
    public static string Examples() =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, "profile.example.yaml")) ? AppContext.BaseDirectory
        : Repo() is { } r ? Path.Combine(r, "examples") : AppContext.BaseDirectory;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern int GetCurrentPackageFamilyName(ref uint length, System.Text.StringBuilder? name);

    /// <summary>The Microsoft Store (MSIX) package family name when installed from the Store, else null (installer or checkout).</summary>
    public static string? PackageFamily()
    {
        if (!OperatingSystem.IsWindows()) return null;
        uint n = 0;
        if (GetCurrentPackageFamilyName(ref n, null) != 122) return null;   // 122 = buffer too small: we are packaged; 15700 = not packaged
        var sb = new System.Text.StringBuilder((int)n);
        return GetCurrentPackageFamilyName(ref n, sb) == 0 ? sb.ToString() : null;
    }

    /// <summary>Folder for the organisation's own files: STENWATCH_DATA if set, else data/ in a checkout, else %APPDATA%\Stenwatch.
    /// From the Store: the package's own LocalState folder, a real path (MSIX would otherwise redirect %APPDATA% where Explorer cannot see it).</summary>
    public static string DataRoot()
    {
        var env = Environment.GetEnvironmentVariable("STENWATCH_DATA");
        var dir = !string.IsNullOrEmpty(env) ? env
            : PackageFamily() is { } pfn ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages", pfn, "LocalState", "Stenwatch")
            : File.Exists(Path.Combine(AppContext.BaseDirectory, "profile.example.yaml")) || Repo() is null
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Stenwatch")
                : Path.Combine(Repo()!, "data");
        Directory.CreateDirectory(dir);
        return dir;
    }

    // ---- MSP mode: several organisations in one install ----------------------------------------------------------------------
    // The default organisation keeps the data root itself (nothing moves for a single-organisation install);
    // every other one gets DataRoot()/orgs/<name>. The open one is named in DataRoot()/org.txt, or STENWATCH_ORG.

    /// <summary>The open organisation's folder.</summary>
    public static string Data()
    {
        var dir = Org() is { Length: > 0 } o ? Path.Combine(DataRoot(), "orgs", o) : DataRoot();
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>The open organisation: STENWATCH_ORG, else org.txt; "" = the default one. An invalid name falls back to the default.</summary>
    public static string Org()
    {
        var f = Path.Combine(DataRoot(), "org.txt");
        var o = Environment.GetEnvironmentVariable("STENWATCH_ORG") ?? (File.Exists(f) ? File.ReadAllText(f).Trim() : "");
        return ValidOrg(o) ? o : "";
    }

    /// <summary>The other organisations, by folder name.</summary>
    public static List<string> Orgs()
    {
        var d = Path.Combine(DataRoot(), "orgs");
        return Directory.Exists(d) ? Directory.GetDirectories(d).Select(Path.GetFileName).Where(n => ValidOrg(n!)).Order().ToList()! : new();
    }

    /// <summary>A name that is safe as one folder name: letters, digits, space, dot, dash, underscore; no path parts, no trailing dot or space.</summary>
    public static bool ValidOrg(string s) =>
        System.Text.RegularExpressions.Regex.IsMatch(s, @"^\w[\w .-]{0,62}$") && !s.EndsWith('.') && !s.EndsWith(' ');

    /// <summary>Open another organisation ("" = the default). Its folder is created on first use.</summary>
    public static void SetOrg(string o)
    {
        if (o != "" && !ValidOrg(o)) throw new ArgumentException($"Not a valid organisation name: {o}");
        File.WriteAllText(Path.Combine(DataRoot(), "org.txt"), o);
    }
}
