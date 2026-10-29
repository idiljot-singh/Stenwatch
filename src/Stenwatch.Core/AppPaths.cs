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
    public static string Data()
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
}
