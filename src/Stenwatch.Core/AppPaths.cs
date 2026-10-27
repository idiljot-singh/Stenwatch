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

    /// <summary>Folder for the organisation's own files: STENWATCH_DATA if set, else data/ in a checkout, else %APPDATA%\Stenwatch.</summary>
    public static string Data()
    {
        var env = Environment.GetEnvironmentVariable("STENWATCH_DATA");
        var dir = !string.IsNullOrEmpty(env) ? env
            : File.Exists(Path.Combine(AppContext.BaseDirectory, "profile.example.yaml")) || Repo() is null
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Stenwatch")
                : Path.Combine(Repo()!, "data");
        Directory.CreateDirectory(dir);
        return dir;
    }
}
