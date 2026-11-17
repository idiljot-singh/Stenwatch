using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace Stenwatch.App;

/// <summary>Dark or light colour tokens (Themes/*.xaml). "windows" follows the Windows app setting at start; the toolbar button cycles
/// windows, dark, light and the choice is kept in theme.txt in the data folder. Brushes are DynamicResource references, so a swap repaints everything.</summary>
public static class Theme
{
    public static readonly string[] Modes = { "windows", "dark", "light" };
    static string File_ => Path.Combine(Core.AppPaths.DataRoot(), "theme.txt"); // one theme for the install, not per organisation

    public static string Mode { get; private set; } = "windows";
    /// <summary>The theme in use: "dark" or "light".</summary>
    public static string Current => Mode != "windows" ? Mode : WindowsIsLight() ? "light" : "dark";

    /// <summary>HKCU\...\Themes\Personalize AppsUseLightTheme: 1 = light apps, 0 = dark; missing (older Windows) = dark, as the app always was.</summary>
    static bool WindowsIsLight() =>
        Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 0) is int v && v == 1;

    /// <summary>At start: the saved choice, else follow Windows.</summary>
    public static void Load()
    {
        try { if (File.Exists(File_) && File.ReadAllText(File_).Trim() is var m && Modes.Contains(m)) Mode = m; } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        Apply();
    }

    /// <summary>Toolbar: windows, dark, light, windows ... Saved at once.</summary>
    public static void Next()
    {
        Mode = Modes[(Array.IndexOf(Modes, Mode) + 1) % Modes.Length];
        try { File.WriteAllText(File_, Mode); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { } // not saved: the choice still holds for this session
        Apply();
    }

    static void Apply() =>
        Application.Current.Resources.MergedDictionaries[0] = new ResourceDictionary { Source = new Uri($"pack://application:,,,/Themes/{(Current == "light" ? "Light" : "Dark")}.xaml") };

    /// <summary>Set a brush by token name so it follows a theme swap (a brush fetched with FindResource would keep the old colour). Returns the element, for use in initialisers.</summary>
    public static T Res<T>(this T e, DependencyProperty p, string token) where T : FrameworkElement { e.SetResourceReference(p, token); return e; }

    /// <summary>Tooltip and spoken name of the toolbar button: what is on now and what a click does.</summary>
    public static string Label => (Mode == "windows" ? $"Theme: follow Windows ({Current})" : $"Theme: {Mode}") + ". Click for " + (Modes[(Array.IndexOf(Modes, Mode) + 1) % Modes.Length] is var n && n == "windows" ? "follow Windows" : n);
}
