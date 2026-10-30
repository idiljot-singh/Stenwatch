using System.Net;

namespace Stenwatch.Core;

/// <summary>Turns a failure into one plain line that says what to do next, and keeps the full detail (stack trace) in out/errors.log in the data folder.</summary>
public static class Errors
{
    public static string Explain(Exception e)
    {
        try { var dir = Path.Combine(AppPaths.Data(), "out"); Directory.CreateDirectory(dir); File.AppendAllText(Path.Combine(dir, "errors.log"), $"{DateTime.Now:s}  {e}\n\n"); }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException) { }
        var hint = e switch
        {
            KeyNotFoundException or System.Text.Json.JsonException or InvalidDataException => "A feed sent data in an unexpected shape. Everything saved so far is kept; run it again",
            HttpRequestException { StatusCode: HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests } => "The feed is rate-limiting. Add NVD_API_KEY on the Settings page, or wait a few minutes",
            HttpRequestException or TaskCanceledException => "Network error or timeout. Check the connection (or a firewall/proxy) and run it again",
            Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 5 or 6 } => "cve.db is in use. Close the other Stenwatch window and run it again",
            UnauthorizedAccessException or IOException => "A file could not be read or written. Check it is not open in another program",
            _ => ""
        };
        return (hint == "" ? e.Message : $"{hint}. ({e.Message})") + "  Details: out/errors.log";
    }
}
