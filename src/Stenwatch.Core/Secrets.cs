using System.Runtime.InteropServices;
using System.Text;

namespace Stenwatch.Core;

/// <summary>Secrets: Windows Credential Manager first (the same entries the Python version's keyring wrote), environment variable as fallback.</summary>
public static class Secrets
{
    const string Service = "stenwatch";

    public static string? Get(string name)
    {
        if (OperatingSystem.IsWindows())
            foreach (var target in new[] { $"{name}@{Service}", $"{Service}:{name}" })
                if (Read(target) is { Length: > 0 } v) return v;
        return Environment.GetEnvironmentVariable(name);
    }

    /// <summary>Store a secret in Windows Credential Manager (same target and UTF-16 blob that Get reads).</summary>
    public static void Set(string name, string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        var blob = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, blob, bytes.Length);
        try
        {
            var c = new CREDENTIAL { Type = 1, TargetName = $"{name}@{Service}", UserName = name, Blob = blob, BlobSize = bytes.Length, Persist = 2 };
            if (!CredWrite(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(blob); }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredWrite(ref CREDENTIAL cred, int flags);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredRead(string target, int type, int flags, out IntPtr cred);
    [DllImport("advapi32.dll")] static extern void CredFree(IntPtr cred);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDENTIAL
    {
        public int Flags, Type; public string TargetName, Comment; public long LastWritten;
        public int BlobSize; public IntPtr Blob; public int Persist, AttrCount; public IntPtr Attrs; public string TargetAlias, UserName;
    }

    static string? Read(string target)
    {
        if (!CredRead(target, 1, 0, out var p)) return null;
        try
        {
            var c = Marshal.PtrToStructure<CREDENTIAL>(p);
            var bytes = new byte[c.BlobSize]; Marshal.Copy(c.Blob, bytes, 0, c.BlobSize);
            return Encoding.Unicode.GetString(bytes); // keyring stores UTF-16
        }
        finally { CredFree(p); }
    }
}
