using Microsoft.Data.Sqlite;
using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>An inventory export (one row per host, no CPE) becomes Stenwatch assets by looking names up among NVD's own products.</summary>
public class InventoryTests
{
    [Fact]
    public void Inventory_MatchesOsAndProductAgainstNvdNames_GroupsHosts_ListsUnmatched()
    {
        using var db = new SqliteConnection("Data Source=:memory:"); db.Open();
        using (var c = db.CreateCommand())
        {
            c.CommandText = "CREATE TABLE cve (id TEXT, cpes TEXT); INSERT INTO cve VALUES " +
                "('a', '[{\"criteria\": \"cpe:2.3:o:microsoft:windows_11_23h2:-:*:*:*:*:*:*:*\"}]')," +
                "('b', '[{\"criteria\": \"cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*\"}, {\"criteria\": \"cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*\"}]')," +
                "('c', '[{\"criteria\": \"cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*\"}, {\"criteria\": \"cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*\"}]')," +
                "('d', '[{\"criteria\": \"cpe:2.3:o:arubanetworks:arubaos:*:*:*:*:*:*:*:*\"}]')";
            c.ExecuteNonQuery();
        }
        var csv = Path.GetTempFileName();
        File.WriteAllText(csv, "asset_id,hostname,type,vendor,product,version,os,exposure,criticality\n" +
            "1,WS-1,workstation,Dell,Precision 5860,BIOS 2.3,Windows 11 23H2,internal,4\n" +
            "2,WS-2,workstation,Dell,Precision 5860,BIOS 2.3,Windows 11 23H2,internal,2\n" +
            "3,PH-1,mobile,Apple,iPhone 15,n/a,iOS 18.0,internal,3\n" +
            "4,MFT,server,Progress,MOVEit Transfer,2023.0,Windows Server 2022,internet,4\n" +
            "5,AP-1,access point,Aruba,AP-515,8.10,ArubaOS,internal,2\n" +
            "6,PR-1,printer,Canon,imageRUNNER C5560,3.x,firmware,internal,1\n");
        Assert.True(Inventory.IsInventory(csv));

        var r = Inventory.Convert(csv, db);
        string[] Row(string cpe) => r.Assets.Single(a => a[1] == cpe);

        Assert.Equal(6, r.Hosts);
        Assert.Equal(new[] { "Windows 11 23H2 (2 hosts)", "cpe:2.3:o:microsoft:windows_11_23h2", "", "3", "n" }, Row("cpe:2.3:o:microsoft:windows_11_23h2")); // BIOS is not the OS version; criticality capped at 3
        Assert.Equal("18.0", Row("cpe:2.3:o:apple:iphone_os")[2]);   // iOS is iphone_os in NVD, never Cisco IOS
        Assert.Equal("2023.0", Row("cpe:2.3:a:progress:moveit_transfer")[2]);
        Assert.Equal("", Row("cpe:2.3:o:microsoft:windows_server_2022")[2]); // the version cell belongs to MOVEit, not the OS
        Assert.Equal("y", Row("cpe:2.3:a:progress:moveit_transfer")[4]);
        Assert.Equal("8.10", Row("cpe:2.3:o:arubanetworks:arubaos")[2]);    // no product match: the version cell is the OS's
        Assert.Equal(("Canon imageRUNNER C5560 firmware", 1), Assert.Single(r.Unmatched));

        // with an OS build column the build becomes the version, so NVD's ranges can rule out patched CVEs
        File.WriteAllText(csv, "hostname,vendor,product,os,os_build\nWS-1,Dell,Precision 5860,Windows 11 23H2,10.0.22631.4317\n");
        Assert.Equal("10.0.22631.4317", Inventory.Convert(csv, db).Assets.Single()[2]);
        File.Delete(csv);
    }
}
