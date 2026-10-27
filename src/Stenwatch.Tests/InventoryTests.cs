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

    [Fact]
    public void Inventory_ReadsSemicolonCsv_Xlsx_AndSbom_WithVendorPrefixedAndEditionNames()
    {
        using var db = new SqliteConnection("Data Source=:memory:"); db.Open();
        using (var c = db.CreateCommand())
        {
            c.CommandText = "CREATE TABLE cve (id TEXT, cpes TEXT); INSERT INTO cve VALUES " +
                "('a', '[{\"criteria\": \"cpe:2.3:o:microsoft:windows_11_23h2:-:*:*:*:*:*:*:*\"}, {\"criteria\": \"cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*\"}]')," +
                "('b', '[{\"criteria\": \"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*\"}, {\"criteria\": \"cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*\"}]')," +
                "('c', '[{\"criteria\": \"cpe:2.3:a:veeam:veeam_backup_\\\\&_replication:*:*:*:*:*:*:*:*\"}]')";
            c.ExecuteNonQuery();
        }
        var dir = Directory.CreateTempSubdirectory().FullName;

        // Intune-style export, semicolon-separated (Excel in many European locales), vendor in the product name, edition in the OS name
        var csv = Path.Combine(dir, "intune.csv");
        File.WriteAllText(csv, "Device name;Operating system;OS version;Application name;Publisher;Application version\n" +
            "PC-1;Windows 11 Pro 23H2;10.0.22631.4317;Microsoft SQL Server 2019;Microsoft Corporation;\n" +
            "PC-2;Windows 11 Enterprise 23H2;10.0.22631.4317;Apache Tomcat;;9.0.80\n" +
            "PC-3;;;Veeam Backup & Replication;Veeam;12.1.2\n");
        Assert.True(Inventory.IsInventory(csv));
        var r = Inventory.Convert(csv, db);
        Assert.Contains(r.Assets, a => a[1] == "cpe:2.3:o:microsoft:windows_11_23h2" && a[2] == "10.0.22631.4317" && a[0].Contains("2 hosts"));
        Assert.Contains(r.Assets, a => a[1] == "cpe:2.3:a:microsoft:sql_server" && a[2] == "2019");
        Assert.Contains(r.Assets, a => a[1] == "cpe:2.3:a:apache:tomcat" && a[2] == "9.0.80");
        Assert.Contains(r.Assets, a => a[1] == @"cpe:2.3:a:veeam:veeam_backup_\&_replication" && a[2] == "12.1.2");
        Assert.Empty(r.Unmatched);

        // CycloneDX SBOM of a web server: components by name, or by the CPE the SBOM already gives
        var sbom = Path.Combine(dir, "portal.json");
        File.WriteAllText(sbom, "{\"bomFormat\":\"CycloneDX\",\"metadata\":{\"component\":{\"name\":\"portal\"}},\"components\":[" +
            "{\"name\":\"php\",\"version\":\"8.1.12\"},{\"name\":\"tomcat\",\"group\":\"org.apache\",\"version\":\"9.0.80\",\"cpe\":\"cpe:2.3:a:apache:tomcat:9.0.80:*:*:*:*:*:*:*\"}]}");
        r = Inventory.Convert(sbom, db);
        Assert.Contains(r.Assets, a => a[1] == "cpe:2.3:a:php:php" && a[2] == "8.1.12");
        Assert.Contains(r.Assets, a => a[1] == "cpe:2.3:a:apache:tomcat" && a[2] == "9.0.80");

        // Excel .xlsx, first sheet, shared strings
        var xlsx = Path.Combine(dir, "assets.xlsx");
        using (var z = System.IO.Compression.ZipFile.Open(xlsx, System.IO.Compression.ZipArchiveMode.Create))
        {
            void Put(string name, string xml) { using var w = new StreamWriter(z.CreateEntry(name).Open()); w.Write(xml); }
            const string ns = "xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"";
            Put("xl/sharedStrings.xml", $"<sst {ns}><si><t>hostname</t></si><si><t>software</t></si><si><t>version</t></si><si><t>SRV-1</t></si><si><t>PHP</t></si></sst>");
            Put("xl/worksheets/sheet1.xml", $"<worksheet {ns}><sheetData><row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c><c r=\"B1\" t=\"s\"><v>1</v></c><c r=\"C1\" t=\"s\"><v>2</v></c></row>" +
                "<row r=\"2\"><c r=\"A2\" t=\"s\"><v>3</v></c><c r=\"B2\" t=\"s\"><v>4</v></c><c r=\"C2\" t=\"inlineStr\"><is><t>8.2.4</t></is></c></row></sheetData></worksheet>");
        }
        Assert.True(Inventory.IsInventory(xlsx));
        Assert.Equal(new[] { "PHP 8.2.4 (1 host)", "cpe:2.3:a:php:php", "8.2.4", "2", "n" }, Assert.Single(Inventory.Convert(xlsx, db).Assets));
        Directory.Delete(dir, true);
    }
}
