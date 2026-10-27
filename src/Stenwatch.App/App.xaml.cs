using System.Globalization;
using System.Windows;

namespace Stenwatch.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.CurrentCulture = CultureInfo.InvariantCulture; // reports read the same on every machine
        DispatcherUnhandledException += (_, a) => { MessageBox.Show(a.Exception.Message, "Stenwatch", MessageBoxButton.OK, MessageBoxImage.Warning); a.Handled = true; };
        base.OnStartup(e);
    }
}
