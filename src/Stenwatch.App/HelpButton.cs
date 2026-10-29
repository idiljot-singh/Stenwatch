using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace Stenwatch.App;

/// <summary>A small round "?" that keeps explanations off the page: hover shows the text, click (or Enter/Space) opens it in a popup, Esc closes.
/// Warn = true colours it amber, for "something here needs a look" (a feed or the LLM failed).</summary>
public class HelpButton : ToggleButton
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(HelpButton), new(""));
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(nameof(Title), typeof(string), typeof(HelpButton), new(""));
    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    bool warn;
    public bool Warn { get => warn; set { warn = value; BorderBrush = Foreground = (Brush)FindResource(value ? "Attend" : "Accent"); } }

    readonly Popup popup;
    readonly TextBlock title = new() { FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) }, body = new() { TextWrapping = TextWrapping.Wrap };

    public HelpButton()
    {
        Content = "?"; Focusable = true; Cursor = Cursors.Hand; VerticalAlignment = VerticalAlignment.Center; Margin = new Thickness(6, 0, 6, 0);
        SetResourceReference(StyleProperty, "Help");
        var panel = new StackPanel(); panel.Children.Add(title); panel.Children.Add(body);
        popup = new Popup
        {
            PlacementTarget = this, Placement = PlacementMode.Bottom, StaysOpen = false, AllowsTransparency = true,
            Child = new Border { Child = panel, MaxWidth = 380, Padding = new Thickness(12, 10, 12, 10), CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1),
                Background = (Brush)FindResource("Card"), BorderBrush = (Brush)FindResource("Line") }
        };
        TextElement.SetForeground(popup.Child, (Brush)FindResource("Fg"));
        // a click on the "?" while the popup is open would close and reopen it; ignore clicks until it has closed
        popup.Opened += (_, _) => IsHitTestVisible = false;
        popup.Closed += (_, _) => { IsHitTestVisible = true; IsChecked = false; };
        Checked += (_, _) => { title.Text = Title; title.Visibility = Title == "" ? Visibility.Collapsed : Visibility.Visible; body.Text = Text; popup.IsOpen = true; };
        Unchecked += (_, _) => popup.IsOpen = false;
        PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape) IsChecked = false; };
        Loaded += (_, _) => { ToolTip = Text; AutomationProperties.SetName(this, "Help: " + (Title != "" ? Title : "more information")); };
    }

    protected override void OnPropertyChanged(DependencyPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.Property == TextProperty && IsLoaded) ToolTip = Text;
    }
}
