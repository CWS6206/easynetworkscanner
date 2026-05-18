using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;

namespace LanScoutWin;

public partial class MainWindow : Window
{
    private readonly AppState _state = new();
    private readonly NetworkScanner _scanner = new();
    private readonly InternetTester _internetTester = new();
    private readonly LanPerformanceTester _lanPerformanceTester = new();
    private readonly WifiInspector _wifiInspector = new();
    private readonly NetworkToolbox _networkToolbox = new();
    private readonly LogManager _logManager = new();
    private readonly HtmlReportBuilder _reportBuilder = new();
    private CancellationTokenSource? _busyTokenSource;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _state;
        RefreshAdapters();
        RefreshLogs();
        _ = _logManager.WriteAsync("App gestartet.");
    }

    private void RefreshAdapters_Click(object sender, RoutedEventArgs e)
    {
        RefreshAdapters();
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        if (AdapterBox.SelectedItem is not NetworkAdapterInfo adapter)
        {
            SetStatus("Bitte zuerst einen Netzwerkadapter auswaehlen.");
            return;
        }

        var maxHosts = int.TryParse(MaxHostsBox.Text, out var parsed) ? parsed : 254;
        maxHosts = Math.Clamp(maxHosts, 1, 4096);
        await RunBusyAsync($"Scan auf {adapter.NetworkLabel} laeuft...", async token =>
        {
            _state.Devices.Clear();
            _state.ScanProgress = 0;
            var progress = new Progress<int>(value => _state.ScanProgress = value);
            var devices = await _scanner.ScanAsync(adapter, maxHosts, progress, token);
            foreach (var device in devices)
            {
                _state.Devices.Add(device);
            }

            await _logManager.WriteAsync($"Netzwerk-Scan abgeschlossen: {devices.Count} Geraete gefunden.");
            SetStatus($"Scan fertig: {devices.Count} Geraete gefunden.");
        });
    }

    private async void InternetTest_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Internet-Test laeuft...", async token =>
        {
            var result = await _internetTester.RunAsync(token);
            _state.InternetTests.Insert(0, result);
            await _logManager.WriteAsync($"Internet-Test: Ping {result.AveragePingMs:N1} ms, Down {result.DownloadMbps:N2} Mbit/s, Up {result.UploadMbps:N2} Mbit/s.");
            SetStatus("Internet-Test abgeschlossen.");
        });
    }

    private async void LanPerformance_Click(object sender, RoutedEventArgs e)
    {
        var sizeMb = int.TryParse(FileSizeBox.Text, out var parsed) ? parsed : 64;
        await RunBusyAsync("LAN-Performance-Test laeuft...", async token =>
        {
            var result = await _lanPerformanceTester.RunAsync(SharePathBox.Text.Trim(), sizeMb, token);
            _state.LanTests.Insert(0, result);
            await _logManager.WriteAsync($"LAN-Test: {result.TargetPath}, Schreiben {result.WriteMbps:N2}, Lesen {result.ReadMbps:N2} Mbit/s.");
            SetStatus("LAN-Performance-Test abgeschlossen.");
        });
    }

    private async void WifiRefresh_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("WLAN-Daten werden gelesen...", async _ =>
        {
            var items = await _wifiInspector.ReadAsync();
            _state.WifiItems.Clear();
            foreach (var item in items)
            {
                _state.WifiItems.Add(item);
            }

            await _logManager.WriteAsync($"WLAN aktualisiert: {items.Count} Eintraege.");
            SetStatus("WLAN-Daten aktualisiert.");
        });
    }

    private async void TraceRoute_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Traceroute laeuft...", async token =>
        {
            _state.TraceHops.Clear();
            var hops = await _networkToolbox.TraceRouteAsync(TraceTargetBox.Text, token);
            foreach (var hop in hops)
            {
                _state.TraceHops.Add(hop);
            }

            await _logManager.WriteAsync($"Traceroute ausgefuehrt: {TraceTargetBox.Text}, {hops.Count} Hops.");
            SetStatus($"Traceroute abgeschlossen: {hops.Count} Hops.");
        });
    }

    private async void NetworkConfig_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Gateway-, DHCP- und DNS-Infos werden gelesen...", async _ =>
        {
            _state.NetworkConfig.Clear();
            var items = _networkToolbox.GetNetworkConfig();
            foreach (var item in items)
            {
                _state.NetworkConfig.Add(item);
            }

            await _logManager.WriteAsync($"Netzwerk-Konfiguration gelesen: {items.Count} Adapter.");
            SetStatus("Gateway-, DHCP- und DNS-Infos aktualisiert.");
        });
    }

    private async void RoutingTable_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Routing-Tabelle wird gelesen...", async token =>
        {
            var filter = (RoutingFilterBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Alle";
            ToolOutputBox.Text = await _networkToolbox.GetRoutingTableAsync(filter, token);
            await _logManager.WriteAsync($"Routing-Tabelle gelesen: {filter}.");
            SetStatus("Routing-Tabelle aktualisiert.");
        });
    }

    private async void DnsCache_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("DNS-Cache wird gelesen...", async token =>
        {
            ToolOutputBox.Text = await _networkToolbox.GetDnsCacheAsync(token);
            await _logManager.WriteAsync("DNS-Cache angezeigt.");
            SetStatus("DNS-Cache geladen.");
        });
    }

    private async void DnsFlush_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("DNS-Cache wird geleert...", async token =>
        {
            await _networkToolbox.FlushDnsAsync(token);
            ToolOutputBox.Text = "DNS-Cache wurde geleert.";
            await _logManager.WriteAsync("DNS-Cache geleert.");
            SetStatus("DNS-Cache geleert.");
        });
    }

    private async void NetworkProfiles_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Netzwerkprofile werden gelesen...", async token =>
        {
            ToolOutputBox.Text = await _networkToolbox.GetNetworkProfilesAsync(token);
            await _logManager.WriteAsync("Netzwerkprofile und Firewall-Profil gelesen.");
            SetStatus("Netzwerkprofile aktualisiert.");
        });
    }

    private async void Connections_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Lokale Verbindungen werden gelesen...", async token =>
        {
            _state.Connections.Clear();
            var rows = await _networkToolbox.GetConnectionsAsync(token);
            foreach (var row in rows)
            {
                _state.Connections.Add(row);
            }

            await _logManager.WriteAsync($"Lokale Verbindungen gelesen: {rows.Count} Eintraege.");
            SetStatus("Lokale Verbindungen aktualisiert.");
        });
    }

    private async void AdvancedPortScan_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Erweiterter Portscan laeuft...", async token =>
        {
            _state.PortScanResults.Clear();
            _state.ScanProgress = 0;
            var progress = new Progress<int>(value => _state.ScanProgress = value);
            var rows = await _networkToolbox.ScanPortsAsync(PortHostBox.Text, PortListBox.Text, progress, token);
            foreach (var row in rows)
            {
                _state.PortScanResults.Add(row);
            }

            await _logManager.WriteAsync($"Erweiterter Portscan: {PortHostBox.Text}, {rows.Count} Ports.");
            SetStatus($"Portscan abgeschlossen: {rows.Count} Ports.");
        });
    }

    private async void ExportPorts_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Portscan als CSV speichern",
            Filter = "CSV-Datei (*.csv)|*.csv",
            FileName = $"Easy-Network-Scanner-Ports-{DateTime.Now:yyyyMMdd-HHmm}.csv",
            InitialDirectory = _logManager.ReportDirectory
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await RunBusyAsync("Portscan-CSV wird geschrieben...", async _ =>
        {
            await _networkToolbox.ExportPortsCsvAsync(dialog.FileName, _state.PortScanResults);
            await _logManager.WriteAsync($"Portscan-CSV exportiert: {dialog.FileName}");
            SetStatus($"CSV exportiert: {dialog.FileName}");
        });
    }

    private async void WifiExtended_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Erweiterte WLAN-Daten werden gelesen...", async _ =>
        {
            var sample = await _wifiInspector.ReadQualitySampleAsync();
            if (sample is not null)
            {
                _state.WifiHistory.Insert(0, sample);
            }

            _state.WifiChannels.Clear();
            foreach (var channel in await _wifiInspector.ReadChannelSummaryAsync())
            {
                _state.WifiChannels.Add(channel);
            }

            _state.WifiProfiles.Clear();
            foreach (var profile in await _wifiInspector.ReadProfilesAsync())
            {
                _state.WifiProfiles.Add(profile);
            }

            await _logManager.WriteAsync("Erweiterte WLAN-Daten aktualisiert.");
            SetStatus("Erweiterte WLAN-Daten aktualisiert.");
        });
    }

    private void LogsRefresh_Click(object sender, RoutedEventArgs e)
    {
        RefreshLogs();
    }

    private async void LogsArchive_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync("Logs werden archiviert...", async _ =>
        {
            var path = _logManager.Archive();
            await _logManager.WriteAsync($"Logs archiviert: {path}");
            RefreshLogs();
            SetStatus($"Archiv erstellt: {path}");
        });
    }

    private async void Report_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "HTML-Report speichern",
            Filter = "HTML-Datei (*.html)|*.html",
            FileName = $"Easy-Network-Scanner-Report-{DateTime.Now:yyyyMMdd-HHmm}.html",
            InitialDirectory = _logManager.ReportDirectory
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await RunBusyAsync("Report wird erstellt...", async _ =>
        {
            await _reportBuilder.WriteAsync(dialog.FileName, _state.Devices, _state.InternetTests, _state.WifiItems, _state.LanTests);
            await _logManager.WriteAsync($"HTML-Report erstellt: {dialog.FileName}");
            RefreshLogs();
            SetStatus($"Report erstellt: {dialog.FileName}");
        });
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _busyTokenSource?.Cancel();
        SetStatus("Abbruch angefordert...");
    }

    private void RefreshAdapters()
    {
        _state.Adapters.Clear();
        foreach (var adapter in _scanner.GetAdapters())
        {
            _state.Adapters.Add(adapter);
        }

        if (_state.Adapters.Count > 0)
        {
            AdapterBox.SelectedIndex = 0;
            SetStatus($"{_state.Adapters.Count} Adapter gefunden.");
        }
        else
        {
            SetStatus("Keine aktiven IPv4-Adapter gefunden.");
        }
    }

    private void RefreshLogs()
    {
        _state.LogFiles.Clear();
        foreach (var file in _logManager.List())
        {
            _state.LogFiles.Add(file);
        }
    }

    private async Task RunBusyAsync(string status, Func<CancellationToken, Task> action)
    {
        if (_state.IsBusy)
        {
            SetStatus("Es laeuft bereits ein Vorgang.");
            return;
        }

        _busyTokenSource = new CancellationTokenSource();
        _state.IsBusy = true;
        SetStatus(status);
        try
        {
            await action(_busyTokenSource.Token);
        }
        catch (OperationCanceledException)
        {
            await _logManager.WriteAsync("Vorgang abgebrochen.");
            SetStatus("Vorgang abgebrochen.");
        }
        catch (Exception ex)
        {
            await _logManager.WriteAsync($"Fehler: {ex.Message}");
            SetStatus($"Fehler: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Easy Network Scanner", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _state.IsBusy = false;
            _busyTokenSource.Dispose();
            _busyTokenSource = null;
            RefreshLogs();
        }
    }

    private void SetStatus(string message)
    {
        _state.Status = message;
    }
}
