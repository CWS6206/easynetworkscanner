using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace LanScoutWin;

public sealed class NetworkAdapterInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Address { get; init; } = "";
    public int PrefixLength { get; init; }
    public string Gateway { get; init; } = "";
    public string NetworkLabel => $"{Address}/{PrefixLength}";
    public override string ToString() => $"{Name} - {NetworkLabel}";
}

public sealed class DeviceResult
{
    public string IpAddress { get; init; } = "";
    public string HostName { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string OperatingSystemHint { get; init; } = "";
    public string OpenPorts { get; init; } = "";
    public long PingMs { get; init; }
    public string Status { get; init; } = "";
}

public sealed class InternetTestResult
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public double AveragePingMs { get; init; }
    public double JitterMs { get; init; }
    public double DownloadMbps { get; init; }
    public double UploadMbps { get; init; }
    public string Protocol { get; init; } = "";
    public string Notes { get; init; } = "";
}

public sealed class WifiInfo
{
    public string Scope { get; init; } = "";
    public string Ssid { get; init; } = "";
    public string Signal { get; init; } = "";
    public string Channel { get; init; } = "";
    public string Band { get; init; } = "";
    public string ReceiveRate { get; init; } = "";
    public string TransmitRate { get; init; } = "";
    public string Authentication { get; init; } = "";
}

public sealed class LanPerformanceResult
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public string TargetPath { get; init; } = "";
    public int FileSizeMb { get; init; }
    public double WriteMbps { get; init; }
    public double ReadMbps { get; init; }
    public string Notes { get; init; } = "";
}

public sealed class LogFileInfo
{
    public string Name { get; init; } = "";
    public string FullPath { get; init; } = "";
    public DateTime LastWriteTime { get; init; }
    public long SizeBytes { get; init; }
}

public sealed class TraceHop
{
    public int Hop { get; init; }
    public string Latency1 { get; init; } = "";
    public string Latency2 { get; init; } = "";
    public string Latency3 { get; init; } = "";
    public string Target { get; init; } = "";
    public string Status { get; init; } = "";
}

public sealed class NetworkConfigItem
{
    public string Adapter { get; init; } = "";
    public string IPv4 { get; init; } = "";
    public string Gateway { get; init; } = "";
    public string DhcpServer { get; init; } = "";
    public string DnsServers { get; init; } = "";
    public string Lease { get; init; } = "";
}

public sealed class PortScanResult
{
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string Service { get; init; } = "";
    public string State { get; init; } = "";
    public long DurationMs { get; init; }
}

public sealed class ConnectionInfo
{
    public string Protocol { get; init; } = "";
    public string LocalAddress { get; init; } = "";
    public string LocalPort { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public string RemotePort { get; init; } = "";
    public string State { get; init; } = "";
    public string ProcessId { get; init; } = "";
    public string ProcessName { get; init; } = "";
}

public sealed class WifiQualitySample
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public string Ssid { get; init; } = "";
    public string Signal { get; init; } = "";
    public string Channel { get; init; } = "";
    public string Band { get; init; } = "";
    public string ReceiveRate { get; init; } = "";
    public string TransmitRate { get; init; } = "";
}

public sealed class WifiChannelSummary
{
    public string Channel { get; init; } = "";
    public string Band { get; init; } = "";
    public int NetworkCount { get; init; }
    public string StrongestSignal { get; init; } = "";
    public string Ssids { get; init; } = "";
}

public sealed class WifiProfileInfo
{
    public string Name { get; init; } = "";
    public string Authentication { get; init; } = "";
    public string Encryption { get; init; } = "";
    public string AutoConnect { get; init; } = "";
}

public sealed class AppState : INotifyPropertyChanged
{
    private string _status = "Bereit";
    private int _scanProgress;
    private bool _isBusy;

    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = [];
    public ObservableCollection<DeviceResult> Devices { get; } = [];
    public ObservableCollection<InternetTestResult> InternetTests { get; } = [];
    public ObservableCollection<WifiInfo> WifiItems { get; } = [];
    public ObservableCollection<LanPerformanceResult> LanTests { get; } = [];
    public ObservableCollection<LogFileInfo> LogFiles { get; } = [];
    public ObservableCollection<TraceHop> TraceHops { get; } = [];
    public ObservableCollection<NetworkConfigItem> NetworkConfig { get; } = [];
    public ObservableCollection<PortScanResult> PortScanResults { get; } = [];
    public ObservableCollection<ConnectionInfo> Connections { get; } = [];
    public ObservableCollection<WifiQualitySample> WifiHistory { get; } = [];
    public ObservableCollection<WifiChannelSummary> WifiChannels { get; } = [];
    public ObservableCollection<WifiProfileInfo> WifiProfiles { get; } = [];

    public string Status
    {
        get => _status;
        set => SetField(ref _status, value);
    }

    public int ScanProgress
    {
        get => _scanProgress;
        set => SetField(ref _scanProgress, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetField(ref _isBusy, value);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
