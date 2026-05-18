using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace LanScoutWin;

public sealed class NetworkScanner
{
    private static readonly int[] DefaultPorts = [21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 3389, 5357, 5900, 8000, 8080, 8443];
    private static readonly Dictionary<string, string> VendorPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["00-1A-11"] = "Google",
        ["00-1B-63"] = "Apple",
        ["00-1C-B3"] = "Apple",
        ["00-24-D7"] = "Intel",
        ["00-50-56"] = "VMware",
        ["00-05-69"] = "VMware",
        ["00-0C-29"] = "VMware",
        ["08-00-27"] = "VirtualBox",
        ["18-E8-29"] = "Ubiquiti",
        ["24-A4-3C"] = "Ubiquiti",
        ["3C-5A-B4"] = "Google",
        ["44-65-0D"] = "Amazon",
        ["48-5D-60"] = "AzureWave",
        ["5C-C9-D3"] = "Pace/Arris",
        ["70-85-C2"] = "ASRock",
        ["74-83-C2"] = "Ubiquiti",
        ["B8-27-EB"] = "Raspberry Pi",
        ["BC-92-6B"] = "Apple",
        ["C8-2A-14"] = "Apple",
        ["D8-3A-DD"] = "Raspberry Pi",
        ["FC-EC-DA"] = "Ubiquiti"
    };

    public IReadOnlyList<NetworkAdapterInfo> GetAdapters()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address))
                .Select(u => new NetworkAdapterInfo
                {
                    Name = n.Name,
                    Description = n.Description,
                    Address = u.Address.ToString(),
                    PrefixLength = u.PrefixLength,
                    Gateway = n.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() ?? ""
                }))
            .OrderBy(a => a.Name)
            .ToList();
    }

    public async Task<IReadOnlyList<DeviceResult>> ScanAsync(NetworkAdapterInfo adapter, int maxHosts, IProgress<int> progress, CancellationToken cancellationToken)
    {
        var targets = BuildTargets(adapter, maxHosts).ToList();
        var completed = 0;
        var found = new List<DeviceResult>();
        var arpBefore = await ReadArpTableAsync();
        using var gate = new SemaphoreSlim(64);
        var tasks = targets.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                var result = await ProbeAsync(ip, cancellationToken);
                if (result is not null)
                {
                    lock (found)
                    {
                        found.Add(result);
                    }
                }
            }
            finally
            {
                gate.Release();
                var value = Interlocked.Increment(ref completed) * 100 / Math.Max(1, targets.Count);
                progress.Report(value);
            }
        });

        await Task.WhenAll(tasks);
        var arpAfter = await ReadArpTableAsync();
        var arp = arpBefore.Concat(arpAfter).GroupBy(x => x.Key).ToDictionary(x => x.Key, x => x.Last().Value);

        return found
            .Select(d =>
            {
                arp.TryGetValue(d.IpAddress, out var mac);
                return WithMac(d, mac);
            })
            .OrderBy(d => IPAddress.Parse(d.IpAddress).GetAddressBytes(), ByteArrayComparer.Instance)
            .ToList();
    }

    private static async Task<DeviceResult?> ProbeAsync(IPAddress ip, CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        PingReply reply;
        try
        {
            reply = await ping.SendPingAsync(ip, TimeSpan.FromMilliseconds(850), cancellationToken: cancellationToken);
        }
        catch
        {
            return null;
        }

        if (reply.Status != IPStatus.Success)
        {
            return null;
        }

        var hostName = "";
        try
        {
            hostName = (await Dns.GetHostEntryAsync(ip)).HostName;
        }
        catch
        {
            hostName = "";
        }

        var openPorts = await ScanPortsAsync(ip, DefaultPorts, cancellationToken);
        return new DeviceResult
        {
            IpAddress = ip.ToString(),
            HostName = hostName,
            PingMs = reply.RoundtripTime,
            OperatingSystemHint = GuessOs(reply.Options?.Ttl),
            OpenPorts = openPorts.Count == 0 ? "" : string.Join(", ", openPorts),
            Status = "Online"
        };
    }

    private static async Task<List<int>> ScanPortsAsync(IPAddress ip, IEnumerable<int> ports, CancellationToken cancellationToken)
    {
        var open = new List<int>();
        foreach (var port in ports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(ip, port, cancellationToken).AsTask();
                var completed = await Task.WhenAny(connectTask, Task.Delay(350, cancellationToken));
                if (completed == connectTask && client.Connected)
                {
                    open.Add(port);
                }
            }
            catch
            {
                // Closed or filtered ports are expected during a scan.
            }
        }

        return open;
    }

    private static IEnumerable<IPAddress> BuildTargets(NetworkAdapterInfo adapter, int maxHosts)
    {
        var address = ToUInt32(IPAddress.Parse(adapter.Address));
        var prefix = Math.Clamp(adapter.PrefixLength, 8, 30);
        var mask = uint.MaxValue << (32 - prefix);
        var network = address & mask;
        var broadcast = network | ~mask;
        var limit = Math.Min(maxHosts, Math.Max(0, (int)Math.Min(int.MaxValue, broadcast - network - 1)));
        for (uint value = network + 1; value < broadcast && limit > 0; value++, limit--)
        {
            yield return FromUInt32(value);
        }
    }

    private static async Task<Dictionary<string, string>> ReadArpTableAsync()
    {
        var output = await ProcessRunner.RunAsync("arp", "-a");
        var table = new Dictionary<string, string>();
        foreach (Match match in Regex.Matches(output, @"(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})"))
        {
            table[match.Groups["ip"].Value] = match.Groups["mac"].Value.Replace(':', '-').ToUpperInvariant();
        }

        return table;
    }

    private static string GuessVendor(string mac)
    {
        if (mac.Length < 8)
        {
            return "";
        }

        return VendorPrefixes.TryGetValue(mac[..8], out var vendor) ? vendor : "";
    }

    private static string GuessOs(int? ttl)
    {
        if (ttl is null)
        {
            return "";
        }

        return ttl switch
        {
            <= 64 => "Linux/Unix/Embedded",
            <= 128 => "Windows",
            _ => "Netzwerkgerät"
        };
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static IPAddress FromUInt32(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return new IPAddress(bytes);
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public int Compare(byte[]? x, byte[]? y)
        {
            if (x is null || y is null)
            {
                return x is null ? -1 : 1;
            }

            for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
            {
                var c = x[i].CompareTo(y[i]);
                if (c != 0)
                {
                    return c;
                }
            }

            return x.Length.CompareTo(y.Length);
        }
    }

    private static DeviceResult WithMac(DeviceResult result, string? mac)
    {
        mac ??= "";
        return new DeviceResult
        {
            IpAddress = result.IpAddress,
            HostName = result.HostName,
            MacAddress = mac,
            Vendor = GuessVendor(mac),
            OperatingSystemHint = result.OperatingSystemHint,
            OpenPorts = result.OpenPorts,
            PingMs = result.PingMs,
            Status = result.Status
        };
    }
}

public sealed class InternetTester
{
    private static readonly HttpClient Http = CreateHttpClient();

    public async Task<InternetTestResult> RunAsync(CancellationToken cancellationToken)
    {
        var pingSamples = await MeasurePingAsync(cancellationToken);
        var notes = new List<string>();
        var (download, downloadNote) = await MeasureDownloadAsync(cancellationToken);
        var (upload, uploadNote) = await MeasureUploadAsync(cancellationToken);
        AddNote(notes, downloadNote);
        AddNote(notes, uploadNote);

        return new InternetTestResult
        {
            AveragePingMs = pingSamples.Count == 0 ? 0 : pingSamples.Average(),
            JitterMs = pingSamples.Count < 2 ? 0 : pingSamples.Max() - pingSamples.Min(),
            DownloadMbps = download,
            UploadMbps = upload,
            Protocol = "HTTPS + ICMP",
            Notes = notes.Count == 0
                ? "Messung abgeschlossen. Ergebnisse koennen je nach Firewall, WLAN und Testendpunkt schwanken."
                : string.Join(" ", notes)
        };
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("EasyNetworkScanner/1.1");
        client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
        return client;
    }

    private static async Task<List<double>> MeasurePingAsync(CancellationToken cancellationToken)
    {
        var samples = new List<double>();
        using var ping = new Ping();
        foreach (var host in new[] { "1.1.1.1", "8.8.8.8", "example.com" })
        {
            try
            {
                var reply = await ping.SendPingAsync(host, TimeSpan.FromSeconds(2), cancellationToken: cancellationToken);
                if (reply.Status == IPStatus.Success)
                {
                    samples.Add(reply.RoundtripTime);
                }
            }
            catch
            {
                // Some networks block ICMP; the HTTP tests can still run.
            }
        }

        return samples;
    }

    private static async Task<(double Mbps, string Note)> MeasureDownloadAsync(CancellationToken cancellationToken)
    {
        var endpoints = new[]
        {
            "https://speed.cloudflare.com/__down?bytes=8000000",
            "https://proof.ovh.net/files/10Mb.dat",
            "https://ash-speed.hetzner.com/10MB.bin"
        };

        var errors = new List<string>();
        foreach (var endpoint in endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                response.EnsureSuccessStatusCode();
                var sw = Stopwatch.StartNew();
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                var bytes = await ReadMeasuredBytesAsync(stream, 12 * 1024 * 1024, cancellationToken);
                sw.Stop();
                if (bytes > 0)
                {
                    return (ToMbps(bytes, sw.Elapsed), "");
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add($"{HostName(endpoint)}: {ShortError(ex)}");
            }
        }

        return (0, $"Download konnte nicht gemessen werden ({string.Join("; ", errors)}).");
    }

    private static async Task<(double Mbps, string Note)> MeasureUploadAsync(CancellationToken cancellationToken)
    {
        var endpoints = new[]
        {
            "https://speed.cloudflare.com/__up",
            "https://postman-echo.com/post",
            "https://httpbin.org/post"
        };

        var bytes = new byte[1024 * 1024];
        Random.Shared.NextBytes(bytes);
        var errors = new List<string>();
        foreach (var endpoint in endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var content = new ByteArrayContent(bytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                var sw = Stopwatch.StartNew();
                using var response = await Http.PostAsync(endpoint, content, cancellationToken);
                sw.Stop();
                response.EnsureSuccessStatusCode();
                return (ToMbps(bytes.Length, sw.Elapsed), "");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add($"{HostName(endpoint)}: {ShortError(ex)}");
            }
        }

        return (0, $"Upload konnte nicht gemessen werden ({string.Join("; ", errors)}).");
    }

    private static async Task<long> ReadMeasuredBytesAsync(Stream stream, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (total < maxBytes)
        {
            var bytesToRead = (int)Math.Min(buffer.Length, maxBytes - total);
            var read = await stream.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static void AddNote(List<string> notes, string note)
    {
        if (!string.IsNullOrWhiteSpace(note))
        {
            notes.Add(note);
        }
    }

    private static string HostName(string url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
    }

    private static string ShortError(Exception ex)
    {
        return ex is HttpRequestException http && http.StatusCode is not null
            ? $"{(int)http.StatusCode} {http.StatusCode}"
            : ex.Message;
    }

    private static double ToMbps(long bytes, TimeSpan elapsed)
    {
        return elapsed.TotalSeconds <= 0 ? 0 : Math.Round(bytes * 8d / elapsed.TotalSeconds / 1_000_000d, 2);
    }
}

public sealed class LanPerformanceTester
{
    public async Task<LanPerformanceResult> RunAsync(string targetFolder, int sizeMb, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(targetFolder) || !Directory.Exists(targetFolder))
        {
            throw new DirectoryNotFoundException("Der Zielordner wurde nicht gefunden.");
        }

        sizeMb = Math.Clamp(sizeMb, 1, 2048);
        var path = Path.Combine(targetFolder, $"easy-network-scanner-test-{Guid.NewGuid():N}.bin");
        var buffer = new byte[1024 * 1024];
        Random.Shared.NextBytes(buffer);
        var writeSw = Stopwatch.StartNew();
        try
        {
            await using (var writer = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, buffer.Length, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                for (var i = 0; i < sizeMb; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await writer.WriteAsync(buffer, cancellationToken);
                }
            }

            writeSw.Stop();
            var readBuffer = new byte[buffer.Length];
            var readSw = Stopwatch.StartNew();
            await using (var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, readBuffer.Length, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                while (await reader.ReadAsync(readBuffer, cancellationToken) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }

            readSw.Stop();
            return new LanPerformanceResult
            {
                TargetPath = targetFolder,
                FileSizeMb = sizeMb,
                WriteMbps = Math.Round(sizeMb * 8d / writeSw.Elapsed.TotalSeconds, 2),
                ReadMbps = Math.Round(sizeMb * 8d / readSw.Elapsed.TotalSeconds, 2),
                Notes = "Temporaere Testdatei wurde geschrieben, gelesen und entfernt."
            };
        }
        finally
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // Cleanup best effort.
            }
        }
    }
}

public sealed class WifiInspector
{
    public async Task<IReadOnlyList<WifiInfo>> ReadAsync()
    {
        var items = new List<WifiInfo>();
        var interfaces = await ProcessRunner.RunAsync("netsh", "wlan show interfaces");
        var current = ParseKeyValue(interfaces);
        if (current.Count > 0)
        {
            items.Add(new WifiInfo
            {
                Scope = "Verbunden",
                Ssid = FirstValue(current, "SSID"),
                Signal = FirstValue(current, "Signal"),
                Channel = FirstValue(current, "Channel", "Kanal"),
                Band = FirstValue(current, "Band", "Radio type", "Funktyp"),
                ReceiveRate = FirstValue(current, "Receive rate (Mbps)", "Empfangsrate (MBit/s)"),
                TransmitRate = FirstValue(current, "Transmit rate (Mbps)", "Uebertragungsrate (MBit/s)"),
                Authentication = FirstValue(current, "Authentication", "Authentifizierung")
            });
        }

        var networks = await ProcessRunner.RunAsync("netsh", "wlan show networks mode=bssid");
        foreach (var block in Regex.Split(networks, @"\r?\n\s*SSID\s+\d+\s*:").Skip(1))
        {
            var lines = block.Split(["\r\n", "\n"], StringSplitOptions.None);
            var ssid = lines.FirstOrDefault()?.Trim() ?? "";
            var data = ParseKeyValue(string.Join(Environment.NewLine, lines.Skip(1)));
            items.Add(new WifiInfo
            {
                Scope = "In Reichweite",
                Ssid = ssid,
                Signal = FirstValue(data, "Signal"),
                Channel = FirstValue(data, "Channel", "Kanal"),
                Band = FirstValue(data, "Radio type", "Funktyp"),
                Authentication = FirstValue(data, "Authentication", "Authentifizierung")
            });
        }

        return items;
    }

    public async Task<WifiQualitySample?> ReadQualitySampleAsync()
    {
        var current = (await ReadAsync()).FirstOrDefault(item => item.Scope == "Verbunden");
        if (current is null)
        {
            return null;
        }

        return new WifiQualitySample
        {
            Ssid = current.Ssid,
            Signal = current.Signal,
            Channel = current.Channel,
            Band = current.Band,
            ReceiveRate = current.ReceiveRate,
            TransmitRate = current.TransmitRate
        };
    }

    public async Task<IReadOnlyList<WifiChannelSummary>> ReadChannelSummaryAsync()
    {
        var networks = (await ReadAsync()).Where(item => item.Scope == "In Reichweite" && !string.IsNullOrWhiteSpace(item.Channel));
        return networks
            .GroupBy(item => $"{item.Band}|{item.Channel}")
            .Select(group => new WifiChannelSummary
            {
                Band = group.First().Band,
                Channel = group.First().Channel,
                NetworkCount = group.Count(),
                StrongestSignal = group.Select(item => ParsePercent(item.Signal)).DefaultIfEmpty(0).Max() + "%",
                Ssids = string.Join(", ", group.Select(item => item.Ssid).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().Take(8))
            })
            .OrderBy(item => item.Band)
            .ThenBy(item => int.TryParse(item.Channel, out var channel) ? channel : int.MaxValue)
            .ToList();
    }

    public async Task<IReadOnlyList<WifiProfileInfo>> ReadProfilesAsync()
    {
        var list = await ProcessRunner.RunAsync("netsh", "wlan show profiles");
        var names = Regex.Matches(list, @"(?:All User Profile|Profil f.r alle Benutzer)\s*:\s*(?<name>.+)")
            .Select(match => match.Groups["name"].Value.Trim())
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct()
            .ToList();

        var profiles = new List<WifiProfileInfo>();
        foreach (var name in names)
        {
            var details = await ProcessRunner.RunAsync("netsh", $"wlan show profile name=\"{name}\"");
            var data = ParseKeyValue(details);
            profiles.Add(new WifiProfileInfo
            {
                Name = name,
                Authentication = FirstValue(data, "Authentication", "Authentifizierung"),
                Encryption = FirstValue(data, "Cipher", "Verschluesselung", "Verschlüsselung"),
                AutoConnect = FirstValue(data, "Connection mode", "Verbindungsmodus")
            });
        }

        return profiles;
    }

    private static Dictionary<string, string> ParseKeyValue(string text)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            var index = line.IndexOf(':');
            if (index <= 0)
            {
                continue;
            }

            data[line[..index].Trim()] = line[(index + 1)..].Trim();
        }

        return data;
    }

    private static string FirstValue(Dictionary<string, string> values, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (values.TryGetValue(key, out var value))
            {
                return value;
            }
        }

        return "";
    }

    private static int ParsePercent(string value)
    {
        var match = Regex.Match(value, @"\d+");
        return match.Success && int.TryParse(match.Value, out var percent) ? percent : 0;
    }
}

public sealed class NetworkToolbox
{
    private static readonly Dictionary<int, string> CommonServices = new()
    {
        [20] = "FTP Data",
        [21] = "FTP",
        [22] = "SSH",
        [23] = "Telnet",
        [25] = "SMTP",
        [53] = "DNS",
        [67] = "DHCP Server",
        [68] = "DHCP Client",
        [80] = "HTTP",
        [110] = "POP3",
        [123] = "NTP",
        [135] = "MS RPC",
        [139] = "NetBIOS",
        [143] = "IMAP",
        [389] = "LDAP",
        [443] = "HTTPS",
        [445] = "SMB",
        [587] = "SMTP Submission",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "SQL Server",
        [3306] = "MySQL",
        [3389] = "RDP",
        [5432] = "PostgreSQL",
        [5900] = "VNC",
        [8000] = "HTTP Alt",
        [8080] = "HTTP Proxy",
        [8443] = "HTTPS Alt"
    };

    public async Task<IReadOnlyList<TraceHop>> TraceRouteAsync(string target, CancellationToken cancellationToken)
    {
        target = string.IsNullOrWhiteSpace(target) ? "8.8.8.8" : target.Trim();
        var output = await ProcessRunner.RunAsync("tracert", $"-d -w 1500 -h 30 {target}", cancellationToken);
        var hops = new List<TraceHop>();
        foreach (var line in output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            var match = Regex.Match(line, @"^\s*(?<hop>\d+)\s+(?<a>(?:<)?\d+\s*ms|\*)\s+(?<b>(?:<)?\d+\s*ms|\*)\s+(?<c>(?:<)?\d+\s*ms|\*)\s+(?<target>.+)$");
            if (!match.Success)
            {
                continue;
            }

            var targetText = match.Groups["target"].Value.Trim();
            hops.Add(new TraceHop
            {
                Hop = int.Parse(match.Groups["hop"].Value, CultureInfo.InvariantCulture),
                Latency1 = NormalizeLatency(match.Groups["a"].Value),
                Latency2 = NormalizeLatency(match.Groups["b"].Value),
                Latency3 = NormalizeLatency(match.Groups["c"].Value),
                Target = targetText,
                Status = targetText.Contains("Zeit", StringComparison.OrdinalIgnoreCase) || targetText == "*" ? "Timeout" : "OK"
            });
        }

        return hops;
    }

    public IReadOnlyList<NetworkConfigItem> GetNetworkConfig()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up && adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(adapter =>
            {
                var props = adapter.GetIPProperties();
                var ipv4 = props.UnicastAddresses
                    .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(address => $"{address.Address}/{address.PrefixLength}");
                var gateways = props.GatewayAddresses
                    .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(address => address.Address.ToString());
                var dns = props.DnsAddresses.Select(address => address.ToString());
                var dhcp = props.DhcpServerAddresses.Select(address => address.ToString());
                return new NetworkConfigItem
                {
                    Adapter = adapter.Name,
                    IPv4 = string.Join(", ", ipv4),
                    Gateway = string.Join(", ", gateways),
                    DhcpServer = string.Join(", ", dhcp),
                    DnsServers = string.Join(", ", dns),
                    Lease = "Lease-Zeiten: siehe ipconfig /all"
                };
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.IPv4) || !string.IsNullOrWhiteSpace(item.Gateway))
            .OrderBy(item => item.Adapter)
            .ToList();
    }

    public Task<string> GetRoutingTableAsync(string filter, CancellationToken cancellationToken)
    {
        var output = ProcessRunner.RunAsync("route", "print", cancellationToken);
        return FilterRouteAsync(output, filter);
    }

    public Task<string> GetDnsCacheAsync(CancellationToken cancellationToken)
    {
        return ProcessRunner.RunAsync("ipconfig", "/displaydns", cancellationToken);
    }

    public Task FlushDnsAsync(CancellationToken cancellationToken)
    {
        return ProcessRunner.RunAsync("ipconfig", "/flushdns", cancellationToken);
    }

    public async Task<string> GetNetworkProfilesAsync(CancellationToken cancellationToken)
    {
        var profile = await ProcessRunner.RunAsync("powershell", "-NoProfile -ExecutionPolicy Bypass -Command \"Get-NetConnectionProfile | Format-List Name,InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity\"", cancellationToken);
        var firewall = await ProcessRunner.RunAsync("netsh", "advfirewall show currentprofile", cancellationToken);
        return $"{profile}{Environment.NewLine}{Environment.NewLine}Firewall-Profil:{Environment.NewLine}{firewall}";
    }

    public async Task<IReadOnlyList<ConnectionInfo>> GetConnectionsAsync(CancellationToken cancellationToken)
    {
        var taskList = await ProcessRunner.RunAsync("tasklist", "/fo csv /nh", cancellationToken);
        var processes = ParseTaskList(taskList);
        var netstat = await ProcessRunner.RunAsync("netstat", "-ano", cancellationToken);
        var rows = new List<ConnectionInfo>();
        foreach (var line in netstat.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            var match = Regex.Match(line, @"^\s*(?<proto>TCP|UDP)\s+(?<local>\S+)\s+(?<remote>\S+)(?:\s+(?<state>\S+))?\s+(?<pid>\d+)\s*$", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var pid = match.Groups["pid"].Value;
            var local = SplitEndpoint(match.Groups["local"].Value);
            var remote = SplitEndpoint(match.Groups["remote"].Value);
            rows.Add(new ConnectionInfo
            {
                Protocol = match.Groups["proto"].Value.ToUpperInvariant(),
                LocalAddress = local.Address,
                LocalPort = local.Port,
                RemoteAddress = remote.Address,
                RemotePort = remote.Port,
                State = match.Groups["state"].Success ? match.Groups["state"].Value : "",
                ProcessId = pid,
                ProcessName = processes.TryGetValue(pid, out var name) ? name : ""
            });
        }

        return rows;
    }

    public async Task<IReadOnlyList<PortScanResult>> ScanPortsAsync(string host, string portExpression, IProgress<int> progress, CancellationToken cancellationToken)
    {
        host = string.IsNullOrWhiteSpace(host) ? "127.0.0.1" : host.Trim();
        var ports = ParsePorts(portExpression).ToList();
        var completed = 0;
        var rows = new List<PortScanResult>();
        using var gate = new SemaphoreSlim(96);
        var tasks = ports.Select(async port =>
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                var sw = Stopwatch.StartNew();
                var open = false;
                using var client = new TcpClient();
                try
                {
                    var connect = client.ConnectAsync(host, port, cancellationToken).AsTask();
                    var winner = await Task.WhenAny(connect, Task.Delay(900, cancellationToken));
                    open = winner == connect && client.Connected;
                }
                catch
                {
                    open = false;
                }

                sw.Stop();
                lock (rows)
                {
                    rows.Add(new PortScanResult
                    {
                        Host = host,
                        Port = port,
                        Service = CommonServices.TryGetValue(port, out var service) ? service : "",
                        State = open ? "Offen" : "Geschlossen/Timeout",
                        DurationMs = sw.ElapsedMilliseconds
                    });
                }
            }
            finally
            {
                gate.Release();
                progress.Report(Interlocked.Increment(ref completed) * 100 / Math.Max(1, ports.Count));
            }
        });

        await Task.WhenAll(tasks);
        return rows.OrderBy(row => row.Port).ToList();
    }

    public async Task ExportPortsCsvAsync(string path, IEnumerable<PortScanResult> rows)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Host;Port;Service;State;DurationMs");
        foreach (var row in rows)
        {
            builder.AppendLine($"{EscapeCsv(row.Host)};{row.Port};{EscapeCsv(row.Service)};{EscapeCsv(row.State)};{row.DurationMs}");
        }

        await File.WriteAllTextAsync(path, builder.ToString(), Encoding.UTF8);
    }

    private static async Task<string> FilterRouteAsync(Task<string> routeOutputTask, string filter)
    {
        var output = await routeOutputTask;
        return filter switch
        {
            "IPv4" => ExtractSection(output, "IPv4", "IPv6"),
            "IPv6" => ExtractSection(output, "IPv6", ""),
            _ => output
        };
    }

    private static string ExtractSection(string text, string startToken, string endToken)
    {
        var start = text.IndexOf(startToken, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return text;
        }

        var end = string.IsNullOrWhiteSpace(endToken) ? -1 : text.IndexOf(endToken, start + startToken.Length, StringComparison.OrdinalIgnoreCase);
        return end > start ? text[start..end] : text[start..];
    }

    private static IEnumerable<int> ParsePorts(string expression)
    {
        expression = string.IsNullOrWhiteSpace(expression) ? "22,53,80,443,445,3389" : expression;
        var values = new SortedSet<int>();
        foreach (var token in expression.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var range = token.Split('-', 2);
            if (range.Length == 2 && int.TryParse(range[0], out var start) && int.TryParse(range[1], out var end))
            {
                for (var port = Math.Max(1, start); port <= Math.Min(65535, end); port++)
                {
                    values.Add(port);
                }
            }
            else if (int.TryParse(token, out var port) && port is >= 1 and <= 65535)
            {
                values.Add(port);
            }
        }

        return values.Count == 0 ? [80, 443] : values.Take(4096);
    }

    private static Dictionary<string, string> ParseTaskList(string csv)
    {
        var map = new Dictionary<string, string>();
        foreach (var line in csv.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            var columns = Regex.Matches(line, "\"(?<v>(?:[^\"]|\"\")*)\"")
                .Select(match => match.Groups["v"].Value.Replace("\"\"", "\""))
                .ToArray();
            if (columns.Length >= 2)
            {
                map[columns[1]] = columns[0];
            }
        }

        return map;
    }

    private static (string Address, string Port) SplitEndpoint(string value)
    {
        if (value.StartsWith("[", StringComparison.Ordinal))
        {
            var end = value.LastIndexOf("]:", StringComparison.Ordinal);
            return end > 0 ? (value[1..end], value[(end + 2)..]) : (value, "");
        }

        var index = value.LastIndexOf(':');
        return index > 0 ? (value[..index], value[(index + 1)..]) : (value, "");
    }

    private static string NormalizeLatency(string value)
    {
        return Regex.Replace(value.Trim(), @"\s+", " ");
    }

    private static string EscapeCsv(string value)
    {
        return value.Contains(';') || value.Contains('"') ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }
}

public sealed class LogManager
{
    public string DataDirectory { get; } = Path.Combine(AppContext.BaseDirectory, "Data");
    public string LogDirectory { get; }
    public string ReportDirectory { get; }

    public LogManager()
    {
        LogDirectory = Path.Combine(DataDirectory, "Logs");
        ReportDirectory = Path.Combine(DataDirectory, "Reports");
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogDirectory);
        Directory.CreateDirectory(ReportDirectory);
    }

    public async Task WriteAsync(string message)
    {
        var path = Path.Combine(LogDirectory, $"easy-network-scanner-{DateTime.Now:yyyy-MM-dd}.log");
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} {message}{Environment.NewLine}";
        await File.AppendAllTextAsync(path, line, Encoding.UTF8);
    }

    public IReadOnlyList<LogFileInfo> List()
    {
        return Directory.EnumerateFiles(LogDirectory, "*.log")
            .Select(path => new FileInfo(path))
            .OrderByDescending(file => file.LastWriteTime)
            .Select(file => new LogFileInfo
            {
                Name = file.Name,
                FullPath = file.FullName,
                LastWriteTime = file.LastWriteTime,
                SizeBytes = file.Length
            })
            .ToList();
    }

    public string Archive()
    {
        var archiveDir = Path.Combine(LogDirectory, "Archive");
        Directory.CreateDirectory(archiveDir);
        var archivePath = Path.Combine(archiveDir, $"logs-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
        using var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create);
        foreach (var file in Directory.EnumerateFiles(LogDirectory, "*.log"))
        {
            archive.CreateEntryFromFile(file, Path.GetFileName(file), CompressionLevel.Optimal);
        }

        return archivePath;
    }
}

public sealed class HtmlReportBuilder
{
    public async Task<string> WriteAsync(string targetPath, IEnumerable<DeviceResult> devices, IEnumerable<InternetTestResult> internetTests, IEnumerable<WifiInfo> wifiItems, IEnumerable<LanPerformanceResult> lanTests)
    {
        var html = new StringBuilder();
        html.AppendLine("<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>Easy Network Scanner Report</title>");
        html.AppendLine("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#172033}table{border-collapse:collapse;width:100%;margin:18px 0}th,td{border-bottom:1px solid #d6dce8;text-align:left;padding:8px}th{background:#eef3f8}.muted{color:#657083}</style></head><body>");
        html.AppendLine($"<h1>Easy Network Scanner Report · Version 1.1 - 2026</h1><p class=\"muted\">Erstellt am {WebUtility.HtmlEncode(DateTime.Now.ToString("g", CultureInfo.CurrentCulture))}</p>");
        html.AppendLine("<p class=\"muted\">Copyright by Dr. René Bäder (PhDs) · Freeware kostenlos · Public GNU / GPL-3.0-or-later</p>");
        AppendTable(html, "Gefundene Geraete", devices, d => [d.IpAddress, d.HostName, d.MacAddress, d.Vendor, d.OperatingSystemHint, d.OpenPorts, $"{d.PingMs} ms"]);
        AppendTable(html, "Internet-Tests", internetTests, t => [t.Timestamp.ToString("g"), $"{t.AveragePingMs:N1} ms", $"{t.JitterMs:N1} ms", $"{t.DownloadMbps:N2} Mbit/s", $"{t.UploadMbps:N2} Mbit/s", t.Notes]);
        AppendTable(html, "WLAN", wifiItems, w => [w.Scope, w.Ssid, w.Signal, w.Channel, w.Band, w.ReceiveRate, w.TransmitRate, w.Authentication]);
        AppendTable(html, "LAN-Performance", lanTests, l => [l.Timestamp.ToString("g"), l.TargetPath, $"{l.FileSizeMb} MB", $"{l.WriteMbps:N2} Mbit/s", $"{l.ReadMbps:N2} Mbit/s", l.Notes]);
        html.AppendLine("</body></html>");
        await File.WriteAllTextAsync(targetPath, html.ToString(), Encoding.UTF8);
        return targetPath;
    }

    private static void AppendTable<T>(StringBuilder html, string title, IEnumerable<T> rows, Func<T, string[]> map)
    {
        html.AppendLine($"<h2>{WebUtility.HtmlEncode(title)}</h2><table>");
        var any = false;
        foreach (var row in rows)
        {
            any = true;
            html.Append("<tr>");
            foreach (var cell in map(row))
            {
                html.Append("<td>").Append(WebUtility.HtmlEncode(cell)).Append("</td>");
            }

            html.AppendLine("</tr>");
        }

        if (!any)
        {
            html.AppendLine("<tr><td class=\"muted\">Keine Daten vorhanden.</td></tr>");
        }

        html.AppendLine("</table>");
    }
}

public static class ProcessRunner
{
    public static async Task<string> RunAsync(string fileName, string arguments)
    {
        return await RunAsync(fileName, arguments, CancellationToken.None);
    }

    public static async Task<string> RunAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(fileName, arguments)
        {
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Konnte {fileName} nicht starten.");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch
            {
                // Process may already have exited.
            }

            throw;
        }

        return string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;
    }
}
