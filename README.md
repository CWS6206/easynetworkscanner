# Easy Network Scanner

Easy Network Scanner ist eine portable Windows-11-App fuer LAN-, WLAN- und Performance-Diagnose.

Version 1.1 - 2026

## Portable Nutzung

Die App kann als portabler Ordner ohne Installation ausgefuehrt werden. Starte dazu `EasyNetworkScanner.exe` direkt aus dem Publish-Ordner oder von einem USB-Stick. Laufzeitdaten bleiben neben der EXE unter `Data`:

- `Data/Logs` fuer Logdateien und Archive
- `Data/Reports` als Standardordner fuer HTML-Reports

Ein portabler Self-contained-Build fuer Windows x64 kann so erstellt werden:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o .\publish\easy-network-scanner-win-x64
```

## Funktionsumfang

- Netzwerk-Scan ueber aktive IPv4-Adapter
- Erkennung erreichbarer Hosts per ICMP
- DNS-Name, ARP/MAC-Adresse, einfache Hersteller-Hinweise und TTL-basierter OS-Hinweis
- TCP-Pruefung haeufiger Ports
- Internet-Test mit Ping, Download- und Upload-Messung
- LAN-Performance-Test gegen lokale Ordner oder Netzwerkfreigaben
- Traceroute, Gateway/DHCP/DNS-Infos, Routing-Tabelle und DNS-Cache
- Netzwerkprofile, Firewall-Profil und offene lokale Verbindungen
- Erweiterter Portscanner mit Portbereichen, Dienstnamen und CSV-Export
- WLAN-Uebersicht ueber Windows `netsh`
- WLAN-Qualitaetsverlauf, Kanaluebersicht und WLAN-Profil-Details
- Portable Logdateien, ZIP-Archivierung und HTML-Report
- Eigenes App-Icon fuer EXE und Fenster

## Copyright- und Lizenzabgrenzung

Copyright by Dr. René Bäder (PhDs).

Easy Network Scanner ist Freeware und kostenlos nutzbar. Das Tool wird unter der GNU General Public License, Version 3 oder spaeter, veroeffentlicht (`GPL-3.0-or-later`).

Diese App ist eine eigene Neuimplementierung. Sie verwendet keinen Quellcode, keine Assets, kein Branding und keine geschuetzten Texte aus `SattlerIT/sit-lanscanner`. Der Link zum Original diente nur als Referenz fuer den dokumentierten Funktionsumfang.

## Hinweise

- Fuer vollstaendige Netzwerkergebnisse kann ein Start mit Administratorrechten helfen.
- ICMP, ARP, `netsh` und HTTPS-Speedtests koennen durch Firewall, VPN, WLAN-Roaming oder Unternehmensrichtlinien beeinflusst werden.
- Die Hersteller-Erkennung nutzt bewusst nur eine kleine, selbst gepflegte Prefix-Liste. Fuer produktive Inventarisierung kann spaeter eine lizenzierte OUI-Datenquelle angebunden werden.
