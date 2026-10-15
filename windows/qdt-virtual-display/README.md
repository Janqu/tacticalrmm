# QDT Virtual Display

Minimaler UMDF/IDDCX-Treiber für die QDT-Fernwartung. Er stellt virtuelle
Bildschirme bereit, wenn ein Windows-Agent keinen nutzbaren Monitor hat. Der
Treiber enthält keinen Netzwerkcode und verarbeitet keine Eingaben.

Unterstützte Modi (je Monitor, bevorzugt ist der erste):

- 3840 × 2160 bei 60 Hz (4K, bevorzugt)
- 5120 × 2880 bei 60 Hz (5K)
- 3440 × 1440 bei 60 Hz (Ultrawide)
- 2560 × 1440 bei 60 Hz
- 1920 × 1080 bei 60 Hz
- 1280 × 720 bei 60 Hz

## Mehrere Bildschirme

Der Adapter meldet bis zu vier virtuelle Monitore (`QDT_MAX_MONITOR_COUNT`).
Wie viele davon tatsächlich erscheinen, steht als `MonitorCount` (REG_DWORD) im
Hardware-Key des Geräts; die INF legt den Standardwert 1 an. Der Go-Agent
schreibt den Wert vor dem Aktivieren des Geräts und startet es neu, damit die
Anzahl übernommen wird — der Wert wird nur beim Power-Up gelesen. Fehlt oder ist
er ungültig, bleibt es bei einem Monitor; größere Werte werden auf vier gekappt.

Jeder Monitor bekommt eine eigene, stabile Container-ID (Basis-GUID plus
Connector-Index), damit Windows die Bildschirme auseinanderhält und nicht bei
jedem Start neue anlegt.

Zielplattform ist Windows 10 ab Build 19041 und Windows 11 auf x64. Die
Hardware-ID lautet `Root\QDTVirtualDisplay`. Der Go-Agent installiert und
aktiviert das Gerät nur für eine Headless-Fernwartung und deaktiviert es nach
Sitzungsende wieder.

## Bauen

Benötigt werden Visual Studio 2022, Desktop C++, das aktuelle Windows SDK und
WDK. In einer Developer PowerShell:

```powershell
msbuild .\QdtVirtualDisplay.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Für Entwicklung darf ausschließlich auf einer Testmaschine mit aktivierter
Testsignierung gebaut werden. Für Releases müssen DLL, INF und CAT über das
Microsoft Hardware Dev Center signiert werden. Das signierte Paket wird nach
`build/qdt-virtual-display/package/` des Agent-Repositories kopiert; der
Inno-Installer nimmt es dann unter `drivers/qdt-virtual-display` auf.

Vor einer Freigabe sind mindestens Standby/Wakeup, Ab- und Anmeldung,
Windows-Update sowie Intel-, AMD-, NVIDIA- und VM-Grafikadapter zu prüfen.

## Herkunft

Die IDDCX-Grundstruktur basiert auf Microsofts `IddSampleDriver`. Dessen
MIT-Lizenz liegt als `LICENSE.microsoft.txt` bei. QDT-spezifisch sind die
Geräteidentität, die EDID-losen Monitore mit stabilen Container-IDs, die
konfigurierbare Monitoranzahl und die Modusliste bis 5K.
