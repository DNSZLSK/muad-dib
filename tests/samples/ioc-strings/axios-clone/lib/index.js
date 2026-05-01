// Test fixture: simulates the Axios npm 2026-03 setup.js dropper.
// Should fire ioc_string_match against multiple Axios family IOCs.
const XOR_KEY = "OrDeR_7077";
function decode(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ XOR_KEY.charCodeAt(i % XOR_KEY.length);
  return out;
}

const COMMANDS = {
  rsp_peinject: () => {},
  rsp_runscript: () => {},
  rsp_kill: () => {},
  rsp_rundir: () => {}
};

module.exports = { decode, COMMANDS };
