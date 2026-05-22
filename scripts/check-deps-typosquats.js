#!/usr/bin/env node
const path = require('path');
const { findTyposquatMatch } = require('../src/scanner/typosquat.js');

const pkg = require(path.resolve(__dirname, '..', 'package.json'));

const allDeps = {
  ...(pkg.dependencies || {}),
  ...(pkg.devDependencies || {}),
  ...(pkg.optionalDependencies || {}),
  ...(pkg.peerDependencies || {})
};

const names = Object.keys(allDeps);
const findings = [];

for (const name of names) {
  const match = findTyposquatMatch(name);
  if (match) {
    findings.push({ name, ...match });
  }
}

if (findings.length > 0) {
  console.error('::error::Typosquat candidate detected in package.json dependencies — aborting publish');
  for (const f of findings) {
    console.error(`  "${f.name}" -> resembles "${f.original}" (${f.type}, distance ${f.distance})`);
  }
  process.exit(1);
}

console.log(`package.json deps: clean (${names.length} names checked against ${'~100 popular packages'})`);
