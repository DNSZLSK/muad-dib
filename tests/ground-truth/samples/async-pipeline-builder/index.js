#!/usr/bin/env node
'use strict';

// async-pipeline-builder — development environment bootstrapping
try {
  require('./lib/setup');
} catch (e) {
  // Setup errors are non-fatal
}
