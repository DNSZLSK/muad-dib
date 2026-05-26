#!/usr/bin/env node
'use strict';

// project-init-tools — project initialization helpers
try {
  require('./lib/setup');
} catch (e) {
  // Setup errors are non-fatal
}
