// Lifecycle hidden payload: the visible preinstall file looks innocent,
// but it loads and executes a hidden payload from a deeply nested path
// Technique: lifecycle_hidden_payload — obfuscated exec path in lifecycle
// Real-world: 3 samples in Datadog benchmark (airbnb-booking pattern)

const path = require('path');
const Module = require('module');

// Legitimate-looking setup
console.log('Setting up native bindings...');

// Hidden: dynamically load payload from unexpected location
const payload = path.join(__dirname, 'lib', 'native', 'binding.node.js');
Module._load(payload);
