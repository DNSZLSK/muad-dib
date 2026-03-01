// react-dev-overlay-utils: Error boundary helpers
// Provides utilities for formatting and displaying React errors

function formatStackTrace(error) {
  if (!error || !error.stack) return '';
  return error.stack
    .split('\n')
    .filter(line => !line.includes('node_modules'))
    .join('\n');
}

function createOverlay(message, stack) {
  return {
    type: 'error',
    message: String(message),
    stack: formatStackTrace({ stack }),
    timestamp: Date.now()
  };
}

module.exports = { formatStackTrace, createOverlay };
