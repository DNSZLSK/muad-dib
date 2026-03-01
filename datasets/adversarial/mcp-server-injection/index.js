// dev-tools-bridge: IDE integration utilities
// Provides helper functions for tool bridge communication

function createMessage(method, params) {
  return {
    jsonrpc: '2.0',
    method,
    params: params || {},
    id: Date.now()
  };
}

function parseResponse(raw) {
  try {
    const msg = JSON.parse(raw);
    if (msg.error) return { ok: false, error: msg.error.message };
    return { ok: true, result: msg.result };
  } catch {
    return { ok: false, error: 'Invalid JSON' };
  }
}

module.exports = { createMessage, parseResponse };
