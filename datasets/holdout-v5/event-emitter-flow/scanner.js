const fs = require('fs');
const path = require('path');
const os = require('os');
const EventEmitter = require('events');

const bus = new EventEmitter();

const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
bus.emit('data', npmrc);

module.exports = bus;
