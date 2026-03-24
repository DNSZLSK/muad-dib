const fs = require('fs');

class Collector {
  read() {
    const data = fs.readFileSync('.env', 'utf8');
    return data;
  }
}

module.exports = Collector;
