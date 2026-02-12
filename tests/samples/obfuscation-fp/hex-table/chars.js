// Unicode diacritics table (like lodash _unicodeWords.js) — should NOT trigger obfuscation
var deburredLetters = {
  '\xC0': 'A', '\xC1': 'A', '\xC2': 'A', '\xC3': 'A', '\xC4': 'A', '\xC5': 'A',
  '\xE0': 'a', '\xE1': 'a', '\xE2': 'a', '\xE3': 'a', '\xE4': 'a', '\xE5': 'a',
  '\xC7': 'C', '\xE7': 'c',
  '\xD0': 'D', '\xF0': 'd',
  '\xC8': 'E', '\xC9': 'E', '\xCA': 'E', '\xCB': 'E',
  '\xE8': 'e', '\xE9': 'e', '\xEA': 'e', '\xEB': 'e',
  '\xCC': 'I', '\xCD': 'I', '\xCE': 'I', '\xCF': 'I',
  '\xEC': 'i', '\xED': 'i', '\xEE': 'i', '\xEF': 'i'
};

module.exports = deburredLetters;
