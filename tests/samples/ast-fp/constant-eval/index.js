// Lodash-style globalThis polyfill — should be LOW not HIGH
var root = Function('return this')();
var result = eval('1 + 2');
