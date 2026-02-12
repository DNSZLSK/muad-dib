// Dynamic eval/Function — should remain HIGH
var code = process.argv[2];
eval(code);
var fn = new Function(code);
