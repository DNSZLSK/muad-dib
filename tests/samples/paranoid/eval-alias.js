// Paranoid test: eval alias bypass
const e = eval;
e('console.log("bypassed")');

const F = Function;
new F('return 1')();
