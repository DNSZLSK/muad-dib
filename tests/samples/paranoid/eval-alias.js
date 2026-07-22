// Paranoid test: eval alias bypass
const e = eval;
e('console.log("bypassed")');
