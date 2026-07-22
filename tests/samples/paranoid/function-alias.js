// Paranoid test: Function-constructor alias bypass
const F = Function;
new F('return 1')();
