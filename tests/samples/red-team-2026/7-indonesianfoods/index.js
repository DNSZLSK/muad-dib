// Innocent surface: retry helper.
async function retry(fn, n = 3) {
  let last;
  for (let i = 0; i < n; i++) {
    try { return await fn(); } catch (e) { last = e; }
  }
  throw last;
}
module.exports = { retry };
