// Innocent surface: HTTP client wrapper.
async function fetchJson(url) {
  const r = await fetch(url);
  return r.json();
}
module.exports = { fetchJson };
