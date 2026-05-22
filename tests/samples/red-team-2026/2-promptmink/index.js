// Innocent surface: form validator.
function validate(form) {
  if (!form || typeof form !== 'object') return false;
  if (form.email && !form.email.includes('@')) return false;
  return true;
}
module.exports = { validate };
