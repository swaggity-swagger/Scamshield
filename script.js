const form = document.getElementById('appointment-form');

if (form) {
  const fields = { name: document.getElementById('patient-name'), mobile: document.getElementById('mobile'), email: document.getElementById('email'), department: document.getElementById('department'), date: document.getElementById('visit-date') };
  const today = new Date().toISOString().slice(0, 10);
  fields.date.min = today;
  function setError(id, message) { document.getElementById(id).textContent = message; }
  form.addEventListener('submit', function (event) {
    event.preventDefault(); let valid = true;
    ['name-error','mobile-error','email-error','department-error','date-error'].forEach(id => setError(id, ''));
    if (!/^[A-Za-z][A-Za-z .'-]{1,59}$/.test(fields.name.value.trim())) { setError('name-error', 'Enter a valid patient name.'); valid = false; }
    if (!/^[6-9]\d{9}$/.test(fields.mobile.value.trim())) { setError('mobile-error', 'Enter a valid 10-digit Indian mobile number.'); valid = false; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email.value.trim())) { setError('email-error', 'Enter a valid email address.'); valid = false; }
    if (!fields.department.value) { setError('department-error', 'Select a department.'); valid = false; }
    if (!fields.date.value || fields.date.value < today) { setError('date-error', 'Choose today or a future date.'); valid = false; }
    const result = document.getElementById('form-result');
    result.textContent = valid ? `Thank you, ${fields.name.value.trim().split(' ')[0]}. Your sample appointment request is confirmed.` : 'Please correct the highlighted fields.';
    if (valid) form.reset();
  });
}
