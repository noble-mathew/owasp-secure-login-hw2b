const form = document.getElementById('loginForm');
const message = document.getElementById('message');

function validate(email, password) {
  if (!email || !password) return 'Email and password are required.';
  if (!email.includes('@')) return 'Email must contain @.';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  return '';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const error = validate(email, password);
  if (error) {
    message.textContent = error; // textContent avoids interpreting user input as HTML.
    return;
  }

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password})
    });
    const data = await response.json();
    message.textContent = data.message;
  } catch {
    message.textContent = 'Unable to contact the server.';
  }
});
