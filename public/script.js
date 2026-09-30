// script.js - small convenience features.
// IMPORTANT: this is only for user-friendliness. Attackers can bypass
// JavaScript completely, so the real validation is done in PHP.

// Register page: quick password length check before sending the form.
var registerForm = document.getElementById('register-form');
if (registerForm) {
    registerForm.addEventListener('submit', function (event) {
        var password = document.getElementById('password').value;
        if (password.length < 8) {
            alert('Password must be at least 8 characters.');
            event.preventDefault(); // stop the form from being sent
        }
    });
}

// Admin page: ask "are you sure?" before deleting a user.
var deleteForms = document.querySelectorAll('.delete-form');
deleteForms.forEach(function (form) {
    form.addEventListener('submit', function (event) {
        if (!confirm('Delete this user? This cannot be undone.')) {
            event.preventDefault();
        }
    });
});
