// server.js - the whole backend: routes for register, login, dashboard,
// admin, logout.
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { requireLogin, requireAdmin } = require('./auth');

const app = express();

// EJS templates (views/*.ejs). In EJS, <%= value %> ESCAPES the value.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false })); // read HTML form data
app.use(express.static(path.join(__dirname, 'public'))); // style.css, script.js

// SESSION MANAGEMENT: after login the server remembers the user in memory
// and gives the browser a cookie holding only a random session ID.
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret-in-real-projects',
    resave: false,
    saveUninitialized: false, // no session (and no cookie) until we store something
    cookie: {
      httpOnly: true, // JavaScript cannot read the cookie, so XSS can't steal it
      sameSite: 'lax', // the browser won't send it on most cross-site requests
      maxAge: 60 * 60 * 1000, // 1 hour
      // secure: true,  // turn on when the site uses HTTPS
    },
  })
);

// Form fields can arrive as arrays or objects (e.g. name=a&name=b).
// This helper accepts only plain strings.
const str = (value) => (typeof value === 'string' ? value : '');

// ---------- Home ----------
app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/dashboard' : '/login');
});

// ---------- Register ----------
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('register', { errors: [], name: '', email: '', role: 'user' });
});

app.post('/register', async (req, res) => {
  const name = str(req.body.name).trim();
  const email = str(req.body.email).trim().toLowerCase();
  const password = str(req.body.password); // do NOT trim passwords
  const role = str(req.body.role);

  // INPUT VALIDATION: never trust data from the browser.
  const errors = [];
  if (name === '' || name.length > 100) {
    errors.push('Name is required (max 100 characters).');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 150) {
    errors.push('Enter a valid email address.');
  }
  // bcrypt only uses the first 72 characters, so we cap the length there.
  if (password.length < 8 || password.length > 72) {
    errors.push('Password must be 8 to 72 characters.');
  }
  // Whitelist: only accept the exact values we expect.
  // NOTE: letting people pick "admin" is only for this demo. In a real
  // system, admin accounts are created by an existing admin.
  if (!['admin', 'user'].includes(role)) {
    errors.push('Choose a valid role.');
  }

  if (errors.length === 0) {
    // PASSWORD HASHING: bcrypt adds a random salt and is deliberately slow,
    // so stolen hashes are very hard to crack. "10" is the cost factor.
    const hash = await bcrypt.hash(password, 10);

    try {
      // SQL INJECTION PROTECTION: prepared statement.
      // The "?" placeholders are filled from the array. The SQL and the
      // data are sent separately, so input can never change the query.
      await db.execute(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [name, email, hash, role]
      );
      return res.redirect('/login?registered=1');
    } catch (err) {
      // The email column is UNIQUE, so MySQL rejects duplicates for us.
      if (err.code === 'ER_DUP_ENTRY') {
        errors.push('That email is already registered.');
      } else {
        throw err;
      }
    }
  }

  res.render('register', { errors, name, email, role });
});

// ---------- Login ----------
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error: '', email: '', registered: 'registered' in req.query });
});

app.post('/login', async (req, res, next) => {
  const email = str(req.body.email).trim().toLowerCase();
  const password = str(req.body.password);

  // SQL INJECTION PROTECTION: prepared statement again.
  // Even if someone types  ' OR '1'='1  as the email, it is treated as
  // plain text to search for, not as SQL.
  const [rows] = await db.execute(
    'SELECT id, name, password, role FROM users WHERE email = ?',
    [email]
  );
  const user = rows[0];

  // PASSWORD VERIFICATION: bcrypt.compare() hashes the typed password and
  // compares it with the stored hash. We never decrypt anything.
  if (user && (await bcrypt.compare(password, user.password))) {
    // SESSION FIXATION PROTECTION: create a brand-new session ID after login
    // so an attacker can't reuse an ID they planted before the user logged in.
    req.session.regenerate((err) => {
      if (err) return next(err);

      // Store only what we need. Never store the password in the session.
      req.session.user = { id: user.id, name: user.name, role: user.role };
      res.redirect('/dashboard');
    });
    return;
  }

  // SECURITY: same message for "no such email" and "wrong password",
  // so attackers can't find out which emails are registered.
  res.render('login', { error: 'Incorrect email or password.', email, registered: false });
});

// ---------- User dashboard ----------
// requireLogin runs first. If it fails, this handler never runs.
app.get('/dashboard', requireLogin, async (req, res) => {
  // Use the ID from the session (not from the URL), so a user can only
  // ever see their own data.
  const [rows] = await db.execute(
    `SELECT name, email, role, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
     FROM users WHERE id = ?`,
    [req.session.user.id]
  );

  // The account may have been deleted by an admin while the user was logged in.
  if (rows.length === 0) {
    return req.session.destroy(() => res.redirect('/login'));
  }

  res.render('dashboard', { user: rows[0] });
});

// ---------- Admin dashboard ----------
// RBAC: requireAdmin blocks normal users even if they type /admin in the
// address bar.
async function showAdminPage(req, res, message = '', type = 'success') {
  // The password column is deliberately not selected.
  const [users] = await db.query(
    `SELECT id, name, email, role, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
     FROM users ORDER BY id`
  );
  res.render('admin', { admin: req.session.user, users, message, type });
}

app.get('/admin', requireAdmin, (req, res) => showAdminPage(req, res));

// Deleting uses POST (not a link), so it can't be triggered by accident.
app.post('/admin/delete', requireAdmin, async (req, res) => {
  const id = Number.parseInt(str(req.body.id), 10); // force it to be a number

  if (Number.isNaN(id)) {
    return showAdminPage(req, res, 'Invalid user.', 'error');
  }
  if (id === req.session.user.id) {
    return showAdminPage(req, res, 'You cannot delete your own account.', 'error');
  }

  await db.execute('DELETE FROM users WHERE id = ?', [id]);
  showAdminPage(req, res, 'User deleted.');
});

// ---------- Access denied ----------
app.get('/access-denied', (req, res) => {
  // 403 = "Forbidden": you may be known, but you are not allowed here.
  res.status(403).render('access-denied', { loggedIn: Boolean(req.session.user) });
});

// ---------- Logout ----------
app.post('/logout', (req, res) => {
  // Destroy the session on the server, then delete the cookie in the browser.
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ---------- Error handler ----------
// SECURITY: show a generic message. Detailed errors can leak database
// names and file paths to attackers. The details go to the server console.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong. Please try again.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
