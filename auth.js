// auth.js - middleware that protects routes.
// A middleware runs BEFORE the route handler. If the check fails it
// redirects and the handler never runs.

// AUTHENTICATION check: is someone logged in? (We save req.session.user at login.)
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// AUTHORIZATION / RBAC check: only admins may continue.
// The role comes from the server-side session, which the user cannot edit.
// Hiding a link is NOT security - the check must happen on the server.
function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.role !== 'admin') {
    return res.redirect('/access-denied');
  }
  next();
}

module.exports = { requireLogin, requireAdmin };
