// db.js - database connection, used by server.js.
const mysql = require('mysql2/promise');

// A pool keeps a few connections open and reuses them (faster than
// opening a new connection for every request).
// XAMPP defaults: user "root" with an empty password.
// In a real project, use a dedicated low-privilege DB user and keep the
// password in an environment variable, never in the code.
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'secure_auth',
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;
