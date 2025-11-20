const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, '../oidc.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

function init() {
  // Clients Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT,
      redirect_uris TEXT NOT NULL, -- JSON array
      client_name TEXT
    )
  `);

  // Authorization Codes Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS auth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT,
      sub TEXT,
      code_challenge TEXT,
      code_challenge_method TEXT,
      expires_at INTEGER NOT NULL
    )
  `);

  // Users Table (for delegated identity mapping)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      sub TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      name TEXT
    )
  `);

  // WebAuthn Credentials Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      sign_count INTEGER DEFAULT 0,
      user_sub TEXT NOT NULL,
      transports TEXT, -- JSON array
      FOREIGN KEY(user_sub) REFERENCES users(sub)
    )
  `);
  
  // Seed a default client for testing
  const stmt = db.prepare('SELECT client_id FROM clients WHERE client_id = ?');
  if (!stmt.get('oidc-client-test')) {
      const insert = db.prepare('INSERT INTO clients (client_id, client_secret, redirect_uris, client_name) VALUES (?, ?, ?, ?)');
      insert.run('oidc-client-test', 'secret', JSON.stringify(['http://localhost:3000/callback']), 'Test Client');
      console.log('Seeded test client: oidc-client-test');
  }

  console.log('Database initialized');
}

module.exports = {
  db,
  init
};
