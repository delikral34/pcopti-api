const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const https = require('https');
const url = require('url');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'pcopti-secret-key-change-in-production';
const WEBHOOK_URL = process.env.DISCORD_WEBHOOK || 'https://discord.com/api/webhooks/1483589251667984455/vkrpUVU37a5vOa-Rb1-6WhVAHRtkXqxd2VyxL5UppVsgF-Qft1lrOdBAAYvi0jYN78Rr';

// DB setup
const db = new Database(path.join(__dirname, 'users.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

app.use(cors());
app.use(express.json());

// Discord webhook sender
function sendLog(embed) {
  const body = JSON.stringify({ embeds: [embed] });
  const parsed = url.parse(WEBHOOK_URL);
  const options = {
    hostname: parsed.hostname,
    path: parsed.path,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  };
  const req = https.request(options);
  req.on('error', () => {});
  req.write(body);
  req.end();
}

function getIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

function timestamp() {
  return new Date().toISOString();
}

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(username, email, hashed);

    sendLog({
      title: '📝 New Registration',
      color: 0x6c63ff,
      fields: [
        { name: 'Username', value: username, inline: true },
        { name: 'Email', value: email, inline: true },
        { name: 'IP', value: getIp(req), inline: true },
      ],
      timestamp: timestamp(),
      footer: { text: 'PCOpti Auth' },
    });

    res.json({ message: 'Account created successfully' });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      res.status(409).json({ error: 'Username or email already exists' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    sendLog({
      title: '❌ Failed Login Attempt',
      color: 0xff6584,
      fields: [
        { name: 'Email', value: email, inline: true },
        { name: 'IP', value: getIp(req), inline: true },
      ],
      timestamp: timestamp(),
      footer: { text: 'PCOpti Auth' },
    });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

  sendLog({
    title: '✅ User Login',
    color: 0x43e97b,
    fields: [
      { name: 'Username', value: user.username, inline: true },
      { name: 'Email', value: user.email, inline: true },
      { name: 'IP', value: getIp(req), inline: true },
    ],
    timestamp: timestamp(),
    footer: { text: 'PCOpti Auth' },
  });

  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// Log action (optimizer actions)
app.post('/api/log', authMiddleware, (req, res) => {
  const { action, details } = req.body;

  const colors = {
    'RAM Optimize': 0x6c63ff,
    'Temp Clean': 0x43e97b,
    'DNS Flush': 0xf7971e,
  };

  sendLog({
    title: `⚡ ${action}`,
    color: colors[action] || 0x6c63ff,
    fields: [
      { name: 'User', value: req.user.username, inline: true },
      { name: 'Email', value: req.user.email, inline: true },
      { name: 'IP', value: getIp(req), inline: true },
      ...(details ? [{ name: 'Result', value: details, inline: false }] : []),
    ],
    timestamp: timestamp(),
    footer: { text: 'PCOpti Actions' },
  });

  res.json({ ok: true });
});

// Get current user
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

app.get('/', (req, res) => res.json({ status: 'PCOpti API running' }));

app.listen(PORT, () => console.log(`PCOpti API running on port ${PORT}`));
