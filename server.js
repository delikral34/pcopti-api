const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
const url = require('url');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'pcopti-secret-key';

const SUPABASE_URL = 'https://gpvwteflexhwtybigtct.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imdwdnd0ZWZsZXhod3R5YmlndGN0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3Mzc3MjY3MiwiZXhwIjoyMDg5MzQ4NjcyfQ.bPE8kmgww7LNnJk-ZJwDDJQpuV1Rx-tZqME5vV6AWBg';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const WEBHOOK_URL = 'https://discord.com/api/webhooks/1483589251667984455/vkrpUVU37a5vOa-Rb1-6WhVAHRtkXqxd2VyxL5UppVsgF-Qft1lrOdBAAYvi0jYN78Rr';

app.use(cors());
app.use(express.json());

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
    const { error } = await supabase.from('users').insert({ username, email, password: hashed });

    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
      return res.status(500).json({ error: 'Server error' });
    }

    sendLog({
      title: '📝 New Registration',
      color: 0x6c63ff,
      fields: [
        { name: 'Username', value: username, inline: true },
        { name: 'Email', value: email, inline: true },
        { name: 'IP', value: getIp(req), inline: true },
      ],
      timestamp: new Date().toISOString(),
      footer: { text: 'PCOpti Auth' },
    });

    res.json({ message: 'Account created successfully' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const { data: users } = await supabase.from('users').select('*').eq('email', email).limit(1);
  const user = users?.[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    sendLog({
      title: '❌ Failed Login',
      color: 0xff6584,
      fields: [
        { name: 'Email', value: email, inline: true },
        { name: 'IP', value: getIp(req), inline: true },
      ],
      timestamp: new Date().toISOString(),
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
    timestamp: new Date().toISOString(),
    footer: { text: 'PCOpti Auth' },
  });

  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// Discord OAuth
app.post('/api/discord-auth', async (req, res) => {
  const { discordId, username, email, avatar } = req.body;
  if (!discordId) return res.status(400).json({ error: 'Missing discord data' });

  const fakeEmail = email || `discord_${discordId}@pcopti.app`;
  const { data: existing } = await supabase.from('users').select('*').eq('email', fakeEmail).limit(1);
  let user = existing?.[0];

  if (!user) {
    const fakePass = await bcrypt.hash(discordId + JWT_SECRET, 10);
    let uname = username;
    const { data: ucheck } = await supabase.from('users').select('id').eq('username', uname).limit(1);
    if (ucheck?.[0]) uname = `${username}_${discordId.slice(-4)}`;

    const { data: inserted, error } = await supabase.from('users').insert({ username: uname, email: fakeEmail, password: fakePass }).select().single();
    if (error) return res.status(500).json({ error: 'Server error' });
    user = inserted;

    sendLog({
      title: '📝 New Discord Registration',
      color: 0x5865f2,
      fields: [
        { name: 'Username', value: uname, inline: true },
        { name: 'Discord ID', value: discordId, inline: true },
        { name: 'IP', value: getIp(req), inline: true },
      ],
      timestamp: new Date().toISOString(),
      footer: { text: 'PCOpti Auth' },
    });
  }

  const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('users').select('id, username, email, created_at').eq('id', req.user.id).single();
  res.json(data);
});

app.get('/', (req, res) => res.json({ status: 'PCOpti API running' }));
app.listen(PORT, () => console.log(`PCOpti API running on port ${PORT}`));
