const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    await db.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'User already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.execute('SELECT password_hash FROM users WHERE email = ?', [email]);

  if (rows.length > 0 && await bcrypt.compare(password, rows[0].password_hash)) {
    res.json({ message: 'Login successful' });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));