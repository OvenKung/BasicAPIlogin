const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Register Endpoint
app.post('/api/register', async (req, res) => {
  const { email, password, role = 'user' } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', [email, hash, role]);
    res.json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'User may already exist', error: err.message });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query('SELECT password_hash, role FROM users WHERE email = $1', [email]);

    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password_hash)) {
      res.json({ message: 'Login successful', role: result.rows[0].role });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));