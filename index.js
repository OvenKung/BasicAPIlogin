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
  const { email, password, role = 'user', fullname } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.query('INSERT INTO users (email, password_hash, role, fullname) VALUES ($1, $2, $3, $4)', [email, hash, role, fullname]);
    res.json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'User may already exist', error: err.message });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query('SELECT password_hash, role, fullname FROM users WHERE email = $1', [email]);

    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password_hash)) {
      res.json({
        message: 'Login successful',
        email: email, // เพิ่ม email ลงใน response
        role: result.rows[0].role,
        fullname: result.rows[0].fullname
      });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Change Password Endpoint
app.post('/api/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  try {
    const result = await db.query('SELECT password_hash FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(oldPassword, result.rows[0].password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Old password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE email = $2', [newHash, email]);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Schedule Endpoint (fetch schedule)
app.post('/api/schedule', async (req, res) => {
  const { email } = req.body;

  try {
    const result = await db.query(
      'SELECT date, status, time_range FROM schedules WHERE email = $1 ORDER BY date',
      [email]
    );

    const schedules = result.rows.map(row => ({
      date: row.date,
      status: row.status,
      timeRange: row.time_range
    }));

    res.json({ schedules });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch schedules', error: err.message });
  }
});

// Request Leave Endpoint
// Body: { email: string, date: 'YYYY-MM-DD', timeRange?: string }
// If the schedule row already exists, change its status to 'pending'.
// Otherwise insert a new row with status = 'pending'.
app.post('/api/request-leave', async (req, res) => {
  const { email, date, timeRange = '09:00 - 17:00' } = req.body;

  try {
    const updateResult = await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3',
      ['pending', email, date]
    );

    // If no row was updated, create one.
    if (updateResult.rowCount === 0) {
      await db.query(
        'INSERT INTO schedules (email, date, status, time_range) VALUES ($1, $2, $3, $4)',
        [email, date, 'pending', timeRange]
      );
    }

    res.json({ message: 'Leave requested', date });
  } catch (err) {
    res.status(500).json({ message: 'Failed to request leave', error: err.message });
  }
});

// Cancel Leave Endpoint
// Body: { email: string, date: 'YYYY-MM-DD' }
// Revert the status back to 'work'.
app.post('/api/cancel-leave', async (req, res) => {
  const { email, date } = req.body;

  try {
    await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3',
      ['work', email, date]
    );
    res.json({ message: 'Leave canceled', date });
  } catch (err) {
    res.status(500).json({ message: 'Failed to cancel leave', error: err.message });
  }
});

// Add Schedule Endpoint
// Body: { email: string, date: 'YYYY-MM-DD', timeRange: string, status: string }
app.post('/api/add-schedule', async (req, res) => {
  const { email, date, timeRange, status } = req.body;

  try {
    await db.query(
      'INSERT INTO schedules (email, date, time_range, status) VALUES ($1, $2, $3, $4)',
      [email, date, timeRange, status]
    );

    res.json({ message: 'Schedule added successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add schedule', error: err.message });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));