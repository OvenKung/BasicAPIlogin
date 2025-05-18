const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');
const bodyParser = require('body-parser');

// Ensure the users table has a 'status' TEXT column with values like 'active' | 'disabled'

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Register (status = active)
app.post('/api/register', async (req, res) => {
  const { email, password, role = 'user', fullname, imageUrl } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.query(
      'INSERT INTO users (email, password_hash, role, fullname, image_url, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [email, hash, role, fullname, imageUrl, 'active']
    );
    res.json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'User may already exist', error: err.message });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const q = await db.query(
      'SELECT password_hash, role, fullname, image_url, COALESCE(status, \'active\') AS status FROM users WHERE email = $1',
      [email.trim()]
    );

    if (q.rows.length === 0)
      return res.status(401).json({ message: 'Invalid credentials' });

    const row    = q.rows[0];
    const status = (row.status || 'active').toString().trim().toLowerCase();

    /*  🔒  If not explicitly “active” → reject login  */
    if (status !== 'active')
      return res.status(403).json({ message: 'Account disabled' });

    /*  check password  */
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok)
      return res.status(401).json({ message: 'Invalid credentials' });

    res.json({
      message : 'Login successful',
      email   : email.trim(),
      role    : row.role,
      fullname: row.fullname,
      imageUrl: row.image_url ?? null,
      status  : status
    });
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

app.post('/api/schedule', async (req, res) => {
  const { email } = req.body;
  console.log("📩 Email received:", email); // ✅ LOG นี้ดูว่าค่าเป็นอะไร

  try {
    let result;
    if (email && email !== '*') {
      console.log("🔍 Query for specific user...");
      result = await db.query(
        'SELECT email, date, status, time_range, COALESCE(reason, \'\') AS reason FROM schedules WHERE email = $1 ORDER BY date',
        [email]
      );
    } else {
      console.log("🔍 Query for all pending...");
      result = await db.query(
        "SELECT email, date, status, time_range, COALESCE(reason, '') AS reason FROM schedules WHERE status = 'pending' ORDER BY date"
      );
    }

    console.log("📦 Result:", result.rows); // ✅ LOG ดูผลลัพธ์

    const schedules = result.rows.map(row => ({
      email: row.email,
      date: row.date,
      status: row.status,
      timeRange: row.time_range,
      reason: row.reason
    }));

    res.json({ schedules });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch schedules', error: err.message });
  }
});
// ✅ GET schedule by email and date (used for QR scan)
app.get('/api/schedule', async (req, res) => {
  const { email = '*', date } = req.query;
  if (!date) return res.status(400).json({ message: 'Missing date' });

  try {
    const q = email === '*'
      ? await db.query(
          `SELECT s.email,
                  s.date,
                  s.status,
                  s.time_range,
                  COALESCE(s.reason,'') AS reason,
                  COALESCE(u.image_url,'') AS image_url
             FROM schedules s
             LEFT JOIN users u ON u.email = s.email
            WHERE s.date = $1
            ORDER BY s.email`,
          [date]
        )
      : await db.query(
          `SELECT s.email,
                  s.date,
                  s.status,
                  s.time_range,
                  COALESCE(s.reason,'') AS reason,
                  COALESCE(u.image_url,'') AS image_url
             FROM schedules s
             LEFT JOIN users u ON u.email = s.email
            WHERE s.email = $1
              AND s.date  = $2`,
          [email, date]
        );

    if (q.rows.length === 0)
      return res.status(404).json({ message: 'Schedule not found' });

    // ส่งออกเป็น array สม่ำเสมอ
    const schedules = q.rows.map(r => {
      const [startTime, endTime] = r.time_range.split(' - ');
      return { email: r.email, date: r.date, status: r.status, startTime, endTime, imageUrl: r.image_url, reason: r.reason };
    });

    res.json({ schedules });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch', error: err.message });
  }
});
// Request Leave Endpoint
// Body: { email: string, date: 'YYYY-MM-DD', timeRange?: string }
// If the schedule row already exists, change its status to 'pending'.
// Otherwise insert a new row with status = 'pending'.
app.post('/api/request-leave', async (req, res) => {
  const { email, date, timeRange = '09:00 - 17:00', reason = '' } = req.body;

  try {
    const updateResult = await db.query(
      'UPDATE schedules SET status = $1, reason = $2 WHERE email = $3 AND date = $4',
      ['pending', reason, email, date]
    );

    // If no row was updated, create one.
    if (updateResult.rowCount === 0) {
      await db.query(
        'INSERT INTO schedules (email, date, status, time_range, reason) VALUES ($1, $2, $3, $4, $5)',
        [email, date, 'pending', timeRange, reason]
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

// Update Schedule Endpoint
// Body: { email, oldDate, oldTimeRange, date, timeRange, status }
app.post('/api/update-schedule', async (req, res) => {
  const { email, oldDate, oldTimeRange, date, timeRange, status } = req.body;

  if (!email || !oldDate || !oldTimeRange || !date || !timeRange || !status) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  try {
    const result = await db.query(
      `UPDATE schedules
          SET date = $1,
              time_range = $2,
              status = $3
        WHERE email      = $4
          AND date       = $5
          AND time_range = $6`,
      [date, timeRange, status, email, oldDate, oldTimeRange]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Schedule not found to update' });
    }

    res.json({ message: 'Schedule updated' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update schedule', error: err.message });
  }
});

// Approve Leave Endpoint
// Body: { email: string, date: 'YYYY-MM-DD' }
app.post('/api/approve-leave', async (req, res) => {
  const { email, date } = req.body;

  try {
    await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3 AND status = $4',
      ['leave', email, date, 'pending']
    );
    res.json({ message: 'Leave approved', date });
  } catch (err) {
    res.status(500).json({ message: 'Failed to approve leave', error: err.message });
  }
});

// Reject Leave Endpoint
// Body: { email: string, date: 'YYYY-MM-DD' }
app.post('/api/reject-leave', async (req, res) => {
  const { email, date } = req.body;

  try {
    await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3 AND status = $4',
      ['work', email, date, 'pending']
    );
    res.json({ message: 'Leave rejected', date });
  } catch (err) {
    res.status(500).json({ message: 'Failed to reject leave', error: err.message });
  }
});

// Update Leave Status Endpoint (Unified for Approve/Reject)
// Body: { email: string, date: 'YYYY-MM-DD', status: 'leave' | 'work' }
app.post('/api/update-leave-status', async (req, res) => {
  const { email, date, status } = req.body;

  if (!email || !date || !status) {
    return res.status(400).json({ message: 'Missing email, date, or status' });
  }

  try {
    const result = await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3 AND status = $4',
      [status, email, date, 'pending']
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'No pending schedule found to update' });
    }

    res.json({ message: `Status updated to '${status}'`, date });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status', error: err.message });
  }
});

// Check-In Endpoint
// Body: { email: string, date: 'YYYY-MM-DD' }
app.post('/api/checkin', async (req, res) => {
  const { email, date, status } = req.body;

  if (!email || !date || !status) {
    return res.status(400).json({ message: 'Missing data' });
  }

  try {
    const result = await db.query(
      'SELECT status FROM schedules WHERE email = $1 AND date = $2',
      [email, date]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    const currentStatus = result.rows[0].status;
    if (currentStatus !== 'work') {
      return res.status(400).json({ message: `Cannot check in. Current status: ${currentStatus}` });
    }

    await db.query(
      'UPDATE schedules SET status = $1 WHERE email = $2 AND date = $3',
      [status, email, date]
    );

    res.json({ message: `Check-in successful: ${status}`, date });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// POST /api/update-user
// body: { email, fullname, role, imageUrl, password? }
app.post('/api/update-user', async (req, res) => {
  const { email, fullname, role, imageUrl, status, password } = req.body;

  /* ------ ตรวจ params ------ */
  if (!email) return res.status(400).json({ message: 'Missing email' });

  /* ------ สร้าง SET clause แบบ dynamic ------ */
  const fields   = [];
  const values   = [];
  let   idx      = 1;            // $1, $2, …

  const pushSet = (col, val) => {
    fields.push(`${col} = $${idx}`);
    values.push(val);
    idx++;
  };

  if (fullname !== undefined) pushSet('fullname' , fullname);
  if (role     !== undefined) pushSet('role'     , role);
  if (imageUrl !== undefined) pushSet('image_url', imageUrl);
  if (status   !== undefined) pushSet('status'   , status);

  if (password && password.trim() !== '') {
    const hash = await bcrypt.hash(password, 10);
    pushSet('password_hash', hash);
  }

  if (fields.length === 0)
    return res.status(400).json({ message: 'Nothing to update' });

  /* push email เป็น parameter สุดท้าย */
  values.push(email);

  try {
    const q = await db.query(
      `UPDATE users SET ${fields.join(', ')} WHERE email = $${idx}`,
      values
    );

    if (q.rowCount === 0)
      return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'User updated' });
  } catch (err) {
    res.status(500).json({ message: 'Update failed', error: err.message });
  }
});

// ────────────────────────────────
// Get all users (includes status)
app.get('/api/users', async (req, res) => {
  try {
    const q = await db.query(
      "SELECT email, fullname, role, COALESCE(image_url, '') AS image_url, status FROM users ORDER BY fullname"
    );
    res.json({ users: q.rows }); // return { users: [...] }
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users', error: err.message });
  }
});

app.delete('/api/users/:email', async (req, res) => {
  const email = decodeURIComponent(req.params.email || '').trim();

  if (!email) {
    return res.status(400).json({ message: 'Missing e‑mail in URL' });
  }

  try {
    const q = await db.query(
      'UPDATE users SET status = $1 WHERE email = $2 AND status <> $1',
      ['disabled', email]
    );

    if (q.rowCount === 0)
      return res.status(404).json({ message: 'User not found or already disabled' });

    res.json({ message: 'User disabled' });
  } catch (err) {
    res.status(500).json({ message: 'Disable failed', error: err.message });
  }
});
// ────────────────────────────────

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));