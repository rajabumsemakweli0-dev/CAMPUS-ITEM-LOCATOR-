require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// PostgreSQL connection (Neon.tech)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test connection
pool.query('SELECT NOW()', (err) => {
  if (err) console.error('PostgreSQL connection failed:', err);
  else console.log('Connected to PostgreSQL (Neon.tech)');
});

// Multer for image uploads
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// Auth middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register (student)
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [name, email, phone, hashed, 'student']
    );
    const userId = result.rows[0].id;
    const token = jwt.sign({ id: userId, role: 'student', email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, role: 'student' });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      console.log('No user found for email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    console.log('User found:', user.email, 'Role:', user.role, 'Status:', user.status);

    if (user.status === 'blocked') return res.status(403).json({ error: 'Account blocked' });

    const match = await bcrypt.compare(password, user.password);
    console.log('Password from form:', password); // usi-share hii kwenye public
    console.log('Stored hash:', user.password);
    console.log('Password match result:', match);

    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, role: user.role });
  } catch (err) {
    console.error('Login error:', err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload item (student only)
app.post('/api/items', authenticate, upload.single('image'), async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Student only' });

  const { title, description, category, location, date_lost } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : '';

  try {
    await pool.query(
      'INSERT INTO items (title, description, category, location, date_lost, image, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [title, description, category, location, date_lost, image, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all items
app.get('/api/items', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM items ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
// ... code zingine zote ...

// Redirect root to login
app.get('/', (req, res) => {
  res.redirect('/base.html');
});
// Get total students (for admin dashboard)
app.get('/api/admin/students/count', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  try {
    const result = await pool.query("SELECT COUNT(*) AS count FROM users WHERE role = 'student'");
    res.json({ total: result.rows[0].count });
  } catch (err) {
    console.error('Students count error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get total items (for admin dashboard)
app.get('/api/admin/items/count', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  try {
    const result = await pool.query('SELECT COUNT(*) AS count FROM items');
    res.json({ total: result.rows[0].count });
  } catch (err) {
    console.error('Items count error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// Get all students (for admin manage students page)
app.get('/api/admin/students', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  try {
    const result = await pool.query('SELECT id, name, email, phone, role, status FROM users WHERE role = $1 ORDER BY created_at DESC', ['student']);
    res.json(result.rows);
  } catch (err) {
    console.error('Get students error:', err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});
// Add more routes as needed (my-items, mark-found, admin routes)

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});