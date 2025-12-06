// server.js - OTP-enabled backend with email sending (Nodemailer)

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// trust proxy for rate-limit behind proxies (Railway/Heroku)
app.set('trust proxy', 1);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected successfully');
});

// Nodemailer transporter (Gmail example)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting (applies to /api/)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use('/api/', limiter);

// Helper: generate 6-digit OTP and expiry Date object
function generateOtpAndExpiry(minutes = 10) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = new Date(Date.now() + minutes * 60 * 1000);
  return { otp, expiry };
}

// Auth middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ---------------------------
// Register (OTP send by email)
// ---------------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, passoutYear, collegeDomain } = req.body;

    if (!email || !password || !firstName || !lastName || !passoutYear) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const domain = collegeDomain || 'college.edu';

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // generate OTP + expiry
    const { otp, expiry } = generateOtpAndExpiry(10); // 10 minutes

    // Insert or update: set verification_status = 'pending'
    await pool.query(
      `INSERT INTO users (
         email, password, first_name, last_name, passout_year,
         college_domain, verification_status, otp, otp_expires, created_at, updated_at
       ) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,NOW(),NOW())
       ON CONFLICT (email) DO UPDATE SET
         password = EXCLUDED.password,
         first_name = COALESCE(EXCLUDED.first_name, users.first_name),
         last_name = COALESCE(EXCLUDED.last_name, users.last_name),
         passout_year = COALESCE(EXCLUDED.passout_year, users.passout_year),
         college_domain = COALESCE(EXCLUDED.college_domain, users.college_domain),
         verification_status = 'pending',
         otp = EXCLUDED.otp,
         otp_expires = EXCLUDED.otp_expires,
         updated_at = NOW()
      `,
      [email, hashedPassword, firstName, lastName, passoutYear, domain, otp, expiry]
    );

    // Send OTP email
    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Alumni Network',
      text: `Your verification OTP is ${otp}. It expires in 10 minutes.`
    };

    // send email (catch but don't crash)
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Error sending OTP email:', err);
      } else {
        console.log('OTP email sent:', info.response || info);
      }
    });

    // For development you can also log the OTP
    console.log('Issued OTP (for debugging):', otp);

    return res.json({ message: 'OTP sent to email (check inbox)', email });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ message: 'Registration failed' });
  }
});

// ---------------------------
// Verify OTP
// ---------------------------
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: 'Email and OTP required' });

    const q = await pool.query('SELECT id, otp, otp_expires FROM users WHERE email = $1', [email]);
    if (q.rows.length === 0) return res.status(400).json({ message: 'User not found' });

    const row = q.rows[0];
    if (!row.otp || row.otp !== otp) return res.status(400).json({ message: 'Incorrect OTP' });

    const now = new Date();
    if (row.otp_expires && new Date(row.otp_expires) < now) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    await pool.query(
      `UPDATE users SET verification_status = 'verified', otp = NULL, otp_expires = NULL, updated_at = NOW()
       WHERE id = $1`,
      [row.id]
    );

    return res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('OTP verify error:', error);
    return res.status(500).json({ message: 'OTP verification failed' });
  }
});

// ---------------------------
// Resend OTP
// ---------------------------
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email required' });

    const q = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (q.rows.length === 0) return res.status(400).json({ message: 'User not found' });

    const { otp, expiry } = generateOtpAndExpiry(10);
    await pool.query('UPDATE users SET otp = $1, otp_expires = $2, verification_status = $3, updated_at = NOW() WHERE email = $4',
                     [otp, expiry, 'pending', email]);

    // send email
    transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Alumni Network (resend)',
      text: `Your verification OTP is ${otp}. It expires in 10 minutes.`
    }, (err, info) => {
      if (err) console.error('Resend OTP email error:', err);
      else console.log('Resend OTP email sent:', info.response || info);
    });

    console.log('Resent OTP (for debugging):', otp);

    return res.json({ message: 'OTP resent' });
  } catch (error) {
    console.error('Resend OTP error:', error);
    return res.status(500).json({ message: 'Failed to resend OTP' });
  }
});

// ---------------------------
// Login (blocks unverified users)
// ---------------------------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const q = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (q.rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

    const user = q.rows[0];
    if (user.verification_status !== 'verified') {
      return res.status(403).json({ message: 'Please verify your email before logging in' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    delete user.password;
    return res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Login failed' });
  }
});

// ---------------------------
// Other endpoints stay same (me, directory, profile, jobs, events)
// We reuse your existing handlers below -- paste/keep the rest of your code
// For brevity I'll re-add your existing handlers (adapted slightly):
// ---------------------------

// Get current user
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, first_name, last_name, role, verification_status, headline, bio FROM users WHERE id = $1',
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Failed to fetch user' });
  }
});

// Directory
app.get('/api/users/directory', verifyToken, async (req, res) => {
  try {
    const { search, passoutYear, limit = 20, offset = 0 } = req.query;

    let query = `
      SELECT id, first_name, last_name, email, headline, bio, 
             passout_year, current_company, current_position, 
             profile_picture_url, skills
      FROM users 
      WHERE verification_status = 'verified'
    `;

    const params = [];
    let paramIndex = 1;

    if (search) {
      query += ` AND (first_name ILIKE $${paramIndex} OR last_name ILIKE $${paramIndex} OR email ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    if (passoutYear) {
      query += ` AND passout_year = $${paramIndex}`;
      params.push(passoutYear);
      paramIndex++;
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({ users: result.rows, count: result.rows.length });
  } catch (error) {
    console.error('Directory error:', error);
    res.status(500).json({ message: 'Failed to fetch directory' });
  }
});

// Update profile
app.put('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      headline,
      bio,
      skills,
      currentCompany,
      currentPosition,
      location,
      website,
      linkedin,
      github
    } = req.body;

    const result = await pool.query(
      `UPDATE users SET 
        first_name = COALESCE($1, first_name),
        last_name = COALESCE($2, last_name),
        headline = COALESCE($3, headline),
        bio = COALESCE($4, bio),
        skills = COALESCE($5, skills),
        current_company = COALESCE($6, current_company),
        current_position = COALESCE($7, current_position),
        location = COALESCE($8, location),
        website = COALESCE($9, website),
        linkedin = COALESCE($10, linkedin),
        github = COALESCE($11, github),
        updated_at = NOW()
      WHERE id = $12
      RETURNING id, email, first_name, last_name, headline, bio`,
      [firstName, lastName, headline, bio, skills, currentCompany, 
       currentPosition, location, website, linkedin, github, req.userId]
    );

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

// Jobs (GET/POST)
app.get('/api/jobs', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT j.*, u.first_name, u.last_name 
      FROM jobs j
      JOIN users u ON j.posted_by = u.id
      WHERE j.is_active = true
      ORDER BY j.created_at DESC
      LIMIT 50
    `);
    
    res.json({ jobs: result.rows });
  } catch (error) {
    console.error('Get jobs error:', error);
    res.status(500).json({ message: 'Failed to fetch jobs' });
  }
});

app.post('/api/jobs', verifyToken, async (req, res) => {
  try {
    const {
      title,
      company,
      description,
      requirements,
      location,
      salaryRange,
      jobType,
      experienceLevel
    } = req.body;
    
    const result = await pool.query(
      `INSERT INTO jobs (
        posted_by, title, company, description, requirements,
        location, salary_range, job_type, experience_level
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *`,
      [req.userId, title, company, description, requirements,
       location, salaryRange, jobType, experienceLevel]
    );
    
    res.status(201).json({ job: result.rows[0] });
  } catch (error) {
    console.error('Create job error:', error);
    res.status(500).json({ message: 'Failed to create job' });
  }
});

// Events
app.get('/api/events', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, u.first_name, u.last_name 
      FROM events e
      JOIN users u ON e.created_by = u.id
      WHERE e.is_active = true AND e.start_time > NOW()
      ORDER BY e.start_time ASC
      LIMIT 50
    `);
    
    res.json({ events: result.rows });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ message: 'Failed to fetch events' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    message: err.message || 'Something went wrong!',
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
