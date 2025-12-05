const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully');
  }
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

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

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      passoutYear,
      collegeDomain
    } = req.body;
    
    // Validate required fields
    if (!email || !password || !firstName || !lastName || !passoutYear) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const result = await pool.query(
      `INSERT INTO users (
        email, password, first_name, last_name, 
        passout_year, college_domain, verification_status
      ) VALUES ($1, $2, $3, $4, $5, $6, 'verified') 
      RETURNING id, email, first_name, last_name, verification_status`,
      [email, hashedPassword, firstName, lastName, passoutYear, collegeDomain || 'edu.in']
    );
    
    const user = result.rows[0];
    
    res.status(201).json({
      message: 'Registration successful',
      user
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Remove password from response
    delete user.password;
    
    res.json({ token, user });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

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

// Get all users (directory)
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

// Get jobs
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

// Create job
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

// Get events
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
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});