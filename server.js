// ==========================================
//  ALUMNI NETWORK BACKEND (CLEAN VERSION)
//  OTP EMAIL VERIFICATION + JOBS + EVENTS
// ==========================================

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

// Railway/Heroku require trust proxy for correct IP + rate-limit
app.set("trust proxy", 1);

// --------------------------
// DATABASE CONNECTION
// --------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query("SELECT NOW()", (err) => {
  if (err) console.error("Database connection error:", err);
  else console.log("Database connected successfully");
});

// --------------------------
// EMAIL TRANSPORT (BREVO SMTP)
// --------------------------
const axios = require("axios");

async function sendOtpEmail(email, otp) {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { email: process.env.FROM_EMAIL },
        to: [{ email }],
        subject: "Your OTP for Alumni Network",
        htmlContent: `<h2>Your OTP is: <strong>${otp}</strong></h2>`
      },
      {
        headers: {
          "accept": "application/json",
          "api-key": process.env.BREVO_API_KEY,
          "content-type": "application/json"
        }
      }
    );

    console.log("OTP email sent using Brevo API");
  } catch (err) {
    console.error("OTP Email Error:", err.response?.data || err.message);
  }
}


// --------------------------
// MIDDLEWARE
// --------------------------
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiter (100 requests / 15 min)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use("/api/", limiter);

// --------------------------
// UTILS - OTP GENERATOR
// --------------------------
function generateOtpAndExpiry(minutes = 10) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = new Date(Date.now() + minutes * 60000);
  return { otp, expiry };
}

// --------------------------
// AUTH MIDDLEWARE
// --------------------------
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer "))
    return res.status(401).json({ message: "Authentication required" });

  const token = auth.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// --------------------------
// HEALTH CHECK
// --------------------------
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ==========================================
//                AUTH ROUTES
// ==========================================

// --------------------------
// REGISTER → Send OTP (FIXED VERSION)
// --------------------------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName, passoutYear } = req.body;

    if (!email || !password || !firstName || !lastName || !passoutYear)
      return res.status(400).json({ message: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const { otp, expiry } = generateOtpAndExpiry();

    await pool.query(
      `INSERT INTO users (
         email, password, first_name, last_name, passout_year,
         verification_status, otp, otp_expires, created_at, updated_at
       )
       VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,NOW(),NOW())
       ON CONFLICT (email) DO UPDATE SET
         password = EXCLUDED.password,
         first_name = EXCLUDED.first_name,
         last_name = EXCLUDED.last_name,
         passout_year = EXCLUDED.passout_year,
         verification_status = 'pending',
         otp = EXCLUDED.otp,
         otp_expires = EXCLUDED.otp_expires,
         updated_at = NOW()`,
      [email, hashedPassword, firstName, lastName, passoutYear, otp, expiry]
    );

    // 👉 SEND OTP USING BREVO API
    await sendOtpEmail(email, otp);

    console.log("OTP issued:", otp);

    res.json({ message: "OTP sent to email", email });

  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Registration failed" });
  }
});


// --------------------------
// VERIFY OTP
// --------------------------
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const q = await pool.query(
      "SELECT id, otp, otp_expires FROM users WHERE email = $1",
      [email]
    );

    if (q.rows.length === 0)
      return res.status(400).json({ message: "User not found" });

    const user = q.rows[0];

    if (user.otp !== otp)
      return res.status(400).json({ message: "Incorrect OTP" });

    if (new Date(user.otp_expires) < new Date())
      return res.status(400).json({ message: "OTP expired" });

    await pool.query(
      `UPDATE users
       SET verification_status = 'verified', otp = NULL, otp_expires = NULL
       WHERE id = $1`,
      [user.id]
    );

    res.json({ message: "Email verified successfully" });

  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ message: "OTP verification failed" });
  }
});

// --------------------------
// RESEND OTP
// --------------------------
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    const q = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    if (q.rows.length === 0)
      return res.status(400).json({ message: "User not found" });

    const { otp, expiry } = generateOtpAndExpiry();

    await pool.query(
      "UPDATE users SET otp = $1, otp_expires = $2, verification_status = 'pending' WHERE email = $3",
      [otp, expiry, email]
    );

    await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: email,
      subject: "Your New OTP",
      html: `<h2>Your new OTP is: <strong>${otp}</strong></h2>`,
    });

    console.log("Resent OTP:", otp);

    res.json({ message: "OTP resent" });

  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ message: "Failed to resend OTP" });
  }
});

// --------------------------
// LOGIN (requires verified email)
// --------------------------
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const q = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (q.rows.length === 0)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = q.rows[0];

    if (user.verification_status !== "verified")
      return res.status(403).json({
        message: "Please verify your email before logging in",
      });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ message: "Invalid credentials" });

    await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [
      user.id,
    ]);

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    delete user.password;

    res.json({ token, user });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

// ==========================================
//          USER + DIRECTORY + PROFILE
// ==========================================

// GET CURRENT USER
app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      "SELECT id, email, first_name, last_name, headline, bio, role FROM users WHERE id = $1",
      [req.userId]
    );

    if (q.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json({ user: q.rows[0] });

  } catch (err) {
    console.error("Me error:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

// DIRECTORY LISTING
app.get("/api/users/directory", verifyToken, async (req, res) => {
  try {
    const { search, passoutYear, limit = 20, offset = 0 } = req.query;

    let query = `
      SELECT id, first_name, last_name, email, headline, bio, passout_year
      FROM users WHERE verification_status = 'verified'
    `;

    const params = [];
    let i = 1;

    if (search) {
      query += ` AND (first_name ILIKE $${i} OR last_name ILIKE $${i} OR email ILIKE $${i})`;
      params.push(`%${search}%`);
      i++;
    }

    if (passoutYear) {
      query += ` AND passout_year = $${i}`;
      params.push(passoutYear);
      i++;
    }

    query += ` ORDER BY created_at DESC LIMIT $${i} OFFSET $${i + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({ users: result.rows });

  } catch (err) {
    console.error("Directory error:", err);
    res.status(500).json({ message: "Failed to fetch directory" });
  }
});

// UPDATE PROFILE
app.put("/api/users/profile", verifyToken, async (req, res) => {
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
      github,
    } = req.body;

    const q = await pool.query(
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
      [
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
        github,
        req.userId,
      ]
    );

    res.json({ user: q.rows[0] });

  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});
// GET SINGLE USER PROFILE BY ID
app.get("/api/users/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const q = await pool.query(
      `SELECT id, first_name, last_name, email, headline, bio, 
              passout_year, skills, current_company, current_position, 
              location, website, linkedin, github
       FROM users 
       WHERE id = $1 AND verification_status = 'verified'`,
      [id]
    );

    if (q.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user: q.rows[0] });

  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});


// DIRECTORY LISTING
app.get("/api/users/directory", verifyToken, async (req, res) => {
  // ... existing code
});

// 👇 ADD THE NEW ENDPOINT HERE
app.get("/api/users/:id", verifyToken, async (req, res) => {
  // ... new code above
});
// ==========================================
//                JOBS
// ==========================================

// GET JOBS
app.get("/api/jobs", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT j.*, u.first_name, u.last_name
       FROM jobs j
       JOIN users u ON j.posted_by = u.id
       WHERE j.is_active = true
       ORDER BY j.created_at DESC
       LIMIT 50`
    );

    res.json({ jobs: q.rows });

  } catch (err) {
    console.error("Get jobs error:", err);
    res.status(500).json({ message: "Failed to fetch jobs" });
  }
});

// CREATE JOB
// CREATE JOB
app.post("/api/jobs", verifyToken, async (req, res) => {
  try {
    console.log("📝 Creating job with data:", req.body);
    console.log("👤 Posted by user ID:", req.userId);
    
    const {
      title,
      company,
      description,
      requirements,
      location,
      salaryRange,
      jobType,
      experienceLevel,
    } = req.body;

    // Validate required fields
    if (!title || !company || !description) {
      console.log("❌ Missing required fields");
      return res.status(400).json({ 
        message: "Title, company, and description are required" 
      });
    }

    const q = await pool.query(
      `INSERT INTO jobs (
         posted_by, title, company, description, requirements,
         location, salary_range, job_type, experience_level
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        req.userId,
        title,
        company,
        description,
        requirements || null,
        location || null,
        salaryRange || null,
        jobType || null,
        experienceLevel || null,
      ]
    );

    console.log("✅ Job created successfully:", q.rows[0].id);
    res.status(201).json({ job: q.rows[0] });

  } catch (err) {
    console.error("❌ Create job error:", err);
    console.error("Error details:", err.message);
    res.status(500).json({ 
      message: "Failed to create job",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
// ==========================================
//               EVENTS
// ==========================================

// GET UPCOMING EVENTS
app.get("/api/events", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT e.*, u.first_name, u.last_name
       FROM events e
       JOIN users u ON e.created_by = u.id
       WHERE e.is_active = true
       AND e.start_time > NOW()
       ORDER BY e.start_time ASC
       LIMIT 50`
    );

    res.json({ events: q.rows });

  } catch (err) {
    console.error("Events error:", err);
    res.status(500).json({ message: "Failed to fetch events" });
  }
});

// ==========================================
// ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  res.status(500).json({ message: "Server error" });
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));





