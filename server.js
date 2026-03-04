// ==========================================
//  ALUMNI NETWORK BACKEND (FINAL VERSION)
// ==========================================

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
require("dotenv").config();

const app = express();

app.set("trust proxy", 1);

// --------------------------
// DATABASE CONNECTION
// --------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query("SELECT NOW()", (err) => {
  if (err) console.error("❌ Database connection error:", err);
  else console.log("✅ Database connected successfully");
});

// --------------------------
// MIDDLEWARE (MUST BE BEFORE ROUTES)
// --------------------------
app.use(helmet());

// ✅ FIXED CORS CONFIGURATION
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use("/api/", limiter);

// --------------------------
// UTILS
// --------------------------
function generateOtpAndExpiry(minutes = 10) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = new Date(Date.now() + minutes * 60000);
  return { otp, expiry };
}

// --------------------------
// EMAIL FUNCTION
// --------------------------
async function sendOtpEmail(email, otp) {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { email: process.env.FROM_EMAIL, name: "Alumni Network" },
        to: [{ email }],
        subject: "🎓 Verify Your Email - Alumni Network",
        htmlContent: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; background: #f9fafb; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; background: white; border-radius: 8px; }
              .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
              .content { padding: 20px; }
              .otp-box { background: #f3f4f6; padding: 20px; text-align: center; margin: 20px 0; border: 2px solid #2563eb; border-radius: 8px; }
              .otp-code { font-size: 30px; font-weight: bold; color: #2563eb; letter-spacing: 8px; font-family: monospace; }
              .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>🎓 Alumni Network</h1>
              </div>
              <div class="content">
                <p>Hello,</p>
                <p>You're almost there! Use the OTP below to verify your email address:</p>
                
                <div class="otp-box">
                  <p style="margin: 0 0 10px 0; color: #6b7280;">Your verification code:</p>
                  <div class="otp-code">${otp}</div>
                  <p style="margin: 10px 0 0 0; color: #6b7280; font-size: 14px;">Valid for 10 minutes</p>
                </div>
                
                <p>If you didn't request this, please ignore this email.</p>
                
                <p>Best regards,<br><strong>Alumni Network Team</strong></p>
              </div>
              <div class="footer">
                <p>&copy; 2024 Alumni Network. All rights reserved.</p>
              </div>
            </div>
          </body>
          </html>
        `
      },
      {
        headers: {
          "accept": "application/json",
          "api-key": process.env.BREVO_API_KEY,
          "content-type": "application/json"
        }
      }
    );
    console.log("✅ OTP email sent to:", email);
  } catch (err) {
    console.error("❌ OTP Email Error:", err.response?.data || err.message);
  }
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

    await sendOtpEmail(email, otp);
    console.log("📧 OTP issued:", otp);

    res.json({ message: "OTP sent to email", email });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ message: "Registration failed" });
  }
});

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
    console.error("❌ Verify OTP error:", err);
    res.status(500).json({ message: "OTP verification failed" });
  }
});

// ✅ RESEND OTP ENDPOINT
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    const q = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (q.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const { otp, expiry } = generateOtpAndExpiry();

    await pool.query(
      "UPDATE users SET otp = $1, otp_expires = $2 WHERE email = $3",
      [otp, expiry, email]
    );

    await sendOtpEmail(email, otp);
    console.log("📧 OTP resent:", otp);

    res.json({ message: "OTP sent to email" });
  } catch (err) {
    console.error("❌ Resend OTP error:", err);
    res.status(500).json({ message: "Failed to resend OTP" });
  }
});

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
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

// ✅ FORGOT PASSWORD ENDPOINT
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const q = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (q.rows.length === 0) {
      return res.status(404).json({ message: "Email not found" });
    }

    const userId = q.rows[0].id;
    const resetToken = jwt.sign(
      { userId, type: "reset" },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Store reset token in database
    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '1 hour' WHERE id = $2",
      [resetToken, userId]
    );

    // Send reset email
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { email: process.env.FROM_EMAIL, name: "Alumni Network" },
        to: [{ email }],
        subject: "🔐 Reset Your Password - Alumni Network",
        htmlContent: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; background: #f9fafb; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; background: white; border-radius: 8px; }
              .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
              .content { padding: 20px; }
              .button { background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; }
              .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>🎓 Alumni Network</h1>
              </div>
              <div class="content">
                <p>Hello,</p>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                
                <div style="text-align: center;">
                  <a href="${resetLink}" class="button">Reset Password</a>
                </div>
                
                <p style="color: #6b7280; font-size: 14px;">
                  This link expires in 1 hour.
                </p>
                
                <p>If you didn't request this, please ignore this email.</p>
                
                <p>Best regards,<br><strong>Alumni Network Team</strong></p>
              </div>
              <div class="footer">
                <p>&copy; 2024 Alumni Network. All rights reserved.</p>
              </div>
            </div>
          </body>
          </html>
        `
      },
      {
        headers: {
          "accept": "application/json",
          "api-key": process.env.BREVO_API_KEY,
          "content-type": "application/json"
        }
      }
    );

    console.log("✅ Password reset link sent to:", email);
    res.json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.error("❌ Forgot password error:", err);
    res.status(500).json({ message: "Failed to send reset link" });
  }
});

// ✅ RESET PASSWORD ENDPOINT
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: "Token and password are required" });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    // Check if reset token matches in database
    const q = await pool.query(
      "SELECT id, reset_token_expires FROM users WHERE id = $1 AND reset_token = $2",
      [decoded.userId, token]
    );

    if (q.rows.length === 0) {
      return res.status(400).json({ message: "Invalid reset token" });
    }

    if (new Date(q.rows[0].reset_token_expires) < new Date()) {
      return res.status(400).json({ message: "Reset token has expired" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Update password and clear reset token
    await pool.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2",
      [hashedPassword, decoded.userId]
    );

    console.log("✅ Password reset successful for user:", decoded.userId);
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("❌ Reset password error:", err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// ==========================================
//          USER ROUTES (FIXED)
// ==========================================

app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT id, email, first_name, last_name, headline, bio, role, 
              location, current_company as company, passout_year
       FROM users WHERE id = $1`,
      [req.userId]
    );

    if (q.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json({ user: q.rows[0] });
  } catch (err) {
    console.error("❌ Me error:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

app.get("/api/users/directory", verifyToken, async (req, res) => {
  try {
    const { search, passoutYear, limit = 20, offset = 0 } = req.query;

    let query = `
      SELECT id, first_name, last_name, email, headline, bio, passout_year,
             location, current_company as company
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
    console.error("❌ Directory error:", err);
    res.status(500).json({ message: "Failed to fetch directory" });
  }
});

app.get("/api/users/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const q = await pool.query(
      `SELECT id, first_name, last_name, email, headline, bio, 
              passout_year, skills, current_company as company, current_position, 
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
    console.error("❌ Get user error:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

app.put("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { headline, bio, location, company } = req.body;

    console.log("📝 Updating profile for user:", req.userId);
    console.log("Data received:", { headline, bio, location, company });

    const q = await pool.query(
      `UPDATE users SET
         headline = COALESCE($1, headline),
         bio = COALESCE($2, bio),
         location = COALESCE($3, location),
         current_company = COALESCE($4, current_company),
         updated_at = NOW()
       WHERE id = $5
       RETURNING id, email, first_name, last_name, headline, bio, location, 
                 current_company as company`,
      [headline, bio, location, company, req.userId]
    );

    console.log("✅ Profile updated successfully");
    res.json({ user: q.rows[0] });
  } catch (err) {
    console.error("❌ Profile update error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

// DELETE ACCOUNT (user deletes their own account)
app.delete("/api/users/account", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    // Delete all job applications from this user
    await pool.query(
      "DELETE FROM job_applications WHERE applicant_id = $1",
      [userId]
    );

    // Delete all jobs posted by this user
    await pool.query(
      "DELETE FROM jobs WHERE posted_by = $1",
      [userId]
    );

    // Delete the user account
    await pool.query(
      "DELETE FROM users WHERE id = $1",
      [userId]
    );

    console.log("✅ Account deleted:", userId);
    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("❌ Delete account error:", err);
    res.status(500).json({ message: "Failed to delete account" });
  }
});

// ==========================================
//          JOBS ROUTES (FIXED)
// ==========================================

app.get("/api/jobs", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT 
        j.id, j.title, j.company, j.description, j.requirements,
        j.location, j.salary_range, j.job_type, j.experience_level,
        j.is_active, j.created_at, j.expires_at, j.posted_by,
        u.first_name,
        u.last_name,
        COUNT(ja.id) as application_count
       FROM jobs j
       JOIN users u ON j.posted_by = u.id
       LEFT JOIN job_applications ja ON j.id = ja.job_id
       WHERE j.is_active = true OR j.posted_by = $1
       GROUP BY j.id, u.first_name, u.last_name
       ORDER BY j.created_at DESC
       LIMIT 50`,
      [req.userId]
    );

    res.json({ jobs: q.rows });
  } catch (err) {
    console.error("❌ Get jobs error:", err);
    res.status(500).json({ message: "Failed to fetch jobs" });
  }
});

app.post("/api/jobs", verifyToken, async (req, res) => {
  try {
    console.log("📝 Creating job, user:", req.userId);
    console.log("Request body:", req.body);
    
    const {
      title,
      company,
      description,
      requirements,
      location,
      salaryRange,
      jobType,
      experienceLevel,
      expiresAt
    } = req.body;

    if (!title || !company || !description) {
      return res.status(400).json({ 
        message: "Title, company, and description are required" 
      });
    }

    const q = await pool.query(
      `INSERT INTO jobs (
         posted_by, title, company, description, requirements,
         location, salary_range, job_type, experience_level, expires_at, 
         is_active, created_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,NOW())
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
        expiresAt || null
      ]
    );

    console.log("✅ Job created with ID:", q.rows[0].id);
    res.status(201).json({ 
      job: q.rows[0], 
      message: "Job posted successfully" 
    });
  } catch (err) {
    console.error("❌ CREATE JOB ERROR:", err);
    res.status(500).json({ 
      message: "Failed to create job",
      error: err.message
    });
  }
});

// DELETE JOB (only by who posted it)
app.delete("/api/jobs/:jobId", verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const jobCheck = await pool.query(
      "SELECT posted_by FROM jobs WHERE id = $1",
      [jobId]
    );

    if (jobCheck.rows.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }

    if (jobCheck.rows[0].posted_by !== req.userId) {
      return res.status(403).json({ message: "You can only delete jobs you posted" });
    }

    await pool.query("DELETE FROM jobs WHERE id = $1", [jobId]);

    console.log("✅ Job deleted:", jobId);
    res.json({ message: "Job deleted successfully" });
  } catch (err) {
    console.error("❌ Delete job error:", err);
    res.status(500).json({ message: "Failed to delete job" });
  }
});

// ==========================================
//         JOB APPLICATIONS
// ==========================================

app.post("/api/jobs/:jobId/apply", verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { coverLetter, resume, phone, linkedinUrl } = req.body;

    const existing = await pool.query(
      "SELECT id FROM job_applications WHERE job_id = $1 AND applicant_id = $2",
      [jobId, req.userId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "You have already applied to this job" });
    }

    const result = await pool.query(
      `INSERT INTO job_applications (
        job_id, applicant_id, cover_letter, resume_url, phone, linkedin_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *`,
      [jobId, req.userId, coverLetter, resume, phone, linkedinUrl || null]
    );

    console.log("✅ Application submitted:", result.rows[0].id);
    res.status(201).json({ 
      application: result.rows[0],
      message: "Application submitted successfully" 
    });
  } catch (err) {
    console.error("❌ Apply job error:", err);
    res.status(500).json({ message: "Failed to submit application" });
  }
});

app.get("/api/jobs/:jobId/applications", verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const jobCheck = await pool.query(
      "SELECT posted_by FROM jobs WHERE id = $1",
      [jobId]
    );

    if (jobCheck.rows.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }

    if (jobCheck.rows[0].posted_by !== req.userId) {
      return res.status(403).json({ message: "You can only view applications for your own jobs" });
    }

    const result = await pool.query(
      `SELECT 
        ja.*,
        u.first_name,
        u.last_name,
        u.email,
        u.headline
      FROM job_applications ja
      JOIN users u ON ja.applicant_id = u.id
      WHERE ja.job_id = $1
      ORDER BY ja.created_at DESC`,
      [jobId]
    );

    res.json({ applications: result.rows });
  } catch (err) {
    console.error("❌ Get applications error:", err);
    res.status(500).json({ message: "Failed to fetch applications" });
  }
});

// ==========================================
//               EVENTS
// ==========================================

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
    console.error("❌ Events error:", err);
    res.status(500).json({ message: "Failed to fetch events" });
  }
});

// ==========================================
// ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  console.error("❌ Unhandled Error:", err);
  res.status(500).json({ message: "Server error" });
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
