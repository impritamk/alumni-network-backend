// ==========================================
//  ALUMNI NETWORK BACKEND (WITH CONNECT FEATURE)
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
  max: 800, // 🟢 CHANGED THIS FROM 100 TO 800
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
    const rawEmail = req.body.email;
    if (!rawEmail || !req.body.password || !req.body.firstName || !req.body.lastName || !req.body.passoutYear) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const email = rawEmail.toLowerCase().trim();
    const { password, firstName, lastName, passoutYear } = req.body;

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
    const email = req.body.email?.toLowerCase().trim();
    const otp = req.body.otp;

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

app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();

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
    const email = req.body.email?.toLowerCase().trim();
    const password = req.body.password;

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

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();

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

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '1 hour' WHERE id = $2",
      [resetToken, userId]
    );

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

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: "Token and password are required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

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

    const hashedPassword = await bcrypt.hash(password, 12);

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
//          USER ROUTES
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

// 🟢 NEW FEATURE: Backend Name Updating
app.put("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { headline, bio, location, company, firstName, lastName } = req.body;

    const q = await pool.query(
      `UPDATE users SET
         headline = COALESCE($1, headline),
         bio = COALESCE($2, bio),
         location = COALESCE($3, location),
         current_company = COALESCE($4, current_company),
         first_name = COALESCE($5, first_name),
         last_name = COALESCE($6, last_name),
         updated_at = NOW()
       WHERE id = $7
       RETURNING id, email, first_name, last_name, headline, bio, location, 
                 current_company as company`,
      [headline, bio, location, company, firstName, lastName, req.userId]
    );

    res.json({ user: q.rows[0] });
  } catch (err) {
    console.error("❌ Profile update error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

app.delete("/api/users/account", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    await pool.query("DELETE FROM job_applications WHERE applicant_id = $1", [userId]);
    await pool.query("DELETE FROM jobs WHERE posted_by = $1", [userId]);
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);

    console.log("✅ Account deleted:", userId);
    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("❌ Delete account error:", err);
    res.status(500).json({ message: "Failed to delete account" });
  }
});

// 🟢 FIXED FEATURE: True Unread Indicator Logic
// ==========================================
app.get("/api/user/indicators", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    
    const jobsQuery = await pool.query(
      `SELECT COUNT(*) FROM jobs 
       WHERE created_at > (SELECT COALESCE(last_login, '1970-01-01'::timestamp) FROM users WHERE id = $1)
       AND posted_by != $1`,
      [userId]
    );
    const hasNewJobs = parseInt(jobsQuery.rows[0].count) > 0;

    const msgsQuery = await pool.query(
      `SELECT COUNT(*) FROM chat_messages cm
       JOIN chat_rooms cr ON cm.room_id = cr.id
       WHERE cr.name LIKE $1 
       AND cm.sender_id != $2 
       AND (cm.read_by IS NULL OR NOT ($2 = ANY(cm.read_by)))`,
      [`%${userId}%`, userId]
    );
    const hasUnreadMessages = parseInt(msgsQuery.rows[0].count) > 0;

    res.json({ hasNewJobs, hasUnreadMessages });
  } catch (err) {
    res.json({ hasNewJobs: false, hasUnreadMessages: false });
  }
});

// ==========================================
//          JOBS ROUTES
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
    const {
      title, company, description, requirements, location,
      salaryRange, jobType, experienceLevel, expiresAt
    } = req.body;

    if (!title || !company || !description) {
      return res.status(400).json({ message: "Title, company, and description are required" });
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
        req.userId, title, company, description, requirements || null,
        location || null, salaryRange || null, jobType || null,
        experienceLevel || null, expiresAt || null
      ]
    );

    res.status(201).json({ job: q.rows[0], message: "Job posted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to create job" });
  }
});

app.delete("/api/jobs/:jobId", verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const jobCheck = await pool.query("SELECT posted_by FROM jobs WHERE id = $1", [jobId]);

    if (jobCheck.rows.length === 0) return res.status(404).json({ message: "Job not found" });
    if (jobCheck.rows[0].posted_by !== req.userId) return res.status(403).json({ message: "Unauthorized" });

    await pool.query("DELETE FROM jobs WHERE id = $1", [jobId]);

    res.json({ message: "Job deleted successfully" });
  } catch (err) {
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

    let finalCoverLetter = coverLetter || "";
    if (phone) finalCoverLetter += `\n\nPhone Number: ${phone}`;
    if (linkedinUrl) finalCoverLetter += `\nLinkedIn Profile: ${linkedinUrl}`;

    const result = await pool.query(
      `INSERT INTO job_applications (
        job_id, applicant_id, cover_letter, resume_url
      ) VALUES ($1, $2, $3, $4)
      RETURNING *`,
      [jobId, req.userId, finalCoverLetter, resume]
    );

    res.status(201).json({ application: result.rows[0], message: "Application submitted successfully" });
  } catch (err) {
    console.error("❌ Apply job error:", err);
    res.status(500).json({ message: "Failed to submit application" });
  }
});

app.get("/api/jobs/:jobId/applications", verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const jobCheck = await pool.query("SELECT posted_by FROM jobs WHERE id = $1", [jobId]);

    if (jobCheck.rows.length === 0) return res.status(404).json({ message: "Job not found" });
    if (jobCheck.rows[0].posted_by !== req.userId) return res.status(403).json({ message: "Unauthorized" });

    const result = await pool.query(
      `SELECT ja.*, u.first_name, u.last_name, u.email, u.headline
      FROM job_applications ja
      JOIN users u ON ja.applicant_id = u.id
      WHERE ja.job_id = $1
      ORDER BY ja.applied_at DESC`,
      [jobId]
    );

    res.json({ applications: result.rows });
  } catch (err) {
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
    res.status(500).json({ message: "Failed to fetch events" });
  }
});

// ==========================================
//        CONNECT FEATURE ROUTES
// ==========================================

app.post("/api/connections/:userId/request", verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const senderId = req.userId;

    if (userId === senderId) return res.status(400).json({ message: "Cannot connect with yourself" });

    const userCheck = await pool.query("SELECT id FROM users WHERE id = $1", [userId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const existingConnection = await pool.query(
      `SELECT id, status FROM connections 
       WHERE (user_id = $1 AND connected_user_id = $2) 
          OR (user_id = $2 AND connected_user_id = $1)`,
      [senderId, userId]
    );

    if (existingConnection.rows.length > 0) {
      const status = existingConnection.rows[0].status;
      if (status === "accepted") return res.status(409).json({ message: "Already connected" });
      if (status === "pending") return res.status(409).json({ message: "Connection request already sent" });
    }

    const result = await pool.query(
      `INSERT INTO connections (user_id, connected_user_id, status, created_at)
       VALUES ($1, $2, 'pending', NOW())
       RETURNING *`,
      [senderId, userId]
    );

    res.status(201).json({ connection: result.rows[0], message: "Connection request sent" });
  } catch (err) {
    res.status(500).json({ message: "Failed to send connection request" });
  }
});

app.get("/api/connections", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { status = "accepted" } = req.query;

    let query = `
      SELECT c.id as connection_id, c.user_id, c.connected_user_id, c.status, c.created_at,
        CASE WHEN c.user_id = $1 THEN c.connected_user_id ELSE c.user_id END as connected_to,
        u.id, u.first_name, u.last_name, u.headline, u.email, u.passout_year
      FROM connections c
      JOIN users u ON (CASE WHEN c.user_id = $1 THEN c.connected_user_id = u.id ELSE c.user_id = u.id END)
      WHERE (c.user_id = $1 OR c.connected_user_id = $1)
    `;

    const params = [userId];

    if (status) {
      query += ` AND c.status = $2`;
      params.push(status);
    }

    query += ` ORDER BY c.created_at DESC`;

    const result = await pool.query(query, params);
    res.json({ connections: result.rows });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch connections" });
  }
});

app.get("/api/connections/pending-requests", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    const result = await pool.query(
      `SELECT c.id as connection_id, c.user_id, c.created_at,
        u.id, u.first_name, u.last_name, u.headline, u.email, u.passout_year
      FROM connections c
      JOIN users u ON c.user_id = u.id
      WHERE c.connected_user_id = $1 AND c.status = 'pending'
      ORDER BY c.created_at DESC`,
      [userId]
    );

    res.json({ pending: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch pending requests" });
  }
});

app.post("/api/connections/:connectionId/accept", verifyToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    const userId = req.userId;

    const connectionCheck = await pool.query("SELECT id, connected_user_id FROM connections WHERE id = $1", [connectionId]);

    if (connectionCheck.rows.length === 0) return res.status(404).json({ message: "Connection not found" });
    if (connectionCheck.rows[0].connected_user_id !== userId) return res.status(403).json({ message: "Unauthorized" });

    const result = await pool.query(`UPDATE connections SET status = 'accepted', updated_at = NOW() WHERE id = $1 RETURNING *`, [connectionId]);

    res.json({ connection: result.rows[0], message: "Connection accepted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to accept connection" });
  }
});

app.delete("/api/connections/:connectionId/reject", verifyToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    const userId = req.userId;

    const connectionCheck = await pool.query("SELECT id, connected_user_id FROM connections WHERE id = $1", [connectionId]);

    if (connectionCheck.rows.length === 0) return res.status(404).json({ message: "Connection not found" });
    if (connectionCheck.rows[0].connected_user_id !== userId) return res.status(403).json({ message: "Unauthorized" });

    await pool.query("DELETE FROM connections WHERE id = $1", [connectionId]);
    res.json({ message: "Connection request rejected" });
  } catch (err) {
    res.status(500).json({ message: "Failed to reject connection" });
  }
});

app.delete("/api/connections/:userId", verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.userId;

    await pool.query(
      `DELETE FROM connections 
       WHERE (user_id = $1 AND connected_user_id = $2) OR (user_id = $2 AND connected_user_id = $1)`,
      [currentUserId, userId]
    );

    res.json({ message: "Connection removed" });
  } catch (err) {
    res.status(500).json({ message: "Failed to remove connection" });
  }
});

app.get("/api/connections/check/:userId", verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.userId;

    const result = await pool.query(
      `SELECT status FROM connections 
       WHERE (user_id = $1 AND connected_user_id = $2) OR (user_id = $2 AND connected_user_id = $1)`,
      [currentUserId, userId]
    );

    if (result.rows.length === 0) return res.json({ status: "not_connected" });

    res.json({ status: result.rows[0].status });
  } catch (err) {
    res.status(500).json({ message: "Failed to check connection status" });
  }
});

// ==========================================
//        MESSAGING ROUTES
// ==========================================

app.post("/api/messages/room/:otherUserId", verifyToken, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const { otherUserId } = req.params;

    const roomName = [currentUserId, otherUserId].sort().join('_');

    let roomCheck = await pool.query("SELECT * FROM chat_rooms WHERE name = $1 AND type = 'direct'", [roomName]);

    let room;
    if (roomCheck.rows.length === 0) {
      const newRoom = await pool.query(
        `INSERT INTO chat_rooms (name, type, created_by, created_at) VALUES ($1, 'direct', $2, NOW()) RETURNING *`,
        [roomName, currentUserId]
      );
      room = newRoom.rows[0];
    } else {
      room = roomCheck.rows[0];
    }

    const otherUser = await pool.query("SELECT id, first_name, last_name, profile_picture_url FROM users WHERE id = $1", [otherUserId]);

    res.json({ room, otherUser: otherUser.rows[0] });
  } catch (err) {
    res.status(500).json({ message: "Failed to load chat room" });
  }
});

app.get("/api/messages/:roomId", verifyToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.userId;
    
    // 🟢 FIXED: Null-safe Array check when marking messages as read
    await pool.query(
      `UPDATE chat_messages 
       SET read_by = array_append(COALESCE(read_by, ARRAY[]::uuid[]), $1) 
       WHERE room_id = $2 
       AND sender_id != $1 
       AND (read_by IS NULL OR NOT ($1 = ANY(read_by)))`,
      [userId, roomId]
    );

    const messages = await pool.query(
      `SELECT m.*, u.first_name, u.last_name 
       FROM chat_messages m
       JOIN users u ON m.sender_id = u.id
       WHERE m.room_id = $1
       ORDER BY m.created_at ASC`,
      [roomId]
    );

    res.json({ messages: messages.rows });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});

app.post("/api/messages/:roomId", verifyToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { message } = req.body;
    const senderId = req.userId;

    if (!message.trim()) return res.status(400).json({ message: "Message cannot be empty" });

    const newMsg = await pool.query(
      `INSERT INTO chat_messages (room_id, sender_id, message, created_at) 
       VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [roomId, senderId, message]
    );

    res.json({ message: newMsg.rows[0] });
  } catch (err) {
    res.status(500).json({ message: "Failed to send message" });
  }
});

// 🟢 NEW FEATURE: Inbox with precise unread notification dots!
app.get("/api/inbox", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const rooms = await pool.query(
      `SELECT * FROM chat_rooms WHERE name LIKE $1 ORDER BY created_at DESC`,
      [`%${userId}%`]
    );
    
    const inboxData = await Promise.all(rooms.rows.map(async (room) => {
      const ids = room.name.split('_');
      const otherUserId = ids[0] === userId ? ids[1] : ids[0];
      
      const userRes = await pool.query(
        "SELECT id, first_name, last_name FROM users WHERE id = $1", 
        [otherUserId]
      );

      const unreadQuery = await pool.query(
        `SELECT COUNT(*) FROM chat_messages 
         WHERE room_id = $1 
         AND sender_id != $2 
         AND (read_by IS NULL OR NOT ($2 = ANY(read_by)))`,
        [room.id, userId]
      );
      
      const hasUnread = parseInt(unreadQuery.rows[0].count) > 0;
      
      return { room: room, otherUser: userRes.rows[0], hasUnread };
    }));

    res.json({ rooms: inboxData });
  } catch (err) {
    res.status(500).json({ message: "Failed to load inbox" });
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

