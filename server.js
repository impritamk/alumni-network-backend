const express = require("express");
const http = require("http");             // <-- Added this
const { Server } = require("socket.io");  // <-- Added this
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

const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL, 
  ssl: { rejectUnauthorized: false } 
});

pool.query("SELECT NOW()", (err) => { 
  if (err) console.error("❌ DB Error:", err); 
  else console.log("✅ DB connected"); 
});

app.use(helmet());
app.use(cors({ 
  origin: process.env.FRONTEND_URL || 'http://localhost:3000', 
  credentials: true, 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], 
  allowedHeaders: ['Content-Type', 'Authorization'] 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, max: 800 }));

function generateOtpAndExpiry(minutes = 10) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  return { otp, expiry: new Date(Date.now() + minutes * 60000) };
}

async function sendOtpEmail(email, otp) {
  try {
    const emailHtml = `
    <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #f8fafc; padding: 40px 20px; margin: 0;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 40px 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); text-align: center;">
        <h1 style="color: #2563eb; margin-top: 0; font-size: 26px; margin-bottom: 10px;">Connect Alumni</h1>
        <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
          Welcome to the Chaibasa Engineering College Alumni Network! Please use the verification code below to complete your registration.
        </p>
        
        <div style="background-color: #f1f5f9; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 10px; color: #0f172a; display: block; margin-left: 10px;">${otp}</span>
        </div>
        
        <p style="color: #64748b; font-size: 14px;">This code will expire in <strong>10 minutes</strong>.</p>
        
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
        <p style="color: #94a3b8; font-size: 12px; margin: 0;">If you did not request this email, you can safely ignore it. No account will be created.</p>
      </div>
    </div>
    `;

    await axios.post("https://api.brevo.com/v3/smtp/email", {
      sender: { email: process.env.FROM_EMAIL, name: "Connect Alumni" },
      to: [{ email }],
      subject: "🎓 Verify Your Email - Connect Alumni",
      htmlContent: emailHtml
    }, { headers: { "api-key": process.env.BREVO_API_KEY } });
  } catch (err) { 
    console.error("❌ OTP Email Error:", err.message); 
  }
}

async function sendNotificationEmail(email, name, subject, content) {
  try {
    // 👇 THIS IS THE FORMAT OF THE EMAIL 👇
    const emailHtml = `
    <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; padding: 30px; background-color: #f8fafc;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px;">
        <h2 style="color: #0f172a; margin-top: 0;">Hi ${name},</h2>
        
        <p style="color: #475569; font-size: 16px; line-height: 1.6;">${content}</p>
        
        <a href="${process.env.FRONTEND_URL}" style="display: inline-block; background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px; font-weight: bold;">
          Open ConnectAlumni
        </a>
      </div>
    </div>
    `;
    // 👆 -------------------------------- 👆

    await axios.post("https://api.brevo.com/v3/smtp/email", {
      sender: { email: process.env.FROM_EMAIL, name: "Connect Alumni" },
      to: [{ email }],
      subject: subject,
      htmlContent: emailHtml
    }, { headers: { "api-key": process.env.BREVO_API_KEY } });
  } catch (err) { 
    console.error("❌ Notification Error:", err.message); 
  }
}

const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ message: "Authentication required" });
  
  try { 
    const decoded = jwt.verify(auth.split(" ")[1], process.env.JWT_SECRET); 
    req.userId = decoded.userId; 
    req.userRole = decoded.role; 
    req.userEmail = decoded.email; // Save the email to check later

    // --- NEW: GUEST LOCKDOWN LOGIC ---
    // If the guest tries to do anything other than read data (GET)
    if (req.userEmail === 'alumninetworkplatform@gmail.com' && req.method !== 'GET') {
      // Allow them to open a chat room (so the UI doesn't crash), but block everything else
      if (!req.path.includes('/messages/room')) {
        return res.status(403).json({ message: "Read-only mode. Guest accounts cannot modify data." });
      }
    }
    // ---------------------------------

    next(); 
  } catch { 
    return res.status(401).json({ message: "Invalid token" }); 
  }
};

const requireAdmin = (req, res, next) => { 
  if (req.userRole !== 'admin') return res.status(403).json({ message: "Access denied." }); 
  next(); 
};

// ==========================================
//               AUTH ROUTES
// ==========================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const { password, firstName, lastName, passoutYear, collegeName } = req.body;
    if (!email || !password || !firstName) return res.status(400).json({ message: "Required fields missing" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const { otp, expiry } = generateOtpAndExpiry();

    await pool.query(
      `INSERT INTO users (email, password, first_name, last_name, passout_year, college_name, verification_status, otp, otp_expires, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,NOW(),NOW())
       ON CONFLICT (email) DO UPDATE SET password=EXCLUDED.password, first_name=EXCLUDED.first_name, last_name=EXCLUDED.last_name, passout_year=EXCLUDED.passout_year, college_name=EXCLUDED.college_name, verification_status='pending', otp=EXCLUDED.otp, otp_expires=EXCLUDED.otp_expires, updated_at=NOW()`,
      [email, hashedPassword, firstName, lastName, passoutYear, collegeName || 'Chaibasa Engineering College', otp, expiry]
    );
    await sendOtpEmail(email, otp);
    res.json({ message: "OTP sent to email", email });
  } catch (err) { res.status(500).json({ message: "Registration failed" }); }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const q = await pool.query("SELECT id, otp, otp_expires FROM users WHERE email = $1", [req.body.email?.toLowerCase().trim()]);
    if (q.rows.length === 0) return res.status(400).json({ message: "User not found" });
    const user = q.rows[0];
    if (user.otp !== req.body.otp) return res.status(400).json({ message: "Incorrect OTP" });
    if (new Date(user.otp_expires) < new Date()) return res.status(400).json({ message: "OTP expired" });
    await pool.query(`UPDATE users SET verification_status = 'verified', otp = NULL, otp_expires = NULL WHERE id = $1`, [user.id]);
    res.json({ message: "Email verified successfully" });
  } catch (err) { res.status(500).json({ message: "OTP verification failed" }); }
});

app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const q = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (q.rows.length === 0) return res.status(404).json({ message: "User not found" });
    const { otp, expiry } = generateOtpAndExpiry();
    await pool.query("UPDATE users SET otp = $1, otp_expires = $2 WHERE email = $3", [otp, expiry, email]);
    await sendOtpEmail(email, otp);
    res.json({ message: "OTP sent to email" });
  } catch (err) { res.status(500).json({ message: "Failed to resend OTP" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const q = await pool.query("SELECT * FROM users WHERE email = $1", [req.body.email?.toLowerCase().trim()]);
    if (q.rows.length === 0) return res.status(401).json({ message: "Invalid credentials" });
    const user = q.rows[0];
    if (user.is_banned) return res.status(403).json({ message: "Account banned." });
    if (user.verification_status !== "verified") return res.status(403).json({ message: "Verify email first" });
    if (!(await bcrypt.compare(req.body.password, user.password))) return res.status(401).json({ message: "Invalid credentials" });

    await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [user.id]);
    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    delete user.password; 
    res.json({ token, user });
  } catch (err) { res.status(500).json({ message: "Login failed" }); }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const q = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (q.rows.length === 0) return res.status(404).json({ message: "Email not found" });
    const userId = q.rows[0].id;
    const resetToken = jwt.sign({ userId, type: "reset" }, process.env.JWT_SECRET, { expiresIn: "1h" });
    await pool.query("UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '1 hour' WHERE id = $2", [resetToken, userId]);
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const resetHtml = `
    <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #f8fafc; padding: 40px 20px; margin: 0;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 40px 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); text-align: center;">
        <h1 style="color: #2563eb; margin-top: 0; font-size: 26px; margin-bottom: 10px;">Connect Alumni</h1>
        <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
          We received a request to reset the password for your account. Click the button below to choose a new password.
        </p>
        
        <a href="${resetLink}" style="display: inline-block; background-color: #2563eb; color: #ffffff; font-weight: 600; font-size: 16px; text-decoration: none; padding: 14px 28px; border-radius: 8px; margin-bottom: 30px;">
          Reset My Password
        </a>
        
        <p style="color: #64748b; font-size: 14px;">This link will expire in <strong>1 hour</strong>.</p>
        
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
        <p style="color: #94a3b8; font-size: 12px; margin: 0;">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
      </div>
    </div>
    `;

    await axios.post("https://api.brevo.com/v3/smtp/email", {
      sender: { email: process.env.FROM_EMAIL, name: "Connect Alumni" },
      to: [{ email }],
      subject: "🔐 Reset Your Password - Connect Alumni",
      htmlContent: resetHtml
    }, { headers: { "api-key": process.env.BREVO_API_KEY } });
    res.json({ message: "Password reset link sent to your email" });
  } catch (err) { res.status(500).json({ message: "Failed to send reset link" }); }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ message: "Token and password are required" });
    let decoded;
    try { decoded = jwt.verify(token, process.env.JWT_SECRET); } 
    catch (err) { return res.status(400).json({ message: "Invalid or expired reset token" }); }

    const q = await pool.query("SELECT id, reset_token_expires FROM users WHERE id = $1 AND reset_token = $2", [decoded.userId, token]);
    if (q.rows.length === 0) return res.status(400).json({ message: "Invalid reset token" });
    if (new Date(q.rows[0].reset_token_expires) < new Date()) return res.status(400).json({ message: "Reset token has expired" });

    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.query("UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2", [hashedPassword, decoded.userId]);
    res.json({ message: "Password reset successfully" });
  } catch (err) { res.status(500).json({ message: "Failed to reset password" }); }
});

// ==========================================
//          USER ROUTES
// ==========================================
app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(`SELECT id, email, first_name, last_name, headline, bio, role, is_banned, location, current_company as company, passout_year, college_name FROM users WHERE id = $1`, [req.userId]);
    res.json({ user: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to fetch user" }); }
});

app.get("/api/users/directory", verifyToken, async (req, res) => {
  try {
    const { search, passoutYear, limit = 50, offset = 0 } = req.query;
    
    let query = `SELECT id, first_name, last_name, email, headline, passout_year, college_name, location, current_company as company FROM users WHERE verification_status = 'verified' AND is_banned = false AND email != 'alumninetworkplatform@gmail.com'`;
    
    const params = []; let i = 1;
    if (search) { 
      // --- ADDED passout_year::text to the search condition ---
      query += ` AND (first_name ILIKE $${i} OR last_name ILIKE $${i} OR email ILIKE $${i} OR passout_year::text ILIKE $${i})`; 
      params.push(`%${search}%`); i++; 
    }
    if (passoutYear) { query += ` AND passout_year = $${i}`; params.push(passoutYear); i++; }
    query += ` ORDER BY created_at DESC LIMIT $${i} OFFSET $${i + 1}`; params.push(limit, offset);
    
    const result = await pool.query(query, params); 
    res.json({ users: result.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch directory" }); }
});

app.get("/api/users/:id", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(`SELECT id, first_name, last_name, email, headline, bio, passout_year, college_name, current_company as company, location FROM users WHERE id = $1 AND verification_status = 'verified' AND is_banned = false`, [req.params.id]);
    res.json({ user: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to fetch user" }); }
});

app.put("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { headline, bio, location, company, firstName, lastName, collegeName } = req.body;
    const q = await pool.query(
      `UPDATE users SET headline=COALESCE($1, headline), bio=COALESCE($2, bio), location=COALESCE($3, location), current_company=COALESCE($4, current_company), first_name=COALESCE($5, first_name), last_name=COALESCE($6, last_name), college_name=COALESCE($7, college_name), updated_at=NOW() WHERE id=$8 RETURNING *`,
      [headline, bio, location, company, firstName, lastName, collegeName, req.userId]
    );
    res.json({ user: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to update profile" }); }
});

app.delete("/api/users/account", verifyToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]); 
    res.json({ message: "Account deleted" });
  } catch (err) { res.status(500).json({ message: "Failed to delete account" }); }
});

app.get("/api/user/indicators", verifyToken, async (req, res) => {
  try {
    const jobsQuery = await pool.query(`SELECT COUNT(*) FROM jobs WHERE created_at > (SELECT COALESCE(last_login, '1970-01-01'::timestamp) FROM users WHERE id = $1) AND posted_by != $1`, [req.userId]);
    const msgsQuery = await pool.query(`SELECT COUNT(*) FROM chat_messages cm JOIN chat_rooms cr ON cm.room_id = cr.id WHERE cr.name LIKE $1 AND cm.sender_id != $2 AND (cm.read_by IS NULL OR NOT ($2 = ANY(read_by)))`, [`%${req.userId}%`, req.userId]);
    res.json({ hasNewJobs: parseInt(jobsQuery.rows[0].count) > 0, hasUnreadMessages: parseInt(msgsQuery.rows[0].count) > 0 });
  } catch (err) { res.json({ hasNewJobs: false, hasUnreadMessages: false }); }
});

// ==========================================
//          ADMIN ROUTES
// ==========================================
app.get("/api/admin/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { search } = req.query;
    // --- ADDED passout_year to the SELECT statement ---
    let query = "SELECT id, first_name, last_name, email, role, is_banned, college_name, passout_year FROM users";
    let params = [];
    if (search) { 
      // --- ADDED passout_year::text to the search condition ---
      query += " WHERE first_name ILIKE $1 OR last_name ILIKE $1 OR email ILIKE $1 OR passout_year::text ILIKE $1"; 
      params.push(`%${search}%`); 
    }
    query += " ORDER BY created_at DESC";
    const q = await pool.query(query, params); 
    res.json({ users: q.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch users" }); }
});

app.patch("/api/admin/users/:id/ban", verifyToken, requireAdmin, async (req, res) => { 
  await pool.query("UPDATE users SET is_banned = true WHERE id = $1", [req.params.id]); res.json({ message: "User banned" }); 
});
app.patch("/api/admin/users/:id/unban", verifyToken, requireAdmin, async (req, res) => { 
  await pool.query("UPDATE users SET is_banned = false WHERE id = $1", [req.params.id]); res.json({ message: "User unbanned" }); 
});
app.patch("/api/admin/users/:id/role", verifyToken, requireAdmin, async (req, res) => { 
  await pool.query("UPDATE users SET role = $1 WHERE id = $2", [req.body.role, req.params.id]); res.json({ message: `Role updated` }); 
});

// 👇 PASTE THIS NEW ROUTE HERE 👇
app.post("/api/admin/broadcast-email", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { subject, message, targetEmail } = req.body;

    // If you pass a specific email, send it just to them
    if (targetEmail) {
      const targetUser = await pool.query("SELECT email, first_name FROM users WHERE email = $1", [targetEmail]);
      if (targetUser.rows.length === 0) return res.status(404).json({ message: "User not found" });
      
      await sendNotificationEmail(targetUser.rows[0].email, targetUser.rows[0].first_name, subject, message);
      return res.json({ message: `Manual email sent to ${targetEmail}!` });
    } 
    
    // If no target email is passed, send to EVERY verified user
    const allUsers = await pool.query("SELECT email, first_name FROM users WHERE verification_status = 'verified'");
    
    for (const user of allUsers.rows) {
      sendNotificationEmail(user.email, user.first_name, subject, message);
    }

    res.json({ message: `Manual email broadcasted to ${allUsers.rows.length} users!` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to send manual emails" });
  }
});
// 👆 -------------------------- 👆

// ==========================================
//          FEED (POSTS, LIKES, COMMENTS)
// ==========================================
app.get("/api/posts", verifyToken, async (req, res) => {
  try {
    const { sort } = req.query;
    let orderBy = "p.created_at DESC"; 
    if (sort === "oldest") orderBy = "p.created_at ASC";
    else if (sort === "top") orderBy = "like_count DESC, p.created_at DESC";

    const q = await pool.query(`
      SELECT p.id, p.content, p.created_at, p.user_id, u.first_name, u.last_name, u.role,
        (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) as like_count,
        EXISTS(SELECT 1 FROM post_likes WHERE post_id = p.id AND user_id = $1) as user_liked,
        COALESCE((SELECT json_agg(json_build_object('id', c.id, 'content', c.content, 'created_at', c.created_at, 'user_id', c.user_id, 'first_name', cu.first_name, 'last_name', cu.last_name, 'role', cu.role) ORDER BY c.created_at ASC) FROM post_comments c JOIN users cu ON c.user_id = cu.id WHERE c.post_id = p.id), '[]'::json) as comments
      FROM posts p JOIN users u ON p.user_id = u.id WHERE u.is_banned = false
      ORDER BY ${orderBy}
    `, [req.userId]);
    res.json({ posts: q.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch posts" }); }
});

app.post("/api/posts", verifyToken, async (req, res) => {
  try {
    const q = await pool.query("INSERT INTO posts (user_id, content, created_at) VALUES ($1, $2, NOW()) RETURNING *", [req.userId, req.body.content]);
    res.status(201).json({ post: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to create post" }); }
});

app.delete("/api/posts/:id", verifyToken, async (req, res) => {
  try {
    if (req.userRole === 'admin') await pool.query("DELETE FROM posts WHERE id = $1", [req.params.id]);
    else await pool.query("DELETE FROM posts WHERE id = $1 AND user_id = $2", [req.params.id, req.userId]);
    res.json({ message: "Deleted" });
  } catch (err) { res.status(500).json({ message: "Failed to delete" }); }
});

app.post("/api/posts/:id/like", verifyToken, async (req, res) => {
  try {
    const check = await pool.query("SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2", [req.params.id, req.userId]);
    if (check.rows.length > 0) { 
      await pool.query("DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2", [req.params.id, req.userId]); res.json({ liked: false }); 
    } else { 
      await pool.query("INSERT INTO post_likes (post_id, user_id) VALUES ($1, $2)", [req.params.id, req.userId]); res.json({ liked: true }); 
    }
  } catch (err) { res.status(500).json({ message: "Failed to toggle like" }); }
});

app.post("/api/posts/:id/comments", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(`INSERT INTO post_comments (post_id, user_id, content) VALUES ($1, $2, $3) RETURNING *`, [req.params.id, req.userId, req.body.content]);
    res.status(201).json({ comment: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to post comment" }); }
});

app.delete("/api/posts/comments/:commentId", verifyToken, async (req, res) => {
  try {
    if (req.userRole === 'admin') await pool.query("DELETE FROM post_comments WHERE id = $1", [req.params.commentId]);
    else await pool.query("DELETE FROM post_comments WHERE id = $1 AND user_id = $2", [req.params.commentId, req.userId]);
    res.json({ message: "Deleted" });
  } catch (err) { res.status(500).json({ message: "Failed to delete comment" }); }
});

// ==========================================
//          JOBS ROUTES
// ==========================================
app.get("/api/jobs", verifyToken, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT j.*, u.first_name, u.last_name, COUNT(ja.id) as application_count FROM jobs j JOIN users u ON j.posted_by = u.id LEFT JOIN job_applications ja ON j.id = ja.job_id WHERE j.is_active = true OR j.posted_by = $1 GROUP BY j.id, u.first_name, u.last_name ORDER BY j.created_at DESC`,
      [req.userId]
    ); 
    res.json({ jobs: q.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch jobs" }); }
});

app.post("/api/jobs", verifyToken, async (req, res) => {
  try {
    // 1. Added applyLink to req.body extraction
    const { title, company, description, requirements, location, salaryRange, jobType, experienceLevel, applyLink } = req.body;
    const q = await pool.query(
      // 2. Added apply_link to the INSERT statement and $10 to VALUES
      `INSERT INTO jobs (posted_by, title, company, description, requirements, location, salary_range, job_type, experience_level, apply_link, is_active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,NOW()) RETURNING *`,
      [req.userId, title, company, description, requirements, location, salaryRange, jobType, experienceLevel, applyLink]
    ); 
    res.status(201).json({ job: q.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to create job" }); }
});

app.put("/api/jobs/:jobId", verifyToken, async (req, res) => {
  try {
    // 1. Added applyLink to req.body extraction
    const { title, company, description, requirements, location, salaryRange, jobType, experienceLevel, applyLink } = req.body;
    const jobCheck = await pool.query("SELECT posted_by FROM jobs WHERE id = $1", [req.params.jobId]);
    if (jobCheck.rows.length === 0) return res.status(404).json({ message: "Job not found" });
    if (req.userRole !== 'admin' && String(jobCheck.rows[0].posted_by) !== String(req.userId)) return res.status(403).json({ message: "Unauthorized" });

    const q = await pool.query(
      // 2. Added apply_link=$9 and shifted the ID to $10
      `UPDATE jobs SET title=$1, company=$2, description=$3, requirements=$4, location=$5, salary_range=$6, job_type=$7, experience_level=$8, apply_link=$9 WHERE id=$10 RETURNING *`,
      [title, company, description, requirements, location, salaryRange, jobType, experienceLevel, applyLink, req.params.jobId]
    ); 
    res.json({ job: q.rows[0], message: "Job updated successfully" });
  } catch (err) { res.status(500).json({ message: "Failed to update job" }); }
});
app.delete("/api/jobs/:jobId", verifyToken, async (req, res) => {
  try {
    const jobCheck = await pool.query("SELECT posted_by FROM jobs WHERE id = $1", [req.params.jobId]);
    if (jobCheck.rows.length === 0) return res.status(404).json({ message: "Job not found" });
    if (req.userRole !== 'admin' && String(jobCheck.rows[0].posted_by) !== String(req.userId)) return res.status(403).json({ message: "Unauthorized" });
    await pool.query("DELETE FROM jobs WHERE id = $1", [req.params.jobId]); 
    res.json({ message: "Deleted" });
  } catch (err) { res.status(500).json({ message: "Failed to delete" }); }
});

app.post("/api/jobs/:jobId/apply", verifyToken, async (req, res) => {
  try {
    const { coverLetter, resume, phone, linkedinUrl } = req.body;
    const existing = await pool.query("SELECT id FROM job_applications WHERE job_id = $1 AND applicant_id = $2", [req.params.jobId, req.userId]);
    if (existing.rows.length > 0) return res.status(409).json({ message: "You have already applied to this job" });

    let finalCoverLetter = coverLetter || "";
    if (phone) finalCoverLetter += `\n\nPhone Number: ${phone}`;
    if (linkedinUrl) finalCoverLetter += `\nLinkedIn Profile: ${linkedinUrl}`;

    const result = await pool.query(
      `INSERT INTO job_applications (job_id, applicant_id, cover_letter, resume_url) VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.jobId, req.userId, finalCoverLetter, resume]
    );
    res.status(201).json({ application: result.rows[0], message: "Application submitted successfully" });
  } catch (err) { res.status(500).json({ message: "Failed to submit application" }); }
});

app.get("/api/jobs/:jobId/applications", verifyToken, async (req, res) => {
  try {
    const jobCheck = await pool.query("SELECT posted_by FROM jobs WHERE id = $1", [req.params.jobId]);
    if (jobCheck.rows.length === 0) return res.status(404).json({ message: "Job not found" });
    if (req.userRole !== 'admin' && String(jobCheck.rows[0].posted_by) !== String(req.userId)) return res.status(403).json({ message: "Unauthorized" });

    const result = await pool.query(
      `SELECT ja.*, u.first_name, u.last_name, u.email, u.headline FROM job_applications ja JOIN users u ON ja.applicant_id = u.id WHERE ja.job_id = $1 ORDER BY ja.applied_at DESC`,
      [req.params.jobId]
    );
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch applications" }); }
});

// ==========================================
//        CONNECT & MESSAGING ROUTES
// ==========================================
app.post("/api/connections/:userId/request", verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    if (String(userId) === String(req.userId)) return res.status(400).json({ message: "Cannot connect with yourself" });
    
    const userCheck = await pool.query("SELECT id FROM users WHERE id = $1", [userId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const existingConnection = await pool.query(
      `SELECT id, status FROM connections WHERE (user_id = $1 AND connected_user_id = $2) OR (user_id = $2 AND connected_user_id = $1)`,
      [req.userId, userId]
    );
    
    if (existingConnection.rows.length > 0) {
      if (existingConnection.rows[0].status === "accepted") return res.status(409).json({ message: "Already connected" });
      if (existingConnection.rows[0].status === "pending") return res.status(409).json({ message: "Connection request already sent" });
    }

    const result = await pool.query(`INSERT INTO connections (user_id, connected_user_id, status, created_at) VALUES ($1, $2, 'pending', NOW()) RETURNING *`, [req.userId, userId]);
    // --- NEW EMAIL TRIGGER LOGIC ---
    // Fetch the target user's email and name directly from the database
    const targetUser = await pool.query("SELECT email, first_name FROM users WHERE id = $1", [userId]);
    
    if (targetUser.rows.length > 0) {
      // Send the email in the background (no await) so it doesn't slow down the user's UI
      sendNotificationEmail(
        targetUser.rows[0].email,
        targetUser.rows[0].first_name,
        "New Connection Request! 🤝",
        "Someone just sent you a connection request on the Alumni Network. Log in to see who it is!"
      );
    }
    // --------------------------------
    res.status(201).json({ connection: result.rows[0], message: "Connection request sent" });
  } catch (err) { res.status(500).json({ message: "Failed to send connection request" }); }
});

app.get("/api/connections", verifyToken, async (req, res) => {
  try {
    const { status = "accepted" } = req.query;
    let query = `
      SELECT c.id as connection_id, c.user_id, c.connected_user_id, c.status, c.created_at,
        CASE WHEN c.user_id = $1 THEN c.connected_user_id ELSE c.user_id END as connected_to,
        u.id, u.first_name, u.last_name, u.headline, u.email, u.passout_year
      FROM connections c JOIN users u ON (CASE WHEN c.user_id = $1 THEN c.connected_user_id = u.id ELSE c.user_id = u.id END)
      WHERE (c.user_id = $1 OR c.connected_user_id = $1)
    `;
    const params = [req.userId];
    if (status) { query += ` AND c.status = $2`; params.push(status); }
    query += ` ORDER BY c.created_at DESC`;

    const result = await pool.query(query, params);
    res.json({ connections: result.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch connections" }); }
});

app.get("/api/connections/pending-requests", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id as connection_id, c.user_id, c.created_at, u.id, u.first_name, u.last_name, u.headline, u.email, u.passout_year
      FROM connections c JOIN users u ON c.user_id = u.id WHERE c.connected_user_id = $1 AND c.status = 'pending' ORDER BY c.created_at DESC`,
      [req.userId]
    );
    res.json({ pending: result.rows, count: result.rows.length });
  } catch (err) { res.status(500).json({ message: "Failed to fetch pending requests" }); }
});

app.post("/api/connections/:connectionId/accept", verifyToken, async (req, res) => {
  try {
    const connectionCheck = await pool.query("SELECT id, connected_user_id FROM connections WHERE id = $1", [req.params.connectionId]);
    if (connectionCheck.rows.length === 0) return res.status(404).json({ message: "Connection not found" });
    if (String(connectionCheck.rows[0].connected_user_id) !== String(req.userId)) return res.status(403).json({ message: "Unauthorized" });

    const result = await pool.query(`UPDATE connections SET status = 'accepted', updated_at = NOW() WHERE id = $1 RETURNING *`, [req.params.connectionId]);
    res.json({ connection: result.rows[0], message: "Connection accepted" });
  } catch (err) { res.status(500).json({ message: "Failed to accept connection" }); }
});

app.delete("/api/connections/:connectionId/reject", verifyToken, async (req, res) => {
  try {
    const connectionCheck = await pool.query("SELECT id, connected_user_id FROM connections WHERE id = $1", [req.params.connectionId]);
    if (connectionCheck.rows.length === 0) return res.status(404).json({ message: "Connection not found" });
    if (String(connectionCheck.rows[0].connected_user_id) !== String(req.userId)) return res.status(403).json({ message: "Unauthorized" });

    await pool.query("DELETE FROM connections WHERE id = $1", [req.params.connectionId]);
    res.json({ message: "Connection request rejected" });
  } catch (err) { res.status(500).json({ message: "Failed to reject connection" }); }
});

app.delete("/api/connections/:userId", verifyToken, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM connections WHERE (user_id = $1 AND connected_user_id = $2) OR (user_id = $2 AND connected_user_id = $1)`,
      [req.userId, req.params.userId]
    );
    res.json({ message: "Connection removed" });
  } catch (err) { res.status(500).json({ message: "Failed to remove connection" }); }
});

app.get("/api/connections/check/:userId", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT status FROM connections WHERE (user_id = $1 AND connected_user_id = $2) OR (user_id = $2 AND connected_user_id = $1)`,
      [req.userId, req.params.userId]
    );
    if (result.rows.length === 0) return res.json({ status: "not_connected" });
    res.json({ status: result.rows[0].status });
  } catch (err) { res.status(500).json({ message: "Failed to check connection status" }); }
});

app.post("/api/messages/room/:otherUserId", verifyToken, async (req, res) => {
  try {
    const currentUserId = String(req.userId);
    const otherUserId = String(req.params.otherUserId);
    const roomName = [currentUserId, otherUserId].sort().join('_');

    let roomCheck = await pool.query("SELECT * FROM chat_rooms WHERE name = $1 AND type = 'direct'", [roomName]);
    let room;
    if (roomCheck.rows.length === 0) {
      const newRoom = await pool.query(`INSERT INTO chat_rooms (name, type, created_by, created_at) VALUES ($1, 'direct', $2, NOW()) RETURNING *`, [roomName, req.userId]);
      room = newRoom.rows[0];
    } else { 
      room = roomCheck.rows[0]; 
    }

    const otherUser = await pool.query("SELECT id, first_name, last_name, profile_picture_url FROM users WHERE id = $1", [otherUserId]);
    res.json({ room, otherUser: otherUser.rows[0] });
  } catch (err) { res.status(500).json({ message: "Failed to load chat room" }); }
});

app.get("/api/messages/:roomId", verifyToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE chat_messages SET read_by = array_append(COALESCE(read_by, ARRAY[]::uuid[]), $1) WHERE room_id = $2 AND sender_id != $1 AND (read_by IS NULL OR NOT ($1 = ANY(read_by)))`,
      [req.userId, req.params.roomId]
    );
    const messages = await pool.query(
      `SELECT m.*, u.first_name, u.last_name FROM chat_messages m JOIN users u ON m.sender_id = u.id WHERE m.room_id = $1 ORDER BY m.created_at ASC`,
      [req.params.roomId]
    );
    res.json({ messages: messages.rows });
  } catch (err) { res.status(500).json({ message: "Failed to fetch messages" }); }
});

app.post("/api/messages/:roomId", verifyToken, async (req, res) => {
  try {
    if (!req.body.message.trim()) return res.status(400).json({ message: "Message cannot be empty" });
    
    // 1. Save message to PostgreSQL
    const newMsg = await pool.query(
      `INSERT INTO chat_messages (room_id, sender_id, message, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [req.params.roomId, req.userId, req.body.message]
    );

    // 2. Broadcast the message instantly to the WebSocket room
    req.app.get("io").to(req.params.roomId).emit("receiveMessage", newMsg.rows[0]);

    // Note: Instant email notifications for messages are disabled to save API quota.
    // The frontend will still show the red "Unread Message" dot thanks to the WebSocket!

    res.json({ message: newMsg.rows[0] });
  } catch (err) { 
    res.status(500).json({ message: "Failed to send message" }); 
  }
});
app.delete("/api/messages/room/:roomId", verifyToken, async (req, res) => {
  try {
    // Ensure the user actually belongs to this room before deleting
    const roomCheck = await pool.query(
      "SELECT id FROM chat_rooms WHERE id = $1 AND name LIKE $2", 
      [req.params.roomId, `%${req.userId}%`]
    );
    
    if (roomCheck.rows.length === 0) {
      return res.status(403).json({ message: "Unauthorized or room not found" });
    }

    // Deleting the room will automatically delete the messages if you have ON DELETE CASCADE in your DB.
    // If not, delete messages manually first:
    await pool.query("DELETE FROM chat_messages WHERE room_id = $1", [req.params.roomId]);
    await pool.query("DELETE FROM chat_rooms WHERE id = $1", [req.params.roomId]);
    
    res.json({ message: "Chat deleted successfully" });
  } catch (err) { 
    res.status(500).json({ message: "Failed to delete chat" }); 
  }
});

// 🟢 FIXED: Inbox sorting and safe ID comparison
app.get("/api/inbox", verifyToken, async (req, res) => {
  try {
    const rooms = await pool.query(`
      SELECT cr.*, COALESCE((SELECT MAX(created_at) FROM chat_messages WHERE room_id = cr.id), cr.created_at) as last_activity
      FROM chat_rooms cr WHERE name LIKE $1 ORDER BY last_activity DESC
    `, [`%${req.userId}%`]);
    
    const inboxData = await Promise.all(rooms.rows.map(async (room) => {
      const ids = room.name.split('_');
      // Safely compare IDs using strings
      const otherUserId = String(ids[0]) === String(req.userId) ? ids[1] : ids[0];
      
      const userRes = await pool.query("SELECT id, first_name, last_name FROM users WHERE id = $1", [otherUserId]);
      const unreadQuery = await pool.query(`SELECT COUNT(*) FROM chat_messages WHERE room_id = $1 AND sender_id != $2 AND (read_by IS NULL OR NOT ($2 = ANY(read_by)))`, [room.id, req.userId]);
      return { room, otherUser: userRes.rows[0], hasUnread: parseInt(unreadQuery.rows[0].count) > 0 };
    }));
    
    res.json({ rooms: inboxData });
  } catch (err) { 
    console.error(err);
    res.status(500).json({ message: "Failed to load inbox" }); 
  }
});

app.use((err, req, res, next) => { console.error("❌ Error:", err); res.status(500).json({ message: "Server error" }); });

// --- ALL YOUR EXISTING ROUTES STAY ABOVE THIS LINE ---

const PORT = process.env.PORT || 5000;

// 1. Wrap your Express app in an HTTP server
const server = http.createServer(app);

// 2. Attach Socket.io to that new server
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  }
});

// 3. Make 'io' available inside your Express routes
app.set("io", io);

// 4. Listen for when users connect to the chat
io.on("connection", (socket) => {
  socket.on("joinRoom", (roomId) => {
    socket.join(roomId);
  });
  // 👇 PASTE THIS NEW BLOCK RIGHT HERE 👇
  socket.on("markAsRead", async ({ roomId, userId }) => {
    try {
      // Update the database to mark messages as read
      await pool.query(
        "UPDATE chat_messages SET read_status = 'read' WHERE room_id = $1 AND sender_id != $2 AND read_status != 'read'", 
        [roomId, userId]
      );
      
      // Tell everyone in the room to update their UI
      io.to(roomId).emit("messagesRead", { roomId, readerId: userId });
    } catch (err) {
      console.error("Failed to mark messages as read", err);
    }
  });
  // 👆 -------------------------------- 👆
  // --- NEW: TYPING INDICATORS ---
  socket.on("typing", (roomId) => {
    // Broadcast to everyone in the room EXCEPT the sender
    socket.to(roomId).emit("userTyping"); 
  });

  socket.on("stopTyping", (roomId) => {
    socket.to(roomId).emit("userStoppedTyping");
  });
  // ------------------------------
});

// 5. Start the server using 'server.listen' instead of 'app.listen'
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
