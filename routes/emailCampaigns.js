const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const router = express.Router();

// ==========================================
// 1. 25 ROTATING ALUMNI EMAIL TEMPLATES
// ==========================================
const EMAIL_TEMPLATES = [
  { key: "reconnect_batchmates", subject: "👋 Catch up with your CEC batchmates", content: "See who from your batch recently updated their role, location, or company on Connect Alumni." },
  { key: "share_job_opening", subject: "💼 Hiring at your company? Help a fellow alumnus", content: "Got an open role or referral opportunity? Post it on the Connect Alumni Job Board in under a minute." },
  { key: "explore_new_jobs", subject: "🚀 Fresh opportunities posted on Connect Alumni", content: "Alumni across tech, core engineering, and management have shared new openings. Check them out today." },
  { key: "complete_profile", subject: "✨ Make your alumni profile stand out", content: "Add your current company, skills, and LinkedIn link so juniors and batchmates can find and connect with you." },
  { key: "mentor_juniors", subject: "🎓 Guide the next wave of CEC graduates", content: "A 10-minute chat or referral tip can change a junior's career path. Update your 'Open To' status to mentoring." },
  { key: "share_milestone", subject: "🎉 Switched jobs or launched something new?", content: "Share your latest career milestone or project update with the Chaibasa Engineering College community." },
  { key: "weekend_check_in", subject: "☕ Quick check-in from Connect Alumni", content: "Drop by the feed to see what fellow alumni are building, discussing, and celebrating this week." },
  { key: "city_network", subject: "📍 Connect with alumni in your city", content: "Search the directory by location to find fellow CEC graduates working near you." },
  { key: "branch_network", subject: "🛠️ Reconnect with your engineering branch", content: "Filter the directory by branch and passout year to see where your classmates are now." },
  { key: "referral_power", subject: "🤝 One referral can open big doors", content: "Looking for a switch or willing to refer? Update your profile status so the right people reach out." },
  { key: "feed_discussions", subject: "💬 Join the latest conversations on the feed", content: "Alumni are sharing interview experiences, tech stacks, and career advice. Jump into the discussion." },
  { key: "internship_help", subject: "🌱 Know of an internship opening?", content: "Students are actively looking for internships. Share any leads from your team on the job board." },
  { key: "startup_founders", subject: "⚡ Building a startup or side project?", content: "Post what you're working on in the alumni feed—find collaborators, feedback, or early users." },
  { key: "invite_classmate", subject: "📨 Missing a classmate on Connect Alumni?", content: "Invite your college friends and hostel mates so your entire batch stays connected in one place." },
  { key: "career_advice", subject: "🧭 What advice would you give your college self?", content: "Share one practical career lesson on the feed to inspire current students and recent grads." },
  { key: "direct_messages", subject: "✉️ Say hello to someone you haven't spoken to in years", content: "Use direct messaging on Connect Alumni to reconnect with old friends or reach out to seniors." },
  { key: "higher_studies", subject: "📚 Pursuing MS, MBA, or GATE?", content: "Connect with alumni who have walked the higher-studies path and share your insights." },
  { key: "tech_trends", subject: "💻 What tools or skills are hot in your industry?", content: "Start a quick thread on the feed about what skills hiring managers are prioritizing right now." },
  { key: "alumni_spotlight", subject: "🌟 Every alumnus has a story worth sharing", content: "Update your bio and headline so others can learn about your journey since graduation." },
  { key: "open_to_work", subject: "🔎 Looking for your next role?", content: "Set your 'Open To' badge on your profile so hiring alumni can spot you right away." },
  { key: "campus_memories", subject: "🏛️ Throwback to Chaibasa Engineering College", content: "Reconnect with the people who made your college years memorable—check out who's online today." },
  { key: "interview_prep", subject: "🎯 Ace your next interview with alumni insights", content: "Ask questions on the feed and get real-world tips from alumni working at top companies." },
  { key: "network_growth", subject: "📈 Our alumni network is growing stronger every week", content: "More graduates are joining every week. Browse the latest members in the directory." },
  { key: "quick_update", subject: "🔔 New activity waiting for you on Connect Alumni", content: "Log in to check new posts, job listings, and messages from your network." },
  { key: "stay_connected", subject: "🌐 Your lifelong CEC network is one click away", content: "Whether you're hiring, job hunting, or just catching up—your alumni community is here." }
];

// ==========================================
// 2. HTML ESCAPE & BREVO SENDER
// ==========================================
function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function sendNotificationEmail(email, name, subject, content) {
  const safeName = escapeHtml(name || "Alumni");
  const safeContent = escapeHtml(content).replace(/\n/g, "<br/>");

  const emailHtml = `
    <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; padding: 30px; background-color: #f8fafc;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <h2 style="color: #0f172a; margin-top: 0;">Hi ${safeName},</h2>
        <p style="color: #475569; font-size: 16px; line-height: 1.6;">${safeContent}</p>
        <a href="${process.env.FRONTEND_URL}" style="display: inline-block; background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px; font-weight: bold;">
          Open ConnectAlumni
        </a>
      </div>
    </div>
  `;

  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: { email: process.env.FROM_EMAIL, name: "Connect Alumni" },
      to: [{ email }],
      subject,
      htmlContent: emailHtml
    },
    { headers: { "api-key": process.env.BREVO_API_KEY } }
  );
}

// ==========================================
// 3. DB LOGGING & 3-DAY AUTOMATED ROTATION
// ==========================================
async function ensureCampaignLogTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS automated_email_logs (
      id SERIAL PRIMARY KEY,
      template_index INT NOT NULL,
      template_key TEXT NOT NULL,
      recipient_count INT NOT NULL DEFAULT 0,
      sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function runThreeDayAutoCampaign(pool, force = false) {
  await ensureCampaignLogTable(pool);

  // Check last automated send (enforces exact 3-day gap)
  const lastLog = await pool.query(
    "SELECT template_index, sent_at FROM automated_email_logs ORDER BY id DESC LIMIT 1"
  );

  if (!force && lastLog.rows.length > 0) {
    const lastSent = new Date(lastLog.rows[0].sent_at);
    const threeDaysMs = 3 * 24 * 60 * 60 * 1000;
    if (Date.now() - lastSent.getTime() < threeDaysMs) {
      return { skipped: true, reason: "Less than 3 days since last automated campaign." };
    }
  }

  // Pick next template in rotation (0 -> 24 -> 0)
  const nextIndex =
    lastLog.rows.length > 0
      ? (lastLog.rows[0].template_index + 1) % EMAIL_TEMPLATES.length
      : 0;
  const template = EMAIL_TEMPLATES[nextIndex];

  // Fetch verified, active users (excluding guest demo account)
  const usersRes = await pool.query(
    `SELECT email, first_name FROM users 
     WHERE verification_status = 'verified' 
       AND is_banned = false 
       AND email != 'alumninetworkplatform@gmail.com'`
  );

  let sentCount = 0;
  for (const user of usersRes.rows) {
    try {
      await sendNotificationEmail(user.email, user.first_name, template.subject, template.content);
      sentCount++;
    } catch (err) {
      console.error(`❌ Auto-email failed for ${user.email}:`, err.message);
    }
  }

  await pool.query(
    "INSERT INTO automated_email_logs (template_index, template_key, recipient_count) VALUES ($1, $2, $3)",
    [nextIndex, template.key, sentCount]
  );

  console.log(`✅ 3-Day Auto Email [${template.key}] sent to ${sentCount} users.`);
  return { skipped: false, templateKey: template.key, sentCount };
}

// ==========================================
// 4. FACTORY FUNCTION (MOUNTS ROUTES + CRON)
// ==========================================
module.exports = function initEmailModule({ pool, verifyToken, requireAdmin }) {
  // Helper for two-step admin confirmation hash
  const buildHash = (adminId, subject, message, targetEmail = "") =>
    crypto.createHash("sha256").update(`${adminId}|${subject}|${message}|${targetEmail}`).digest("hex");

  // A. Manual Admin Broadcast WITH Two-Step Confirmation
  router.post("/admin/broadcast-email", verifyToken, requireAdmin, async (req, res) => {
    try {
      const { subject, message, targetEmail, confirmed, confirmationToken } = req.body;
      if (!subject?.trim() || !message?.trim()) {
        return res.status(400).json({ message: "Subject and message are required." });
      }

      const cleanSubject = subject.trim();
      const cleanMessage = message.trim();
      const cleanTarget = targetEmail?.trim().toLowerCase() || "";

      const recipientsRes = cleanTarget
        ? await pool.query(
            "SELECT email, first_name FROM users WHERE LOWER(email) = $1 AND verification_status = 'verified' AND is_banned = false",
            [cleanTarget]
          )
        : await pool.query(
            "SELECT email, first_name FROM users WHERE verification_status = 'verified' AND is_banned = false AND email != 'alumninetworkplatform@gmail.com'"
          );

      const recipients = recipientsRes.rows;
      if (recipients.length === 0) {
        return res.status(404).json({ message: "No verified recipients found." });
      }

      const expectedHash = buildHash(req.userId, cleanSubject, cleanMessage, cleanTarget);

      // Step 1: Return preview + 5-minute confirmation token
      if (!confirmed) {
        const token = jwt.sign(
          { adminId: req.userId, payloadHash: expectedHash, purpose: "broadcast-confirm" },
          process.env.JWT_SECRET,
          { expiresIn: "5m" }
        );
        return res.json({
          requiresConfirmation: true,
          confirmationToken: token,
          recipientCount: recipients.length,
          preview: {
            to: cleanTarget || `All ${recipients.length} verified users`,
            subject: cleanSubject,
            message: cleanMessage
          },
          message: `Please confirm sending to ${recipients.length} recipient(s).`
        });
      }

      // Step 2: Verify confirmation token before sending
      let decoded;
      try {
        decoded = jwt.verify(confirmationToken || "", process.env.JWT_SECRET);
      } catch {
        return res.status(400).json({ message: "Confirmation expired or invalid. Please preview again." });
      }

      if (
        decoded.purpose !== "broadcast-confirm" ||
        decoded.adminId !== req.userId ||
        decoded.payloadHash !== expectedHash
      ) {
        return res.status(400).json({ message: "Email changed after confirmation. Please confirm again." });
      }

      let sentCount = 0;
      for (const user of recipients) {
        await sendNotificationEmail(user.email, user.first_name, cleanSubject, cleanMessage);
        sentCount++;
      }

      return res.json({
        message: cleanTarget
          ? `Confirmed and sent email to ${cleanTarget}!`
          : `Confirmed and broadcasted email to ${sentCount} users!`
      });
    } catch (err) {
      console.error("❌ Broadcast Error:", err.message);
      return res.status(500).json({ message: "Failed to send broadcast email." });
    }
  });

  // B. Admin endpoint to view templates & automation history
  router.get("/admin/email-campaigns/status", verifyToken, requireAdmin, async (req, res) => {
    try {
      await ensureCampaignLogTable(pool);
      const logs = await pool.query("SELECT * FROM automated_email_logs ORDER BY id DESC LIMIT 10");
      res.json({
        totalTemplates: EMAIL_TEMPLATES.length,
        templates: EMAIL_TEMPLATES,
        recentRuns: logs.rows
      });
    } catch (err) {
      res.status(500).json({ message: "Failed to load campaign status" });
    }
  });

  // C. Start daily 10:00 AM IST check (triggers actual send every 3 days)
  cron.schedule(
    "0 10 * * *",
    () => {
      runThreeDayAutoCampaign(pool, false).catch((err) =>
        console.error("❌ Scheduled 3-day campaign error:", err.message)
      );
    },
    { timezone: "Asia/Kolkata" }
  );

  return router;
};
