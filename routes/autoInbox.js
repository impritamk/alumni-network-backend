const express = require("express");
const cron = require("node-cron");

const router = express.Router();

const AUTO_INBOX_TEMPLATES = [
  {
    title: "Quick Check-In 👋",
    body: "Just checking in from ConnectAlumni! See who from your batch or branch has posted updates or job leads lately."
  },
  {
    title: "Network & Referrals 🤝",
    body: "Looking for a role, hiring on your team, or open to mentoring juniors? Update your profile or explore the directory today."
  },
  {
    title: "Batch & City Catch-Up 📍",
    body: "Filter the alumni directory by passout year, branch, or city to spot classmates and seniors near you."
  },
  {
    title: "Stay Connected ✨",
    body: "Drop a post on the feed or say hi to someone in your network—even a quick note keeps the community active."
  }
];

const AUTOMATED_FOOTER =
  "\n\n— Automated check-in sent periodically to keep our platform and database active.";

async function ensureInboxLogTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS automated_inbox_logs (
      id SERIAL PRIMARY KEY,
      template_index INT NOT NULL,
      recipient_count INT NOT NULL DEFAULT 0,
      sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function getOrCreateDirectRoom(pool, senderId, recipientId) {
  const roomName = [String(senderId), String(recipientId)].sort().join("_");

  const existing = await pool.query(
    "SELECT * FROM chat_rooms WHERE name = $1 AND type = 'direct' LIMIT 1",
    [roomName]
  );

  if (existing.rows.length > 0) {
    return existing.rows[0];
  }

  const created = await pool.query(
    `INSERT INTO chat_rooms (name, type, created_by, created_at)
     VALUES ($1, 'direct', $2, NOW())
     RETURNING *`,
    [roomName, senderId]
  );

  return created.rows[0];
}

async function runPeriodicAutoInbox(pool, io) {
  await ensureInboxLogTable(pool);

  const botEmail = process.env.GUEST_BOT_EMAIL || "alumninetworkplatform@gmail.com";
  const botRes = await pool.query("SELECT id FROM users WHERE email = $1 LIMIT 1", [botEmail]);

  if (botRes.rows.length === 0) {
    console.warn("⚠️ Auto-inbox skipped: guest account not found for", botEmail);
    return;
  }

  const senderId = botRes.rows[0].id;

  const lastLog = await pool.query(
    "SELECT template_index, sent_at FROM automated_inbox_logs ORDER BY id DESC LIMIT 1"
  );

  // Enforce a 4-day gap with a 2-hour buffer (94 hours)
  if (lastLog.rows.length > 0) {
    const lastSent = new Date(lastLog.rows[0].sent_at);
    const fourDaysMs = 4 * 24 * 60 * 60 * 1000;
    const bufferMs = 2 * 60 * 60 * 1000;
    if (Date.now() - lastSent.getTime() < fourDaysMs - bufferMs) {
      return;
    }
  }

  const nextIndex =
    lastLog.rows.length > 0
      ? (lastLog.rows[0].template_index + 1) % AUTO_INBOX_TEMPLATES.length
      : 0;

  const tpl = AUTO_INBOX_TEMPLATES[nextIndex];
  const fullMessage = `${tpl.title}\n\n${tpl.body}${AUTOMATED_FOOTER}`;

  const usersRes = await pool.query(
    `SELECT id FROM users
     WHERE verification_status = 'verified'
       AND is_banned = false
       AND id != $1`,
    [senderId]
  );

  let sentCount = 0;

  for (const user of usersRes.rows) {
    try {
      const room = await getOrCreateDirectRoom(pool, senderId, user.id);

      const inserted = await pool.query(
        `INSERT INTO chat_messages (room_id, sender_id, message, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING *`,
        [room.id, senderId, fullMessage]
      );

      if (io && inserted.rows[0]) {
        io.to(String(room.id)).emit("receiveMessage", inserted.rows[0]);
      }

      sentCount++;
    } catch (err) {
      console.error(`❌ Auto-inbox failed for user ${user.id}:`, err.message);
    }
  }

  await pool.query(
    "INSERT INTO automated_inbox_logs (template_index, recipient_count) VALUES ($1, $2)",
    [nextIndex, sentCount]
  );

  console.log(`✅ Periodic Auto-Inbox [#${nextIndex}] sent to ${sentCount} users.`);
}

module.exports = function initAutoInboxModule({ pool, io }) {
  // Runs daily at 10:00 AM IST; sends once 4 days (minus 2h buffer) have passed
  cron.schedule(
    "0 10 * * *",
    () => {
      runPeriodicAutoInbox(pool, io).catch((err) =>
        console.error("❌ Scheduled auto-inbox error:", err.message)
      );
    },
    { timezone: "Asia/Kolkata" }
  );

  return router;
};
