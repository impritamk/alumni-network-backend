const express = require("express");
const axios = require("axios");
const cron = require("node-cron");

const router = express.Router();

// 100 rotating templates for the automatic every-3-days email
const AUTO_EMAIL_TEMPLATES = [
  { key: "hello_world", subject: "Hello World! (It's been a while) 👋", content: "Just a quick ping to see how you are doing!\n\nThe ConnectAlumni network has been growing, and your batchmates are missing you. We have some fresh job postings and new conversations happening right now.\n\nTake a quick break from your screen and come say hi!" },
  { key: "error_404", subject: "Error 404: Alumni Not Found 🔍", content: "We ran a search for you on the network recently, but you were nowhere to be found!\n\nDon't worry, we saved your spot. The Chaibasa Engineering community has been sharing some great new job referrals and interview tips this week.\n\nLog back in and let us know what you've been working on lately!" },
  { key: "code_compiling", subject: "While your code is compiling... ⏳", content: "...why not check in with your college network?\n\nWe know you are busy, but there are some new job opportunities and alumni discussions waiting for you. It only takes a minute to see what’s new.\n\nGrab some water, stretch your legs, and come see what your batchmates are up to!" },
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
  { key: "stay_connected", subject: "🌐 Your lifelong CEC network is one click away", content: "Whether you're hiring, job hunting, or just catching up—your alumni community is here." },
  { key: "merge_conflict", subject: "🔀 Zero merge conflicts in real friendships", content: "Even after graduation, your branch and batchmates are just a message away on Connect Alumni." },
  { key: "git_commit", subject: "📌 Commit to staying connected this week", content: "Push a quick update to your profile or feed—your network loves seeing what you're up to." },
  { key: "coffee_break", subject: "🍵 Tea or coffee break? Check the feed", content: "Take a 2-minute break to read recent posts and job leads from Chaibasa Engineering alumni." },
  { key: "senior_insights", subject: "🧠 Learn from seniors who've been there", content: "Browse profiles of alumni in your field and start a friendly conversation." },
  { key: "junior_spark", subject: "✨ Fresh energy from recent batches", content: "See the latest projects, skills, and updates shared by newer graduates on the platform." },
  { key: "remote_work_tips", subject: "🏡 Working remote or hybrid? Share your setup", content: "Post your favorite productivity habits or remote work tips for fellow alumni." },
  { key: "resume_feedback", subject: "📄 Need a second pair of eyes on your resume?", content: "Connect with alumni in your domain for practical career and resume guidance." },
  { key: "core_engineering", subject: "⚙️ Core engineering updates & opportunities", content: "Mechanical, civil, electrical, metallurgy, or ECE—find peers and roles across every branch." },
  { key: "software_craft", subject: "💻 Building software? Share what you're shipping", content: "Tell the community about the tools, frameworks, or side projects exciting you right now." },
  { key: "data_and_ai", subject: "📊 Exploring data, analytics, or AI workflows?", content: "Swap notes and real-world lessons with alumni working in data and tech." },
  { key: "product_and_ops", subject: "📋 Product, management, or operations roles?", content: "Connect with alumni leading teams, deliveries, and operations across industries." },
  { key: "govt_and_psu", subject: "🏛️ Preparing for or serving in public sector roles?", content: "Share exam tips, experiences, and guidance with fellow CEC members." },
  { key: "first_job_story", subject: "🌱 How did you land your first opportunity?", content: "Your story could give a current student or recent grad the exact confidence they need." },
  { key: "interview_lessons", subject: "💡 One interview question you'll never forget", content: "Share a memorable interview lesson on the feed to help others prepare." },
  { key: "weekend_reads", subject: "📖 Catch up on posts you might have missed", content: "Scroll through the latest alumni updates and job shares whenever you have a spare moment." },
  { key: "monday_momentum", subject: "⚡ Start your week strong with your network", content: "Check new job openings, update your status, and say hello to someone new." },
  { key: "midweek_pulse", subject: "💓 Midweek check-in from Connect Alumni", content: "See who joined recently and what conversations are trending in the community." },
  { key: "friday_wind_down", subject: "🎉 Wrapping up the week? Drop a quick update", content: "Share a win from this week or see what your batchmates achieved." },
  { key: "new_members", subject: "👋 Welcome new faces to Connect Alumni", content: "Check the directory for recently joined alumni and send a welcoming note." },
  { key: "batch_pride", subject: "🎓 Every passout year brings something special", content: "Filter by batch year in the directory to reconnect with your graduating class." },
  { key: "hostel_stories", subject: "🏠 Remember late-night hostel talks?", content: "Reconnect with old friends and see where life has taken them since campus days." },
  { key: "exam_days_tbt", subject: "📝 Remember semester exam nights?", content: "Laugh about college memories with your batchmates and see what they're doing today." },
  { key: "fest_memories", subject: "🎭 College fests and campus moments", content: "Your college circle is still right here—log in and catch up with familiar names." },
  { key: "location_search", subject: "🗺️ Moving to a new city soon?", content: "Search the directory by location before you move—find CEC alumni already there." },
  { key: "company_search", subject: "🏢 Curious who works at a specific company?", content: "Use the directory search to spot alumni across companies and roles." },
  { key: "open_to_mentor", subject: "🧭 Open to mentoring? Let others know", content: "Update your 'Open To' field on your profile so juniors and peers can reach out." },
  { key: "open_to_collaborate", subject: "🤝 Looking for a project partner or co-builder?", content: "Share what you want to build and connect with like-minded alumni." },
  { key: "open_to_hire", subject: "📢 Got openings on your team?", content: "Post a job or referral opportunity on Connect Alumni and help a fellow graduate." },
  { key: "open_to_network", subject: "🌐 Expanding your professional circle?", content: "Browse profiles, send a connection request, and start meaningful conversations." },
  { key: "profile_headline", subject: "✍️ A crisp headline helps people find you", content: "Keep your headline and current company up to date so batchmates always recognize you." },
  { key: "linkedin_github", subject: "🔗 Keep your LinkedIn & GitHub linked", content: "Adding your links makes it easy for peers and hiring alumni to check out your work." },
  { key: "quick_hello", subject: "😊 A 30-second hello goes a long way", content: "Send a quick message to a senior, junior, or classmate you haven't chatted with lately." },
  { key: "community_spirit", subject: "❤️ Alumni helping alumni", content: "Strong networks are built on small favors—a reply, a tip, or a referral." },
  { key: "job_board_alert", subject: "💼 Don't miss recent job board listings", content: "Visit the Jobs section to view newly shared roles and referral leads." },
  { key: "post_an_update", subject: "📝 Got something on your mind? Make a post", content: "Share an article, question, or update with the Connect Alumni feed." },
  { key: "like_and_comment", subject: "👍 Cheer on a fellow alumnus today", content: "Leave a comment or like on a recent post to support someone in your network." },
  { key: "inbox_check", subject: "📥 Any unread messages waiting for you?", content: "Check your inbox on Connect Alumni so you don't miss a note from a batchmate." },
  { key: "connection_requests", subject: "🤝 Pending connection requests to review", content: "Log in to accept new connections and grow your alumni circle." },
  { key: "career_pivot", subject: "🔄 Thinking about a career switch?", content: "Reach out to alumni who made similar transitions and learn from their path." },
  { key: "skill_exchange", subject: "🛠️ Trade tips, tools, and workflows", content: "Ask the community how they solve tough problems in their day-to-day work." },
  { key: "book_or_course", subject: "📚 Recommend a great book, resource, or course", content: "Share something valuable you've read or learned lately on the feed." },
  { key: "conference_or_event", subject: "🎤 Attending a tech or industry event?", content: "See if fellow CEC alumni are nearby or share takeaways with the group." },
  { key: "burnout_check", subject: "🌿 Take a breather—check in with your circle", content: "Work gets hectic; take a quick pause and reconnect with familiar faces." },
  { key: "big_wins", subject: "🏆 Celebrate small and big wins together", content: "Promotion, new offer, certification, or side project—share your win on the feed." },
  { key: "honest_questions", subject: "❓ Have a question you're hesitant to ask?", content: "Your alumni community is a supportive space to ask career and growth questions." },
  { key: "branch_pride_cse", subject: "💻 CSE & IT alumni—what are you building?", content: "Connect with computer and IT graduates sharing roles, projects, and tips." },
  { key: "branch_pride_mech", subject: "⚙️ Mechanical alumni—where are you making impact?", content: "Reconnect with mechanical graduates across manufacturing, design, and operations." },
  { key: "branch_pride_ee", subject: "⚡ Electrical & ECE alumni—let's connect", content: "Find electrical and electronics classmates and seniors across power, core, and tech." },
  { key: "branch_pride_civil", subject: "🏗️ Civil alumni—share what you're working on", content: "Connect with civil engineering graduates across infrastructure, planning, and projects." },
  { key: "branch_pride_meta", subject: "🔥 Metallurgical alumni—stay connected", content: "Catch up with fellow metallurgy graduates and share opportunities across the field." },
  { key: "fresh_grads", subject: "🎓 Recent graduate? Build your network early", content: "Connect with seniors and peers on Connect Alumni to learn, grow, and find leads." },
  { key: "experienced_pros", subject: "🌟 Experienced alumnus? Your perspective matters", content: "Even a short note of advice from your experience can help someone take the next step." },
  { key: "referral_reminder", subject: "🎟️ Employee referral window open at your org?", content: "Let the community know—a quick referral link can help a fellow alumnus." },
  { key: "hiring_manager_ping", subject: "👔 Hiring for your team right now?", content: "Post the opening on Connect Alumni and reach verified graduates directly." },
  { key: "project_showcase", subject: "🚀 Built something cool lately? Show it off", content: "Share a demo, repo, or project update with fellow engineers and creators." },
  { key: "side_hustle_talk", subject: "💡 Side projects & weekend experiments", content: "Tell the feed what you're tinkering with outside your main role." },
  { key: "system_design_chat", subject: "📐 Designing systems at scale?", content: "Swap architecture and engineering notes with fellow alumni in tech." },
  { key: "field_work_stories", subject: "🏭 Stories from plants, sites, and the field", content: "Share real-world lessons from on-site, plant, or field operations." },
  { key: "leadership_notes", subject: "🧭 Leading a team for the first time?", content: "Connect with alumni who have navigated management and team leadership." },
  { key: "freelance_and_consulting", subject: "💼 Freelancing or consulting on your own?", content: "Share tips on clients, delivery, and independent work with the network." },
  { key: "work_life_balance", subject: "⚖️ Balancing ambition with rest", content: "Start a conversation on sustainable growth and healthy work habits." },
  { key: "city_meetup_idea", subject: "📍 Want to meet alumni in your city?", content: "Spot classmates and seniors in your city using the directory." },
  { key: "batch_reunion_vibe", subject: "🎊 Keep your batch thread alive", content: "Check in with your passout year and see who's active on Connect Alumni." },
  { key: "forgotten_password_ok", subject: "🔑 Need to refresh your profile or say hi?", content: "Head back to Connect Alumni anytime—your network is waiting." },
  { key: "silent_reader", subject: "👀 Reading silently? Come say hello!", content: "Even if you mostly lurk, drop a quick comment or update your profile when you can." },
  { key: "one_connection_goal", subject: "🎯 Make just one new connection this week", content: "Browse the directory and send one connection request today." },
  { key: "one_post_goal", subject: "✍️ Share just one helpful tip this week", content: "One post on the feed can spark great conversations and opportunities." },
  { key: "appreciation_note", subject: "🙏 Thank you for being part of Connect Alumni", content: "Every active member makes this community more helpful for everyone." },
  { key: "growth_together", subject: "🌱 Growing together, batch after batch", content: "From campus days to career milestones—stay connected with your CEC family." },
  { key: "weekly_digest_vibe", subject: "📬 Fresh updates on Connect Alumni", content: "New posts, job openings, and alumni activity are waiting for you on the platform." },
  { key: "never_stop_learning", subject: "📘 What new skill are you picking up?", content: "Share what you're learning right now and see what others are exploring." },
  { key: "career_questions", subject: "💬 Have a career question for the community?", content: "Post your question on the feed and get perspectives from fellow alumni." },
  { key: "bridge_the_gap", subject: "🌉 Bridging seniors, batchmates, and juniors", content: "Connect across batches on Connect Alumni to share knowledge and opportunities." },
  { key: "always_welcome", subject: "🚪 Your seat in the alumni network is always open", content: "Drop in whenever you're free to catch up, post a job, or connect with peers." },
  { key: "century_template", subject: "💯 Template #100: Stay connected with Connect Alumni", content: "Here's to staying connected with your batchmates, seniors, and juniors—log in anytime to see what's new!" }
];

function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function sendAutoEmail(email, name, subject, content) {
  const safeName = escapeHtml(name || "Alumni");
  
  // Splits text by double-newlines into properly spaced paragraphs
  const formattedBody = escapeHtml(content)
    .split(/\n\s*\n/)
    .map(
      (paragraph) =>
        `<p style="color: #475569; font-size: 16px; line-height: 1.6; margin: 0 0 16px 0;">${paragraph.replace(/\n/g, "<br/>")}</p>`
    )
    .join("");

  const emailHtml = `
    <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; padding: 30px; background-color: #f8fafc;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <h2 style="color: #0f172a; margin-top: 0; margin-bottom: 16px;">Hi ${safeName},</h2>
        ${formattedBody}
        <a href="${process.env.FRONTEND_URL}" style="display: inline-block; background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 8px; font-weight: bold;">
          Open ConnectAlumni
        </a>
        
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 28px 0 16px 0;" />
        <p style="color: #94a3b8; font-size: 12px; line-height: 1.5; margin: 0;">
          <strong>Please do not reply to this email</strong>—this inbox is unmonitored.<br/>
          You receive this brief check-in once every 3 days to share community updates and keep our free alumni platform active and running smoothly.
        </p>
      </div>
    </div>
  `;

  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: { email: process.env.FROM_EMAIL, name: "Connect Alumni (No-Reply)" },
      to: [{ email }],
      subject,
      htmlContent: emailHtml
    },
    { headers: { "api-key": process.env.BREVO_API_KEY } }
  );
}

async function ensureLogTable(pool) {
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

async function runThreeDayAutoCampaign(pool) {
  await ensureLogTable(pool);

  const lastLog = await pool.query(
    "SELECT template_index, sent_at FROM automated_email_logs ORDER BY id DESC LIMIT 1"
  );

  // Enforce exact 3-day gap
  if (lastLog.rows.length > 0) {
    const lastSent = new Date(lastLog.rows[0].sent_at);
    const threeDaysMs = 3 * 24 * 60 * 60 * 1000;
    if (Date.now() - lastSent.getTime() < threeDaysMs) {
      return;
    }
  }

  const nextIndex =
    lastLog.rows.length > 0
      ? (lastLog.rows[0].template_index + 1) % AUTO_EMAIL_TEMPLATES.length
      : 0;
  const template = AUTO_EMAIL_TEMPLATES[nextIndex];

  const usersRes = await pool.query(
    `SELECT email, first_name FROM users 
     WHERE verification_status = 'verified' 
       AND is_banned = false 
       AND email != 'alumninetworkplatform@gmail.com'`
  );

  let sentCount = 0;
  for (const user of usersRes.rows) {
    try {
      await sendAutoEmail(user.email, user.first_name, template.subject, template.content);
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
}

module.exports = function initEmailModule({ pool, verifyToken, requireAdmin }) {
  // Optional route to inspect history & templates
  router.get("/admin/email-campaigns/status", verifyToken, requireAdmin, async (req, res) => {
    try {
      await ensureLogTable(pool);
      const logs = await pool.query("SELECT * FROM automated_email_logs ORDER BY id DESC LIMIT 10");
      res.json({ totalTemplates: AUTO_EMAIL_TEMPLATES.length, recentRuns: logs.rows });
    } catch (err) {
      res.status(500).json({ message: "Failed to load campaign status" });
    }
  });

  // Runs every day at 10:00 AM IST; sends if 3 days have passed
  cron.schedule(
    "0 10 * * *",
    () => {
      runThreeDayAutoCampaign(pool).catch((err) =>
        console.error("❌ Scheduled 3-day campaign error:", err.message)
      );
    },
    { timezone: "Asia/Kolkata" }
  );

  return router;
};
