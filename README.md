

# 🎓 ConnectAlumni

![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)

**ConnectAlumni** is a robust, full-stack professional networking platform engineered to bridge the gap between college alumni and current students. Built with a decoupled Client-Server architecture, it features secure authentication, an intelligent job board, and a mathematical private messaging engine.

🌐 **Live Demo:** [https://alumni-network-frontend-sepia.vercel.app](https://alumni-network-frontend-sepia.vercel.app/)  
⚙️ **Backend API:** [https://alumni-network-backend-9p0y.onrender.com](https://alumni-network-backend-9p0y.onrender.com)  

---

## ✨ Core Features

* **🔐 Secure Authentication:** Stateless JWT session management with `bcryptjs` password hashing. Includes Brevo SMTP integration for secure 6-digit OTP email verification and password resets.
* **💼 Intelligent Job Ecosystem:** Users can post roles and apply with cover letters and resume links. The system utilizes PostgreSQL composite keys and frontend logic to prevent users from applying to their own jobs or double-applying. Includes a dedicated "Applicant Dashboard" for job posters.
* **💬 Algorithmic Chat Engine:** 1-on-1 private messaging without heavy junction tables. The backend deterministically generates unique chat rooms based on sorted UUIDs. Includes real-time short-polling and smart "Read Receipt" notification dots.
* **🤝 Network Management:** Dynamic connection states (`not_connected`, `pending`, `accepted`) allowing users to curate their professional network.
* **🌙 Premium UI/UX:** Fully responsive CSS Grid layout with a non-destructive Dark Mode toggle, SVG auto-inversion, and asynchronous toast notifications.

---

## 🛠️ Technology Stack

**Frontend (Client)**
* **Library:** React.js (Hooks, Context API)
* **Routing:** React Router v6
* **HTTP Client:** Axios
* **Styling:** Pure CSS3 (Flexbox/Grid/Variables)
* **Deployment:** Vercel

**Backend (API Gateway)**
* **Runtime:** Node.js
* **Framework:** Express.js
* **Database Engine:** PostgreSQL (via `pg` node-postgres)
* **Security:** Helmet (HTTP headers), CORS, Express Rate Limit (DDoS protection)
* **Deployment:** Render

---

## 🔒 Security Implementations

* **SQL Injection Prevention:** 100% Parameterized queries (`$1, $2`) for all database interactions.
* **Rate Limiting:** API endpoints are throttled to 800 requests per 15 minutes to mitigate brute-force and DDoS attacks.
* **Data Sanitization:** Strict `.toLowerCase().trim()` processing on auth endpoints to ensure data integrity across mobile and desktop keyboards.
* **Route Protection:** React Higher-Order Components (HOC) securely trap and redirect unauthenticated traffic.

---

## 🚀 Getting Started (Local Development)

To run this project locally, you will need Node.js and a running PostgreSQL instance.

### 1. Clone the repository
```bash
git clone [https://github.com/impritamk/connectalumni.git](https://github.com/impritamk/connectalumni.git)
cd connectalumni
2. Backend Setup
Bash
cd backend
npm install
Create a .env file in the /backend directory with the following keys (refer to .env.example):

Code snippet
PORT=5000
DATABASE_URL=your_postgresql_connection_string
JWT_SECRET=your_super_secret_jwt_key
BREVO_API_KEY=your_brevo_smtp_key
FROM_EMAIL=your_verified_sender_email
FRONTEND_URL=[https://alumni-network-frontend-sepia.vercel.app](https://alumni-network-frontend-sepia.vercel.app)
Run the server:

Bash
npm start
3. Frontend Setup
Open a new terminal window:

Bash
cd frontend
npm install
Create a .env file in the /frontend directory:

Code snippet
REACT_APP_API_URL=[https://alumni-network-backend-9p0y.onrender.com](https://alumni-network-backend-9p0y.onrender.com)
Start the React application:

Bash
npm start
🗄️ Database Architecture Highlights
The platform relies on a strictly normalized RDBMS structure:

users: Core entity utilizing UUID primary keys.

connections: Self-referential mapping table for network curation.

jobs & job_applications: Linked via foreign keys with composite unique constraints.

chat_rooms & chat_messages: Utilizes PostgreSQL Array data types for read receipts.

👨‍💻 Author
Pritam Full-Stack Developer | Software Engineering Student at Chaibasa Engineering College * LinkedIn: https://www.linkedin.com/in/im-pritamk/

Portfolio: https://pritam.ct.ws

GitHub: @impritamk

If you found this project interesting, please consider giving it a ⭐!
