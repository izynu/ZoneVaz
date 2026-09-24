# ✨ ZoneVaz Studio

<p align="center">
  <strong>Aesthetic Music. Personal Library. Your Space.</strong>
</p>

<p align="center">
  A full music web application built with HTML, CSS, JavaScript, Node.js and PHP.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-ff9ebd?style=for-the-badge">
  <img src="https://img.shields.io/badge/Node.js-14%2B-c49fff?style=for-the-badge&logo=node.js&logoColor=white">
  <img src="https://img.shields.io/badge/PWA-Ready-ff9ebd?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-c49fff?style=for-the-badge">
</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/HTML5-e34f26?style=flat&logo=html5&logoColor=white">
  <img src="https://img.shields.io/badge/CSS3-1572b6?style=flat&logo=css3&logoColor=white">
  <img src="https://img.shields.io/badge/JavaScript-f7df1e?style=flat&logo=javascript&logoColor=black">
  <img src="https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white">
  <img src="https://img.shields.io/badge/PHP-777bb4?style=flat&logo=php&logoColor=white">
</p>

---

## 🌸 About

**ZoneVaz Studio** is a personal music ecosystem focused on creating a smooth and aesthetic listening experience.

The project brings together music discovery, playlists, personal libraries, lyrics, downloads, trending content and an interactive visualizer inside one interface.

The frontend is designed around a dark glass style with pink and purple accents, while the backend handles authentication, sessions, user data, playlists, API communication and administrative functionality.

The application also includes Progressive Web App support through a manifest and service worker.

---

## 🎧 What You Can Do

<table>
<tr>
<td width="50%">

### 🎵 Music

🔎 Search for music

🎶 Play music

📥 Download tracks

📖 View lyrics

🔥 Explore trending music

🎚️ Use the interactive visualizer

</td>

<td width="50%">

### 👤 Personal Space

🔐 Create an account

👤 Manage your profile

❤️ Manage your library

📁 Create playlists

🎨 Change themes

💾 Keep personal settings

</td>
</tr>
</table>

---

## ✨ Highlights

```text
╭──────────────────────────────────────────╮
│                                          │
│        ✨ Z O N E V A Z   S T U D I O   │
│                                          │
│     🎵 Music                            │
│     📁 Personal Library                 │
│     🎶 Playlists                        │
│     🎤 Lyrics                           │
│     🔥 Trending                         │
│     🔮 Visualizer                       │
│     👤 User Accounts                    │
│     👑 Admin Panel                      │
│     📱 PWA Support                      │
│                                          │
╰──────────────────────────────────────────╯
```

---

# 🎨 Interface

ZoneVaz uses a dark aesthetic design with glass style components, soft gradients and animated visual elements.

The application currently includes three main visual styles.

| Theme      | Style                |
| :--------- | :------------------- |
| 🌸 Default | Dark pink and purple |
| ⚡ Cyber    | Cyan and magenta     |
| 🌸 Sakura  | Soft pink and rose   |

Theme settings can be synchronized across pages and cached locally for faster loading.

---

# 📱 Progressive Web App

ZoneVaz is configured as a Progressive Web App.

The project includes:

```text
manifest.json
sw.js
```

The service worker caches the main application shell and supports network first navigation with cached fallbacks. API requests are intentionally excluded from caching so live application data remains fresh.
This allows the application to behave more like an installable application rather than a normal website.

---

# 🧩 Project Structure

```text
ZoneVaz Studio
│
├── 🌐 index.html
├── 🔐 login.html
├── 📥 download.html
├── 👤 profile.html
├── 📁 playlists.html
├── 🔥 trending.html
├── 🔮 visualizer.html
├── 🎤 lyrics.html
├── 💜 lounge.html
├── 👑 admin.html
├── 🚫 404.html
│
├── ⚙️ common.js
├── 🖥️ server.js
├── 🐘 api.php
├── 📱 sw.js
├── 📋 manifest.json
├── 📦 package.json
├── 🔒 .htaccess
│
└── 💾 data
    └── Application Data
```

---

# 🖥️ Backend

The primary backend is written in Node.js.

The server uses Node.js built in modules such as:

```text
http
https
fs
path
crypto
```

No external Node.js framework is required for the main server.

The backend handles:

```text
🔐 Authentication
👤 User Accounts
📁 Personal Libraries
🎶 Playlists
🔎 Search
📥 Downloads
🎤 Lyrics
🎧 Streaming
👑 Administration
⚙️ Settings
📋 Logs
💾 Backup
♻️ Restore
```

---

# 🔐 Security

Security is handled on the server side rather than relying only on frontend checks.

### Passwords

The Node.js backend uses the built in `crypto.scryptSync` function for password hashing.

### Sessions

User sessions are maintained by the server.

### CSRF

The frontend API helper receives and sends CSRF information when communicating with the backend.

### Rate Limiting

The backend includes login attempt controls and request rate limiting.

### API Keys

External API credentials are handled through the backend instead of being exposed directly to the frontend.

> ⚠️ **Important:** Never publish active API keys, administrator passwords or other private credentials inside a public GitHub repository.

---

# 🗃️ Data Storage

ZoneVaz currently uses JSON files for persistent application data.

```text
data/
│
├── settings.json
├── users.json
├── sessions.json
├── playlists.json
├── library.json
├── logs.json
└── ...
```

The backend automatically creates the data directory when required and provides JSON read and write helpers.

This keeps the setup lightweight and avoids requiring a traditional database for the current project.

---

# ⚡ Installation

## 1️⃣ Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
```

## 2️⃣ Enter the Project

```bash
cd zonevaz-studio
```

## 3️⃣ Check Node.js

ZoneVaz requires Node.js 14 or newer.

```bash
node --version
```

## 4️⃣ Start ZoneVaz

```bash
node server.js
```

Or:

```bash
npm start
```

The project package configuration defines `node server.js` as the start command.

## 5️⃣ Open the Website

Open the local address displayed by the server in your browser.

---

# 🐘 PHP Version

A PHP backend is also included through:

```text
api.php
```

This version is useful for hosting environments where Node.js is not available.

The PHP backend handles authentication, sessions, CSRF protection, libraries, playlists, administration, external API requests, downloads, lyrics, streaming and backups.

---

# 🛠️ Technology

<p align="center">

| Technology   | Purpose                            |
| :----------- | :--------------------------------- |
| 🌐 HTML      | Application structure              |
| 🎨 CSS       | Interface and animations           |
| ⚡ JavaScript | Frontend functionality             |
| 🟢 Node.js   | Main backend                       |
| 🐘 PHP       | Alternative backend                |
| 📄 JSON      | Application storage                |
| 📱 PWA       | Installable application support    |
| 🔐 Crypto    | Password security                  |
| 🎧 Web APIs  | Music and visualizer functionality |

</p>

---

# 📂 Main Pages

| File              | Purpose                  |
| :---------------- | :----------------------- |
| `index.html`      | Main ZoneVaz interface   |
| `login.html`      | Login and registration   |
| `download.html`   | Music download interface |
| `profile.html`    | User profile             |
| `playlists.html`  | Personal playlists       |
| `trending.html`   | Trending music           |
| `visualizer.html` | Interactive visualizer   |
| `lyrics.html`     | Lyrics interface         |
| `lounge.html`     | Music lounge             |
| `admin.html`      | Administration panel     |
| `404.html`        | Custom error page        |

---

# 🎨 Frontend

The shared frontend helper is located in:

```text
common.js
```

It provides functionality for:

```text
API requests
CSRF handling
Session bootstrap
Theme synchronization
Palette handling
Local storage handling
Cached settings
```

The helper also escapes user supplied content before it is inserted into HTML.

---

# 📦 Package

Current project information:

```text
Name       zonevaz-studio
Version    2.0.0
Runtime    Node.js 14+
License    UNLICENSED
```

The project is currently marked private in its package configuration.

---

# ⚠️ Before Publishing

If you are uploading this project to a public GitHub repository, check these files before pushing:

```text
server.js
api.php
data/
.htaccess
```

Remove or replace:

```text
🔑 API keys
🔐 Administrator credentials
🍪 Session secrets
🗝️ Private configuration
📂 User generated data
```

Use environment variables or a private configuration file for production secrets.

Add sensitive files to `.gitignore`.

Example:

```gitignore
data/
.env
*.log
node_modules/
```

---

# 🧪 Development

ZoneVaz is currently structured as a lightweight application rather than a large framework based project.

The frontend pages are directly accessible HTML files while the backend provides the application logic and API functionality.

This makes the project relatively easy to inspect, modify and experiment with.

---

# 🌙 Project Status

```text
████████████████████████████████  Active Development
```

ZoneVaz Studio is an ongoing personal project.

Features, design elements and backend functionality may continue to change as development progresses.

---

# 🖤 Why I Built This

ZoneVaz started as an experiment in building a complete music experience from scratch.

The goal was not just to make a music player.

I wanted to experiment with:

```text
Frontend Design
Backend Development
Authentication
API Integration
Music Streaming
Progressive Web Apps
Caching
Security
User Data
Admin Systems
Interactive Visuals
```

Everything is being developed around one simple idea:

> **Make something that feels like your own space.**

---

# 📜 License

The current project is marked as:

```text
UNLICENSED
```

If the repository is made public, add a suitable license before allowing others to reuse or redistribute the project.

---

<p align="center">

## ✨ ZoneVaz Studio

**Music • Design • Code • Creativity**

Built with curiosity and a lot of late nights. 🌙

<br>

⭐ If you like the project, consider giving the repository a star.

</p>
