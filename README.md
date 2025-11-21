# OOPs Project K11 – Socket-based Secure Chat App

This project is a full-stack, end‑to‑end **secure chat application** built as an OOP (Object-Oriented Programming) project. It combines a C++ socket server for secure message handling with a modern React-based chat UI and Supabase-backed authentication.

---

## Project Overview

- **Backend (C++ server in `server/`)**
  - Socket-based TCP chat server
  - Multi-client handling using dedicated connection/client handler classes
  - Message broadcasting and private messaging
  - Password hashing and user management via `users.json`
  - Enhanced encryption layer for secure message transport
  - Logging utilities and helper scripts to remove credentials from history

- **Frontend (React app in `react-chat-app/`)**
  - Modern chat UI with sidebar, chat layout and message list
  - Login & signup flows with Supabase authentication
  - WebSocket-based real-time messaging
  - AI chat integration via Gemini/OpenRouter (configurable)
  - Rich animations using Lottie (loading, typing, message delivery, etc.)
  - Emoji picker, file preview and polished UI components

---

## Tech Stack

- **Backend**: C++, CMake, sockets, custom encryption & password hashing
- **Frontend**: React, Vite/Webpack, CSS modules, Lottie animations
- **Auth & Data**: Supabase (PostgreSQL + Auth)
- **Real-time**: WebSockets
- **AI Integration**: Google Gemini or OpenRouter (configurable via env)

---

## Repository Structure

```text
.
├─ server/             # C++ socket server + encryption + user management
│  ├─ *.cpp / *.h      # Core server, connection, user, message, logger, crypto
│  ├─ users.json*      # User credential store (example + backup)
│  └─ build/           # CMake build artifacts (ignored in git)
│
├─ react-chat-app/     # React chat frontend
│  ├─ src/
│  │  ├─ components/   # Auth, Chat, Sidebar, Common UI components
│  │  ├─ context/      # Chat & WebSocket context providers
│  │  ├─ hooks/        # Custom hooks (e.g. smooth scrolling)
│  │  └─ utils/        # Crypto utilities
│  ├─ public/          # Static files + Lottie animation JSON
│  ├─ certs/           # Local SSL development certificates (ignored in git)
│  └─ server.js        # Dev server / bridge for frontend
│
├─ .gitignore
├─ .dockerignore
└─ README.md           # You are here
```

---

## Prerequisites

- **Node.js** (LTS) + pnpm or npm
- **C++ compiler** with CMake (for the server)
- **Supabase account**
- (Optional) API key for **Gemini** or **OpenRouter** for AI chat

---

## Backend Setup (`server/`)

1. Open a terminal in the project root:

```powershell
cd "C:\Users\sidde\OneDrive\Desktop\FSD\SecureChatServer\server"
```

2. Configure and build with CMake:

```powershell
cmake -S . -B build
cmake --build build
```

3. Create or edit your `users.json` based on `users.json.example` and use the password hashing utilities (see `password_hash.cpp`) if required.

4. Run the server executable produced in `build/` (name may vary depending on your CMake config):

```powershell
cd build
./chat_server   # or the generated executable name
```

> **Note:** See `server/CREDENTIALS_SECURITY.md` and `server/IMMEDIATE_ACTION_REQUIRED.md` for important security notes.

---

## Frontend Setup (`react-chat-app/`)

1. Open a terminal in the project root and go to the React app:

```powershell
cd "C:\Users\sidde\OneDrive\Desktop\FSD\SecureChatServer\react-chat-app"
```

2. Install dependencies:

```powershell
pnpm install   # or: npm install
```

3. Copy `.env.example` to `.env` and fill in your values:

```powershell
Copy-Item .env.example .env
```

Update the following keys in `.env`:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `AI_PROVIDER` (e.g. `gemini` or `openrouter`)
- `GEMINI_API_KEY` / `OPENROUTER_API_KEY`
- `REACT_APP_WS_URL` (WebSocket URL for the C++ server)
- `REACT_APP_API_URL` (if you expose REST endpoints)

4. Start the React dev server:

```powershell
pnpm dev   # or: npm run dev
```

5. Open the printed local URL (usually `http://localhost:5173` or similar) in your browser.

---

## Running the Full System

1. **Start the C++ server** from `server/build`.
2. **Start the React frontend** from `react-chat-app`.
3. Sign up / log in, then start chatting in public rooms, private chats or with the AI assistant.

---

## Architecture Diagram (Textual)

```text
+---------------------------+          +------------------------------+
|   React Frontend (SPA)    |          |   Supabase (Auth + DB)      |
|  - Chat UI (React)        |  HTTPS   |  - User auth (optional)     |
|  - Context & Hooks        +---------->  - Profile / metadata       |
|  - AI Chat Panel          |          +------------------------------+
|  - Animations (Lottie)    |
+-------------+-------------+
              |
              |  WebSocket / HTTP (API/bridge)
              v
+-------------+-------------+
|   C++ Chat Server         |
|  - TCP socket listener    |
|  - ClientHandler /        |
|    Connection classes     |
|  - Message routing        |
|  - Encryption & hashing   |
|  - Logging                |
+-------------+-------------+
              |
              |  Encrypted TCP messages
              v
+-------------+-------------+
|   Other Chat Clients      |
| (React app instances)     |
+---------------------------+
```

---

## Sequence Diagram (Login + Send Message)

```text
User           React App           C++ Server             Other Client
 |                |                    |                      |
 |  Open app      |                    |                      |
 |--------------->|                    |                      |
 |                |  POST /login       |                      |
 |                |------------------->|                      |
 |                |   verify user,     |                      |
 |                |   hash password    |                      |
 |                |<-------------------|                      |
 |                |  login success     |                      |
 |<---------------|                    |                      |
 |                |                    |                      |
 |  Type message  |                    |                      |
 |--------------->|                    |                      |
 |                |  send over         |                      |
 |                |  WebSocket/TCP     |                      |
 |                |------------------->|                      |
 |                |                    |  decrypt, route      |
 |                |                    |  (broadcast/private) |
 |                |                    |--------------------->|
 |                |                    |   deliver message    |
 |                |<-------------------|                      |
 |  show message  |                    |                      |
 |<---------------|                    |                      |
 |                                    ...                    ...
```

---

## Security & Credentials

- Do **not** commit real credentials. Use `.env` files which are already ignored via `.gitignore`.
- `users.json` in `server/` should only contain hashed passwords.
- Read `server/CREDENTIALS_SECURITY.md` and `server/IMMEDIATE_ACTION_REQUIRED.md` carefully before deploying or sharing the project.

---

## Future Improvements

- Deployment-ready Docker setup for both server and client
- Enhanced monitoring/logging views in the frontend
- More advanced AI features (summarization, moderation, etc.)

---

## License

This project is for educational and demonstration purposes. Add your preferred license here if you plan to make it public/production-ready.
