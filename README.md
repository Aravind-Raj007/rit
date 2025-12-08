# SIMPLIFIED CYBER DEFENCE FOR THREATS (CyberGuard Lite)

A local-only personal cybersecurity desktop application built with Electron, Next.js, and SQLite.

## 🔒 Privacy First

CyberGuard Lite is a **100% local application** - no internet connection required, no cloud services, no data leaves your device.

## 🚀 Features (Planned)

- **Threat Detection**: Scan files and URLs for potential security threats
- **Network Scanner**: Monitor devices on your local network
- **Encryption Vault**: Securely store sensitive data with AES-256 encryption
- **Scheduled Tasks**: Automate security scans and monitoring
- **Local Authentication**: Secure login with bcrypt password hashing

## 📁 Project Structure

```
project-root/
├── pages/              # Next.js pages
├── components/         # React components
├── lib/               # Business logic
│   ├── threatDetector.js
│   ├── networkScanner.js
│   └── encryption.js
├── public/            # Static assets
├── styles/            # CSS files
├── electron/          # Electron app files
│   ├── main.js       # Main process
│   ├── preload.js    # Preload script
│   ├── database.js   # SQLite database
│   ├── localAuth.js  # Authentication
│   └── scheduler.js  # Task scheduler
├── assets/           # App icons
└── package.json
```

## 🛠️ Tech Stack

- **Frontend**: Next.js 14 + React 18
- **Desktop**: Electron 27
- **Database**: SQLite (better-sqlite3)
- **Security**: bcrypt for password hashing, crypto for encryption
- **Scheduler**: node-schedule for automated tasks

## 📦 Installation

```bash
# Install dependencies
npm install

# Install additional required packages
npm install better-sqlite3 bcrypt node-schedule
```

## 🔧 Development

```bash
# Run in development mode (Next.js + Electron)
npm run electron-dev
```

This will:

1. Start the Next.js development server on http://localhost:3000
2. Wait for the server to be ready
3. Launch the Electron app

## 📦 Building

```bash
# Build Next.js app and package Electron app
npm run electron-build

# Package without building (for testing)
npm run electron-pack

# Create distributable
npm run electron-dist
```

## 🗄️ Database Schema

The app uses SQLite with the following tables:

- **users**: User accounts with bcrypt-hashed passwords
- **threat_scans**: History of threat scans
- **network_devices**: Discovered network devices
- **scheduled_tasks**: Automated task configurations
- **encrypted_vault**: Encrypted data storage

## 🔐 Security Features

- **Local-only**: No internet connection required
- **Encrypted storage**: AES-256-GCM encryption for sensitive data
- **Secure authentication**: bcrypt password hashing with salt
- **Context isolation**: Electron security best practices
- **No remote code**: All code runs locally

## 📝 Current Status

✅ Basic project structure created
✅ Configuration files set up
✅ Electron main process configured
✅ Database schema defined
✅ Authentication system scaffolded
✅ Encryption module implemented
✅ Next.js pages created

⏳ Feature implementation (next phase)
⏳ UI/UX design (next phase)
⏳ Testing (next phase)

## 🚧 Development Notes

This is the initial setup phase. The following modules are currently placeholders:

- Threat detection logic
- Network scanning functionality
- Scheduled task execution

These will be implemented in future phases.

## 📄 License

ISC

## 🤝 Contributing

This is a personal project. Contributions are not currently accepted.
