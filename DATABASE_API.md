# CyberGuard Lite - Database API Documentation

## Overview

The CyberGuard Lite database is a **local-only SQLite database** that stores all user data on the computer. No data is ever sent to the cloud or internet.

**Database Location:**

- Windows: `C:\Users\[username]\AppData\Local\CyberGuard-Lite\cyberguard.db`
- macOS: `~/Library/Application Support/CyberGuard-Lite/cyberguard.db`
- Linux: `~/.config/CyberGuard-Lite/cyberguard.db`

---

## Database Tables

### 1. **users**

Stores user accounts with bcrypt-hashed passwords.

| Column          | Type                 | Description                       |
| --------------- | -------------------- | --------------------------------- |
| `id`            | INTEGER PRIMARY KEY  | Auto-incrementing user ID         |
| `username`      | TEXT UNIQUE NOT NULL | Username (unique)                 |
| `password_hash` | TEXT NOT NULL        | Bcrypt hashed password            |
| `created_at`    | TEXT NOT NULL        | ISO timestamp of account creation |
| `last_login`    | TEXT                 | ISO timestamp of last login       |

### 2. **encrypted_files**

Metadata for encrypted files (.locked files).

| Column            | Type                | Description                 |
| ----------------- | ------------------- | --------------------------- |
| `id`              | INTEGER PRIMARY KEY | Auto-incrementing file ID   |
| `user_id`         | INTEGER NOT NULL    | References users.id         |
| `file_name`       | TEXT NOT NULL       | Original filename           |
| `file_path`       | TEXT NOT NULL       | Original file location      |
| `encrypted_path`  | TEXT NOT NULL       | Location of .locked file    |
| `file_size`       | INTEGER NOT NULL    | File size in bytes          |
| `encryption_date` | TEXT NOT NULL       | ISO timestamp of encryption |

### 3. **scan_history**

History of threat and network scans.

| Column             | Type                | Description                             |
| ------------------ | ------------------- | --------------------------------------- |
| `id`               | INTEGER PRIMARY KEY | Auto-incrementing scan ID               |
| `user_id`          | INTEGER NOT NULL    | References users.id                     |
| `scan_type`        | TEXT NOT NULL       | 'threat' or 'network'                   |
| `scanned_content`  | TEXT NOT NULL       | What was scanned (URL, file path, etc.) |
| `threat_score`     | INTEGER NOT NULL    | Threat score 0-100                      |
| `threats_detected` | TEXT NOT NULL       | JSON array of detected threats          |
| `scan_date`        | TEXT NOT NULL       | ISO timestamp of scan                   |

### 4. **network_devices**

Discovered network devices.

| Column            | Type                | Description                       |
| ----------------- | ------------------- | --------------------------------- |
| `id`              | INTEGER PRIMARY KEY | Auto-incrementing device ID       |
| `user_id`         | INTEGER NOT NULL    | References users.id               |
| `device_name`     | TEXT NOT NULL       | Device hostname/name              |
| `ip_address`      | TEXT NOT NULL       | IP address                        |
| `device_type`     | TEXT NOT NULL       | Device type (router, phone, etc.) |
| `security_status` | TEXT NOT NULL       | 'safe', 'caution', or 'risk'      |
| `discovered_date` | TEXT NOT NULL       | ISO timestamp of discovery        |

### 5. **automation_tasks**

Scheduled automation tasks.

| Column          | Type                | Description                        |
| --------------- | ------------------- | ---------------------------------- |
| `id`            | INTEGER PRIMARY KEY | Auto-incrementing task ID          |
| `user_id`       | INTEGER NOT NULL    | References users.id                |
| `task_name`     | TEXT NOT NULL       | Task name                          |
| `task_type`     | TEXT NOT NULL       | 'daily_scan', 'weekly_check', etc. |
| `schedule_time` | TEXT NOT NULL       | Time in '09:00' format             |
| `schedule_days` | TEXT NOT NULL       | 'daily', 'weekly', 'monthly'       |
| `is_enabled`    | INTEGER NOT NULL    | 0 or 1 (boolean)                   |
| `last_run`      | TEXT                | ISO timestamp of last execution    |
| `next_run`      | TEXT                | ISO timestamp of next execution    |
| `created_date`  | TEXT NOT NULL       | ISO timestamp of creation          |

### 6. **activity_log**

User activity audit log.

| Column           | Type                | Description              |
| ---------------- | ------------------- | ------------------------ |
| `id`             | INTEGER PRIMARY KEY | Auto-incrementing log ID |
| `user_id`        | INTEGER NOT NULL    | References users.id      |
| `action`         | TEXT NOT NULL       | Action description       |
| `action_details` | TEXT NOT NULL       | JSON object with details |
| `timestamp`      | TEXT NOT NULL       | ISO timestamp            |

---

## API Methods

All methods return JSON objects with `success` boolean and relevant data or error messages.

### User Operations

#### `createUser(username, passwordHash)`

Create a new user account.

**Parameters:**

- `username` (string) - Unique username
- `passwordHash` (string) - Bcrypt hashed password

**Returns:**

```javascript
{
  success: true,
  userId: 1,
  message: 'User created successfully'
}
```

**Example:**

```javascript
const result = await window.electronAPI.createUser("john_doe", hashedPassword);
```

---

#### `getUserByUsername(username)`

Retrieve user by username.

**Parameters:**

- `username` (string) - Username to find

**Returns:**

```javascript
{
  success: true,
  user: {
    id: 1,
    username: 'john_doe',
    password_hash: '...',
    created_at: '2025-12-08T07:24:28.000Z',
    last_login: '2025-12-08T07:30:00.000Z'
  }
}
```

---

#### `updateLastLogin(userId)`

Update user's last login timestamp.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  message: 'Last login updated'
}
```

---

### File Operations

#### `saveEncryptedFile(userId, fileInfo)`

Save encrypted file metadata.

**Parameters:**

- `userId` (number) - User ID
- `fileInfo` (object):
  - `fileName` (string) - Original filename
  - `filePath` (string) - Original file path
  - `encryptedPath` (string) - Path to .locked file
  - `fileSize` (number) - File size in bytes

**Returns:**

```javascript
{
  success: true,
  fileId: 1,
  message: 'File metadata saved'
}
```

**Example:**

```javascript
const result = await window.electronAPI.saveEncryptedFile(1, {
  fileName: "document.pdf",
  filePath: "C:\\Users\\John\\Documents\\document.pdf",
  encryptedPath: "C:\\Users\\John\\Documents\\document.pdf.locked",
  fileSize: 1024000,
});
```

---

#### `getEncryptedFiles(userId)`

Get all encrypted files for a user.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  files: [
    {
      id: 1,
      user_id: 1,
      file_name: 'document.pdf',
      file_path: 'C:\\Users\\John\\Documents\\document.pdf',
      encrypted_path: 'C:\\Users\\John\\Documents\\document.pdf.locked',
      file_size: 1024000,
      encryption_date: '2025-12-08T07:24:28.000Z'
    }
  ],
  count: 1
}
```

---

#### `deleteEncryptedFile(fileId)`

Delete encrypted file record.

**Parameters:**

- `fileId` (number) - File ID

**Returns:**

```javascript
{
  success: true,
  message: 'File deleted'
}
```

---

### Scanning Operations

#### `saveScanResult(userId, scanType, content, score, threats)`

Save a scan result.

**Parameters:**

- `userId` (number) - User ID
- `scanType` (string) - 'threat' or 'network'
- `content` (string) - What was scanned
- `score` (number) - Threat score 0-100
- `threats` (array) - Array of detected threats

**Returns:**

```javascript
{
  success: true,
  scanId: 1,
  message: 'Scan result saved'
}
```

**Example:**

```javascript
const result = await window.electronAPI.saveScanResult(
  1,
  "threat",
  "https://example.com",
  75,
  ["Phishing attempt detected", "Suspicious SSL certificate"]
);
```

---

#### `getScanHistory(userId, limit)`

Get scan history.

**Parameters:**

- `userId` (number) - User ID
- `limit` (number) - Number of results (default 20)

**Returns:**

```javascript
{
  success: true,
  scans: [
    {
      id: 1,
      user_id: 1,
      scan_type: 'threat',
      scanned_content: 'https://example.com',
      threat_score: 75,
      threats_detected: ['Phishing attempt detected'],
      scan_date: '2025-12-08T07:24:28.000Z'
    }
  ],
  count: 1
}
```

---

### Network Operations

#### `saveNetworkDevice(userId, deviceInfo)`

Save discovered network device.

**Parameters:**

- `userId` (number) - User ID
- `deviceInfo` (object):
  - `deviceName` (string) - Device name
  - `ipAddress` (string) - IP address
  - `deviceType` (string) - Device type
  - `securityStatus` (string) - 'safe', 'caution', or 'risk'

**Returns:**

```javascript
{
  success: true,
  deviceId: 1,
  message: 'Network device saved'
}
```

**Example:**

```javascript
const result = await window.electronAPI.saveNetworkDevice(1, {
  deviceName: "iPhone-12",
  ipAddress: "192.168.1.105",
  deviceType: "mobile",
  securityStatus: "safe",
});
```

---

#### `getNetworkDevices(userId)`

Get all network devices.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  devices: [
    {
      id: 1,
      user_id: 1,
      device_name: 'iPhone-12',
      ip_address: '192.168.1.105',
      device_type: 'mobile',
      security_status: 'safe',
      discovered_date: '2025-12-08T07:24:28.000Z'
    }
  ],
  count: 1
}
```

---

#### `updateDeviceSecurity(deviceId, status)`

Update device security status.

**Parameters:**

- `deviceId` (number) - Device ID
- `status` (string) - 'safe', 'caution', or 'risk'

**Returns:**

```javascript
{
  success: true,
  message: 'Security status updated'
}
```

---

### Automation Operations

#### `createAutomationTask(userId, taskInfo)`

Create automation task.

**Parameters:**

- `userId` (number) - User ID
- `taskInfo` (object):
  - `taskName` (string) - Task name
  - `taskType` (string) - Task type
  - `scheduleTime` (string) - Time in '09:00' format
  - `scheduleDays` (string) - 'daily', 'weekly', 'monthly'
  - `isEnabled` (number) - 0 or 1 (optional, default 1)

**Returns:**

```javascript
{
  success: true,
  taskId: 1,
  message: 'Automation task created'
}
```

**Example:**

```javascript
const result = await window.electronAPI.createAutomationTask(1, {
  taskName: "Daily Security Scan",
  taskType: "daily_scan",
  scheduleTime: "09:00",
  scheduleDays: "daily",
  isEnabled: 1,
});
```

---

#### `getActiveTasks(userId)`

Get active automation tasks.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  tasks: [
    {
      id: 1,
      user_id: 1,
      task_name: 'Daily Security Scan',
      task_type: 'daily_scan',
      schedule_time: '09:00',
      schedule_days: 'daily',
      is_enabled: 1,
      last_run: null,
      next_run: null,
      created_date: '2025-12-08T07:24:28.000Z'
    }
  ],
  count: 1
}
```

---

#### `updateTask(taskId, updates)`

Update automation task.

**Parameters:**

- `taskId` (number) - Task ID
- `updates` (object) - Fields to update:
  - `taskName` (string) - Optional
  - `scheduleTime` (string) - Optional
  - `scheduleDays` (string) - Optional
  - `isEnabled` (number) - Optional
  - `lastRun` (string) - Optional
  - `nextRun` (string) - Optional

**Returns:**

```javascript
{
  success: true,
  message: 'Task updated'
}
```

**Example:**

```javascript
const result = await window.electronAPI.updateTask(1, {
  scheduleTime: "10:00",
  isEnabled: 0,
});
```

---

### Activity Log Operations

#### `logActivity(userId, action, details)`

Log user activity.

**Parameters:**

- `userId` (number) - User ID
- `action` (string) - Action description
- `details` (object) - Additional details (will be JSON stringified)

**Returns:**

```javascript
{
  success: true,
  logId: 1
}
```

**Example:**

```javascript
const result = await window.electronAPI.logActivity(1, "File Encrypted", {
  fileName: "document.pdf",
  fileSize: 1024000,
});
```

---

#### `getActivityLog(userId, limit)`

Get activity log.

**Parameters:**

- `userId` (number) - User ID
- `limit` (number) - Number of results (default 50)

**Returns:**

```javascript
{
  success: true,
  logs: [
    {
      id: 1,
      user_id: 1,
      action: 'File Encrypted',
      action_details: {
        fileName: 'document.pdf',
        fileSize: 1024000
      },
      timestamp: '2025-12-08T07:24:28.000Z'
    }
  ],
  count: 1
}
```

---

### Statistics

#### `getStats(userId)`

Get database statistics for a user.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  stats: {
    encryptedFiles: 5,
    totalScans: 23,
    networkDevices: 8,
    activeTasks: 3,
    activityLogs: 150
  }
}
```

---

## Usage in React Components

```javascript
import { useEffect, useState } from "react";

function Dashboard() {
  const [stats, setStats] = useState(null);
  const userId = 1; // Get from auth context

  useEffect(() => {
    async function loadStats() {
      const result = await window.electronAPI.getStats(userId);
      if (result.success) {
        setStats(result.stats);
      }
    }
    loadStats();
  }, [userId]);

  return (
    <div>
      <h1>Dashboard</h1>
      {stats && (
        <div>
          <p>Encrypted Files: {stats.encryptedFiles}</p>
          <p>Total Scans: {stats.totalScans}</p>
          <p>Network Devices: {stats.networkDevices}</p>
        </div>
      )}
    </div>
  );
}
```

---

## Error Handling

All methods return a `success` boolean. Always check this before using the data:

```javascript
const result = await window.electronAPI.createUser("john", hashedPassword);

if (result.success) {
  console.log("User created:", result.userId);
} else {
  console.error("Error:", result.error);
  // Show error to user
}
```

---

## Security Notes

1. **Passwords**: Always hash passwords with bcrypt before storing
2. **SQL Injection**: All queries use prepared statements (safe)
3. **Local Only**: Database never leaves the user's computer
4. **Encryption**: Use the encryption module for sensitive data
5. **Foreign Keys**: CASCADE delete ensures data consistency

---

## Database File

The database file `cyberguard.db` is automatically created in the user's app data directory when the app first runs. It uses SQLite's WAL (Write-Ahead Logging) mode for better performance and concurrency.
