const Database = require('better-sqlite3');
const path = require('path');
const { app } = require('electron');

/**
 * Complete SQLite Database Manager for CyberGuard Lite
 * Handles all local data storage - users, files, scans, network, automation, activity
 */
class DatabaseManager {
  constructor() {
    this.db = null;
    this.dbPath = null;
  }

  /**
   * Initialize database connection and create tables
   */
  initialize() {
    try {
      // Store database in user data directory
      // Example: C:\Users\[username]\AppData\Local\CyberGuard-Lite\cyberguard.db
      this.dbPath = path.join(app.getPath('userData'), 'cyberguard.db');
      this.db = new Database(this.dbPath);
      
      // Enable WAL mode for better performance and concurrency
      this.db.pragma('journal_mode = WAL');
      
      // Create all tables
      this.initTables();
      
      console.log(`✅ Database initialized at: ${this.dbPath}`);
      return { success: true, path: this.dbPath };
    } catch (error) {
      console.error('❌ Database initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Create all database tables if they don't exist
   */
  initTables() {
    try {
      // Users table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_login TEXT
        )
      `);

      // Encrypted files table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS encrypted_files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          file_name TEXT NOT NULL,
          file_path TEXT NOT NULL,
          encrypted_path TEXT NOT NULL,
          file_size INTEGER NOT NULL,
          encryption_date TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Scan history table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS scan_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          scan_type TEXT NOT NULL,
          scanned_content TEXT NOT NULL,
          threat_score INTEGER NOT NULL,
          threats_detected TEXT NOT NULL,
          scan_date TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Network devices table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS network_devices (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          device_name TEXT NOT NULL,
          ip_address TEXT NOT NULL,
          device_type TEXT NOT NULL,
          security_status TEXT NOT NULL,
          discovered_date TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Automation tasks table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS automation_tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          task_name TEXT NOT NULL,
          task_type TEXT NOT NULL,
          schedule_time TEXT NOT NULL,
          schedule_days TEXT NOT NULL,
          is_enabled INTEGER NOT NULL DEFAULT 1,
          last_run TEXT,
          next_run TEXT,
          created_date TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Activity log table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS activity_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          action TEXT NOT NULL,
          action_details TEXT NOT NULL,
          timestamp TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      console.log('✅ All database tables created successfully');
    } catch (error) {
      console.error('❌ Table creation failed:', error);
      throw error;
    }
  }

  // ==================== USER OPERATIONS ====================

  /**
   * Create a new user
   * @param {string} username - Username
   * @param {string} passwordHash - Bcrypt hashed password
   * @returns {Object} Result with user ID
   */
  createUser(username, passwordHash) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO users (username, password_hash, created_at)
        VALUES (?, ?, ?)
      `);
      
      const result = stmt.run(username, passwordHash, new Date().toISOString());
      
      return {
        success: true,
        userId: result.lastInsertRowid,
        message: 'User created successfully'
      };
    } catch (error) {
      console.error('❌ Create user failed:', error);
      return {
        success: false,
        error: error.message.includes('UNIQUE') 
          ? 'Username already exists' 
          : 'Failed to create user'
      };
    }
  }

  /**
   * Get user by username
   * @param {string} username - Username to find
   * @returns {Object} User object or null
   */
  getUserByUsername(username) {
    try {
      const stmt = this.db.prepare('SELECT * FROM users WHERE username = ?');
      const user = stmt.get(username);
      
      return {
        success: true,
        user: user || null
      };
    } catch (error) {
      console.error('❌ Get user failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update last login timestamp
   * @param {number} userId - User ID
   * @returns {Object} Result
   */
  updateLastLogin(userId) {
    try {
      const stmt = this.db.prepare(`
        UPDATE users SET last_login = ? WHERE id = ?
      `);
      
      stmt.run(new Date().toISOString(), userId);
      
      return {
        success: true,
        message: 'Last login updated'
      };
    } catch (error) {
      console.error('❌ Update last login failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== FILE OPERATIONS ====================

  /**
   * Save encrypted file metadata
   * @param {number} userId - User ID
   * @param {Object} fileInfo - File information
   * @returns {Object} Result with file ID
   */
  saveEncryptedFile(userId, fileInfo) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO encrypted_files 
        (user_id, file_name, file_path, encrypted_path, file_size, encryption_date)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        fileInfo.fileName,
        fileInfo.filePath,
        fileInfo.encryptedPath,
        fileInfo.fileSize,
        new Date().toISOString()
      );
      
      return {
        success: true,
        fileId: result.lastInsertRowid,
        message: 'File metadata saved'
      };
    } catch (error) {
      console.error('❌ Save encrypted file failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get all encrypted files for a user
   * @param {number} userId - User ID
   * @returns {Object} Result with files array
   */
  getEncryptedFiles(userId) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM encrypted_files WHERE user_id = ? ORDER BY encryption_date DESC
      `);
      
      const files = stmt.all(userId);
      
      return {
        success: true,
        files: files,
        count: files.length
      };
    } catch (error) {
      console.error('❌ Get encrypted files failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Delete encrypted file record
   * @param {number} fileId - File ID
   * @returns {Object} Result
   */
  deleteEncryptedFile(fileId) {
    try {
      const stmt = this.db.prepare('DELETE FROM encrypted_files WHERE id = ?');
      const result = stmt.run(fileId);
      
      return {
        success: result.changes > 0,
        message: result.changes > 0 ? 'File deleted' : 'File not found'
      };
    } catch (error) {
      console.error('❌ Delete encrypted file failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== SCANNING OPERATIONS ====================

  /**
   * Save scan result
   * @param {number} userId - User ID
   * @param {string} scanType - 'threat' or 'network'
   * @param {string} content - What was scanned
   * @param {number} score - Threat score 0-100
   * @param {Array} threats - Array of detected threats
   * @returns {Object} Result with scan ID
   */
  saveScanResult(userId, scanType, content, score, threats) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO scan_history 
        (user_id, scan_type, scanned_content, threat_score, threats_detected, scan_date)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        scanType,
        content,
        score,
        JSON.stringify(threats),
        new Date().toISOString()
      );
      
      return {
        success: true,
        scanId: result.lastInsertRowid,
        message: 'Scan result saved'
      };
    } catch (error) {
      console.error('❌ Save scan result failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get scan history
   * @param {number} userId - User ID
   * @param {number} limit - Number of results (default 20)
   * @returns {Object} Result with scans array
   */
  getScanHistory(userId, limit = 20) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM scan_history 
        WHERE user_id = ? 
        ORDER BY scan_date DESC 
        LIMIT ?
      `);
      
      const scans = stmt.all(userId, limit);
      
      // Parse JSON threats_detected for each scan
      const parsedScans = scans.map(scan => ({
        ...scan,
        threats_detected: JSON.parse(scan.threats_detected)
      }));
      
      return {
        success: true,
        scans: parsedScans,
        count: parsedScans.length
      };
    } catch (error) {
      console.error('❌ Get scan history failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== NETWORK OPERATIONS ====================

  /**
   * Save network device
   * @param {number} userId - User ID
   * @param {Object} deviceInfo - Device information
   * @returns {Object} Result with device ID
   */
  saveNetworkDevice(userId, deviceInfo) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO network_devices 
        (user_id, device_name, ip_address, device_type, security_status, discovered_date)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        deviceInfo.deviceName,
        deviceInfo.ipAddress,
        deviceInfo.deviceType,
        deviceInfo.securityStatus || 'safe',
        new Date().toISOString()
      );
      
      return {
        success: true,
        deviceId: result.lastInsertRowid,
        message: 'Network device saved'
      };
    } catch (error) {
      console.error('❌ Save network device failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get all network devices for a user
   * @param {number} userId - User ID
   * @returns {Object} Result with devices array
   */
  getNetworkDevices(userId) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM network_devices 
        WHERE user_id = ? 
        ORDER BY discovered_date DESC
      `);
      
      const devices = stmt.all(userId);
      
      return {
        success: true,
        devices: devices,
        count: devices.length
      };
    } catch (error) {
      console.error('❌ Get network devices failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update device security status
   * @param {number} deviceId - Device ID
   * @param {string} status - 'safe', 'caution', or 'risk'
   * @returns {Object} Result
   */
  updateDeviceSecurity(deviceId, status) {
    try {
      const stmt = this.db.prepare(`
        UPDATE network_devices SET security_status = ? WHERE id = ?
      `);
      
      const result = stmt.run(status, deviceId);
      
      return {
        success: result.changes > 0,
        message: result.changes > 0 ? 'Security status updated' : 'Device not found'
      };
    } catch (error) {
      console.error('❌ Update device security failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== AUTOMATION OPERATIONS ====================

  /**
   * Create automation task
   * @param {number} userId - User ID
   * @param {Object} taskInfo - Task information
   * @returns {Object} Result with task ID
   */
  createAutomationTask(userId, taskInfo) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO automation_tasks 
        (user_id, task_name, task_type, schedule_time, schedule_days, is_enabled, created_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        taskInfo.taskName,
        taskInfo.taskType,
        taskInfo.scheduleTime,
        taskInfo.scheduleDays,
        taskInfo.isEnabled !== undefined ? taskInfo.isEnabled : 1,
        new Date().toISOString()
      );
      
      return {
        success: true,
        taskId: result.lastInsertRowid,
        message: 'Automation task created'
      };
    } catch (error) {
      console.error('❌ Create automation task failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get active automation tasks
   * @param {number} userId - User ID
   * @returns {Object} Result with tasks array
   */
  getActiveTasks(userId) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM automation_tasks 
        WHERE user_id = ? AND is_enabled = 1 
        ORDER BY created_date DESC
      `);
      
      const tasks = stmt.all(userId);
      
      return {
        success: true,
        tasks: tasks,
        count: tasks.length
      };
    } catch (error) {
      console.error('❌ Get active tasks failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update automation task
   * @param {number} taskId - Task ID
   * @param {Object} updates - Fields to update
   * @returns {Object} Result
   */
  updateTask(taskId, updates) {
    try {
      const fields = [];
      const values = [];
      
      // Build dynamic update query
      if (updates.taskName !== undefined) {
        fields.push('task_name = ?');
        values.push(updates.taskName);
      }
      if (updates.scheduleTime !== undefined) {
        fields.push('schedule_time = ?');
        values.push(updates.scheduleTime);
      }
      if (updates.scheduleDays !== undefined) {
        fields.push('schedule_days = ?');
        values.push(updates.scheduleDays);
      }
      if (updates.isEnabled !== undefined) {
        fields.push('is_enabled = ?');
        values.push(updates.isEnabled);
      }
      if (updates.lastRun !== undefined) {
        fields.push('last_run = ?');
        values.push(updates.lastRun);
      }
      if (updates.nextRun !== undefined) {
        fields.push('next_run = ?');
        values.push(updates.nextRun);
      }
      
      if (fields.length === 0) {
        return { success: false, error: 'No fields to update' };
      }
      
      values.push(taskId);
      const sql = `UPDATE automation_tasks SET ${fields.join(', ')} WHERE id = ?`;
      
      const stmt = this.db.prepare(sql);
      const result = stmt.run(...values);
      
      return {
        success: result.changes > 0,
        message: result.changes > 0 ? 'Task updated' : 'Task not found'
      };
    } catch (error) {
      console.error('❌ Update task failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== ACTIVITY LOG OPERATIONS ====================

  /**
   * Log user activity
   * @param {number} userId - User ID
   * @param {string} action - Action description
   * @param {Object} details - Additional details (will be JSON stringified)
   * @returns {Object} Result
   */
  logActivity(userId, action, details) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO activity_log (user_id, action, action_details, timestamp)
        VALUES (?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        action,
        JSON.stringify(details),
        new Date().toISOString()
      );
      
      return {
        success: true,
        logId: result.lastInsertRowid
      };
    } catch (error) {
      console.error('❌ Log activity failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get activity log
   * @param {number} userId - User ID
   * @param {number} limit - Number of results (default 50)
   * @returns {Object} Result with logs array
   */
  getActivityLog(userId, limit = 50) {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM activity_log 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
      `);
      
      const logs = stmt.all(userId, limit);
      
      // Parse JSON action_details for each log
      const parsedLogs = logs.map(log => ({
        ...log,
        action_details: JSON.parse(log.action_details)
      }));
      
      return {
        success: true,
        logs: parsedLogs,
        count: parsedLogs.length
      };
    } catch (error) {
      console.error('❌ Get activity log failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== UTILITY OPERATIONS ====================

  /**
   * Close database connection
   */
  close() {
    try {
      if (this.db) {
        this.db.close();
        console.log('✅ Database connection closed');
      }
    } catch (error) {
      console.error('❌ Close database failed:', error);
    }
  }

  /**
   * Get database statistics
   * @param {number} userId - User ID
   * @returns {Object} Database statistics
   */
  getStats(userId) {
    try {
      const stats = {
        encryptedFiles: this.db.prepare('SELECT COUNT(*) as count FROM encrypted_files WHERE user_id = ?').get(userId).count,
        totalScans: this.db.prepare('SELECT COUNT(*) as count FROM scan_history WHERE user_id = ?').get(userId).count,
        networkDevices: this.db.prepare('SELECT COUNT(*) as count FROM network_devices WHERE user_id = ?').get(userId).count,
        activeTasks: this.db.prepare('SELECT COUNT(*) as count FROM automation_tasks WHERE user_id = ? AND is_enabled = 1').get(userId).count,
        activityLogs: this.db.prepare('SELECT COUNT(*) as count FROM activity_log WHERE user_id = ?').get(userId).count
      };
      
      return {
        success: true,
        stats: stats
      };
    } catch (error) {
      console.error('❌ Get stats failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

// Export singleton instance
module.exports = new DatabaseManager();
