const { contextBridge, ipcRenderer } = require('electron');

/**
 * Security Preload Bridge for CyberGuard Lite
 * 
 * This file securely exposes Electron APIs to the React renderer process
 * using contextBridge. It follows security best practices:
 * 
 * ✅ Only exposes ipcRenderer.invoke() methods
 * ✅ No access to require(), process, fs, os, or Node.js modules
 * ✅ No direct file system access
 * ✅ No environment variables access
 * ✅ Completely sandboxed and safe
 * 
 * Usage in React: window.electronAPI.functionName()
 */

contextBridge.exposeInMainWorld('electronAPI', {
  /**
   * Test connection to Electron
   * @returns {Promise<string>} Returns 'pong'
   */
  ping: () => ipcRenderer.invoke('ping'),
  
  // ==================== AUTHENTICATION ====================
  
  /**
   * Login user with username and password
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<{success: boolean, userId?: number, username?: string, message: string}>}
   */
  loginUser: (username, password) => ipcRenderer.invoke('login-user', username, password),
  
  /**
   * Register new user account
   * @param {string} username - Username (3-30 characters, alphanumeric + underscore)
   * @param {string} password - Password (minimum 12 characters)
   * @returns {Promise<{success: boolean, userId?: number, message: string}>}
   */
  registerUser: (username, password) => ipcRenderer.invoke('register-user', username, password),
  
  /**
   * Logout current user
   * @returns {Promise<{success: boolean, message: string}>}
   */
  logoutUser: () => ipcRenderer.invoke('logout-user'),
  
  /**
   * Get currently logged-in user
   * @returns {Promise<{userId: number, username: string} | null>}
   */
  getCurrentUser: () => ipcRenderer.invoke('get-current-user'),
  
  // ==================== AUTHENTICATION (ALTERNATIVE HANDLERS) ====================
  
  /**
   * Register user (alternative handler)
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<{success: boolean, userId?: number, message: string}>}
   */
  register: (username, password) => ipcRenderer.invoke('auth:register', username, password),
  
  /**
   * Login user (alternative handler)
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<{success: boolean, userId?: number, username?: string, message: string}>}
   */
  login: (username, password) => ipcRenderer.invoke('auth:login', username, password),
  
  /**
   * Logout user (alternative handler)
   * @returns {Promise<{success: boolean, message: string}>}
   */
  logout: () => ipcRenderer.invoke('auth:logout'),
  
  /**
   * Check if user is logged in
   * @returns {Promise<boolean>}
   */
  isLoggedIn: () => ipcRenderer.invoke('auth:isLoggedIn'),
  
  /**
   * Validate username
   * @param {string} username - Username to validate
   * @returns {Promise<{valid: boolean, message: string}>}
   */
  validateUsername: (username) => ipcRenderer.invoke('auth:validateUsername', username),
  
  /**
   * Validate password and check strength
   * @param {string} password - Password to validate
   * @returns {Promise<{valid: boolean, message: string, strength: 'weak'|'medium'|'strong'}>}
   */
  validatePassword: (password) => ipcRenderer.invoke('auth:validatePassword', password),
  
  /**
   * Change password for current user
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<{success: boolean, message: string}>}
   */
  changePassword: (oldPassword, newPassword) => ipcRenderer.invoke('auth:changePassword', oldPassword, newPassword),
  
  /**
   * Get user statistics
   * @param {number} userId - User ID
   * @returns {Promise<{success: boolean, stats?: object, error?: string}>}
   */
  getUserStats: (userId) => ipcRenderer.invoke('auth:getUserStats', userId),
  
  // ==================== FILE OPERATIONS ====================
  
  /**
   * Get encrypted files for current user
   * @returns {Promise<{success: boolean, files?: Array, count?: number, message?: string}>}
   */
  getEncryptedFiles: () => ipcRenderer.invoke('get-encrypted-files'),
  
  /**
   * Get user statistics
   * @returns {Promise<{success: boolean, stats?: Object, message?: string}>}
   */
  getStats: () => ipcRenderer.invoke('get-stats'),
  
  /**
   * Delete encrypted file
   * @param {number} fileId - File ID to delete
   * @returns {Promise<{success: boolean, message: string}>}
   */
  deleteEncryptedFile: (fileId) => ipcRenderer.invoke('delete-encrypted-file', fileId),
  
  // ==================== SCANNING OPERATIONS ====================
  
  /**
   * Get scan history for current user
   * @returns {Promise<{success: boolean, scans?: Array, count?: number, message?: string}>}
   */
  getScanHistory: () => ipcRenderer.invoke('get-scan-history'),
  
  // ==================== NETWORK OPERATIONS ====================
  
  /**
   * Get network devices for current user
   * @returns {Promise<{success: boolean, devices?: Array, count?: number, message?: string}>}
   */
  getNetworkDevices: () => ipcRenderer.invoke('get-network-devices'),
  
  // ==================== AUTOMATION OPERATIONS ====================
  
  /**
   * Get automation tasks for current user
   * @returns {Promise<{success: boolean, tasks?: Array, count?: number, message?: string}>}
   */
  getAutomationTasks: () => ipcRenderer.invoke('get-automation-tasks'),
  
  // ==================== ACTIVITY LOG ====================
  
  /**
   * Get activity log for current user
   * @returns {Promise<{success: boolean, logs?: Array, count?: number, message?: string}>}
   */
  getActivityLog: () => ipcRenderer.invoke('get-activity-log'),
  
  /**
   * Select file for encryption/decryption
   * @returns {Promise<{success: boolean, filePath?: string, fileName?: string, fileSize?: number}>}
   */
  selectFile: () => ipcRenderer.invoke('select-file'),
  
  /**
   * Encrypt a file with password
   * @param {string} filePath - Path to file to encrypt
   * @param {string} password - Encryption password
   * @returns {Promise<{success: boolean, outputPath?: string, message: string}>}
   */
  encryptFile: (filePath, password) => ipcRenderer.invoke('encrypt-file', filePath, password),
  
  /**
   * Decrypt a file with password
   * @param {string} filePath - Path to encrypted file
   * @param {string} password - Decryption password
   * @returns {Promise<{success: boolean, outputPath?: string, message: string}>}
   */
  decryptFile: (filePath, password) => ipcRenderer.invoke('decrypt-file', filePath, password),
  
  // ==================== DATABASE OPERATIONS (ADVANCED) ====================
  
  /**
   * Direct database access for advanced use cases
   * Requires explicit userId parameter for all operations
   */
  db: {
    /**
     * Create user in database
     * @param {string} username - Username
     * @param {string} passwordHash - Bcrypt hashed password
     * @returns {Promise<{success: boolean, userId?: number, message?: string, error?: string}>}
     */
    createUser: (username, passwordHash) => ipcRenderer.invoke('db:createUser', username, passwordHash),
    
    /**
     * Get user by username
     * @param {string} username - Username
     * @returns {Promise<{success: boolean, user?: object, error?: string}>}
     */
    getUserByUsername: (username) => ipcRenderer.invoke('db:getUserByUsername', username),
    
    /**
     * Update last login timestamp
     * @param {number} userId - User ID
     * @returns {Promise<{success: boolean, message?: string, error?: string}>}
     */
    updateLastLogin: (userId) => ipcRenderer.invoke('db:updateLastLogin', userId),
    
    /**
     * Save encrypted file metadata
     * @param {number} userId - User ID
     * @param {object} fileInfo - File information
     * @returns {Promise<{success: boolean, fileId?: number, message?: string, error?: string}>}
     */
    saveEncryptedFile: (userId, fileInfo) => ipcRenderer.invoke('db:saveEncryptedFile', userId, fileInfo),
    
    /**
     * Get encrypted files for user
     * @param {number} userId - User ID
     * @returns {Promise<{success: boolean, files?: Array, count?: number, error?: string}>}
     */
    getEncryptedFiles: (userId) => ipcRenderer.invoke('db:getEncryptedFiles', userId),
    
    /**
     * Delete encrypted file
     * @param {number} fileId - File ID
     * @returns {Promise<{success: boolean, message?: string, error?: string}>}
     */
    deleteEncryptedFile: (fileId) => ipcRenderer.invoke('db:deleteEncryptedFile', fileId),
    
    /**
     * Save scan result
     * @param {number} userId - User ID
     * @param {string} scanType - 'threat' or 'network'
     * @param {string} content - What was scanned
     * @param {number} score - Threat score 0-100
     * @param {Array} threats - Array of detected threats
     * @returns {Promise<{success: boolean, scanId?: number, message?: string, error?: string}>}
     */
    saveScanResult: (userId, scanType, content, score, threats) => 
      ipcRenderer.invoke('db:saveScanResult', userId, scanType, content, score, threats),
    
    /**
     * Get scan history
     * @param {number} userId - User ID
     * @param {number} limit - Number of results (default 20)
     * @returns {Promise<{success: boolean, scans?: Array, count?: number, error?: string}>}
     */
    getScanHistory: (userId, limit) => ipcRenderer.invoke('db:getScanHistory', userId, limit),
    
    /**
     * Save network device
     * @param {number} userId - User ID
     * @param {object} deviceInfo - Device information
     * @returns {Promise<{success: boolean, deviceId?: number, message?: string, error?: string}>}
     */
    saveNetworkDevice: (userId, deviceInfo) => ipcRenderer.invoke('db:saveNetworkDevice', userId, deviceInfo),
    
    /**
     * Get network devices
     * @param {number} userId - User ID
     * @returns {Promise<{success: boolean, devices?: Array, count?: number, error?: string}>}
     */
    getNetworkDevices: (userId) => ipcRenderer.invoke('db:getNetworkDevices', userId),
    
    /**
     * Update device security status
     * @param {number} deviceId - Device ID
     * @param {string} status - 'safe', 'caution', or 'risk'
     * @returns {Promise<{success: boolean, message?: string, error?: string}>}
     */
    updateDeviceSecurity: (deviceId, status) => ipcRenderer.invoke('db:updateDeviceSecurity', deviceId, status),
    
    /**
     * Create automation task
     * @param {number} userId - User ID
     * @param {object} taskInfo - Task information
     * @returns {Promise<{success: boolean, taskId?: number, message?: string, error?: string}>}
     */
    createAutomationTask: (userId, taskInfo) => ipcRenderer.invoke('db:createAutomationTask', userId, taskInfo),
    
    /**
     * Get active tasks
     * @param {number} userId - User ID
     * @returns {Promise<{success: boolean, tasks?: Array, count?: number, error?: string}>}
     */
    getActiveTasks: (userId) => ipcRenderer.invoke('db:getActiveTasks', userId),
    
    /**
     * Update automation task
     * @param {number} taskId - Task ID
     * @param {object} updates - Fields to update
     * @returns {Promise<{success: boolean, message?: string, error?: string}>}
     */
    updateTask: (taskId, updates) => ipcRenderer.invoke('db:updateTask', taskId, updates),
    
    /**
     * Log user activity
     * @param {number} userId - User ID
     * @param {string} action - Action description
     * @param {object} details - Additional details
     * @returns {Promise<{success: boolean, logId?: number, error?: string}>}
     */
    logActivity: (userId, action, details) => ipcRenderer.invoke('db:logActivity', userId, action, details),
    
    /**
     * Get activity log
     * @param {number} userId - User ID
     * @param {number} limit - Number of results (default 50)
     * @returns {Promise<{success: boolean, logs?: Array, count?: number, error?: string}>}
     */
    getActivityLog: (userId, limit) => ipcRenderer.invoke('db:getActivityLog', userId, limit),
    
    /**
     * Get database statistics
     * @param {number} userId - User ID
     * @returns {Promise<{success: boolean, stats?: object, error?: string}>}
     */
    getStats: (userId) => ipcRenderer.invoke('db:getStats', userId),
  },
});
