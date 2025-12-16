const { app, BrowserWindow, Menu, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const database = require('./database');
const localAuth = require('./localAuth');
const encryption = require('../lib/encryption');
const isDev = !app.isPackaged;

let mainWindow;

/**
 * Create the main application window
 */
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 1000,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
    },
    icon: path.join(__dirname, '../assets/icon.png'),
    title: 'SIMPLIFIED CYBER DEFENCE FOR THREATS',
  });

  // Load the Next.js app
  const startURL = isDev
    ? 'http://localhost:3000'
    : `file://${path.join(app.getAppPath(), 'out', 'index.html')}`;

  mainWindow.loadURL(startURL);

  // Open DevTools in development mode (optional)
  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

/**
 * App ready event - initialize database and create window
 */
app.whenReady().then(() => {
  // Initialize database with error handling
  try {
    const dbResult = database.initialize();
    if (dbResult.success) {
      console.log('✅ Database ready at:', dbResult.path);
      console.log('✅ Database initialized:', database.isInitialized());
    } else {
      console.error('❌ Database initialization failed:', dbResult.error);
      // Show error dialog to user
      dialog.showErrorBox(
        'Database Error',
        'Failed to initialize the database. The application may not work correctly.\n\nError: ' + dbResult.error
      );
    }
  } catch (error) {
    console.error('❌ Critical database error:', error);
    dialog.showErrorBox(
      'Critical Error',
      'Failed to start the database. Please restart the application.\n\nError: ' + error.message
    );
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

/**
 * Window all closed event
 */
app.on('window-all-closed', () => {
  // Close database connection before quitting
  database.close();
  
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// ==================== IPC HANDLERS ====================

// Test handler
ipcMain.handle('ping', () => 'pong');

// ==================== AUTHENTICATION HANDLERS ====================

// Login user
ipcMain.handle('login-user', async (event, username, password) => {
  try {
    return await localAuth.loginUser(username, password);
  } catch (error) {
    console.error('❌ Login error:', error);
    return { success: false, message: 'Login failed. Please try again.' };
  }
});

// Register user
ipcMain.handle('register-user', async (event, username, password) => {
  try {
    return await localAuth.registerUser(username, password);
  } catch (error) {
    console.error('❌ Registration error:', error);
    return { success: false, message: 'Registration failed. Please try again.' };
  }
});

// Logout user
ipcMain.handle('logout-user', async (event) => {
  try {
    return localAuth.logoutUser();
  } catch (error) {
    console.error('❌ Logout error:', error);
    return { success: false, message: 'Logout failed.' };
  }
});

// Get current user
ipcMain.handle('get-current-user', async (event) => {
  try {
    return localAuth.getCurrentUser();
  } catch (error) {
    console.error('❌ Get current user error:', error);
    return null;
  }
});

// ==================== FILE OPERATIONS ====================

// Get encrypted files
ipcMain.handle('get-encrypted-files', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getEncryptedFiles(currentUser.userId);
  } catch (error) {
    console.error('❌ Get encrypted files error:', error);
    return { success: false, message: 'Failed to get encrypted files' };
  }
});

// Get user stats
ipcMain.handle('get-stats', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getStats(currentUser.userId);
  } catch (error) {
    console.error('❌ Get stats error:', error);
    return { success: false, message: 'Failed to get stats' };
  }
});

// Delete encrypted file
ipcMain.handle('delete-encrypted-file', async (event, fileId) => {
  try {
    return database.deleteEncryptedFile(fileId);
  } catch (error) {
    console.error('❌ Delete encrypted file error:', error);
    return { success: false, message: 'Failed to delete file' };
  }
});

// ==================== SCANNING OPERATIONS ====================

// Get scan history
ipcMain.handle('get-scan-history', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getScanHistory(currentUser.userId);
  } catch (error) {
    console.error('❌ Get scan history error:', error);
    return { success: false, message: 'Failed to get scan history' };
  }
});

// ==================== NETWORK OPERATIONS ====================

// Get network devices
ipcMain.handle('get-network-devices', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getNetworkDevices(currentUser.userId);
  } catch (error) {
    console.error('❌ Get network devices error:', error);
    return { success: false, message: 'Failed to get network devices' };
  }
});

// ==================== AUTOMATION OPERATIONS ====================

// Get automation tasks
ipcMain.handle('get-automation-tasks', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getActiveTasks(currentUser.userId);
  } catch (error) {
    console.error('❌ Get automation tasks error:', error);
    return { success: false, message: 'Failed to get automation tasks' };
  }
});

// ==================== ACTIVITY LOG ====================

// Get activity log
ipcMain.handle('get-activity-log', async (event) => {
  try {
    const currentUser = localAuth.getCurrentUser();
    if (!currentUser) {
      return { success: false, message: 'Not logged in' };
    }
    return database.getActivityLog(currentUser.userId);
  } catch (error) {
    console.error('❌ Get activity log error:', error);
    return { success: false, message: 'Failed to get activity log' };
  }
});

// ==================== FILE OPERATIONS ====================

// Select file for encryption/decryption
ipcMain.handle('select-file', async (event) => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      title: 'Select File',
      buttonLabel: 'Select'
    });

    if (result.canceled || result.filePaths.length === 0) {
      return { success: false, message: 'No file selected' };
    }

    const filePath = result.filePaths[0];
    const stats = fs.statSync(filePath);
    
    return {
      success: true,
      filePath,
      fileName: path.basename(filePath),
      fileSize: stats.size
    };
  } catch (error) {
    console.error('❌ File selection error:', error);
    return { success: false, message: 'Failed to select file' };
  }
});

// Encrypt file
ipcMain.handle('encrypt-file', async (event, filePath, password) => {
  try {
    // Read file
    const fileData = fs.readFileSync(filePath);
    
    // Encrypt (convert to base64 first, then encrypt)
    const encrypted = encryption.encrypt(fileData.toString('base64'), password);
    
    // Save encrypted file
    const outputPath = filePath + '.enc';
    fs.writeFileSync(outputPath, encrypted);
    
    // Log activity
    const currentUser = localAuth.getCurrentUser();
    if (currentUser) {
      database.logActivity(
        currentUser.userId,
        'File Encrypted',
        `Encrypted: ${path.basename(filePath)}`
      );
    }
    
    return {
      success: true,
      message: 'File encrypted successfully',
      outputPath
    };
  } catch (error) {
    console.error('❌ Encryption error:', error);
    return { success: false, message: 'Encryption failed: ' + error.message };
  }
});

// Decrypt file
ipcMain.handle('decrypt-file', async (event, filePath, password) => {
  try {
    // Read encrypted file
    const encryptedData = fs.readFileSync(filePath, 'utf8');
    
    // Decrypt
    const decrypted = encryption.decrypt(encryptedData, password);
    
    // Save decrypted file (convert from base64 back to binary)
    const outputPath = filePath.replace('.enc', '.decrypted' + path.extname(filePath.replace('.enc', '')));
    const buffer = Buffer.from(decrypted, 'base64');
    fs.writeFileSync(outputPath, buffer);
    
    // Log activity
    const currentUser = localAuth.getCurrentUser();
    if (currentUser) {
      database.logActivity(
        currentUser.userId,
        'File Decrypted',
        `Decrypted: ${path.basename(filePath)}`
      );
    }
    
    return {
      success: true,
      message: 'File decrypted successfully',
      outputPath
    };
  } catch (error) {
    console.error('❌ Decryption error:', error);
    return { success: false, message: 'Decryption failed. Wrong password?' };
  }
});

// ==================== ADDITIONAL HANDLERS (EXISTING) ====================

// Registration (alternative handler)
ipcMain.handle('auth:register', async (event, username, password) => {
  try {
    return await localAuth.registerUser(username, password);
  } catch (error) {
    console.error('❌ Registration error:', error);
    return { success: false, message: 'Registration failed. Please try again.' };
  }
});

// Login (alternative handler)
ipcMain.handle('auth:login', async (event, username, password) => {
  try {
    return await localAuth.loginUser(username, password);
  } catch (error) {
    console.error('❌ Login error:', error);
    return { success: false, message: 'Login failed. Please try again.' };
  }
});

// Logout (alternative handler)
ipcMain.handle('auth:logout', async (event) => {
  try {
    return localAuth.logoutUser();
  } catch (error) {
    console.error('❌ Logout error:', error);
    return { success: false, message: 'Logout failed.' };
  }
});

// Get current user (alternative handler)
ipcMain.handle('auth:getCurrentUser', async (event) => {
  try {
    return localAuth.getCurrentUser();
  } catch (error) {
    console.error('❌ Get current user error:', error);
    return null;
  }
});

// Check if logged in
ipcMain.handle('auth:isLoggedIn', async (event) => {
  try {
    return localAuth.isLoggedIn();
  } catch (error) {
    console.error('❌ Is logged in error:', error);
    return false;
  }
});

// Validate username
ipcMain.handle('auth:validateUsername', async (event, username) => {
  try {
    return await localAuth.validateUsername(username);
  } catch (error) {
    console.error('❌ Validate username error:', error);
    return { valid: false, message: 'Validation failed' };
  }
});

// Validate password
ipcMain.handle('auth:validatePassword', async (event, password) => {
  try {
    return localAuth.validatePassword(password);
  } catch (error) {
    console.error('❌ Validate password error:', error);
    return { valid: false, message: 'Validation failed', strength: 'weak' };
  }
});

// Change password
ipcMain.handle('auth:changePassword', async (event, oldPassword, newPassword) => {
  try {
    return await localAuth.changePassword(oldPassword, newPassword);
  } catch (error) {
    console.error('❌ Change password error:', error);
    return { success: false, message: 'Failed to change password' };
  }
});

// Get user stats
ipcMain.handle('auth:getUserStats', async (event, userId) => {
  try {
    return localAuth.getUserStats(userId);
  } catch (error) {
    console.error('❌ Get user stats error:', error);
    return { success: false, error: 'Failed to get statistics' };
  }
});

// Database operations (direct access)
ipcMain.handle('db:createUser', async (event, username, passwordHash) => {
  try {
    return database.createUser(username, passwordHash);
  } catch (error) {
    console.error('❌ Create user error:', error);
    return { success: false, error: 'Failed to create user' };
  }
});

ipcMain.handle('db:getUserByUsername', async (event, username) => {
  try {
    return database.getUserByUsername(username);
  } catch (error) {
    console.error('❌ Get user error:', error);
    return { success: false, error: 'Failed to get user' };
  }
});

ipcMain.handle('db:updateLastLogin', async (event, userId) => {
  try {
    return database.updateLastLogin(userId);
  } catch (error) {
    console.error('❌ Update last login error:', error);
    return { success: false, error: 'Failed to update last login' };
  }
});

ipcMain.handle('db:saveEncryptedFile', async (event, userId, fileInfo) => {
  try {
    return database.saveEncryptedFile(userId, fileInfo);
  } catch (error) {
    console.error('❌ Save encrypted file error:', error);
    return { success: false, error: 'Failed to save file' };
  }
});

ipcMain.handle('db:getEncryptedFiles', async (event, userId) => {
  try {
    return database.getEncryptedFiles(userId);
  } catch (error) {
    console.error('❌ Get encrypted files error:', error);
    return { success: false, error: 'Failed to get files' };
  }
});

ipcMain.handle('db:deleteEncryptedFile', async (event, fileId) => {
  try {
    return database.deleteEncryptedFile(fileId);
  } catch (error) {
    console.error('❌ Delete file error:', error);
    return { success: false, error: 'Failed to delete file' };
  }
});

ipcMain.handle('db:saveScanResult', async (event, userId, scanType, content, score, threats) => {
  try {
    return database.saveScanResult(userId, scanType, content, score, threats);
  } catch (error) {
    console.error('❌ Save scan result error:', error);
    return { success: false, error: 'Failed to save scan' };
  }
});

ipcMain.handle('db:getScanHistory', async (event, userId, limit) => {
  try {
    return database.getScanHistory(userId, limit);
  } catch (error) {
    console.error('❌ Get scan history error:', error);
    return { success: false, error: 'Failed to get scan history' };
  }
});

ipcMain.handle('db:saveNetworkDevice', async (event, userId, deviceInfo) => {
  try {
    return database.saveNetworkDevice(userId, deviceInfo);
  } catch (error) {
    console.error('❌ Save network device error:', error);
    return { success: false, error: 'Failed to save device' };
  }
});

ipcMain.handle('db:getNetworkDevices', async (event, userId) => {
  try {
    return database.getNetworkDevices(userId);
  } catch (error) {
    console.error('❌ Get network devices error:', error);
    return { success: false, error: 'Failed to get devices' };
  }
});

ipcMain.handle('db:updateDeviceSecurity', async (event, deviceId, status) => {
  try {
    return database.updateDeviceSecurity(deviceId, status);
  } catch (error) {
    console.error('❌ Update device security error:', error);
    return { success: false, error: 'Failed to update device' };
  }
});

ipcMain.handle('db:createAutomationTask', async (event, userId, taskInfo) => {
  try {
    return database.createAutomationTask(userId, taskInfo);
  } catch (error) {
    console.error('❌ Create automation task error:', error);
    return { success: false, error: 'Failed to create task' };
  }
});

ipcMain.handle('db:getActiveTasks', async (event, userId) => {
  try {
    return database.getActiveTasks(userId);
  } catch (error) {
    console.error('❌ Get active tasks error:', error);
    return { success: false, error: 'Failed to get tasks' };
  }
});

ipcMain.handle('db:updateTask', async (event, taskId, updates) => {
  try {
    return database.updateTask(taskId, updates);
  } catch (error) {
    console.error('❌ Update task error:', error);
    return { success: false, error: 'Failed to update task' };
  }
});

ipcMain.handle('db:logActivity', async (event, userId, action, details) => {
  try {
    return database.logActivity(userId, action, details);
  } catch (error) {
    console.error('❌ Log activity error:', error);
    return { success: false, error: 'Failed to log activity' };
  }
});

ipcMain.handle('db:getActivityLog', async (event, userId, limit) => {
  try {
    return database.getActivityLog(userId, limit);
  } catch (error) {
    console.error('❌ Get activity log error:', error);
    return { success: false, error: 'Failed to get activity log' };
  }
});

ipcMain.handle('db:getStats', async (event, userId) => {
  try {
    return database.getStats(userId);
  } catch (error) {
    console.error('❌ Get stats error:', error);
    return { success: false, error: 'Failed to get statistics' };
  }
});
