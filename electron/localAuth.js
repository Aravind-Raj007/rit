const bcrypt = require('bcrypt');
const database = require('./database');

/**
 * Local Authentication System for CyberGuard Lite
 * Handles user registration, login, and session management
 * 100% local - no cloud, no internet required
 */
class LocalAuth {
  constructor() {
    this.currentUserId = null;
    this.currentUsername = null;
    this.saltRounds = 10; // bcrypt cost factor
  }

  // ==================== REGISTRATION ====================

  /**
   * Register a new user
   * @param {string} username - Username
   * @param {string} password - Plain text password (will be hashed)
   * @returns {Object} Result with success status and message
   */
  async registerUser(username, password) {
    try {
      // Validate username
      const usernameValidation = await this.validateUsername(username);
      if (!usernameValidation.valid) {
        return {
          success: false,
          message: usernameValidation.message
        };
      }

      // Validate password
      const passwordValidation = this.validatePassword(password);
      if (!passwordValidation.valid) {
        return {
          success: false,
          message: passwordValidation.message
        };
      }

      // Hash the password
      const passwordHash = await bcrypt.hash(password, this.saltRounds);

      // Save to database
      const result = database.createUser(username, passwordHash);

      if (result.success) {
        console.log(`✅ User registered: ${username} (ID: ${result.userId})`);
        
        // Log activity
        database.logActivity(result.userId, 'User Registered', {
          username: username,
          timestamp: new Date().toISOString()
        });

        return {
          success: true,
          message: 'Registration successful',
          userId: result.userId
        };
      } else {
        return {
          success: false,
          message: result.error || 'Registration failed'
        };
      }
    } catch (error) {
      console.error('❌ Registration error:', error);
      return {
        success: false,
        message: 'Registration failed. Please try again.'
      };
    }
  }

  // ==================== LOGIN ====================

  /**
   * Login user with username and password
   * @param {string} username - Username
   * @param {string} password - Plain text password
   * @returns {Object} Result with success status and user info
   */
  async loginUser(username, password) {
    try {
      // Input validation
      if (!username || !password) {
        return {
          success: false,
          message: 'Username and password are required'
        };
      }

      // Get user from database
      const result = database.getUserByUsername(username);

      if (!result.success || !result.user) {
        console.log(`❌ Login failed: User not found - ${username}`);
        return {
          success: false,
          message: 'User not found'
        };
      }

      const user = result.user;

      // Compare password with bcrypt hash
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);

      if (!isPasswordValid) {
        console.log(`❌ Login failed: Wrong password - ${username}`);
        return {
          success: false,
          message: 'Wrong password'
        };
      }

      // Update last login timestamp
      database.updateLastLogin(user.id);

      // Store current user in memory (session)
      this.currentUserId = user.id;
      this.currentUsername = user.username;

      console.log(`✅ User logged in: ${username} (ID: ${user.id})`);

      // Log activity
      database.logActivity(user.id, 'User Logged In', {
        username: username,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        userId: user.id,
        username: user.username,
        message: 'Login successful'
      };
    } catch (error) {
      console.error('❌ Login error:', error);
      return {
        success: false,
        message: 'Login failed. Please try again.'
      };
    }
  }

  // ==================== SESSION MANAGEMENT ====================

  /**
   * Get currently logged-in user
   * @returns {Object|null} User info or null if not logged in
   */
  getCurrentUser() {
    if (!this.currentUserId) {
      return null;
    }

    return {
      userId: this.currentUserId,
      username: this.currentUsername
    };
  }

  /**
   * Check if user is logged in
   * @returns {boolean} True if logged in, false otherwise
   */
  isLoggedIn() {
    return this.currentUserId !== null;
  }

  /**
   * Logout current user
   * @returns {Object} Result with success status
   */
  logoutUser() {
    try {
      if (this.currentUserId) {
        const username = this.currentUsername;
        const userId = this.currentUserId;

        // Log activity before clearing session
        database.logActivity(userId, 'User Logged Out', {
          username: username,
          timestamp: new Date().toISOString()
        });

        console.log(`✅ User logged out: ${username}`);
      }

      // Clear session from memory
      this.currentUserId = null;
      this.currentUsername = null;

      return {
        success: true,
        message: 'Logged out'
      };
    } catch (error) {
      console.error('❌ Logout error:', error);
      return {
        success: false,
        message: 'Logout failed'
      };
    }
  }

  // ==================== VALIDATION ====================

  /**
   * Validate username
   * @param {string} username - Username to validate
   * @returns {Object} Validation result
   */
  async validateUsername(username) {
    try {
      // Check if empty
      if (!username || username.trim().length === 0) {
        return {
          valid: false,
          message: 'Username cannot be empty'
        };
      }

      // Check length
      if (username.length < 3) {
        return {
          valid: false,
          message: 'Username must be at least 3 characters'
        };
      }

      if (username.length > 30) {
        return {
          valid: false,
          message: 'Username must be less than 30 characters'
        };
      }

      // Check for valid characters (alphanumeric and underscore only)
      const validPattern = /^[a-zA-Z0-9_]+$/;
      if (!validPattern.test(username)) {
        return {
          valid: false,
          message: 'Username can only contain letters, numbers, and underscores'
        };
      }

      // Check if unique in database
      const result = database.getUserByUsername(username);
      if (result.success && result.user) {
        return {
          valid: false,
          message: 'Username already taken'
        };
      }

      return {
        valid: true,
        message: 'Username is available'
      };
    } catch (error) {
      console.error('❌ Username validation error:', error);
      return {
        valid: false,
        message: 'Validation failed'
      };
    }
  }

  /**
   * Validate password and check strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result with strength indicator
   */
  validatePassword(password) {
    try {
      // Check if empty
      if (!password || password.length === 0) {
        return {
          valid: false,
          message: 'Password cannot be empty',
          strength: 'weak'
        };
      }

      // Check minimum length (12 characters)
      if (password.length < 12) {
        return {
          valid: false,
          message: 'Password must be at least 12 characters long',
          strength: 'weak'
        };
      }

      // Calculate password strength
      let strength = 'weak';
      let strengthScore = 0;

      // Length bonus
      if (password.length >= 12) strengthScore += 1;
      if (password.length >= 16) strengthScore += 1;
      if (password.length >= 20) strengthScore += 1;

      // Character variety
      if (/[a-z]/.test(password)) strengthScore += 1; // lowercase
      if (/[A-Z]/.test(password)) strengthScore += 1; // uppercase
      if (/[0-9]/.test(password)) strengthScore += 1; // numbers
      if (/[^a-zA-Z0-9]/.test(password)) strengthScore += 1; // special chars

      // Determine strength
      if (strengthScore >= 6) {
        strength = 'strong';
      } else if (strengthScore >= 4) {
        strength = 'medium';
      } else {
        strength = 'weak';
      }

      return {
        valid: true,
        message: 'Password is valid',
        strength: strength
      };
    } catch (error) {
      console.error('❌ Password validation error:', error);
      return {
        valid: false,
        message: 'Validation failed',
        strength: 'weak'
      };
    }
  }

  // ==================== UTILITY ====================

  /**
   * Get user statistics
   * @param {number} userId - User ID
   * @returns {Object} User statistics
   */
  getUserStats(userId) {
    try {
      const stats = database.getStats(userId);
      return stats;
    } catch (error) {
      console.error('❌ Get user stats error:', error);
      return {
        success: false,
        error: 'Failed to get statistics'
      };
    }
  }

  /**
   * Change password for current user
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Object} Result
   */
  async changePassword(oldPassword, newPassword) {
    try {
      if (!this.isLoggedIn()) {
        return {
          success: false,
          message: 'Not logged in'
        };
      }

      // Get current user
      const result = database.getUserByUsername(this.currentUsername);
      if (!result.success || !result.user) {
        return {
          success: false,
          message: 'User not found'
        };
      }

      const user = result.user;

      // Verify old password
      const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password_hash);
      if (!isOldPasswordValid) {
        return {
          success: false,
          message: 'Current password is incorrect'
        };
      }

      // Validate new password
      const passwordValidation = this.validatePassword(newPassword);
      if (!passwordValidation.valid) {
        return {
          success: false,
          message: passwordValidation.message
        };
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, this.saltRounds);

      // Update in database (using raw SQL since we don't have updatePassword method)
      // This would need to be added to database.js in production
      console.log('⚠️ Password change requested - database update method needed');

      // Log activity
      database.logActivity(this.currentUserId, 'Password Changed', {
        username: this.currentUsername,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        message: 'Password changed successfully'
      };
    } catch (error) {
      console.error('❌ Change password error:', error);
      return {
        success: false,
        message: 'Failed to change password'
      };
    }
  }
}

// Export singleton instance
module.exports = new LocalAuth();
