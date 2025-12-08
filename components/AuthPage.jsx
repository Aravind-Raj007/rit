import { useState, useEffect } from 'react';
import styles from '../styles/AuthPage.module.css';

/**
 * Authentication Page Component
 * Handles both login and registration for CyberGuard Lite
 */
export default function AuthPage({ onAuthSuccess }) {
  // Mode: 'login' or 'register'
  const [mode, setMode] = useState('login');
  
  // Form fields
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // UI state
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState('');
  const [usernameAvailable, setUsernameAvailable] = useState(null);

  // Clear error when switching modes
  useEffect(() => {
    setError('');
    setPassword('');
    setConfirmPassword('');
    setPasswordStrength('');
    setUsernameAvailable(null);
  }, [mode]);

  // Validate username in real-time (for register mode)
  useEffect(() => {
    if (mode === 'register' && username.length >= 3) {
      const checkUsername = async () => {
        const result = await window.electronAPI.validateUsername(username);
        setUsernameAvailable(result.valid);
        if (!result.valid && result.message !== 'Username already taken') {
          setError(result.message);
        } else {
          setError('');
        }
      };
      
      const timer = setTimeout(checkUsername, 500);
      return () => clearTimeout(timer);
    }
  }, [username, mode]);

  // Validate password strength in real-time (for register mode)
  useEffect(() => {
    if (mode === 'register' && password.length > 0) {
      const checkPassword = async () => {
        const result = await window.electronAPI.validatePassword(password);
        setPasswordStrength(result.strength);
      };
      
      checkPassword();
    }
  }, [password, mode]);

  /**
   * Handle login form submission
   */
  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await window.electronAPI.loginUser(username, password);
      
      if (result.success) {
        // Clear sensitive data
        setPassword('');
        
        // Call parent callback with user info
        onAuthSuccess({
          userId: result.userId,
          username: result.username
        });
      } else {
        setError(result.message);
      }
    } catch (err) {
      setError('Login failed. Please try again.');
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Handle registration form submission
   */
  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');

    // Validate passwords match
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Validate password length
    if (password.length < 12) {
      setError('Password must be at least 12 characters long');
      return;
    }

    // Validate username
    if (username.length < 3) {
      setError('Username must be at least 3 characters long');
      return;
    }

    setLoading(true);

    try {
      const result = await window.electronAPI.registerUser(username, password);
      
      if (result.success) {
        // Auto-login after successful registration
        const loginResult = await window.electronAPI.loginUser(username, password);
        
        if (loginResult.success) {
          // Clear sensitive data
          setPassword('');
          setConfirmPassword('');
          
          // Call parent callback with user info
          onAuthSuccess({
            userId: loginResult.userId,
            username: loginResult.username
          });
        } else {
          setError('Registration successful! Please login.');
          setMode('login');
        }
      } else {
        setError(result.message);
      }
    } catch (err) {
      setError('Registration failed. Please try again.');
      console.error('Registration error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Get password strength color
   */
  const getStrengthColor = () => {
    switch (passwordStrength) {
      case 'strong': return '#10b981'; // green
      case 'medium': return '#f59e0b'; // orange
      case 'weak': return '#ef4444'; // red
      default: return '#6b7280'; // gray
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.authBox}>
        {/* Logo/Header */}
        <div className={styles.header}>
          <div className={styles.logo}>🛡️</div>
          <h1 className={styles.title}>SIMPLIFIED CYBER DEFENCE FOR THREATS</h1>
          <p className={styles.subtitle}>
            {mode === 'login' ? 'Welcome back' : 'Create your account'}
          </p>
        </div>

        {/* Error Message */}
        {error && (
          <div className={styles.error}>
            <span className={styles.errorIcon}>⚠️</span>
            {error}
          </div>
        )}

        {/* Login Form */}
        {mode === 'login' && (
          <form onSubmit={handleLogin} className={styles.form}>
            <div className={styles.formGroup}>
              <label htmlFor="username" className={styles.label}>
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className={styles.input}
                placeholder="Enter your username"
                required
                autoFocus
                disabled={loading}
              />
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="password" className={styles.label}>
                Password
              </label>
              <div className={styles.passwordWrapper}>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={styles.input}
                  placeholder="Enter your password"
                  required
                  disabled={loading}
                />
              </div>
            </div>

            <div className={styles.checkboxGroup}>
              <input
                id="showPassword"
                type="checkbox"
                checked={showPassword}
                onChange={(e) => setShowPassword(e.target.checked)}
                className={styles.checkbox}
              />
              <label htmlFor="showPassword" className={styles.checkboxLabel}>
                Show password
              </label>
            </div>

            <button
              type="submit"
              className={styles.button}
              disabled={loading}
            >
              {loading ? 'Logging in...' : 'Login'}
            </button>

            <div className={styles.switchMode}>
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => setMode('register')}
                className={styles.link}
                disabled={loading}
              >
                Register
              </button>
            </div>
          </form>
        )}

        {/* Register Form */}
        {mode === 'register' && (
          <form onSubmit={handleRegister} className={styles.form}>
            <div className={styles.formGroup}>
              <label htmlFor="username" className={styles.label}>
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className={styles.input}
                placeholder="Choose a username"
                required
                autoFocus
                disabled={loading}
              />
              {username.length >= 3 && usernameAvailable !== null && (
                <div className={styles.validation}>
                  {usernameAvailable ? (
                    <span className={styles.validationSuccess}>
                      ✓ Username available
                    </span>
                  ) : (
                    <span className={styles.validationError}>
                      ✗ Username already taken
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="password" className={styles.label}>
                Password
              </label>
              <div className={styles.passwordWrapper}>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={styles.input}
                  placeholder="Create a strong password"
                  required
                  disabled={loading}
                />
              </div>
              
              {/* Password Strength Indicator */}
              {password.length > 0 && (
                <div className={styles.strengthMeter}>
                  <div className={styles.strengthBar}>
                    <div
                      className={styles.strengthFill}
                      style={{
                        width: passwordStrength === 'strong' ? '100%' : 
                               passwordStrength === 'medium' ? '66%' : '33%',
                        backgroundColor: getStrengthColor()
                      }}
                    />
                  </div>
                  <span 
                    className={styles.strengthLabel}
                    style={{ color: getStrengthColor() }}
                  >
                    {passwordStrength ? `Strength: ${passwordStrength}` : 'Checking...'}
                  </span>
                </div>
              )}
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="confirmPassword" className={styles.label}>
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className={styles.input}
                placeholder="Re-enter your password"
                required
                disabled={loading}
              />
              {confirmPassword.length > 0 && (
                <div className={styles.validation}>
                  {password === confirmPassword ? (
                    <span className={styles.validationSuccess}>
                      ✓ Passwords match
                    </span>
                  ) : (
                    <span className={styles.validationError}>
                      ✗ Passwords do not match
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className={styles.checkboxGroup}>
              <input
                id="showPassword"
                type="checkbox"
                checked={showPassword}
                onChange={(e) => setShowPassword(e.target.checked)}
                className={styles.checkbox}
              />
              <label htmlFor="showPassword" className={styles.checkboxLabel}>
                Show password
              </label>
            </div>

            {/* Password Requirements */}
            <div className={styles.requirements}>
              <p className={styles.requirementsTitle}>Password requirements:</p>
              <ul className={styles.requirementsList}>
                <li className={password.length >= 12 ? styles.requirementMet : ''}>
                  At least 12 characters
                </li>
                <li className={/[a-z]/.test(password) && /[A-Z]/.test(password) ? styles.requirementMet : ''}>
                  Mix of uppercase and lowercase letters
                </li>
                <li className={/[0-9]/.test(password) ? styles.requirementMet : ''}>
                  Include numbers (recommended)
                </li>
                <li className={/[^a-zA-Z0-9]/.test(password) ? styles.requirementMet : ''}>
                  Include special characters (recommended)
                </li>
              </ul>
            </div>

            <button
              type="submit"
              className={styles.button}
              disabled={loading || !usernameAvailable}
            >
              {loading ? 'Creating account...' : 'Register'}
            </button>

            <div className={styles.switchMode}>
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => setMode('login')}
                className={styles.link}
                disabled={loading}
              >
                Login
              </button>
            </div>
          </form>
        )}

        {/* Security Notice */}
        <div className={styles.securityNotice}>
          <span className={styles.lockIcon}>🔒</span>
          Your data is stored locally and never sent to the cloud
        </div>
      </div>
    </div>
  );
}
