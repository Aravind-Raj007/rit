import { useState } from 'react';
import styles from '../styles/FileProtection.module.css';

/**
 * File Protection Component
 * Encrypt and decrypt files with password protection
 */
export default function FileProtection({ onStatsUpdate }) {
  const [mode, setMode] = useState('encrypt'); // 'encrypt' or 'decrypt'
  const [selectedFile, setSelectedFile] = useState(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [processing, setProcessing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // Handle file selection
  const handleSelectFile = async () => {
    try {
      const result = await window.electronAPI.selectFile();
      if (result.success && result.filePath) {
        setSelectedFile({
          path: result.filePath,
          name: result.fileName,
          size: result.fileSize
        });
        setError('');
        setResult(null);
      }
    } catch (err) {
      setError('Failed to select file');
      console.error(err);
    }
  };

  // Handle encryption
  const handleEncrypt = async () => {
    if (!selectedFile) {
      setError('Please select a file first');
      return;
    }

    if (!password) {
      setError('Please enter a password');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setProcessing(true);
    setError('');
    setResult(null);

    try {
      const encryptResult = await window.electronAPI.encryptFile(
        selectedFile.path,
        password
      );

      if (encryptResult.success) {
        setResult({
          type: 'success',
          message: 'File encrypted successfully!',
          outputPath: encryptResult.outputPath
        });

        // Save to database
        const user = await window.electronAPI.getCurrentUser();
        if (user) {
          await window.electronAPI.db.saveEncryptedFile(user.userId, {
            fileName: selectedFile.name,
            filePath: selectedFile.path,
            encryptedPath: encryptResult.outputPath,
            fileSize: selectedFile.size
          });
        }

        // Refresh dashboard stats
        if (onStatsUpdate) {
          onStatsUpdate();
        }

        // Clear form
        setPassword('');
        setConfirmPassword('');
        setSelectedFile(null);
      } else {
        setError(encryptResult.message || 'Encryption failed');
      }
    } catch (err) {
      setError('Encryption failed. Please try again.');
      console.error(err);
    } finally {
      setProcessing(false);
    }
  };

  // Handle decryption
  const handleDecrypt = async () => {
    if (!selectedFile) {
      setError('Please select an encrypted file');
      return;
    }

    if (!password) {
      setError('Please enter the decryption password');
      return;
    }

    setProcessing(true);
    setError('');
    setResult(null);

    try {
      const decryptResult = await window.electronAPI.decryptFile(
        selectedFile.path,
        password
      );

      if (decryptResult.success) {
        setResult({
          type: 'success',
          message: 'File decrypted successfully!',
          outputPath: decryptResult.outputPath
        });

        // Refresh dashboard stats
        if (onStatsUpdate) {
          onStatsUpdate();
        }

        // Clear form
        setPassword('');
        setSelectedFile(null);
      } else {
        setError(decryptResult.message || 'Decryption failed. Wrong password?');
      }
    } catch (err) {
      setError('Decryption failed. Please check your password.');
      console.error(err);
    } finally {
      setProcessing(false);
    }
  };

  // Format file size
  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2>🔒 File Protection</h2>
        <p>Encrypt and decrypt files with military-grade AES-256 encryption</p>
      </div>

      {/* Mode Toggle */}
      <div className={styles.toggleGroup}>
        <button
          className={`${styles.toggleBtn} ${mode === 'encrypt' ? styles.active : ''}`}
          onClick={() => {
            setMode('encrypt');
            setSelectedFile(null);
            setPassword('');
            setConfirmPassword('');
            setError('');
            setResult(null);
          }}
        >
          🔐 Encrypt File
        </button>
        <button
          className={`${styles.toggleBtn} ${mode === 'decrypt' ? styles.active : ''}`}
          onClick={() => {
            setMode('decrypt');
            setSelectedFile(null);
            setPassword('');
            setConfirmPassword('');
            setError('');
            setResult(null);
          }}
        >
          🔓 Decrypt File
        </button>
      </div>

      {/* Error Message */}
      {error && (
        <div className={styles.error}>
          <span className={styles.errorIcon}>⚠️</span>
          {error}
        </div>
      )}

      {/* Success Message */}
      {result && (
        <div className={styles.success}>
          <span className={styles.successIcon}>✅</span>
          <div>
            <div className={styles.successMessage}>{result.message}</div>
            <div className={styles.successPath}>Saved to: {result.outputPath}</div>
          </div>
        </div>
      )}

      {/* File Selection */}
      <div className={styles.fileSection}>
        <label className={styles.label}>
          {mode === 'encrypt' ? 'Select File to Encrypt' : 'Select Encrypted File (.enc)'}
        </label>
        
        {selectedFile ? (
          <div className={styles.selectedFile}>
            <div className={styles.fileIcon}>📄</div>
            <div className={styles.fileInfo}>
              <div className={styles.fileName}>{selectedFile.name}</div>
              <div className={styles.fileSize}>{formatFileSize(selectedFile.size)}</div>
            </div>
            <button
              className={styles.removeBtn}
              onClick={() => setSelectedFile(null)}
            >
              ✕
            </button>
          </div>
        ) : (
          <button className={styles.selectBtn} onClick={handleSelectFile}>
            📁 Choose File
          </button>
        )}
      </div>

      {/* Password Input */}
      <div className={styles.passwordSection}>
        <div className={styles.formGroup}>
          <label className={styles.label}>
            {mode === 'encrypt' ? 'Encryption Password' : 'Decryption Password'}
          </label>
          <input
            type="password"
            className={styles.input}
            placeholder={mode === 'encrypt' ? 'Create a strong password' : 'Enter decryption password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {mode === 'encrypt' && (
          <div className={styles.formGroup}>
            <label className={styles.label}>Confirm Password</label>
            <input
              type="password"
              className={styles.input}
              placeholder="Re-enter password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
        )}
      </div>

      {/* Action Button */}
      <button
        className={styles.actionBtn}
        onClick={mode === 'encrypt' ? handleEncrypt : handleDecrypt}
        disabled={processing || !selectedFile || !password}
      >
        {processing ? (
          mode === 'encrypt' ? '🔐 Encrypting...' : '🔓 Decrypting...'
        ) : (
          mode === 'encrypt' ? '🔐 Encrypt File' : '🔓 Decrypt File'
        )}
      </button>

      {/* Info Box */}
      <div className={styles.infoBox}>
        <h4>ℹ️ How it works</h4>
        {mode === 'encrypt' ? (
          <ul>
            <li>Select any file you want to protect</li>
            <li>Create a strong password (min. 8 characters)</li>
            <li>File will be encrypted with AES-256-GCM</li>
            <li>Encrypted file will be saved with .enc extension</li>
            <li><strong>Remember your password!</strong> It cannot be recovered</li>
          </ul>
        ) : (
          <ul>
            <li>Select an encrypted file (.enc)</li>
            <li>Enter the password used for encryption</li>
            <li>File will be decrypted to its original format</li>
            <li>Decrypted file will be saved in the same location</li>
          </ul>
        )}
      </div>

      {/* Security Notice */}
      <div className={styles.securityNotice}>
        <span className={styles.lockIcon}>🔒</span>
        <div>
          <strong>Military-grade encryption</strong>
          <p>Your files are protected with AES-256-GCM encryption, the same standard used by governments and militaries worldwide.</p>
        </div>
      </div>
    </div>
  );
}
