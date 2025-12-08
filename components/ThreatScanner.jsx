import { useState } from 'react';
import styles from '../styles/ThreatScanner.module.css';

/**
 * Threat Scanner Component
 * Scans text and URLs for security threats
 */
export default function ThreatScanner({ onStatsUpdate }) {
  const [scanType, setScanType] = useState('text'); // 'text' or 'url'
  const [input, setInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!input.trim()) {
      alert('Please enter text or URL to scan');
      return;
    }

    setScanning(true);
    setResult(null);

    try {
      // Import ThreatDetector dynamically
      const ThreatDetector = require('../lib/threatDetector');
      const scanner = new ThreatDetector();

      // Simulate scanning delay for better UX
      await new Promise(resolve => setTimeout(resolve, 1000));

      let scanResult;
      if (scanType === 'url') {
        scanResult = scanner.scanUrl(input);
      } else {
        scanResult = scanner.scanText(input);
      }

      setResult(scanResult);

      // Save to database
      if (window.electronAPI) {
        const user = await window.electronAPI.getCurrentUser();
        if (user) {
          await window.electronAPI.db.saveScanResult(
            user.userId,
            'threat',
            input.substring(0, 100),
            scanResult.threatScore,
            scanResult.threats.map(t => t.pattern)
          );
        }
      }

      // Refresh dashboard stats
      if (onStatsUpdate) {
        onStatsUpdate();
      }
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'SAFE': return '#10b981';
      case 'CAUTION': return '#f59e0b';
      case 'SUSPICIOUS': return '#fb923c';
      case 'DANGER': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getVerdictIcon = (verdict) => {
    switch (verdict) {
      case 'SAFE': return '✅';
      case 'CAUTION': return '⚠️';
      case 'SUSPICIOUS': return '🟠';
      case 'DANGER': return '🚨';
      default: return '❓';
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2>🤖 Threat Scanner</h2>
        <p>Scan text, emails, and URLs for security threats</p>
      </div>

      {/* Scan Type Toggle */}
      <div className={styles.toggleGroup}>
        <button
          className={`${styles.toggleBtn} ${scanType === 'text' ? styles.active : ''}`}
          onClick={() => setScanType('text')}
        >
          📝 Scan Text
        </button>
        <button
          className={`${styles.toggleBtn} ${scanType === 'url' ? styles.active : ''}`}
          onClick={() => setScanType('url')}
        >
          🔗 Scan URL
        </button>
      </div>

      {/* Input Area */}
      <div className={styles.inputSection}>
        {scanType === 'text' ? (
          <textarea
            className={styles.textarea}
            placeholder="Paste suspicious email, message, or text here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={8}
          />
        ) : (
          <input
            type="text"
            className={styles.input}
            placeholder="Enter URL to scan (e.g., https://example.com)"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        )}
      </div>

      {/* Scan Button */}
      <button
        className={styles.scanBtn}
        onClick={handleScan}
        disabled={scanning}
      >
        {scanning ? '🔍 Scanning...' : '🔍 Scan for Threats'}
      </button>

      {/* Results */}
      {result && (
        <div className={styles.results}>
          <div className={styles.scoreCard}>
            <div 
              className={styles.scoreCircle}
              style={{ borderColor: getVerdictColor(result.verdict) }}
            >
              <span className={styles.scoreValue}>{result.threatScore}</span>
              <span className={styles.scoreLabel}>Threat Score</span>
            </div>
            <div className={styles.verdict}>
              <span className={styles.verdictIcon}>{getVerdictIcon(result.verdict)}</span>
              <span 
                className={styles.verdictText}
                style={{ color: getVerdictColor(result.verdict) }}
              >
                {result.verdict}
              </span>
            </div>
          </div>

          {/* Threats Found */}
          {result.threats.length > 0 && (
            <div className={styles.threatsSection}>
              <h3>⚠️ Threats Detected ({result.threats.length})</h3>
              <div className={styles.threatsList}>
                {result.threats.map((threat, index) => (
                  <div key={index} className={styles.threatItem}>
                    <div className={styles.threatHeader}>
                      <span className={styles.threatCategory}>{threat.category}</span>
                      <span className={`${styles.severity} ${styles[threat.severity]}`}>
                        {threat.severity}
                      </span>
                    </div>
                    <p className={styles.threatPattern}>{threat.pattern}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div className={styles.recommendations}>
            <h3>💡 Recommendations</h3>
            <ul className={styles.recommendationsList}>
              {result.recommendations.map((rec, index) => (
                <li key={index}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Example Texts */}
      <div className={styles.examples}>
        <h4>Try these examples:</h4>
        <div className={styles.exampleBtns}>
          <button
            className={styles.exampleBtn}
            onClick={() => {
              setScanType('text');
              setInput('URGENT! Your account has been suspended. Click here immediately to verify your information.');
            }}
          >
            Phishing Email
          </button>
          <button
            className={styles.exampleBtn}
            onClick={() => {
              setScanType('text');
              setInput('Congratulations! You won $1,000,000. Send $500 for processing fees via gift cards.');
            }}
          >
            Scam Message
          </button>
          <button
            className={styles.exampleBtn}
            onClick={() => {
              setScanType('url');
              setInput('http://bit.ly/verify-account-urgent');
            }}
          >
            Suspicious URL
          </button>
        </div>
      </div>
    </div>
  );
}
