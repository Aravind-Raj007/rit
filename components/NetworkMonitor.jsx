import { useState, useEffect } from 'react';
import styles from '../styles/NetworkMonitor.module.css';

/**
 * Network Monitor Component
 * Scans and displays devices on local network
 */
export default function NetworkMonitor({ onStatsUpdate }) {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [lastScan, setLastScan] = useState(null);

  const handleScan = async () => {
    setScanning(true);

    try {
      // Import NetworkScanner dynamically
      const NetworkScanner = require('../lib/networkScanner');
      const scanner = new NetworkScanner();

      // Simulate scanning delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      const result = await scanner.scanNetwork();
      setScanResult(result);
      setLastScan(new Date());

      // Save devices to database
      if (window.electronAPI) {
        const user = await window.electronAPI.getCurrentUser();
        if (user) {
          for (const device of result.devices) {
            await window.electronAPI.db.saveNetworkDevice(user.userId, {
              deviceName: device.name,
              ipAddress: device.ipAddress,
              deviceType: device.deviceType,
              securityStatus: device.securityStatus
            });
          }
        }
      }

      // Refresh dashboard stats
      if (onStatsUpdate) {
        onStatsUpdate();
      }
    } catch (error) {
      console.error('Network scan failed:', error);
      alert('Network scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'safe': return '#10b981';
      case 'caution': return '#f59e0b';
      case 'risk': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'safe': return '✅';
      case 'caution': return '⚠️';
      case 'risk': return '🚨';
      default: return '❓';
    }
  };

  const getDeviceIcon = (type) => {
    const icons = {
      'mobile': '📱',
      'computer': '💻',
      'tablet': '📱',
      'smart-device': '📺',
      'iot': '🏠',
      'gaming': '🎮',
      'unknown': '❓'
    };
    return icons[type] || '🔌';
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2>🎯 Network Monitor</h2>
        <p>Scan and monitor devices on your local network</p>
      </div>

      {/* Scan Button */}
      <button
        className={styles.scanBtn}
        onClick={handleScan}
        disabled={scanning}
      >
        {scanning ? '🔍 Scanning Network...' : '🔍 Scan Network'}
      </button>

      {lastScan && (
        <p className={styles.lastScan}>
          Last scanned: {lastScan.toLocaleTimeString()}
        </p>
      )}

      {/* Results */}
      {scanResult && (
        <div className={styles.results}>
          {/* WiFi Security Score */}
          <div className={styles.wifiCard}>
            <div className={styles.wifiHeader}>
              <h3>📶 WiFi Security</h3>
              <div 
                className={styles.wifiScore}
                style={{ color: getStatusColor(scanResult.wifiStatus) }}
              >
                {scanResult.wifiScore}/100
              </div>
            </div>
            <div className={styles.wifiDetails}>
              <div className={styles.wifiDetail}>
                <span className={styles.label}>Encryption:</span>
                <span className={styles.value}>{scanResult.wifiDetails.encryptionType}</span>
              </div>
              <div className={styles.wifiDetail}>
                <span className={styles.label}>Password Strength:</span>
                <span className={styles.value}>{scanResult.wifiDetails.passwordStrength}</span>
              </div>
              <div className={styles.wifiDetail}>
                <span className={styles.label}>Firmware:</span>
                <span className={styles.value}>
                  {scanResult.wifiDetails.firmwareUpToDate ? '✅ Up to date' : '⚠️ Update available'}
                </span>
              </div>
              <div className={styles.wifiDetail}>
                <span className={styles.label}>Total Devices:</span>
                <span className={styles.value}>{scanResult.wifiDetails.totalDevices}</span>
              </div>
            </div>
          </div>

          {/* Devices List */}
          <div className={styles.devicesSection}>
            <h3>🌐 Devices Found ({scanResult.devices.length})</h3>
            <div className={styles.devicesList}>
              {scanResult.devices.map((device) => (
                <div key={device.id} className={styles.deviceCard}>
                  <div className={styles.deviceHeader}>
                    <span className={styles.deviceIcon}>{getDeviceIcon(device.deviceType)}</span>
                    <div className={styles.deviceInfo}>
                      <div className={styles.deviceName}>{device.name}</div>
                      <div className={styles.deviceType}>{device.vendor || device.deviceType}</div>
                    </div>
                    <span 
                      className={styles.statusBadge}
                      style={{ 
                        backgroundColor: getStatusColor(device.securityStatus) + '20',
                        color: getStatusColor(device.securityStatus)
                      }}
                    >
                      {getStatusIcon(device.securityStatus)} {device.securityStatus}
                    </span>
                  </div>
                  <div className={styles.deviceDetails}>
                    <div className={styles.detail}>
                      <span className={styles.detailLabel}>IP:</span>
                      <span className={styles.detailValue}>{device.ipAddress}</span>
                    </div>
                    <div className={styles.detail}>
                      <span className={styles.detailLabel}>MAC:</span>
                      <span className={styles.detailValue}>{device.macAddress}</span>
                    </div>
                    <div className={styles.detail}>
                      <span className={styles.detailLabel}>Status:</span>
                      <span className={styles.detailValue}>
                        {device.isActive ? '🟢 Active' : '⚪ Inactive'}
                      </span>
                    </div>
                  </div>
                  {device.riskFactors && device.riskFactors.length > 0 && (
                    <div className={styles.riskFactors}>
                      <strong>Risk Factors:</strong>
                      <ul>
                        {device.riskFactors.map((factor, i) => (
                          <li key={i}>{factor}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className={styles.recommendations}>
            <h3>💡 Recommendations</h3>
            <ul className={styles.recommendationsList}>
              {scanResult.recommendations.map((rec, index) => (
                <li key={index}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Info */}
      {!scanResult && !scanning && (
        <div className={styles.info}>
          <p>Click "Scan Network" to discover devices on your local network.</p>
          <p className={styles.note}>
            <strong>Note:</strong> This is currently in demo mode with simulated data for testing.
          </p>
        </div>
      )}
    </div>
  );
}
