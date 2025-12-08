/**
 * Local Network Scanner for CyberGuard Lite
 * Demo mode with realistic data for UI testing
 * 
 * NOTE: This is currently in DEMO mode with simulated data.
 * Real network scanning would require native modules or external tools.
 */

class NetworkScanner {
  constructor() {
    this.demoMode = true; // Set to false when implementing real scanning
    
    // Common device types and names for realistic demo
    this.commonDevices = [
      { name: 'iPhone 13', type: 'mobile', vendor: 'Apple' },
      { name: 'MacBook Pro', type: 'computer', vendor: 'Apple' },
      { name: 'Windows PC', type: 'computer', vendor: 'Microsoft' },
      { name: 'Samsung Galaxy', type: 'mobile', vendor: 'Samsung' },
      { name: 'iPad Air', type: 'tablet', vendor: 'Apple' },
      { name: 'Smart TV', type: 'smart-device', vendor: 'Samsung' },
      { name: 'Amazon Echo', type: 'iot', vendor: 'Amazon' },
      { name: 'Google Nest', type: 'iot', vendor: 'Google' },
      { name: 'PlayStation 5', type: 'gaming', vendor: 'Sony' },
      { name: 'Xbox Series X', type: 'gaming', vendor: 'Microsoft' }
    ];
  }

  /**
   * Main network scanning function
   * @returns {Promise<object>} Scan results with devices and security assessment
   */
  async scanNetwork() {
    if (this.demoMode) {
      return this.generateDemoData();
    }
    
    // Real scanning would go here
    // Would use tools like arp-scan, nmap, or Node.js network modules
    throw new Error('Real network scanning not yet implemented');
  }

  /**
   * Generate realistic demo data for testing
   * @returns {object} Simulated scan results
   */
  generateDemoData() {
    const deviceCount = Math.floor(Math.random() * 5) + 3; // 3-7 devices
    const devices = [];
    
    // Generate random devices
    for (let i = 0; i < deviceCount; i++) {
      const isKnown = Math.random() > 0.2; // 80% chance of known device
      
      if (isKnown) {
        const deviceTemplate = this.commonDevices[Math.floor(Math.random() * this.commonDevices.length)];
        devices.push({
          id: i + 1,
          name: deviceTemplate.name,
          ipAddress: `192.168.1.${50 + i}`,
          macAddress: this.generateMacAddress(),
          deviceType: deviceTemplate.type,
          vendor: deviceTemplate.vendor,
          securityStatus: 'safe',
          lastSeen: new Date(Date.now() - Math.random() * 3600000).toISOString(), // Within last hour
          isActive: true
        });
      } else {
        // Unknown/suspicious device
        devices.push({
          id: i + 1,
          name: 'Unknown Device',
          ipAddress: `192.168.1.${100 + i}`,
          macAddress: this.generateMacAddress(),
          deviceType: 'unknown',
          vendor: 'Unknown',
          securityStatus: Math.random() > 0.5 ? 'caution' : 'risk',
          lastSeen: new Date(Date.now() - Math.random() * 86400000).toISOString(), // Within last day
          isActive: Math.random() > 0.3
        });
      }
    }

    // Assess each device
    devices.forEach(device => {
      this.assessDevice(device);
    });

    // Assess WiFi security
    const wifiAssessment = this.assessWifiSecurity(devices.length);

    // Generate recommendations
    const recommendations = this.generateRecommendations(devices, wifiAssessment);

    return {
      devices,
      wifiScore: wifiAssessment.score,
      wifiStatus: wifiAssessment.status,
      wifiDetails: wifiAssessment.details,
      recommendations,
      scanDate: new Date().toISOString(),
      scanDuration: Math.floor(Math.random() * 5000) + 2000 // 2-7 seconds
    };
  }

  /**
   * Assess security status of a device
   * @param {object} device - Device to assess
   */
  assessDevice(device) {
    // If already marked as unknown, increase risk
    if (device.deviceType === 'unknown') {
      device.securityStatus = 'risk';
      device.riskFactors = [
        'Unknown device type',
        'Unable to identify manufacturer',
        'Unusual network behavior'
      ];
      return;
    }

    // Check for IoT devices (higher risk)
    if (device.deviceType === 'iot') {
      device.securityStatus = 'caution';
      device.riskFactors = [
        'IoT devices often have security vulnerabilities',
        'May not receive regular security updates'
      ];
      return;
    }

    // Check if device is inactive
    const lastSeenDate = new Date(device.lastSeen);
    const hoursSinceLastSeen = (Date.now() - lastSeenDate) / (1000 * 60 * 60);
    
    if (hoursSinceLastSeen > 24) {
      device.securityStatus = 'caution';
      device.riskFactors = [
        'Device has not been active recently',
        'May be unauthorized device'
      ];
      return;
    }

    // Otherwise, device is safe
    device.securityStatus = 'safe';
    device.riskFactors = [];
  }

  /**
   * Assess WiFi security settings
   * @param {number} deviceCount - Number of devices on network
   * @returns {object} WiFi security assessment
   */
  assessWifiSecurity(deviceCount) {
    // Simulate WiFi security check
    const encryptionTypes = ['WPA3', 'WPA2', 'WPA', 'WEP', 'Open'];
    const encryptionType = encryptionTypes[Math.floor(Math.random() * 2)]; // Usually WPA3 or WPA2
    
    const passwordStrengths = ['strong', 'medium', 'weak'];
    const passwordStrength = passwordStrengths[Math.floor(Math.random() * 3)];
    
    const firmwareUpToDate = Math.random() > 0.4; // 60% chance firmware is up to date
    
    let score = 100;
    
    // Deduct points based on issues
    if (encryptionType === 'WPA2') score -= 10;
    if (encryptionType === 'WPA') score -= 30;
    if (encryptionType === 'WEP') score -= 50;
    if (encryptionType === 'Open') score -= 70;
    
    if (passwordStrength === 'medium') score -= 15;
    if (passwordStrength === 'weak') score -= 35;
    
    if (!firmwareUpToDate) score -= 20;
    
    if (deviceCount > 10) score -= 15; // Too many devices
    
    // Determine status
    let status;
    if (score >= 80) status = 'safe';
    else if (score >= 50) status = 'caution';
    else status = 'risk';

    return {
      score,
      status,
      details: {
        encryptionType,
        passwordStrength,
        firmwareUpToDate,
        totalDevices: deviceCount,
        signalStrength: Math.floor(Math.random() * 30) + 70, // 70-100%
        channelCongestion: Math.random() > 0.5 ? 'low' : 'medium'
      }
    };
  }

  /**
   * Generate security recommendations
   * @param {array} devices - List of devices
   * @param {object} wifiAssessment - WiFi security assessment
   * @returns {array} List of recommendations
   */
  generateRecommendations(devices, wifiAssessment) {
    const recommendations = [];

    // WiFi encryption recommendations
    if (wifiAssessment.details.encryptionType === 'WPA2') {
      recommendations.push('Consider upgrading to WPA3 encryption if your router supports it');
    } else if (wifiAssessment.details.encryptionType === 'WPA') {
      recommendations.push('⚠️ URGENT: Upgrade to WPA2 or WPA3 encryption immediately');
    } else if (wifiAssessment.details.encryptionType === 'WEP' || wifiAssessment.details.encryptionType === 'Open') {
      recommendations.push('🚨 CRITICAL: Your network is not secure! Enable WPA2/WPA3 encryption now');
    }

    // Password strength recommendations
    if (wifiAssessment.details.passwordStrength === 'weak') {
      recommendations.push('Change your WiFi password to a stronger one (12+ characters, mixed case, numbers, symbols)');
    } else if (wifiAssessment.details.passwordStrength === 'medium') {
      recommendations.push('Consider strengthening your WiFi password');
    }

    // Firmware recommendations
    if (!wifiAssessment.details.firmwareUpToDate) {
      recommendations.push('Update your router firmware to the latest version for security patches');
    }

    // Unknown device recommendations
    const unknownDevices = devices.filter(d => d.deviceType === 'unknown' || d.securityStatus === 'risk');
    if (unknownDevices.length > 0) {
      recommendations.push(`Investigate ${unknownDevices.length} unknown device(s) on your network`);
    }

    // IoT device recommendations
    const iotDevices = devices.filter(d => d.deviceType === 'iot');
    if (iotDevices.length > 0) {
      recommendations.push('Review security settings on IoT devices and keep them updated');
    }

    // Too many devices
    if (devices.length > 10) {
      recommendations.push('High number of devices detected - review and remove unused devices');
    }

    // Inactive devices
    const inactiveDevices = devices.filter(d => !d.isActive);
    if (inactiveDevices.length > 0) {
      recommendations.push(`${inactiveDevices.length} inactive device(s) detected - consider removing if unauthorized`);
    }

    // General recommendations
    if (recommendations.length === 0) {
      recommendations.push('✅ Your network security looks good!');
      recommendations.push('Continue monitoring for new devices regularly');
    } else {
      recommendations.push('Run network scans regularly to detect new devices');
    }

    return recommendations;
  }

  /**
   * Generate random MAC address
   * @returns {string} MAC address in format XX:XX:XX:XX:XX:XX
   */
  generateMacAddress() {
    const hex = '0123456789ABCDEF';
    let mac = '';
    for (let i = 0; i < 6; i++) {
      if (i > 0) mac += ':';
      mac += hex[Math.floor(Math.random() * 16)];
      mac += hex[Math.floor(Math.random() * 16)];
    }
    return mac;
  }

  /**
   * Get device icon based on type
   * @param {string} deviceType - Type of device
   * @returns {string} Emoji icon
   */
  static getDeviceIcon(deviceType) {
    const icons = {
      'mobile': '📱',
      'computer': '💻',
      'tablet': '📱',
      'smart-device': '📺',
      'iot': '🏠',
      'gaming': '🎮',
      'unknown': '❓'
    };
    return icons[deviceType] || '🔌';
  }

  /**
   * Get security status color
   * @param {string} status - Security status
   * @returns {string} Color code
   */
  static getSecurityColor(status) {
    const colors = {
      'safe': '#10b981',
      'caution': '#f59e0b',
      'risk': '#ef4444'
    };
    return colors[status] || '#6b7280';
  }
}

// Export for use in other modules
module.exports = NetworkScanner;

/**
 * EXAMPLE USAGE:
 * 
 * const NetworkScanner = require('./networkScanner');
 * const scanner = new NetworkScanner();
 * 
 * // Scan network
 * const result = await scanner.scanNetwork();
 * console.log(result);
 * 
 * // Output example:
 * {
 *   devices: [
 *     {
 *       id: 1,
 *       name: 'iPhone 13',
 *       ipAddress: '192.168.1.50',
 *       macAddress: 'A1:B2:C3:D4:E5:F6',
 *       deviceType: 'mobile',
 *       vendor: 'Apple',
 *       securityStatus: 'safe',
 *       lastSeen: '2025-01-08T12:30:00Z',
 *       isActive: true,
 *       riskFactors: []
 *     },
 *     {
 *       id: 2,
 *       name: 'Unknown Device',
 *       ipAddress: '192.168.1.101',
 *       macAddress: '12:34:56:78:9A:BC',
 *       deviceType: 'unknown',
 *       vendor: 'Unknown',
 *       securityStatus: 'risk',
 *       lastSeen: '2025-01-08T11:45:00Z',
 *       isActive: false,
 *       riskFactors: ['Unknown device type', 'Unable to identify manufacturer']
 *     }
 *   ],
 *   wifiScore: 75,
 *   wifiStatus: 'caution',
 *   wifiDetails: {
 *     encryptionType: 'WPA2',
 *     passwordStrength: 'medium',
 *     firmwareUpToDate: false,
 *     totalDevices: 5,
 *     signalStrength: 85,
 *     channelCongestion: 'low'
 *   },
 *   recommendations: [
 *     'Consider upgrading to WPA3 encryption if your router supports it',
 *     'Update your router firmware to the latest version',
 *     'Investigate 1 unknown device(s) on your network'
 *   ],
 *   scanDate: '2025-01-08T13:00:00Z',
 *   scanDuration: 3500
 * }
 */
