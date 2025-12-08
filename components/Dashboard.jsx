import { useState, useEffect } from 'react';
import styles from '../styles/Dashboard.module.css';
import ThreatScanner from './ThreatScanner';
import NetworkMonitor from './NetworkMonitor';
import FileProtection from './FileProtection';

/**
 * Main Dashboard Component for CyberGuard Lite
 * Displays after successful login
 */
export default function Dashboard({ user, onLogout }) {
  // Active tab state
  const [activeTab, setActiveTab] = useState('protect');
  
  // Stats state
  const [stats, setStats] = useState({
    filesProtected: 0,
    recentThreats: 0,
    devicesMonitored: 0,
    tasksScheduled: 0
  });
  
  // Activity feed state
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Calculate security score based on stats
  const calculateSecurityScore = () => {
    const { filesProtected, recentThreats, devicesMonitored, tasksScheduled } = stats;
    
    let score = 50; // Base score
    
    // Add points for protection
    if (filesProtected > 0) score += 15;
    if (devicesMonitored > 0) score += 15;
    if (tasksScheduled > 0) score += 10;
    
    // Deduct points for threats
    if (recentThreats > 5) score -= 20;
    else if (recentThreats > 0) score -= 10;
    
    return Math.max(0, Math.min(100, score));
  };

  const securityScore = calculateSecurityScore();

  // Get score color
  const getScoreColor = (score) => {
    if (score >= 80) return '#10b981'; // green
    if (score >= 50) return '#f59e0b'; // orange
    return '#ef4444'; // red
  };

  // Load stats from database
  const loadStats = async () => {
    try {
      const result = await window.electronAPI.getStats();
      
      if (result.success) {
        setStats({
          filesProtected: result.stats.encryptedFiles || 0,
          recentThreats: 0, // Calculate from recent scans
          devicesMonitored: result.stats.networkDevices || 0,
          tasksScheduled: result.stats.activeTasks || 0
        });
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  // Load activity feed
  const loadActivities = async () => {
    try {
      const result = await window.electronAPI.getActivityLog();
      
      if (result.success) {
        setActivities(result.logs.slice(0, 10)); // Show most recent 10
      }
    } catch (error) {
      console.error('Failed to load activities:', error);
    } finally {
      setLoading(false);
    }
  };

  // Load data on mount
  useEffect(() => {
    loadStats();
    loadActivities();
  }, [user.userId]);

  // Auto-refresh activity feed every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      loadActivities();
      loadStats();
    }, 30000);

    return () => clearInterval(interval);
  }, [user.userId]);

  // Callback for child components to trigger stats refresh
  const handleStatsUpdate = () => {
    loadStats();
    loadActivities();
  };

  // Handle logout
  const handleLogout = async () => {
    try {
      await window.electronAPI.logoutUser();
      onLogout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  // Format timestamp
  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  };

  // Get activity icon
  const getActivityIcon = (action) => {
    if (action.includes('Encrypted') || action.includes('File')) return '🔒';
    if (action.includes('Scan') || action.includes('Threat')) return '🔍';
    if (action.includes('Network') || action.includes('Device')) return '🌐';
    if (action.includes('Task') || action.includes('Scheduled')) return '⚡';
    if (action.includes('Login')) return '👤';
    return '📝';
  };

  return (
    <div className={styles.dashboard}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerLeft}>
          <h1 className={styles.appName}>
            <span className={styles.logo}>🛡️</span>
            SIMPLIFIED CYBER DEFENCE FOR THREATS
          </h1>
        </div>

        <div className={styles.headerCenter}>
          <div className={styles.securityScore}>
            <div 
              className={styles.scoreCircle}
              style={{ borderColor: getScoreColor(securityScore) }}
            >
              <span 
                className={styles.scoreValue}
                style={{ color: getScoreColor(securityScore) }}
              >
                {securityScore}
              </span>
            </div>
            <span className={styles.scoreLabel}>Security Score</span>
          </div>
        </div>

        <div className={styles.headerRight}>
          <div className={styles.userMenu}>
            <button 
              className={styles.userButton}
              onClick={() => setShowUserMenu(!showUserMenu)}
            >
              <span className={styles.userIcon}>👤</span>
              <span className={styles.username}>{user.username}</span>
              <span className={styles.dropdownIcon}>▼</span>
            </button>
            
            {showUserMenu && (
              <div className={styles.userDropdown}>
                <button onClick={handleLogout} className={styles.logoutButton}>
                  <span>🚪</span> Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Quick Stats */}
      <div className={styles.quickStats}>
        <div className={styles.statCard}>
          <div className={styles.statIcon}>🔒</div>
          <div className={styles.statContent}>
            <div className={styles.statValue}>{stats.filesProtected}</div>
            <div className={styles.statLabel}>Files Protected</div>
          </div>
        </div>

        <div className={styles.statCard}>
          <div className={styles.statIcon}>⚠️</div>
          <div className={styles.statContent}>
            <div className={styles.statValue}>{stats.recentThreats}</div>
            <div className={styles.statLabel}>Recent Threats</div>
          </div>
        </div>

        <div className={styles.statCard}>
          <div className={styles.statIcon}>🌐</div>
          <div className={styles.statContent}>
            <div className={styles.statValue}>{stats.devicesMonitored}</div>
            <div className={styles.statLabel}>Devices Monitored</div>
          </div>
        </div>

        <div className={styles.statCard}>
          <div className={styles.statIcon}>⚡</div>
          <div className={styles.statContent}>
            <div className={styles.statValue}>{stats.tasksScheduled}</div>
            <div className={styles.statLabel}>Tasks Scheduled</div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className={styles.mainContent}>
        {/* Tab Navigation */}
        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${activeTab === 'protect' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('protect')}
          >
            <span className={styles.tabIcon}>🔒</span>
            <span className={styles.tabLabel}>Protect Files</span>
          </button>

          <button
            className={`${styles.tab} ${activeTab === 'scan' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('scan')}
          >
            <span className={styles.tabIcon}>🤖</span>
            <span className={styles.tabLabel}>Scan Threats</span>
          </button>

          <button
            className={`${styles.tab} ${activeTab === 'network' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('network')}
          >
            <span className={styles.tabIcon}>🎯</span>
            <span className={styles.tabLabel}>Check Network</span>
          </button>

          {/* Auto-Protect tab - commented out for now */}
          {/* <button
            className={`${styles.tab} ${activeTab === 'auto' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('auto')}
          >
            <span className={styles.tabIcon}>⚡</span>
            <span className={styles.tabLabel}>Auto-Protect</span>
          </button> */}
        </div>

        {/* Tab Content */}
        <div className={styles.tabContent}>
          {activeTab === 'protect' && (
            <FileProtection onStatsUpdate={handleStatsUpdate} />
          )}

          {activeTab === 'scan' && (
            <ThreatScanner onStatsUpdate={handleStatsUpdate} />
          )}

          {activeTab === 'network' && (
            <NetworkMonitor onStatsUpdate={handleStatsUpdate} />
          )}

          {/* Auto-Protect content - commented out for now */}
          {/* {activeTab === 'auto' && (
            <div className={styles.section}>
              <h2>⚡ Auto-Protect</h2>
              <p>Schedule automated security tasks.</p>
              <div className={styles.placeholder}>
                <p>Automation interface coming soon...</p>
                <p className={styles.hint}>This section will manage scheduled tasks</p>
              </div>
            </div>
          )} */}
        </div>
      </div>

      {/* Activity Feed */}
      <div className={styles.activityFeed}>
        <h3 className={styles.activityTitle}>Recent Activity</h3>
        
        {loading ? (
          <div className={styles.activityLoading}>Loading activities...</div>
        ) : activities.length === 0 ? (
          <div className={styles.activityEmpty}>
            No recent activity. Start using CyberGuard Lite!
          </div>
        ) : (
          <div className={styles.activityList}>
            {activities.map((activity) => (
              <div key={activity.id} className={styles.activityItem}>
                <span className={styles.activityIcon}>
                  {getActivityIcon(activity.action)}
                </span>
                <div className={styles.activityContent}>
                  <div className={styles.activityAction}>{activity.action}</div>
                  <div className={styles.activityTime}>
                    {formatTime(activity.timestamp)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
