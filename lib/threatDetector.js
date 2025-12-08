/**
 * Local Threat Detection Engine for CyberGuard Lite
 * Uses pattern matching to detect phishing, scams, and malware
 * No external APIs - 100% local analysis
 */

class ThreatDetector {
  constructor() {
    // Phishing patterns
    this.phishingKeywords = [
      'urgent', 'click here', 'verify', 'suspended', 'confirm', 
      'update', 'action required', 'immediately', 'do not delay', 
      'limited time', 'expires', 'act now', 'dear user', 'dear customer'
    ];

    // Financial scam patterns
    this.financialKeywords = [
      'money', 'prize', 'winner', 'inheritance', 'claim', 'transfer', 
      'account', 'wire money', 'gift cards', 'bitcoin', 'cryptocurrency',
      'lottery', 'congratulations', 'selected', 'refund'
    ];

    // Malware/dangerous patterns
    this.malwareKeywords = [
      'download', 'run', 'execute', 'install', 'attachment', 
      'click attachment', 'open file', 'enable macros', 'disable antivirus'
    ];

    // Suspicious file extensions
    this.suspiciousExtensions = ['.exe', '.bat', '.scr', '.vbs', '.js', '.jar'];

    // URL shortener domains
    this.urlShorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
  }

  /**
   * Main scanning function
   * @param {string} text - Text to scan
   * @returns {object} Scan results with threat score and details
   */
  scanText(text) {
    if (!text || typeof text !== 'string') {
      return {
        threatScore: 0,
        verdict: 'SAFE',
        threats: [],
        recommendations: ['No text to scan']
      };
    }

    const textLower = text.toLowerCase();
    let score = 0;
    const threats = [];
    const recommendations = [];

    // Check for phishing keywords
    const phishingFound = this.containsPhishingKeywords(textLower);
    if (phishingFound.found) {
      score += phishingFound.count * 10;
      threats.push({
        pattern: `Phishing keywords: ${phishingFound.keywords.join(', ')}`,
        category: 'Phishing',
        severity: phishingFound.count > 3 ? 'high' : 'medium'
      });
      recommendations.push('Be cautious of urgent language and pressure tactics');
    }

    // Check for financial scam keywords
    const financialFound = this.containsFinancialKeywords(textLower);
    if (financialFound.found) {
      score += financialFound.count * 25;
      threats.push({
        pattern: `Financial scam keywords: ${financialFound.keywords.join(', ')}`,
        category: 'Financial Scam',
        severity: 'high'
      });
      recommendations.push('Never send money or gift cards to unknown parties');
    }

    // Check for malware keywords
    const malwareFound = this.containsMalwareKeywords(textLower);
    if (malwareFound.found) {
      score += malwareFound.count * 30;
      threats.push({
        pattern: `Malware keywords: ${malwareFound.keywords.join(', ')}`,
        category: 'Malware',
        severity: 'high'
      });
      recommendations.push('Do not download or run attachments from unknown sources');
    }

    // Check for shortened URLs
    const shortenedUrls = this.detectShortenedUrls(text);
    if (shortenedUrls.length > 0) {
      score += shortenedUrls.length * 20;
      threats.push({
        pattern: `Shortened URLs found: ${shortenedUrls.join(', ')}`,
        category: 'Suspicious Link',
        severity: 'medium'
      });
      recommendations.push('Shortened URLs can hide malicious destinations');
    }

    // Check exclamation marks
    const exclamationScore = this.calculateExclamationScore(text);
    if (exclamationScore > 0) {
      score += exclamationScore;
      threats.push({
        pattern: `Excessive exclamation marks (${text.split('!').length - 1})`,
        category: 'Pressure Tactics',
        severity: 'low'
      });
    }

    // Check grammar quality
    const grammarScore = this.analyzeGrammar(text);
    if (grammarScore > 0) {
      score += grammarScore;
      threats.push({
        pattern: 'Poor grammar or spelling detected',
        category: 'Suspicious Content',
        severity: 'low'
      });
      recommendations.push('Legitimate companies typically use proper grammar');
    }

    // Check for suspicious file extensions
    const suspiciousFiles = this.detectSuspiciousFiles(textLower);
    if (suspiciousFiles.length > 0) {
      score += suspiciousFiles.length * 25;
      threats.push({
        pattern: `Suspicious file types: ${suspiciousFiles.join(', ')}`,
        category: 'Dangerous Attachment',
        severity: 'high'
      });
      recommendations.push('Do not open executable files from untrusted sources');
    }

    // Cap score at 100
    score = Math.min(100, score);

    // Determine verdict
    let verdict;
    if (score <= 20) {
      verdict = 'SAFE';
      if (threats.length === 0) {
        recommendations.push('No threats detected');
      }
    } else if (score <= 50) {
      verdict = 'CAUTION';
      recommendations.push('Exercise caution with this content');
    } else if (score <= 80) {
      verdict = 'SUSPICIOUS';
      recommendations.push('This content appears suspicious - verify before taking action');
    } else {
      verdict = 'DANGER';
      recommendations.push('HIGH RISK: Do not interact with this content');
    }

    return {
      threatScore: score,
      verdict,
      threats,
      recommendations
    };
  }

  /**
   * Check for phishing keywords
   * @param {string} text - Text to check (lowercase)
   * @returns {object} Found status and keywords
   */
  containsPhishingKeywords(text) {
    const found = [];
    for (const keyword of this.phishingKeywords) {
      if (text.includes(keyword)) {
        found.push(keyword);
      }
    }
    return {
      found: found.length > 0,
      count: found.length,
      keywords: found
    };
  }

  /**
   * Check for financial scam keywords
   * @param {string} text - Text to check (lowercase)
   * @returns {object} Found status and keywords
   */
  containsFinancialKeywords(text) {
    const found = [];
    for (const keyword of this.financialKeywords) {
      if (text.includes(keyword)) {
        found.push(keyword);
      }
    }
    return {
      found: found.length > 0,
      count: found.length,
      keywords: found
    };
  }

  /**
   * Check for malware keywords
   * @param {string} text - Text to check (lowercase)
   * @returns {object} Found status and keywords
   */
  containsMalwareKeywords(text) {
    const found = [];
    for (const keyword of this.malwareKeywords) {
      if (text.includes(keyword)) {
        found.push(keyword);
      }
    }
    return {
      found: found.length > 0,
      count: found.length,
      keywords: found
    };
  }

  /**
   * Detect shortened URLs
   * @param {string} text - Text to check
   * @returns {array} Found shortened URLs
   */
  detectShortenedUrls(text) {
    const found = [];
    for (const shortener of this.urlShorteners) {
      if (text.toLowerCase().includes(shortener)) {
        found.push(shortener);
      }
    }
    return found;
  }

  /**
   * Detect suspicious file extensions
   * @param {string} text - Text to check (lowercase)
   * @returns {array} Found suspicious extensions
   */
  detectSuspiciousFiles(text) {
    const found = [];
    for (const ext of this.suspiciousExtensions) {
      if (text.includes(ext)) {
        found.push(ext);
      }
    }
    return found;
  }

  /**
   * Calculate score based on exclamation marks
   * @param {string} text - Text to check
   * @returns {number} Score (0 or 15)
   */
  calculateExclamationScore(text) {
    const count = (text.match(/!/g) || []).length;
    return count > 3 ? 15 : 0;
  }

  /**
   * Analyze grammar quality
   * @param {string} text - Text to check
   * @returns {number} Score based on grammar issues
   */
  analyzeGrammar(text) {
    let score = 0;

    // Check for multiple spaces
    if (/\s{2,}/.test(text)) {
      score += 2;
    }

    // Check for missing spaces after punctuation
    if (/[.,!?][a-zA-Z]/.test(text)) {
      score += 3;
    }

    // Check for all caps (more than 50% of letters)
    const letters = text.replace(/[^a-zA-Z]/g, '');
    const uppercase = text.replace(/[^A-Z]/g, '');
    if (letters.length > 10 && uppercase.length / letters.length > 0.5) {
      score += 5;
    }

    // Check for repeated characters (e.g., "hellooo")
    if (/(.)\1{3,}/.test(text)) {
      score += 3;
    }

    return score;
  }

  /**
   * Scan a URL for threats
   * @param {string} url - URL to scan
   * @returns {object} Scan results
   */
  scanUrl(url) {
    if (!url || typeof url !== 'string') {
      return {
        threatScore: 0,
        verdict: 'SAFE',
        threats: [],
        recommendations: ['No URL to scan']
      };
    }

    let score = 0;
    const threats = [];
    const recommendations = [];

    const urlLower = url.toLowerCase();

    // Check for URL shorteners
    const shortenedUrls = this.detectShortenedUrls(url);
    if (shortenedUrls.length > 0) {
      score += 30;
      threats.push({
        pattern: 'URL shortener detected',
        category: 'Suspicious Link',
        severity: 'medium'
      });
      recommendations.push('Shortened URLs can hide malicious destinations');
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    for (const tld of suspiciousTlds) {
      if (urlLower.includes(tld)) {
        score += 20;
        threats.push({
          pattern: `Suspicious domain extension: ${tld}`,
          category: 'Suspicious Domain',
          severity: 'medium'
        });
        break;
      }
    }

    // Check for IP address instead of domain
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 25;
      threats.push({
        pattern: 'IP address instead of domain name',
        category: 'Suspicious URL',
        severity: 'medium'
      });
      recommendations.push('Legitimate websites use domain names, not IP addresses');
    }

    // Check for excessive subdomains
    const domainParts = url.split('/')[2]?.split('.') || [];
    if (domainParts.length > 4) {
      score += 15;
      threats.push({
        pattern: 'Excessive subdomains',
        category: 'Suspicious URL',
        severity: 'low'
      });
    }

    // Check for suspicious keywords in URL
    const suspiciousUrlKeywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm'];
    for (const keyword of suspiciousUrlKeywords) {
      if (urlLower.includes(keyword)) {
        score += 10;
        threats.push({
          pattern: `Suspicious keyword in URL: ${keyword}`,
          category: 'Phishing URL',
          severity: 'medium'
        });
        break;
      }
    }

    // Cap score at 100
    score = Math.min(100, score);

    // Determine verdict
    let verdict;
    if (score <= 20) {
      verdict = 'SAFE';
      if (threats.length === 0) {
        recommendations.push('No obvious threats detected in URL');
      }
    } else if (score <= 50) {
      verdict = 'CAUTION';
      recommendations.push('Exercise caution with this URL');
    } else if (score <= 80) {
      verdict = 'SUSPICIOUS';
      recommendations.push('This URL appears suspicious - verify before visiting');
    } else {
      verdict = 'DANGER';
      recommendations.push('HIGH RISK: Do not visit this URL');
    }

    return {
      threatScore: score,
      verdict,
      threats,
      recommendations
    };
  }
}

// Export for use in other modules
module.exports = ThreatDetector;

/**
 * EXAMPLE USAGE:
 * 
 * const ThreatDetector = require('./threatDetector');
 * const scanner = new ThreatDetector();
 * 
 * // Scan text
 * const result = scanner.scanText("URGENT! Click here to verify your account!");
 * console.log(result);
 * // Output: { threatScore: 70-80, verdict: 'SUSPICIOUS', threats: [...], recommendations: [...] }
 * 
 * // Scan URL
 * const urlResult = scanner.scanUrl("http://bit.ly/verify-account");
 * console.log(urlResult);
 * // Output: { threatScore: 60-70, verdict: 'SUSPICIOUS', threats: [...], recommendations: [...] }
 * 
 * // Safe text example
 * const safeResult = scanner.scanText("Hello, this is a normal message.");
 * console.log(safeResult);
 * // Output: { threatScore: 0, verdict: 'SAFE', threats: [], recommendations: ['No threats detected'] }
 */
