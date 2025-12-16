/**
 * ScamGuard Pro - ThreatDetector Integration
 * Drop-in replacement for the existing threatDetector.js
 * Maintains backward compatibility while using the new 2025 engine
 */

const { ScamDetectionEngine } = require('../scanner/core/engine');

/**
 * ThreatDetector class (backward compatible)
 * Wraps the new ScamDetectionEngine for use with existing components
 */
class ThreatDetector {
  constructor() {
    this.engine = new ScamDetectionEngine({
      useMlModel: false, // Disable ML by default for faster startup
      useYara: true,
      useBlocklist: true,
      resolveShorteners: false, // Disable for sync operation
      useVirusTotal: false,
    });
    
    this.initialized = false;
    this.initPromise = null;
  }

  /**
   * Initialize the engine (called automatically on first scan)
   */
  async initialize() {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;
    
    this.initPromise = this.engine.initialize();
    await this.initPromise;
    this.initialized = true;
  }

  /**
   * Main scanning function (backward compatible)
   * @param {string} text - Text to scan
   * @returns {object} Scan results with threat score and details
   */
  async scanTextAsync(text) {
    if (!text || typeof text !== 'string') {
      return {
        threatScore: 0,
        verdict: 'SAFE',
        threats: [],
        recommendations: ['No text to scan']
      };
    }

    await this.initialize();
    
    try {
      const result = await this.engine.scan(text);
      
      // Transform to backward-compatible format
      return {
        threatScore: result.score,
        verdict: this.mapVerdict(result.verdict),
        threats: result.threats.map(t => ({
          pattern: t.pattern,
          category: t.category,
          severity: t.severity,
          confidence: t.confidence,
          matchedText: t.matchedText,
          ruleId: t.ruleId,
        })),
        recommendations: result.recommendations,
        // Additional fields from new engine
        extractedUrls: result.extractedUrls,
        extractedUpiIds: result.extractedUpiIds,
        processingTimeMs: result.processingTimeMs,
        language: result.metadata?.language,
        mlConfidence: result.mlConfidence,
      };
    } catch (error) {
      console.error('Scan error:', error);
      // Fallback to basic scan
      return this.scanTextSync(text);
    }
  }

  /**
   * Synchronous text scan (uses regex patterns only)
   * For backward compatibility with existing sync code
   * @param {string} text - Text to scan
   * @returns {object} Scan results
   */
  scanText(text) {
    return this.scanTextSync(text);
  }

  /**
   * Synchronous scan implementation
   */
  scanTextSync(text) {
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

    // Quick pattern checks
    const patterns = [
      { regex: /(?:share|send|give)\s*(?:your|ur)\s*otp/gi, category: 'OTP_SCAM', severity: 'critical', score: 50 },
      { regex: /kyc\s*(?:update|verify|expire|suspend)/gi, category: 'KYC_FRAUD', severity: 'critical', score: 40 },
      { regex: /(?:won|winner|selected)\s*(?:in|for|of)\s*(?:lottery|lucky)/gi, category: 'LOTTERY_SCAM', severity: 'high', score: 35 },
      { regex: /scan\s*(?:qr|code)\s*(?:to\s*)?(?:receive|get)/gi, category: 'QR_SCAM', severity: 'critical', score: 45 },
      { regex: /(?:account|a\/c)\s*(?:will\s*be|shall\s*be)\s*(?:blocked|suspended)/gi, category: 'PHISHING', severity: 'high', score: 35 },
      { regex: /(?:urgent|immediate)\s*(?:action|transfer)/gi, category: 'SOCIAL_ENGINEERING', severity: 'medium', score: 20 },
      { regex: /click\s*(?:here|link|below)/gi, category: 'PHISHING', severity: 'medium', score: 15 },
      { regex: /(?:sbi|hdfc|icici|axis)\s*(?:user|customer)/gi, category: 'BANKING_FRAUD', severity: 'medium', score: 15 },
      { regex: /(?:earn|income)\s*(?:rs\.?|₹)?\s*\d+\s*(?:per|\/)\s*(?:day|week|month)/gi, category: 'JOB_SCAM', severity: 'high', score: 30 },
      { regex: /(?:verify|update|confirm)\s*(?:your|ur)\s*(?:account|details)/gi, category: 'PHISHING', severity: 'medium', score: 20 },
      { regex: /(?:processing|registration)\s*fee/gi, category: 'PHISHING', severity: 'high', score: 30 },
      { regex: /(?:arrest|jail)\s*(?:warrant|notice)/gi, category: 'GOVT_IMPERSONATION', severity: 'critical', score: 45 },
      { regex: /(?:cyber\s*cell|cyber\s*crime|police)\s*(?:notice|complaint)/gi, category: 'GOVT_IMPERSONATION', severity: 'critical', score: 40 },
      { regex: /(?:rbi|reserve\s*bank)\s*(?:notice|warning|refund)/gi, category: 'GOVT_IMPERSONATION', severity: 'critical', score: 40 },
      { regex: /(?:double|triple)\s*(?:your\s*)?money/gi, category: 'INVESTMENT_SCAM', severity: 'high', score: 35 },
      { regex: /(?:guaranteed|assured)\s*(?:return|profit)/gi, category: 'INVESTMENT_SCAM', severity: 'high', score: 30 },
      { regex: /(?:loan|credit)\s*(?:without|no)\s*(?:documents?|cibil)/gi, category: 'LOAN_SCAM', severity: 'high', score: 30 },
      { regex: /(?:customs?|duty)\s*(?:clearance|fee)/gi, category: 'FAKE_DELIVERY', severity: 'high', score: 25 },
      { regex: /kbc\s*(?:lottery|winner|prize)/gi, category: 'LOTTERY_SCAM', severity: 'critical', score: 45 },
      { regex: /(?:video|photos?)\s*(?:of\s*you|recorded)\s*(?:will\s*be|to\s*be)?\s*(?:leaked|shared)/gi, category: 'SOCIAL_ENGINEERING', severity: 'critical', score: 45 },
    ];

    for (const p of patterns) {
      const matches = text.match(p.regex);
      if (matches) {
        score += p.score;
        threats.push({
          pattern: matches[0],
          category: p.category,
          severity: p.severity,
        });
      }
    }

    // Check for shortened URLs
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'cutt.ly'];
    for (const s of shorteners) {
      if (textLower.includes(s)) {
        score += 15;
        threats.push({
          pattern: `Shortened URL (${s})`,
          category: 'SUSPICIOUS_DOMAIN',
          severity: 'medium',
        });
      }
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.zip'];
    for (const tld of suspiciousTlds) {
      if (textLower.includes(tld)) {
        score += 20;
        threats.push({
          pattern: `Suspicious TLD (${tld})`,
          category: 'SUSPICIOUS_DOMAIN',
          severity: 'medium',
        });
      }
    }

    // Check exclamation marks
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 3) {
      score += 10;
      threats.push({
        pattern: `Excessive exclamation marks (${exclamationCount})`,
        category: 'SOCIAL_ENGINEERING',
        severity: 'low',
      });
    }

    // Cap score at 100
    score = Math.min(100, score);

    // Determine verdict
    let verdict;
    if (score >= 80) {
      verdict = 'DANGER';
      recommendations.push('🚨 HIGH RISK: Do not interact with this message');
      recommendations.push('🚨 Report this to cybercrime.gov.in or call 1930');
    } else if (score >= 50) {
      verdict = 'SUSPICIOUS';
      recommendations.push('⚠️ This content appears suspicious - verify before taking action');
    } else if (score >= 20) {
      verdict = 'CAUTION';
      recommendations.push('⚠️ Exercise caution with this content');
    } else {
      verdict = 'SAFE';
      if (threats.length === 0) {
        recommendations.push('No threats detected');
      }
    }

    // Add category-specific recommendations
    const categories = new Set(threats.map(t => t.category));
    
    if (categories.has('OTP_SCAM')) {
      recommendations.push('🚨 NEVER share OTP with anyone');
    }
    if (categories.has('KYC_FRAUD')) {
      recommendations.push('⚠️ Banks never ask for KYC updates via SMS links');
    }
    if (categories.has('QR_SCAM')) {
      recommendations.push('⚠️ QR codes are only for SENDING money, not receiving');
    }
    if (categories.has('LOTTERY_SCAM')) {
      recommendations.push('⚠️ You cannot win a lottery you never entered');
    }
    if (categories.has('GOVT_IMPERSONATION')) {
      recommendations.push('⚠️ Government agencies do not demand immediate payments');
    }

    return {
      threatScore: score,
      verdict,
      threats,
      recommendations: [...new Set(recommendations)],
    };
  }

  /**
   * Scan URL (backward compatible)
   * @param {string} url - URL to scan
   * @returns {object} Scan results
   */
  scanUrl(url) {
    return this.scanUrlSync(url);
  }

  /**
   * Synchronous URL scan
   */
  scanUrlSync(url) {
    if (!url || typeof url !== 'string') {
      return {
        threatScore: 0,
        verdict: 'SAFE',
        threats: [],
        recommendations: ['No URL to scan']
      };
    }

    const urlLower = url.toLowerCase();
    let score = 0;
    const threats = [];
    const recommendations = [];

    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy'];
    for (const s of shorteners) {
      if (urlLower.includes(s)) {
        score += 20;
        threats.push({
          pattern: 'URL shortener detected',
          category: 'SHORTENER_ABUSE',
          severity: 'medium',
        });
        recommendations.push('⚠️ Shortened URLs can hide malicious destinations');
        break;
      }
    }

    // Check for suspicious TLDs
    const suspiciousTlds = [
      { tld: '.tk', score: 30 }, { tld: '.ml', score: 30 }, { tld: '.ga', score: 30 },
      { tld: '.cf', score: 30 }, { tld: '.gq', score: 30 }, { tld: '.xyz', score: 25 },
      { tld: '.top', score: 25 }, { tld: '.click', score: 25 }, { tld: '.link', score: 20 },
      { tld: '.zip', score: 40 }, { tld: '.mov', score: 40 },
    ];
    
    for (const { tld, score: tldScore } of suspiciousTlds) {
      if (urlLower.includes(tld + '/') || urlLower.endsWith(tld)) {
        score += tldScore;
        threats.push({
          pattern: `Suspicious TLD: ${tld}`,
          category: 'SUSPICIOUS_DOMAIN',
          severity: tldScore >= 30 ? 'high' : 'medium',
        });
        break;
      }
    }

    // Check for IP address
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 25;
      threats.push({
        pattern: 'IP address instead of domain',
        category: 'SUSPICIOUS_DOMAIN',
        severity: 'medium',
      });
      recommendations.push('⚠️ Legitimate websites use domain names, not IP addresses');
    }

    // Check for suspicious keywords in URL
    const suspiciousKeywords = [
      'login', 'signin', 'verify', 'secure', 'update', 'confirm',
      'account', 'banking', 'sbi', 'hdfc', 'icici', 'paytm',
      'kyc', 'aadhar', 'pan', 'otp', 'password'
    ];
    
    for (const keyword of suspiciousKeywords) {
      if (urlLower.includes(keyword)) {
        score += 10;
        threats.push({
          pattern: `Suspicious keyword: ${keyword}`,
          category: 'PHISHING',
          severity: 'medium',
        });
        break;
      }
    }

    // Check for brand impersonation
    const brands = [
      { name: 'sbi', pattern: /sbi[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i },
      { name: 'hdfc', pattern: /hdfc[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i },
      { name: 'icici', pattern: /icici[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i },
      { name: 'paytm', pattern: /paytm[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i },
      { name: 'phonepe', pattern: /phonepe[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i },
    ];

    for (const brand of brands) {
      if (brand.pattern.test(url)) {
        score += 40;
        threats.push({
          pattern: `Possible ${brand.name.toUpperCase()} impersonation`,
          category: 'BANKING_FRAUD',
          severity: 'critical',
        });
        recommendations.push(`🚨 This may be a fake ${brand.name.toUpperCase()} website`);
        break;
      }
    }

    // Cap score at 100
    score = Math.min(100, score);

    // Determine verdict
    let verdict;
    if (score >= 80) {
      verdict = 'DANGER';
      recommendations.push('🚨 HIGH RISK: Do not visit this URL');
    } else if (score >= 50) {
      verdict = 'SUSPICIOUS';
      recommendations.push('⚠️ This URL appears suspicious - verify before visiting');
    } else if (score >= 20) {
      verdict = 'CAUTION';
      recommendations.push('⚠️ Exercise caution with this URL');
    } else {
      verdict = 'SAFE';
      if (threats.length === 0) {
        recommendations.push('No obvious threats detected in URL');
      }
    }

    return {
      threatScore: score,
      verdict,
      threats,
      recommendations: [...new Set(recommendations)],
    };
  }

  /**
   * Async URL scan
   */
  async scanUrlAsync(url) {
    await this.initialize();
    
    try {
      const result = await this.engine.scan(url, { resolveShorteners: true });
      
      return {
        threatScore: result.score,
        verdict: this.mapVerdict(result.verdict),
        threats: result.threats.map(t => ({
          pattern: t.pattern,
          category: t.category,
          severity: t.severity,
        })),
        recommendations: result.recommendations,
        resolvedUrl: result.extractedUrls?.[0]?.resolved,
      };
    } catch (error) {
      console.error('URL scan error:', error);
      return this.scanUrlSync(url);
    }
  }

  /**
   * Map new verdict to old format
   */
  mapVerdict(verdict) {
    const mapping = {
      'SAFE': 'SAFE',
      'CAUTION': 'CAUTION',
      'SUSPICIOUS': 'SUSPICIOUS',
      'DANGER': 'DANGER',
      'CRITICAL': 'DANGER',
    };
    return mapping[verdict] || 'CAUTION';
  }

  /**
   * Get engine version
   */
  getVersion() {
    return '2025.1.0';
  }
}

// Export for use in other modules
module.exports = ThreatDetector;

/**
 * EXAMPLE USAGE:
 * 
 * const ThreatDetector = require('./threatDetectorV2');
 * const scanner = new ThreatDetector();
 * 
 * // Sync scan (backward compatible)
 * const result = scanner.scanText("URGENT! Click here to verify your KYC!");
 * console.log(result);
 * 
 * // Async scan (uses new engine)
 * const asyncResult = await scanner.scanTextAsync("Your UPI KYC is pending...");
 * console.log(asyncResult);
 * 
 * // URL scan
 * const urlResult = scanner.scanUrl("http://sbi-kyc-update.tk/verify");
 * console.log(urlResult);
 */
