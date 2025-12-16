/**
 * ScamGuard Pro - 2025 Detection Engine Types
 * India's #1 Scam Detection System
 */

export type ThreatCategory =
  | 'UPI_SCAM'
  | 'PHISHING'
  | 'BANKING_FRAUD'
  | 'LOTTERY_SCAM'
  | 'KYC_FRAUD'
  | 'OTP_SCAM'
  | 'JOB_SCAM'
  | 'INVESTMENT_SCAM'
  | 'TECH_SUPPORT_SCAM'
  | 'LOAN_SCAM'
  | 'FAKE_DELIVERY'
  | 'GOVT_IMPERSONATION'
  | 'HOMOGLYPH_ATTACK'
  | 'SHORTENER_ABUSE'
  | 'QR_SCAM'
  | 'VOICE_NOTE_SCAM'
  | 'GOOGLE_FORMS_PHISH'
  | 'REACT2SHELL'
  | 'ZIP_DOMAIN_SCAM'
  | 'FAKE_LOGIN_PAGE'
  | 'SUSPICIOUS_DOMAIN'
  | 'MALWARE'
  | 'SOCIAL_ENGINEERING'
  | 'CRYPTO_SCAM'
  | 'CARD_SKIMMING'
  | 'UNKNOWN';

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Verdict = 'SAFE' | 'CAUTION' | 'SUSPICIOUS' | 'DANGER' | 'CRITICAL';

export interface ThreatDetail {
  pattern: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  matchedText?: string;
  ruleId?: string;
  confidence: number;
}

export interface ThreatResult {
  /** Confidence score 0-100 */
  score: number;
  /** Overall verdict */
  verdict: Verdict;
  /** List of detected threats */
  threats: ThreatDetail[];
  /** Actionable recommendations */
  recommendations: string[];
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Normalized input text */
  normalizedText?: string;
  /** Extracted URLs */
  extractedUrls?: ExtractedUrl[];
  /** Extracted UPI IDs */
  extractedUpiIds?: UpiCheckResult[];
  /** ML model confidence (if used) */
  mlConfidence?: number;
  /** YARA matches */
  yaraMatches?: YaraMatch[];
  /** Domain reputation results */
  domainReputation?: DomainCheckResult[];
  /** Metadata */
  metadata: ScanMetadata;
}

export interface ExtractedUrl {
  original: string;
  normalized: string;
  resolved?: string;
  isShortener: boolean;
  entropy: number;
  suspiciousTokens: string[];
  reputation?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
}

export interface UpiCheckResult {
  upiId: string;
  provider: string;
  isBlocklisted: boolean;
  isSuspicious: boolean;
  reason?: string;
}

export interface DomainCheckResult {
  domain: string;
  isBlocklisted: boolean;
  category?: string;
  registrationAge?: number;
  isSuspiciousTld: boolean;
  homoglyphDetected: boolean;
}

export interface YaraMatch {
  ruleName: string;
  ruleNamespace: string;
  matchedStrings: string[];
  tags: string[];
}

export interface ScanMetadata {
  engineVersion: string;
  scanTimestamp: number;
  inputType: 'text' | 'url' | 'screenshot' | 'qr' | 'email';
  inputLength: number;
  language?: 'hindi' | 'english' | 'hinglish' | 'unknown';
  usedMlModel: boolean;
  usedYara: boolean;
  usedBlocklist: boolean;
}

export interface ScanOptions {
  /** Enable ML model inference */
  useMlModel?: boolean;
  /** Enable YARA rule matching */
  useYara?: boolean;
  /** Enable blocklist lookup */
  useBlocklist?: boolean;
  /** Resolve shortened URLs */
  resolveShorteners?: boolean;
  /** Max shortener resolution depth */
  maxResolveDepth?: number;
  /** Enable OCR for images */
  useOcr?: boolean;
  /** Enable VirusTotal API (optional) */
  useVirusTotal?: boolean;
  /** VirusTotal API key */
  vtApiKey?: string;
  /** Timeout in ms */
  timeout?: number;
}

export interface HomoglyphMapping {
  [key: string]: string;
}

export interface BlocklistEntry {
  type: 'domain' | 'upi' | 'phone' | 'email';
  value: string;
  category: ThreatCategory;
  addedDate: string;
  source: string;
  confidence: number;
}

export interface TokenizerConfig {
  vocab: { [token: string]: number };
  maxLength: number;
  padToken: string;
  unkToken: string;
  clsToken: string;
  sepToken: string;
}

export interface IndicScamModelConfig {
  modelPath: string;
  tokenizerPath: string;
  threshold: number;
  labels: string[];
}
