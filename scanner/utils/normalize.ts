/**
 * ScamGuard Pro - Text Normalization Utilities
 * Handles homoglyphs, zero-width characters, Devanagari tricks, and Unicode normalization
 * 2025 Gold Standard for Indian Scam Detection
 */

import type { HomoglyphMapping } from '../types';

// Comprehensive homoglyph mappings for Indian scam detection
export const HOMOGLYPH_MAP: HomoglyphMapping = {
  // Cyrillic → Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  
  // Greek → Latin
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
  'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
  'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
  
  // Mathematical/Fullwidth
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
  'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
  'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
  'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
  
  // Number lookalikes
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
  '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
  'Ｏ': 'O', 'ｌ': 'l', 'Ｉ': 'I',
  
  // Common substitutions used in scams
  '!': 'i', '|': 'l', '¡': 'i', '¦': 'l',
  '@': 'a', '$': 's', '€': 'e', '£': 'l',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  
  // Special lookalikes
  'ℓ': 'l', 'ℐ': 'I', 'ℑ': 'I', 'ℒ': 'L', 'ℳ': 'M', 'ℕ': 'N', 'ℙ': 'P',
  'ℚ': 'Q', 'ℛ': 'R', 'ℝ': 'R', 'ℤ': 'Z', 'ℨ': 'Z',
  
  // Additional lookalikes for Indian scam detection
  'ı': 'i', 'ȷ': 'j', 'ɑ': 'a', 'ɡ': 'g', 'ɪ': 'i', 'ɴ': 'n',
  'ʀ': 'r', 'ʏ': 'y', 'ᴀ': 'a', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e',
  'ᴊ': 'j', 'ᴋ': 'k', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p',
  'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ᴢ': 'z',
  
  // Unicode fractions that could be used to bypass
  '½': '1/2', '⅓': '1/3', '¼': '1/4', '⅔': '2/3', '¾': '3/4',
};

// Zero-width and invisible characters
const ZERO_WIDTH_CHARS = [
  '\u200B', // Zero Width Space
  '\u200C', // Zero Width Non-Joiner
  '\u200D', // Zero Width Joiner
  '\u200E', // Left-to-Right Mark
  '\u200F', // Right-to-Left Mark
  '\u2060', // Word Joiner
  '\u2061', // Function Application
  '\u2062', // Invisible Times
  '\u2063', // Invisible Separator
  '\u2064', // Invisible Plus
  '\uFEFF', // Zero Width No-Break Space (BOM)
  '\u00AD', // Soft Hyphen
  '\u034F', // Combining Grapheme Joiner
  '\u061C', // Arabic Letter Mark
  '\u115F', // Hangul Filler
  '\u1160', // Hangul Jungseong Filler
  '\u17B4', // Khmer Vowel Inherent AQ
  '\u17B5', // Khmer Vowel Inherent AA
  '\u180E', // Mongolian Vowel Separator
  '\u2800', // Braille Pattern Blank
  '\u3164', // Hangul Filler
  '\uFFA0', // Halfwidth Hangul Filler
];

// Devanagari confusables for Hindi scam detection
const DEVANAGARI_CONFUSABLES: { [key: string]: string } = {
  // Numbers that look like Devanagari or vice versa
  '०': '0', '१': '1', '२': '2', '३': '3', '४': '4',
  '५': '5', '६': '6', '७': '7', '८': '8', '९': '9',
  
  // Common Devanagari letter confusables used in scams
  'अ': 'a', 'ए': 'e', 'ओ': 'o',
};

// Brand names commonly impersonated in Indian scams
const BRAND_PATTERNS: { [key: string]: RegExp } = {
  'sbi': /s[^\w]*b[^\w]*i|st[a@]te[^\w]*b[a@]nk/gi,
  'hdfc': /h[^\w]*d[^\w]*f[^\w]*c/gi,
  'icici': /[i1l][^\w]*c[^\w]*[i1l][^\w]*c[^\w]*[i1l]/gi,
  'axis': /[a@]x[i1l]s/gi,
  'paytm': /p[a@]y[^\w]*t[^\w]*m/gi,
  'phonepe': /ph[o0]ne[^\w]*pe/gi,
  'gpay': /g[^\w]*p[a@]y|g[o0]{2}gle[^\w]*p[a@]y/gi,
  'bhim': /bh[i1l]m/gi,
  'upi': /up[i1l]/gi,
  'rbi': /r[^\w]*b[^\w]*[i1l]|reserve[^\w]*b[a@]nk/gi,
  'kyc': /k[^\w]*y[^\w]*c/gi,
  'aadhar': /[a@]{2}dh[a@]r|[a@]dh[a@]{2}r/gi,
  'pan': /p[a@]n[^\w]*c[a@]rd/gi,
  'indiapost': /[i1l]nd[i1l][a@][^\w]*p[o0]st/gi,
  'flipkart': /fl[i1l]pk[a@]rt/gi,
  'amazon': /[a@]m[a@]z[o0]n/gi,
  'myntra': /myntr[a@]/gi,
  'swiggy': /sw[i1l]ggy/gi,
  'zomato': /z[o0]m[a@]t[o0]/gi,
  'ola': /[o0]l[a@]/gi,
  'uber': /uber/gi,
  'rupay': /rup[a@]y/gi,
  'mastercard': /m[a@]sterc[a@]rd/gi,
  'visa': /v[i1l]s[a@]/gi,
};

/**
 * Remove all zero-width and invisible characters
 */
export function removeZeroWidthChars(text: string): string {
  const zeroWidthRegex = new RegExp(`[${ZERO_WIDTH_CHARS.join('')}]`, 'g');
  return text.replace(zeroWidthRegex, '');
}

/**
 * Replace homoglyphs with their ASCII equivalents
 */
export function replaceHomoglyphs(text: string): string {
  let result = '';
  for (const char of text) {
    result += HOMOGLYPH_MAP[char] || char;
  }
  return result;
}

/**
 * Normalize Devanagari confusables
 */
export function normalizeDevanagari(text: string): string {
  let result = '';
  for (const char of text) {
    result += DEVANAGARI_CONFUSABLES[char] || char;
  }
  return result;
}

/**
 * Normalize Unicode to NFC form
 */
export function normalizeUnicode(text: string): string {
  return text.normalize('NFC');
}

/**
 * Remove excessive whitespace and normalize spacing
 */
export function normalizeWhitespace(text: string): string {
  return text
    .replace(/[\t\r\n]+/g, ' ')  // Replace tabs and newlines with space
    .replace(/\s{2,}/g, ' ')      // Collapse multiple spaces
    .trim();
}

/**
 * Convert text to lowercase for comparison
 */
export function toLowerCaseNormalized(text: string): string {
  return text.toLowerCase();
}

/**
 * Detect if text contains homoglyph attacks
 */
export function detectHomoglyphAttack(text: string): {
  hasAttack: boolean;
  originalChars: string[];
  positions: number[];
} {
  const originalChars: string[] = [];
  const positions: number[] = [];
  
  for (let i = 0; i < text.length; i++) {
    if (HOMOGLYPH_MAP[text[i]]) {
      originalChars.push(text[i]);
      positions.push(i);
    }
  }
  
  return {
    hasAttack: originalChars.length > 0,
    originalChars,
    positions,
  };
}

/**
 * Detect impersonated brand names using pattern matching
 */
export function detectBrandImpersonation(text: string): {
  detected: boolean;
  brands: string[];
  patterns: string[];
} {
  const detectedBrands: string[] = [];
  const matchedPatterns: string[] = [];
  
  const normalizedText = normalizeText(text);
  
  for (const [brand, pattern] of Object.entries(BRAND_PATTERNS)) {
    const matches = normalizedText.match(pattern);
    if (matches) {
      detectedBrands.push(brand);
      matchedPatterns.push(...matches);
    }
  }
  
  return {
    detected: detectedBrands.length > 0,
    brands: [...new Set(detectedBrands)],
    patterns: [...new Set(matchedPatterns)],
  };
}

/**
 * Extract and normalize phone numbers (Indian format)
 */
export function extractPhoneNumbers(text: string): string[] {
  const phonePatterns = [
    /(?:\+91[\s-]?)?[6-9]\d{9}/g,  // Indian mobile
    /(?:\+91[\s-]?)?0?\d{2,4}[\s-]?\d{6,8}/g,  // Indian landline
    /1800[\s-]?\d{3}[\s-]?\d{4}/g,  // Toll-free
  ];
  
  const phones: string[] = [];
  for (const pattern of phonePatterns) {
    const matches = text.match(pattern);
    if (matches) {
      phones.push(...matches.map(p => p.replace(/[\s-]/g, '')));
    }
  }
  
  return [...new Set(phones)];
}

/**
 * Extract UPI IDs from text
 */
export function extractUpiIds(text: string): string[] {
  // UPI ID pattern: alphanumeric@provider
  const upiPattern = /[\w.-]+@[\w.-]+/gi;
  const matches = text.match(upiPattern) || [];
  
  // Filter valid UPI providers
  const validProviders = [
    'upi', 'ybl', 'paytm', 'phonepe', 'gpay', 'oksbi', 'okaxis', 'okicici',
    'okhdfcbank', 'apl', 'axl', 'ibl', 'sbi', 'axisbank', 'icici', 'hdfcbank',
    'kotak', 'indus', 'federal', 'rbl', 'yes', 'idbi', 'citi', 'boi', 'pnb',
    'bob', 'canara', 'union', 'indian', 'iob', 'central', 'dbs', 'hsbc',
    'sc', 'kvb', 'tmb', 'cub', 'csb', 'dcb', 'jkb', 'kbl', 'sib', 'equitas',
    'aubank', 'bandhan', 'idfc', 'freecharge', 'mobikwik', 'airtel', 'jio',
    'slice', 'cred', 'jupiter', 'fi', 'niyo', 'groww', 'uphold', 'nsdl',
    'wa', 'waicici', 'wahdfcbank', 'wasbi', 'waaxis', 'paytmqr',
  ];
  
  return matches.filter(upi => {
    const provider = upi.split('@')[1]?.toLowerCase();
    return provider && validProviders.some(vp => provider.includes(vp));
  });
}

/**
 * Extract URLs from text
 */
export function extractUrls(text: string): string[] {
  const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const matches = text.match(urlPattern) || [];
  
  // Also extract URLs without protocol
  const domainPattern = /(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:\/[^\s]*)?/gi;
  const domainMatches = text.match(domainPattern) || [];
  
  return [...new Set([...matches, ...domainMatches])];
}

/**
 * Calculate Shannon entropy of a string (for detecting random/suspicious tokens)
 */
export function calculateEntropy(text: string): number {
  if (!text || text.length === 0) return 0;
  
  const freq: { [char: string]: number } = {};
  for (const char of text) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = text.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Detect language (Hindi, English, Hinglish)
 */
export function detectLanguage(text: string): 'hindi' | 'english' | 'hinglish' | 'unknown' {
  // Devanagari unicode range
  const devanagariPattern = /[\u0900-\u097F]/g;
  const latinPattern = /[a-zA-Z]/g;
  
  const devanagariCount = (text.match(devanagariPattern) || []).length;
  const latinCount = (text.match(latinPattern) || []).length;
  const totalLetters = devanagariCount + latinCount;
  
  if (totalLetters === 0) return 'unknown';
  
  const devanagariRatio = devanagariCount / totalLetters;
  const latinRatio = latinCount / totalLetters;
  
  if (devanagariRatio > 0.7) return 'hindi';
  if (latinRatio > 0.9) return 'english';
  if (devanagariRatio > 0.1 && latinRatio > 0.1) return 'hinglish';
  
  return 'english';
}

/**
 * Full text normalization pipeline
 */
export function normalizeText(text: string): string {
  if (!text) return '';
  
  let normalized = text;
  
  // Step 1: Unicode normalization
  normalized = normalizeUnicode(normalized);
  
  // Step 2: Remove zero-width characters
  normalized = removeZeroWidthChars(normalized);
  
  // Step 3: Replace homoglyphs
  normalized = replaceHomoglyphs(normalized);
  
  // Step 4: Normalize Devanagari confusables
  normalized = normalizeDevanagari(normalized);
  
  // Step 5: Normalize whitespace
  normalized = normalizeWhitespace(normalized);
  
  return normalized;
}

/**
 * Normalize for comparison (adds lowercase)
 */
export function normalizeForComparison(text: string): string {
  return toLowerCaseNormalized(normalizeText(text));
}

export default {
  normalizeText,
  normalizeForComparison,
  removeZeroWidthChars,
  replaceHomoglyphs,
  normalizeDevanagari,
  normalizeUnicode,
  normalizeWhitespace,
  detectHomoglyphAttack,
  detectBrandImpersonation,
  extractPhoneNumbers,
  extractUpiIds,
  extractUrls,
  calculateEntropy,
  detectLanguage,
  HOMOGLYPH_MAP,
  BRAND_PATTERNS,
};
