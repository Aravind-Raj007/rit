/**
 * ScamGuard Pro - Detection Engine
 * Main entry point for the 2025 detection engine
 */

export * from './types';
export * from './core/engine';
export * from './utils/normalize';

// Re-export main functions and classes
export {
  ScamDetectionEngine,
  getEngine,
  scan,
  scanText,
  scanUrl,
} from './core/engine';

export {
  normalizeText,
  normalizeForComparison,
  detectHomoglyphAttack,
  detectBrandImpersonation,
  extractUrls,
  extractUpiIds,
  extractPhoneNumbers,
  calculateEntropy,
  detectLanguage,
} from './utils/normalize';

// Version
export const VERSION = '2025.1.0';
