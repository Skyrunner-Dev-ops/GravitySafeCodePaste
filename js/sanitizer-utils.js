/**
 * Gravity Safe Code Paste — Sanitizer Utilities
 * Provides generic helpers for string processing, case detection/transformation,
 * entropy calculation, and token safety.
 */

export function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

export function escapeRegex(str) {
  if (!str) return '';
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Calculates Shannon entropy of a string to detect high-entropy secrets/keys.
 */
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Detects the casing style of an identifier.
 */
export function detectCaseStyle(word) {
  if (!word || typeof word !== 'string') return 'unknown';
  if (/^[A-Z0-9_]+$/.test(word) && word.includes('_')) return 'UPPER_SNAKE_CASE';
  if (/^[a-z0-9_]+$/.test(word) && word.includes('_')) return 'lower_snake_case';
  if (/^[a-z0-9-]+$/.test(word) && word.includes('-')) return 'kebab-case';
  if (/^[A-Z0-9]+$/.test(word)) return 'ALL_CAPS';
  if (/^[A-Z][a-zA-Z0-9]*$/.test(word)) return 'PascalCase';
  if (/^[a-z][a-zA-Z0-9]*$/.test(word)) return 'camelCase';
  return 'unknown';
}

/**
 * Splits an identifier (camelCase, PascalCase, snake_case, etc.) into its constituent words.
 */
export function splitIdentifier(identifier) {
  if (!identifier) return [];
  if (Array.isArray(identifier)) {
    return identifier.flatMap(item => splitIdentifier(item));
  }
  return String(identifier)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[-_]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Transforms a target phrase (e.g. ["Sample", "Model"]) to match a specific casing style.
 */
export function applyCaseStyle(words, style) {
  const allWords = splitIdentifier(words);
  if (!allWords || allWords.length === 0) return '';

  const cleanWords = allWords.map(w => w.toLowerCase().replace(/[^a-z0-9]/gi, '')).filter(Boolean);
  if (cleanWords.length === 0) return '';

  const capitalized = cleanWords.map(w => w.charAt(0).toUpperCase() + w.slice(1));

  switch (style) {
    case 'UPPER_SNAKE_CASE':
      return cleanWords.map(w => w.toUpperCase()).join('_');
    case 'lower_snake_case':
      return cleanWords.join('_');
    case 'kebab-case':
      return cleanWords.join('-');
    case 'ALL_CAPS':
      return cleanWords.join('').toUpperCase();
    case 'PascalCase':
      return capitalized.join('');
    case 'camelCase':
      return cleanWords[0] + capitalized.slice(1).join('');
    default:
      return capitalized.join('');
  }
}

/**
 * Checks if a string looks like a standard base64/hex token with high entropy or length.
 */
export function isLikelySecretValue(val) {
  if (!val || typeof val !== 'string') return false;
  val = val.trim();
  if (val.length < 8) return false;
  if (/^(true|false|null|undefined|none|nil|default|localhost|127\.0\.0\.1|0\.0\.0\.0|test|sample|example)$/i.test(val)) return false;
  
  // UUID
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val)) return true;
  // JWT
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val)) return true;
  // Hex strings >= 32 chars
  if (/^[0-9a-f]{32,}$/i.test(val)) return true;
  // Base64 strings >= 24 chars
  if (/^(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(val) && calculateEntropy(val) > 3.0) return true;
  // Complex passwords >= 10 chars with decent entropy
  if (val.length >= 10 && calculateEntropy(val) >= 3.2 && /[A-Za-z]/.test(val) && /[0-9]/.test(val)) return true;

  return false;
}
