/**
 * Gravity Safe Code Paste — Other / Generic Language Sanitizer
 * Fallback sanitizer for mixed languages, Go, Rust, JS/TS, Ruby, PHP, Shell, etc.
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives } from './detector.js';

const GENERIC_COMMON_KEYWORDS = new Set([
  'function', 'class', 'const', 'let', 'var', 'if', 'else', 'for', 'while', 'do', 'switch',
  'case', 'default', 'break', 'continue', 'return', 'try', 'catch', 'finally', 'throw',
  'new', 'this', 'typeof', 'instanceof', 'void', 'delete', 'in', 'of', 'async', 'await',
  'yield', 'import', 'export', 'from', 'as', 'default', 'extends', 'implements', 'interface',
  'package', 'private', 'protected', 'public', 'static', 'readonly', 'type', 'enum', 'true',
  'false', 'null', 'undefined', 'console', 'log', 'error', 'warn', 'info', 'debug',
  'document', 'window', 'global', 'process', 'module', 'require', 'exports', 'string',
  'number', 'boolean', 'symbol', 'bigint', 'object', 'array', 'promise', 'map', 'set',
  'fn', 'pub', 'mut', 'impl', 'struct', 'trait', 'match', 'use', 'crate', 'mod',
  'def', 'end', 'begin', 'rescue', 'ensure', 'nil', 'echo', 'print', 'println', 'fmt'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // If Change Identifiers is enabled in "Other" mode
  if (options && options.changeIdentifiers) {
    // 1. Generic class/struct/interface/type declarations
    const typeRegex = /\b(?:class|struct|interface|type|enum)\s+([A-Za-z0-9_]+)/g;
    let m;
    while ((m = typeRegex.exec(sourceText)) !== null) {
      const typeName = m[1];
      if (!GENERIC_COMMON_KEYWORDS.has(typeName.toLowerCase()) && typeName.length > 2) {
        replacementMap.getOrAddIdentifier(typeName, 'Project Type', 'model');
      }
    }

    // 2. Generic function declarations
    const funcRegex = /\b(?:function|fn|def)\s+([A-Za-z0-9_]+)\s*\(/g;
    while ((m = funcRegex.exec(sourceText)) !== null) {
      const funcName = m[1];
      if (!GENERIC_COMMON_KEYWORDS.has(funcName.toLowerCase()) && funcName.length > 2) {
        replacementMap.getOrAddIdentifier(funcName, 'Function', 'method');
      }
    }

    // 3. Repeated PascalCase or camelCase project terms
    const tokenFreq = new Map();
    const tokenRegex = /\b([A-Z][a-zA-Z0-9]{3,}|[a-z]+[A-Z][a-zA-Z0-9]+)\b/g;
    while ((m = tokenRegex.exec(sourceText)) !== null) {
      const token = m[1];
      if (!GENERIC_COMMON_KEYWORDS.has(token.toLowerCase())) {
        tokenFreq.set(token, (tokenFreq.get(token) || 0) + 1);
      }
    }

    for (const [token, count] of tokenFreq.entries()) {
      if (count >= 2) {
        replacementMap.getOrAddIdentifier(token, 'Identifier', 'variable');
      }
    }
  }

  const sanitizedText = replacementMap.apply(sourceText);

  return {
    sanitizedText,
    mappings: replacementMap.getMappingsList(),
    items: detected.summaryItems
  };
}
