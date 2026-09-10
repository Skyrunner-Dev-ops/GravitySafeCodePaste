/**
 * Gravity Safe Code Paste — Replacement Map Manager
 * Manages consistent mappings between original sensitive/identifier strings and safe replacements.
 * Preserves casing consistency across different casings of the same identifier.
 */

import { escapeRegex, detectCaseStyle, applyCaseStyle, splitIdentifier } from './sanitizer-utils.js';

export class ReplacementMap {
  constructor() {
    this.mappings = new Map(); // key: exact original string -> { replacement, category, isIdentifier }
    this.rootMappings = new Map(); // normalized root (lowercase) -> { baseWords, category }
    this.usedReplacements = new Set();
    this.counters = {
      service: 0,
      repository: 0,
      controller: 0,
      dto: 0,
      model: 0,
      table: 0,
      column: 0,
      database: 0,
      server: 0,
      identifier: 0,
      method: 0,
      variable: 0,
      general: 0
    };
  }

  /**
   * Register a sensitive value mapping (e.g. Password, Secret, Connection String).
   */
  addSensitive(original, replacement, category = 'Secret') {
    if (!original || typeof original !== 'string') return;
    original = original.trim();
    if (!original || original === replacement) return;

    if (!this.mappings.has(original)) {
      this.mappings.set(original, {
        original,
        replacement,
        category,
        isIdentifier: false
      });
      this.usedReplacements.add(replacement);
    }
  }

  /**
   * Register or look up an identifier replacement (preserving casing variations).
   */
  getOrAddIdentifier(original, category = 'Identifier', contextHint = '') {
    if (!original || typeof original !== 'string') return original;
    const trimmed = original.trim();
    if (!trimmed) return original;

    // Check if already mapped exactly
    if (this.mappings.has(trimmed)) {
      return this.mappings.get(trimmed).replacement;
    }

    // Check normalized case variants (e.g., employee_service vs EmployeeService)
    const words = splitIdentifier(trimmed);
    const normalizedKey = words.map(w => w.toLowerCase()).join('_');
    const caseStyle = detectCaseStyle(trimmed);

    let replacementWords;
    if (this.rootMappings.has(normalizedKey)) {
      replacementWords = this.rootMappings.get(normalizedKey).baseWords;
    } else {
      replacementWords = this._generateReplacementWords(words, category, contextHint);
      this.rootMappings.set(normalizedKey, { baseWords: replacementWords, category });
    }

    const replacement = applyCaseStyle(replacementWords, caseStyle) || replacementWords.join('');

    this.mappings.set(trimmed, {
      original: trimmed,
      replacement,
      category,
      isIdentifier: true
    });
    this.usedReplacements.add(replacement);

    return replacement;
  }

  _generateReplacementWords(originalWords, category, contextHint) {
    const origStr = originalWords.join('').toLowerCase();

    // Suffix / Role detection
    if (/service$/i.test(origStr) || contextHint === 'service') {
      this.counters.service++;
      const pool = ['App', 'Core', 'Data', 'Process', 'Entity', 'Business', 'Task'];
      const prefix = pool[(this.counters.service - 1) % pool.length];
      const count = this.counters.service > pool.length ? Math.ceil(this.counters.service / pool.length) : '';
      return [prefix, 'Service' + count];
    }
    if (/repository$/i.test(origStr) || /repo$/i.test(origStr) || contextHint === 'repository') {
      this.counters.repository++;
      const pool = ['Data', 'Entity', 'Record', 'Storage', 'App'];
      const prefix = pool[(this.counters.repository - 1) % pool.length];
      const count = this.counters.repository > pool.length ? Math.ceil(this.counters.repository / pool.length) : '';
      return [prefix, 'Repository' + count];
    }
    if (/controller$/i.test(origStr) || contextHint === 'controller') {
      this.counters.controller++;
      const pool = ['Resource', 'Endpoint', 'Api', 'App', 'Item'];
      const prefix = pool[(this.counters.controller - 1) % pool.length];
      const count = this.counters.controller > pool.length ? Math.ceil(this.counters.controller / pool.length) : '';
      return [prefix, 'Controller' + count];
    }
    if (/dto$/i.test(origStr) || /request$/i.test(origStr) || /response$/i.test(origStr) || contextHint === 'dto') {
      this.counters.dto++;
      const pool = ['Payload', 'Request', 'Response', 'Data', 'Record'];
      const prefix = pool[(this.counters.dto - 1) % pool.length];
      const count = this.counters.dto > pool.length ? Math.ceil(this.counters.dto / pool.length) : '';
      return [prefix, 'Dto' + count];
    }
    if (/table$/i.test(origStr) || category === 'Table') {
      this.counters.table++;
      const pool = [
        ['App', 'Records'],
        ['Entity', 'Data'],
        ['Custom', 'Items'],
        ['System', 'Entries'],
        ['Audit', 'Logs'],
        ['Resource', 'Entities']
      ];
      const pair = pool[(this.counters.table - 1) % pool.length];
      const count = this.counters.table > pool.length ? String(Math.ceil(this.counters.table / pool.length)) : '';
      return [pair[0], pair[1] + count];
    }
    if (/id$/i.test(origStr) || category === 'Column' || category === 'Field') {
      this.counters.column++;
      if (/id$/i.test(origStr)) {
        return ['Reference', 'Id' + (this.counters.column > 1 ? this.counters.column : '')];
      }
      const pool = [
        ['Custom', 'Field'],
        ['Attribute', 'Value'],
        ['Record', 'Property'],
        ['Item', 'Key'],
        ['Entry', 'Code']
      ];
      const pair = pool[(this.counters.column - 1) % pool.length];
      const count = this.counters.column > pool.length ? String(this.counters.column) : '';
      return [pair[0], pair[1] + count];
    }
    if (category === 'Database' || /database|db$/i.test(origStr)) {
      this.counters.database++;
      const pool = [
        ['App', 'Database'],
        ['Primary', 'Database'],
        ['Core', 'Store'],
        ['App', 'Catalog']
      ];
      const pair = pool[(this.counters.database - 1) % pool.length];
      const count = this.counters.database > pool.length ? String(this.counters.database) : '';
      return [pair[0], pair[1] + count];
    }
    if (category === 'Server' || /server|host$/i.test(origStr)) {
      this.counters.server++;
      return ['db', 'server', String(this.counters.server)];
    }
    if (category === 'Method' || category === 'Function') {
      this.counters.method++;
      const pool = [
        ['Execute', 'Action'],
        ['Process', 'Record'],
        ['Handle', 'Request'],
        ['Fetch', 'Data'],
        ['Calculate', 'Result']
      ];
      const pair = pool[(this.counters.method - 1) % pool.length];
      const count = this.counters.method > pool.length ? String(this.counters.method) : '';
      return [pair[0], pair[1] + count];
    }
    if (category === 'Variable' || category === 'Parameter') {
      this.counters.variable++;
      const pool = [
        ['Sample', 'Item'],
        ['Record', 'Data'],
        ['Entity', 'Ref'],
        ['Temp', 'Payload'],
        ['Current', 'Entry']
      ];
      const pair = pool[(this.counters.variable - 1) % pool.length];
      const count = this.counters.variable > pool.length ? String(this.counters.variable) : '';
      return [pair[0], pair[1] + count];
    }

    // General fallback identifier generator
    this.counters.general++;
    const nouns = [
      ['Sample', 'Model'],
      ['App', 'Entity'],
      ['Custom', 'Record'],
      ['Data', 'Entry'],
      ['Business', 'Item'],
      ['System', 'Component']
    ];
    const selected = nouns[(this.counters.general - 1) % nouns.length];
    const count = this.counters.general > nouns.length ? String(Math.ceil(this.counters.general / nouns.length)) : '';
    return [selected[0], selected[1] + count];
  }

  /**
   * Applies all recorded mappings to the source text.
   * Sorts mappings by length descending to prevent partial substring collisions.
   */
  apply(sourceText) {
    let result = sourceText || '';
    if (!result) return result;

    const sortedMappings = Array.from(this.mappings.values()).sort(
      (a, b) => b.original.length - a.original.length
    );

    for (const item of sortedMappings) {
      if (!item.original || item.original === item.replacement) continue;

      if (item.isIdentifier && /^[A-Za-z0-9_]+$/.test(item.original)) {
        // Use word boundary for identifiers
        const regex = new RegExp('\\b' + escapeRegex(item.original) + '\\b', 'g');
        result = result.replace(regex, item.replacement);
      } else {
        // Global literal replacement
        const regex = new RegExp(escapeRegex(item.original), 'g');
        result = result.replace(regex, item.replacement);
      }
    }

    return result;
  }

  /**
   * Returns list of mapped items for UI rendering.
   */
  getMappingsList() {
    return Array.from(this.mappings.values()).map(m => ({
      original: m.original,
      replacement: m.replacement,
      category: m.category
    }));
  }
}
