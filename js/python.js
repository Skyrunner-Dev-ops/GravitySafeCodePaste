/**
 * Gravity Safe Code Paste — Python Language Sanitizer
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives } from './detector.js';

const PYTHON_RESERVED = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def', 'del',
  'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 'in',
  'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while',
  'with', 'yield', 'True', 'False', 'None', 'self', 'cls',
  // Common Builtins & Standard Libraries
  'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray', 'bytes', 'callable', 'chr',
  'classmethod', 'compile', 'complex', 'delattr', 'dict', 'dir', 'divmod', 'enumerate',
  'eval', 'exec', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr',
  'hash', 'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass', 'iter', 'len',
  'list', 'locals', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open',
  'ord', 'pow', 'print', 'property', 'range', 'repr', 'reversed', 'round', 'set', 'setattr',
  'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip',
  'os', 'sys', 'json', 're', 'math', 'time', 'datetime', 'logging', 'pathlib', 'typing',
  'List', 'Dict', 'Set', 'Optional', 'Union', 'Any', 'Tuple', 'Callable', 'Sequence',
  'dataclass', 'field', 'BaseModel', 'FastAPI', 'APIRouter', 'Depends', 'HTTPException',
  'Query', 'Path', 'Body', 'Header', 'Cookie', 'status', 'Request', 'Response', 'Session',
  'create_engine', 'sessionmaker', 'Base', 'Column', 'Integer', 'String', 'DateTime',
  'Boolean', 'ForeignKey', 'relationship', 'select', 'where', 'insert', 'update', 'delete'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // Additional Python-specific security detectors
  // os.getenv("SECRET_NAME") or os.environ.get("...") or os.environ["..."]
  const envVarRegex = /os\.(?:environ(?:\[|\.get\()|getenv\()\s*["']([A-Za-z0-9_.-]+)["']/g;
  let m;
  while ((m = envVarRegex.exec(sourceText)) !== null) {
    const envKey = m[1];
    if (/password|secret|key|token|auth|credential|conn/i.test(envKey)) {
      replacementMap.addSensitive(envKey, 'YOUR_ENV_SECRET_KEY', 'Environment Variable');
    }
  }

  // If Change Identifiers is enabled
  if (options && options.changeIdentifiers) {
    // 1. Classes: class EmployeeAttendance(BaseModel):
    const classRegex = /\bclass\s+([A-Za-z0-9_]+)\b/g;
    while ((m = classRegex.exec(sourceText)) !== null) {
      const className = m[1];
      if (!PYTHON_RESERVED.has(className)) {
        const hint = /Service$/i.test(className) ? 'service'
          : /Repository$/i.test(className) ? 'repository'
          : /Controller$/i.test(className) ? 'controller'
          : /Dto$/i.test(className) ? 'dto'
          : 'model';
        replacementMap.getOrAddIdentifier(className, 'Class', hint);
      }
    }

    // 2. Functions: def process_employee_attendance(...):
    const defRegex = /\b(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(/g;
    while ((m = defRegex.exec(sourceText)) !== null) {
      const funcName = m[1];
      if (!PYTHON_RESERVED.has(funcName) && !funcName.startsWith('__')) {
        replacementMap.getOrAddIdentifier(funcName, 'Function', 'method');
      }
    }

    // 3. Variable assignments: internal_user_id = ...
    const varAssignRegex = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]/gm;
    while ((m = varAssignRegex.exec(sourceText)) !== null) {
      const varName = m[1];
      if (!PYTHON_RESERVED.has(varName) && varName.length > 2 && !varName.startsWith('__')) {
        const hint = /id$/i.test(varName) ? 'column' : 'variable';
        replacementMap.getOrAddIdentifier(varName, 'Variable', hint);
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
