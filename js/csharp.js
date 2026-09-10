/**
 * Gravity Safe Code Paste — C# Language Sanitizer
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives } from './detector.js';

const CSHARP_RESERVED = new Set([
  'abstract', 'as', 'base', 'bool', 'break', 'byte', 'case', 'catch', 'char', 'checked',
  'class', 'const', 'continue', 'decimal', 'default', 'delegate', 'do', 'double', 'else',
  'enum', 'event', 'explicit', 'extern', 'false', 'finally', 'fixed', 'float', 'for',
  'foreach', 'goto', 'if', 'implicit', 'in', 'int', 'interface', 'internal', 'is', 'lock',
  'long', 'namespace', 'new', 'null', 'object', 'operator', 'out', 'override', 'params',
  'private', 'protected', 'public', 'readonly', 'ref', 'return', 'sbyte', 'sealed', 'short',
  'sizeof', 'stackalloc', 'static', 'string', 'struct', 'switch', 'this', 'throw', 'true',
  'try', 'typeof', 'uint', 'ulong', 'unchecked', 'unsafe', 'ushort', 'using', 'virtual',
  'void', 'volatile', 'while', 'add', 'alias', 'ascending', 'async', 'await', 'by', 'descending',
  'dynamic', 'equals', 'from', 'get', 'global', 'group', 'into', 'join', 'let', 'nameof',
  'on', 'orderby', 'partial', 'record', 'remove', 'select', 'set', 'value', 'var', 'when',
  'where', 'yield', 'required', 'init', 'scoped',
  // Common .NET Types / Libraries
  'System', 'Microsoft', 'AspNetCore', 'EntityFrameworkCore', 'IEnumerable', 'ICollection', 'IList',
  'List', 'Dictionary', 'IDictionary', 'HashSet', 'ISet', 'Task', 'ValueTask', 'DateTime',
  'DateTimeOffset', 'TimeSpan', 'Guid', 'Console', 'Math', 'Convert', 'Exception', 'ArgumentException',
  'InvalidOperationException', 'ControllerBase', 'Controller', 'DbContext', 'DbSet', 'IConfiguration',
  'ILogger', 'ActionResult', 'IActionResult', 'CancellationToken', 'IDisposable', 'IAsyncDisposable',
  'HttpClient', 'JsonSerializer', 'JsonPropertyName', 'Key', 'Required', 'Table', 'Column', 'ForeignKey'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // If Change Identifiers is enabled
  if (options && options.changeIdentifiers) {
    // 1. Namespaces (e.g. namespace MyCompany.ProjectManagement)
    const namespaceRegex = /\bnamespace\s+([a-zA-Z0-9_.]+)/g;
    let m;
    while ((m = namespaceRegex.exec(sourceText)) !== null) {
      const parts = m[1].split('.');
      for (const part of parts) {
        if (!CSHARP_RESERVED.has(part) && !/^(System|Microsoft|AspNetCore|Newtonsoft)$/i.test(part)) {
          replacementMap.getOrAddIdentifier(part, 'Project / Namespace', 'namespace');
        }
      }
    }

    // 2. Class, Interface, Record, Struct, Enum Declarations
    const typeDeclRegex = /\b(?:class|interface|record(?:\s+struct|\s+class)?|struct|enum)\s+([A-Za-z0-9_]+)/g;
    while ((m = typeDeclRegex.exec(sourceText)) !== null) {
      const typeName = m[1];
      if (!CSHARP_RESERVED.has(typeName)) {
        const hint = /Service$/i.test(typeName) ? 'service'
          : /Repository$/i.test(typeName) ? 'repository'
          : /Controller$/i.test(typeName) ? 'controller'
          : /Dto$/i.test(typeName) ? 'dto'
          : 'model';
        replacementMap.getOrAddIdentifier(typeName, 'Project Identifier', hint);
      }
    }

    // 3. Properties and Fields: public string AttendanceEmployeeId { get; set; }
    const propRegex = /\b(?:public|private|protected|internal)?\s+(?:readonly\s+)?(?:[A-Za-z0-9_<>\[\],\s?]+)\s+([A-Za-z0-9_]+)\s*\{\s*(?:get|set|init)/g;
    while ((m = propRegex.exec(sourceText)) !== null) {
      const propName = m[1];
      if (!CSHARP_RESERVED.has(propName) && propName.length > 2) {
        const hint = /id$/i.test(propName) ? 'column' : 'variable';
        replacementMap.getOrAddIdentifier(propName, 'Property', hint);
      }
    }

    // 4. Methods: public async Task<Response> ProcessPaymentAsync(...)
    const methodRegex = /\b(?:public|private|protected|internal|static|async|virtual|override|\s)+\s*(?:Task(?:<[A-Za-z0-9_,\s<>?]+>)?|void|[A-Za-z0-9_<>\[\],\s?]+)\s+([A-Za-z0-9_]+)\s*\(/g;
    while ((m = methodRegex.exec(sourceText)) !== null) {
      const methodName = m[1];
      if (!CSHARP_RESERVED.has(methodName) && !/^(Main|Dispose|ToString|Equals|GetHashCode|Configure|ConfigureServices)$/.test(methodName)) {
        replacementMap.getOrAddIdentifier(methodName, 'Method', 'method');
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
