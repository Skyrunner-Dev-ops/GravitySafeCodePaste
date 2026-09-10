/**
 * Gravity Safe Code Paste — Java Language Sanitizer
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives } from './detector.js';

const JAVA_RESERVED = new Set([
  'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class', 'const',
  'continue', 'default', 'do', 'double', 'else', 'enum', 'extends', 'final', 'finally', 'float',
  'for', 'goto', 'if', 'implements', 'import', 'instanceof', 'int', 'interface', 'long', 'native',
  'new', 'package', 'private', 'protected', 'public', 'return', 'short', 'static', 'strictfp',
  'super', 'switch', 'synchronized', 'this', 'throw', 'throws', 'transient', 'try', 'void',
  'volatile', 'while', 'true', 'false', 'null', 'var', 'record', 'yield', 'sealed', 'non-sealed', 'permits',
  // Common Java Types / Frameworks
  'String', 'Object', 'Integer', 'Long', 'Boolean', 'Double', 'Float', 'Byte', 'Short', 'Character',
  'List', 'ArrayList', 'Map', 'HashMap', 'Set', 'HashSet', 'Optional', 'Collection', 'Arrays', 'Collections',
  'System', 'Math', 'StringBuilder', 'StringBuffer', 'Exception', 'RuntimeException', 'Throwable',
  'Override', 'Autowired', 'Component', 'Service', 'Repository', 'Controller', 'RestController',
  'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'RequestBody', 'RequestParam',
  'PathVariable', 'ResponseEntity', 'HttpStatus', 'Logger', 'LoggerFactory', 'Slf4j', 'Value',
  'NonNull', 'Nullable', 'PostConstruct', 'PreDestroy', 'Bean', 'Configuration'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // Additional Java specific detectors (e.g. JDBC connection strings)
  const jdbcRegex = /jdbc:(?:mysql|postgresql|oracle:thin|sqlserver|h2|mariadb):(?:\/\/)?([^:\s/;?]+)(?::(\d+))?[/;](?:databaseName=)?([a-zA-Z0-9_.-]+)/gi;
  let m;
  while ((m = jdbcRegex.exec(sourceText)) !== null) {
    const host = m[1];
    const db = m[3];
    if (host && !/^(localhost|127\.0\.0\.1)$/i.test(host)) {
      replacementMap.addSensitive(host, 'db-host.internal', 'Server name');
    }
    if (db) {
      replacementMap.addSensitive(db, 'AppDB', 'Database name');
    }
  }

  // If Change Identifiers is enabled
  if (options && options.changeIdentifiers) {
    // 1. Packages
    const packageRegex = /\bpackage\s+([a-zA-Z0-9_.]+);/g;
    while ((m = packageRegex.exec(sourceText)) !== null) {
      const parts = m[1].split('.');
      for (const part of parts) {
        if (!/^(com|org|net|io|java|javax|springframework|apache)$/i.test(part) && !JAVA_RESERVED.has(part)) {
          replacementMap.getOrAddIdentifier(part, 'Project / Package', 'package');
        }
      }
    }

    // 2. Class, Interface, Record, Enum Declarations
    const typeDeclRegex = /\b(?:class|interface|record|enum)\s+([A-Za-z0-9_]+)/g;
    while ((m = typeDeclRegex.exec(sourceText)) !== null) {
      const typeName = m[1];
      if (!JAVA_RESERVED.has(typeName)) {
        const hint = /Service$/i.test(typeName) ? 'service'
          : /Repository$/i.test(typeName) ? 'repository'
          : /Controller$/i.test(typeName) ? 'controller'
          : /Dto$/i.test(typeName) ? 'dto'
          : 'model';
        replacementMap.getOrAddIdentifier(typeName, 'Project Identifier', hint);
      }
    }

    // 3. Custom Annotations & Fields
    const fieldDeclRegex = /\b(?:private|protected|public)?\s+(?:final\s+)?(?:[A-Za-z0-9_<>\[\],\s]+)\s+([a-zA-Z0-9_]+)\s*(?:=|;)/g;
    while ((m = fieldDeclRegex.exec(sourceText)) !== null) {
      const fieldName = m[1];
      if (!JAVA_RESERVED.has(fieldName) && fieldName.length > 2) {
        replacementMap.getOrAddIdentifier(fieldName, 'Identifier', 'variable');
      }
    }

    // 4. Method Declarations
    const methodDeclRegex = /\b(?:public|protected|private|static|final|synchronized|\s)+\s*(?:<[A-Za-z0-9_,\s<>]+>\s+)?(?:[A-Za-z0-9_<>\[\]]+)\s+([a-zA-Z0-9_]+)\s*\(/g;
    while ((m = methodDeclRegex.exec(sourceText)) !== null) {
      const methodName = m[1];
      if (!JAVA_RESERVED.has(methodName) && !/^(main|run|get[A-Z]|set[A-Z]|is[A-Z]|toString|equals|hashCode|builder|build)$/.test(methodName)) {
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
