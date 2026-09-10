/**
 * Gravity Safe Code Paste — Configuration Sanitizer
 * Understands JSON, YAML, .env, INI, TOML, XML, and Java/Spring Properties files.
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives, SENSITIVE_KEY_REGEX } from './detector.js';

const STANDARD_CONFIG_KEYS = new Set([
  'version', 'services', 'image', 'ports', 'environment', 'volumes', 'restart', 'build',
  'name', 'apiVersion', 'kind', 'metadata', 'spec', 'template', 'containers', 'labels',
  'dependencies', 'devDependencies', 'scripts', 'main', 'author', 'license', 'repository',
  'logging', 'loglevel', 'default', 'profiles', 'active', 'include', 'exclude', 'enabled',
  'port', 'server', 'database', 'host', 'username', 'password', 'user', 'pwd', 'timeout',
  'connectionstrings', 'connectionstring', 'jwt', 'issuer', 'audience', 'secret', 'secretkey',
  'apikey', 'token', 'type', 'format', 'charset', 'encoding', 'ssl', 'tls', 'pool', 'max'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // 1. Line-by-line configuration parsing (Handles .env, properties, YAML, TOML, INI)
  const lines = sourceText.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';')) continue;

    // .env and properties style: KEY=VALUE or KEY: VALUE
    const kvMatch = trimmed.match(/^([A-Za-z0-9_.-]+)\s*[:=]\s*(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      let val = kvMatch[2].trim().replace(/^["']|["']$/g, '');

      // Check if key is sensitive or host/database
      if (SENSITIVE_KEY_REGEX.test(key)) {
        const repl = /pass|pwd/i.test(key) ? 'your-password' : /token|jwt/i.test(key) ? 'your-token' : 'your-secret-value';
        replacementMap.addSensitive(val, repl, 'Configuration Secret');
      } else if (/(?:db_host|db_server|database_host|datasource_url|server_url|base_url|api_url)/i.test(key)) {
        if (/^https?:\/\//i.test(val)) {
          replacementMap.addSensitive(val, 'https://api.example.com/v1', 'Configuration Endpoint');
        } else if (!/^(localhost|127\.0\.0\.1)$/i.test(val)) {
          replacementMap.addSensitive(val, 'your-server', 'Server name');
        }
      } else if (/(?:db_name|database_name|db_database)/i.test(key)) {
        replacementMap.addSensitive(val, 'AppDB', 'Database name');
      } else if (/(?:db_user|database_user|db_username)/i.test(key)) {
        replacementMap.addSensitive(val, 'appuser', 'Database username');
      }
    }

    // XML configuration style: <add key="Password" value="secret" /> or <property name="url" value="..." />
    const xmlMatch = trimmed.match(/<(?:add|property|setting|entry)\s+[^>]*(?:key|name)=["']([^"']+)["'][^>]*value=["']([^"']+)["']/i);
    if (xmlMatch) {
      const key = xmlMatch[1];
      const val = xmlMatch[2];
      if (SENSITIVE_KEY_REGEX.test(key)) {
        const repl = /pass|pwd/i.test(key) ? 'your-password' : 'your-secret-value';
        replacementMap.addSensitive(val, repl, 'XML Configuration Secret');
      } else if (/server|host|datasource/i.test(key)) {
        replacementMap.addSensitive(val, 'your-server', 'Server name');
      } else if (/database/i.test(key)) {
        replacementMap.addSensitive(val, 'AppDB', 'Database name');
      }
    }
  }

  // If Change Identifiers is enabled in Config
  if (options && options.changeIdentifiers) {
    // Detect custom application-level section headers in INI / TOML: [my_custom_service]
    const sectionRegex = /^\[([A-Za-z0-9_.-]+)\]/gm;
    let m;
    while ((m = sectionRegex.exec(sourceText)) !== null) {
      const sec = m[1];
      if (!STANDARD_CONFIG_KEYS.has(sec.toLowerCase())) {
        replacementMap.getOrAddIdentifier(sec, 'Config Section', 'model');
      }
    }

    // Detect internal service/project names inside JSON/YAML keys that are clearly domain-specific
    const jsonKeyRegex = /"([A-Za-z0-9_-]+)"\s*:\s*\{/g;
    while ((m = jsonKeyRegex.exec(sourceText)) !== null) {
      const key = m[1];
      if (!STANDARD_CONFIG_KEYS.has(key.toLowerCase()) && !/^(ConnectionStrings|Logging|AllowedHosts|Jwt|ApiSettings)$/i.test(key)) {
        replacementMap.getOrAddIdentifier(key, 'Config Key', 'model');
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
