/**
 * Gravity Safe Code Paste — Security Detector Engine
 * Generic pattern-based security detectors with zero hardcoded domain or company names.
 */

import { escapeRegex, isLikelySecretValue } from './sanitizer-utils.js';

export const SENSITIVE_KEY_REGEX = /(?:password|passwd|pwd|pass|secret|secret_?key|api_?key|access_?token|access_?key|refresh_?token|client_?secret|private_?key|auth_?token|credential|credentials|bearer_?token|session_?token|auth_?header|sas_?token|connection_?string|db_?pass|database_?password|smtp_?password)/i;

/**
 * Runs the full suite of security detectors on source code.
 * Fills the replacementMap with detected sensitive items.
 * Returns structured summary of detected items.
 */
export function detectSecuritySensitives(sourceText, replacementMap) {
  if (!sourceText) {
    return {
      tokens: [],
      connectionStrings: [],
      paths: [],
      urls: [],
      pii: [],
      summaryItems: []
    };
  }

  const detected = {
    tokens: [],
    connectionStrings: [],
    paths: [],
    urls: [],
    pii: [],
    keys: []
  };

  // 1. Specific Token Formats & Cloud Credentials
  detectKnownTokens(sourceText, replacementMap, detected);

  // 2. PEM / Private Key Blocks
  detectPrivateKeys(sourceText, replacementMap, detected);

  // 3. Structured Key-Value Connection Strings (ADO.NET, OLEDB, ODBC, etc.)
  detectKeyValueConnectionStrings(sourceText, replacementMap, detected);

  // 4. URI-style Connection Strings (postgresql://..., mongodb://..., etc.)
  detectUriConnectionStrings(sourceText, replacementMap, detected);

  // 5. Sensitive Key-Value Assignments in Code & Config
  detectSensitiveAssignments(sourceText, replacementMap, detected);

  // 6. Filesystem Paths with user/system folders
  detectSensitivePaths(sourceText, replacementMap, detected);

  // 7. Internal / Private URLs and Endpoints with credentials or internal hostnames
  detectSensitiveUrls(sourceText, replacementMap, detected);

  // 8. PII (Emails, Private Network IPs)
  detectPII(sourceText, replacementMap, detected);

  // Compile summary items for UI display
  const summaryItems = [
    { title: 'Sensitive Keys / Tokens', value: detected.tokens.length ? `${detected.tokens.length} found (${detected.tokens[0]})` : null, icon: 'key' },
    { title: 'Connection / Database', value: detected.connectionStrings.length ? `${detected.connectionStrings.length} found` : null, icon: 'database' },
    { title: 'File Paths', value: detected.paths.length ? `${detected.paths.length} found (${detected.paths[0]})` : null, icon: 'folder' },
    { title: 'URLs / Endpoints', value: detected.urls.length ? `${detected.urls.length} found` : null, icon: 'globe' },
    { title: 'PII / Network IPs', value: detected.pii.length ? `${detected.pii.length} found` : null, icon: 'user' }
  ];

  return { ...detected, summaryItems };
}

function detectKnownTokens(source, map, detected) {
  const tokenPatterns = [
    { regex: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, repl: 'your-aws-access-key', cat: 'Cloud Credential' },
    { regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g, repl: 'your-github-token', cat: 'API Token' },
    { regex: /\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b/g, repl: 'your-github-token', cat: 'API Token' },
    { regex: /\b(?:sk_live_|sk_test_|rk_live_|rk_test_)[A-Za-z0-9]{20,}\b/g, repl: 'your-api-key', cat: 'API / Secret Key' },
    { regex: /\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}\b/g, repl: 'your-slack-token', cat: 'API Token' },
    { regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, repl: 'your-google-api-key', cat: 'API Key' },
    { regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, repl: 'your-jwt-token', cat: 'JWT Token' },
    { regex: /(?:Bearer\s+|bearer\s+)([A-Za-z0-9_.\-~+/=]{20,})/g, group: 1, repl: 'your-bearer-token', cat: 'Bearer Token' }
  ];

  for (const { regex, repl, cat, group } of tokenPatterns) {
    let m;
    regex.lastIndex = 0;
    while ((m = regex.exec(source)) !== null) {
      const matchVal = group ? m[group] : m[0];
      if (matchVal && matchVal.length > 5) {
        detected.tokens.push(matchVal);
        map.addSensitive(matchVal, repl, cat);
      }
    }
  }
}

function detectPrivateKeys(source, map, detected) {
  const pemRegex = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;
  let m;
  while ((m = pemRegex.exec(source)) !== null) {
    detected.tokens.push('PRIVATE KEY BLOCK');
    map.addSensitive(m[0], '-----BEGIN PRIVATE KEY-----\n<REDACTED_PRIVATE_KEY_MATERIAL>\n-----END PRIVATE KEY-----', 'Private Key');
  }
}

function detectKeyValueConnectionStrings(source, map, detected) {
  // Matches SQL Server, MySQL, Oracle, etc. connection string patterns
  const connStrRegex = /(?:["'`])([^"'`\r\n]*?(?:Server|Data Source|DataSource|Addr|Address|Host)\s*=[^"'`\r\n]*?(?:Database|Initial Catalog|InitialCatalog|DB)\s*=[^"'`\r\n]*?)(?:["'`])/gi;
  let m;
  while ((m = connStrRegex.exec(source)) !== null) {
    const fullConn = m[1];
    detected.connectionStrings.push(fullConn);

    // Sanitize individual components inside the connection string
    const serverMatch = fullConn.match(/(?:Server|Data Source|DataSource|Addr|Address|Host)\s*=\s*([^;]+)/i);
    const dbMatch = fullConn.match(/(?:Database|Initial Catalog|InitialCatalog|DB)\s*=\s*([^;]+)/i);
    const userMatch = fullConn.match(/(?:User ID|UID|User|Username)\s*=\s*([^;]+)/i);
    const passMatch = fullConn.match(/(?:Password|Pwd)\s*=\s*([^;]+)/i);

    if (serverMatch && serverMatch[1].trim()) {
      map.addSensitive(serverMatch[1].trim(), 'your-server', 'Server name');
    }
    if (dbMatch && dbMatch[1].trim()) {
      map.addSensitive(dbMatch[1].trim(), 'AppDB', 'Database name');
    }
    if (userMatch && userMatch[1].trim()) {
      map.addSensitive(userMatch[1].trim(), 'appuser', 'Database username');
    }
    if (passMatch && passMatch[1].trim()) {
      map.addSensitive(passMatch[1].trim(), 'your-password', 'Password');
    }
  }

  // Also standalone key=value items if found in scripts
  const singleConnPart = /\b(Server|Data Source|DataSource|Database|Initial Catalog|InitialCatalog|User ID|UID|Password|Pwd)\s*=\s*([^;\r\n,"'\}]+)/gi;
  while ((m = singleConnPart.exec(source)) !== null) {
    const k = m[1].toLowerCase();
    const v = m[2].trim();
    if (!v || /^(true|false|null|undefined|sample|example|localhost|127\.0\.0\.1)$/i.test(v)) continue;

    if (/server|data source|datasource/.test(k)) {
      map.addSensitive(v, 'your-server', 'Server name');
    } else if (/database|initial catalog/.test(k)) {
      map.addSensitive(v, 'AppDB', 'Database name');
    } else if (/user id|uid/.test(k)) {
      map.addSensitive(v, 'appuser', 'Database username');
    } else if (/password|pwd/.test(k)) {
      map.addSensitive(v, 'your-password', 'Password');
    }
  }
}

function detectUriConnectionStrings(source, map, detected) {
  const uriRegex = /\b((?:postgresql|postgres|mysql|mariadb|oracle|mssql|mongodb|mongodb\+srv|redis|amqp|jdbc:[a-z0-9_]+):\/\/)(?:([^:\s/@"']+)(?::([^@\s/"']+))?@)?([^:/\s"']+)(?::(\d+))?\/([^?\s"'`]+)/gi;
  let m;
  while ((m = uriRegex.exec(source)) !== null) {
    const [full, proto, user, pass, host, port, db] = m;
    detected.connectionStrings.push(full);

    if (user) map.addSensitive(user, 'dbuser', 'Database username');
    if (pass) map.addSensitive(pass, 'your-password', 'Password');
    if (host && !/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(host)) {
      map.addSensitive(host, 'db-host.internal', 'Server name');
    }
    if (db) map.addSensitive(db, 'app_db', 'Database name');
  }
}

function detectSensitiveAssignments(source, map, detected) {
  // Regex for assignments in code: const password = "...", apiKey: "...", "secret": "...", dbPass = "..."
  const assignRegex = /(?:["'`]?([A-Za-z0-9_.-]*(?:password|passwd|pwd|pass|secret|apiKey|api_key|token|accessToken|refreshToken|clientSecret|privateKey|credential|auth)[A-Za-z0-9_.-]*)["'`]?\s*(?:[:=]|=>)\s*)(["'`])([^"'`\r\n]{3,})\2/gi;
  let m;
  while ((m = assignRegex.exec(source)) !== null) {
    const keyName = m[1];
    const val = m[3].trim();
    if (!val || /^(true|false|null|undefined|none|nil|test|placeholder|your-|sample|example)/i.test(val)) continue;

    const cat = /password|pwd|passwd|pass/i.test(keyName) ? 'Password' 
      : /token/i.test(keyName) ? 'Token'
      : /key/i.test(keyName) ? 'API Key'
      : 'Secret';
    
    const repl = /password|pwd|passwd|pass/i.test(keyName) ? 'your-password' 
      : /token/i.test(keyName) ? 'your-token'
      : /key/i.test(keyName) ? 'your-api-key'
      : 'your-secret-value';

    detected.tokens.push(val);
    map.addSensitive(val, repl, cat);
  }
}

function detectSensitivePaths(source, map, detected) {
  // Windows user paths: C:\Users\Username\... or C:\\Users\\Username\\...
  const winPathRegex = /(?:["'`])([A-Za-z]:(?:\\\\|\\)(?:Users|Documents and Settings)(?:\\\\|\\)([^\\"'`\r\n]+)(?:\\\\|\\)[^"'`\r\n]*)(?:["'`])/gi;
  let m;
  while ((m = winPathRegex.exec(source)) !== null) {
    const fullPath = m[1];
    const user = m[2];
    detected.paths.push(fullPath);
    map.addSensitive(fullPath, 'C:\\path\\to\\file.ext', 'File Path');
    if (user && user.length > 2 && !/^(Public|Default|All Users)$/i.test(user)) {
      map.addSensitive(user, 'Developer', 'Username / Path');
    }
  }

  // Unix user paths: /home/username/... or /Users/username/...
  const unixPathRegex = /(?:["'`])(\/(?:home|Users)\/([^/\s"'`\r\n]+)\/[^"'`\r\n]*)(?:["'`])/gi;
  while ((m = unixPathRegex.exec(source)) !== null) {
    const fullPath = m[1];
    const user = m[2];
    detected.paths.push(fullPath);
    map.addSensitive(fullPath, '/path/to/data/file.ext', 'File Path');
    if (user && user.length > 2 && !/^(root|default|guest)$/i.test(user)) {
      map.addSensitive(user, 'appuser', 'Username / Path');
    }
  }
}

function detectSensitiveUrls(source, map, detected) {
  // URLs containing inline basic auth (https://user:pass@host)
  const authUrlRegex = /https?:\/\/([^:\s/@"']+):([^@\s/"']+)@([^\s"'`<>]+)/gi;
  let m;
  while ((m = authUrlRegex.exec(source)) !== null) {
    const [full, user, pass, rest] = m;
    detected.urls.push(full);
    map.addSensitive(user, 'apiuser', 'Username');
    map.addSensitive(pass, 'your-password', 'Password');
  }

  // Internal/Corporate URLs (.local, .internal, .corp, .lan, etc.)
  const internalUrlRegex = /https?:\/\/[A-Za-z0-9_.-]+\.(?:local|internal|corp|lan|private|intranet)(?::\d+)?(?:\/[^\s"'`<>]*)?/gi;
  while ((m = internalUrlRegex.exec(source)) !== null) {
    detected.urls.push(m[0]);
    map.addSensitive(m[0], 'https://api.example.com/v1', 'Internal URL');
  }

  // General internal endpoints in string literals
  const genericInternalUrlRegex = /(?:["'`])(https?:\/\/(?:internal-[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+-internal)[^\s"'`]*)(?:["'`])/gi;
  while ((m = genericInternalUrlRegex.exec(source)) !== null) {
    detected.urls.push(m[1]);
    map.addSensitive(m[1], 'https://api.example.com/v1', 'Internal URL');
  }
}

function detectPII(source, map, detected) {
  // Email addresses (skip standard example.com/domain.com domains if already generic)
  const emailRegex = /\b[A-Za-z0-9._%+-]+@(?!example\.com|sample\.org|domain\.com|test\.com|localhost)([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/gi;
  let m;
  while ((m = emailRegex.exec(source)) !== null) {
    const email = m[0];
    detected.pii.push(email);
    map.addSensitive(email, 'user@example.com', 'PII (Email)');
  }

  // Private IPv4 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
  const privateIpRegex = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
  while ((m = privateIpRegex.exec(source)) !== null) {
    const ip = m[0];
    detected.pii.push(ip);
    map.addSensitive(ip, '10.0.0.1', 'Internal IP');
  }
}
