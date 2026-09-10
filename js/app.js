/**
 * Gravity Safe Code Paste — Main Application Coordinator
 */

import * as javaSanitizer from './java.js';
import * as csharpSanitizer from './csharp.js';
import * as pythonSanitizer from './python.js';
import * as configSanitizer from './config.js';
import * as otherSanitizer from './other.js';
import * as sqlSanitizer from './sql.js';
import { escapeHtml } from './sanitizer-utils.js';

const SANITIZERS = {
  java: javaSanitizer,
  csharp: csharpSanitizer,
  python: pythonSanitizer,
  config: configSanitizer,
  other: otherSanitizer,
  sql: sqlSanitizer
};

const EXAMPLES = {
  java: `package com.mycompany.projectmanagement.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

@Service
public class EmployeeAttendanceService {
    @Value("\${app.security.jwt-secret}")
    private String jwtSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotShareThisSecretKey";

    private final String dbUrl = "jdbc:postgresql://db-cluster.internal:5432/ProductionHRDB";
    private final String dbUser = "db_admin";
    private final String dbPass = "P@ssw0rd2026!Sec";

    public AttendanceResponseDto processEmployeeRecord(AttendanceRecordDto recordDto) {
        String apiKey = "sk_live_51M0abcdef1234567890XYZ";
        String logPath = "C:\\\\Users\\\\Developer\\\\Documents\\\\attendance.log";
        String endpoint = "https://internal-hr.corp.local/api/v1/sync";
        
        return new AttendanceResponseDto(true, recordDto.getEmployeeId());
    }
}`,

  csharp: `using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace MyCompany.ProjectManagement.Controllers
{
    public class UserPaymentDto
    {
        public string AwsSecretKey { get; set; } = "AKIAIOSFODNN7EXAMPLE";
        public string FilePath { get; set; } = "C:\\\\Users\\\\Developer\\\\Documents\\\\finance.xlsx";
        public string AttendanceEmployeeId { get; set; }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class PaymentServiceController : ControllerBase
    {
        private const string ConnectionString = 
            "Server=prod-db.internal;Database=FinanceDB;User Id=sa;Password=SuperSecretPassword123!;Connect Timeout=30;";

        [HttpPost("process")]
        public async Task<IActionResult> ProcessPaymentAsync([FromBody] UserPaymentDto paymentDto)
        {
            var clientSecret = "sk_live_51M0abcdef1234567890XYZ";
            var internalApi = "https://internal-payments.corp.local/v1/charge";
            return Ok(new { Status = "Success" });
        }
    }
}`,

  python: `import os
from typing import Optional
from pydantic import BaseModel

DATABASE_URL = "postgresql://cluster_admin:SuperSecretPass2026@prod-sql.internal:5432/EmployeeRecordsDB"
API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
SECRET_KEY = os.getenv("JWT_SIGNING_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload.sig")

class EmployeeAttendanceModel(BaseModel):
    employee_id: str
    attendance_record_id: int
    log_file_path: str = "/home/developer/app/logs/audit.log"
    internal_endpoint: str = "https://internal-auth.corp.local/v2/tokens"

def process_attendance_record(record: EmployeeAttendanceModel) -> bool:
    api_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload.signature"
    return True
`,

  config: `{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=testdb,1983;Database=ProjectManagement;User ID=devteam;Password=devteam;Connect Timeout=30;MultipleActiveResultSets=true;TrustServerCertificate=true;"
  },
  "Jwt": {
    "SecretKey": "my-super-secret-jwt-signing-key-12345",
    "Issuer": "https://auth.internal.corp.local",
    "TokenLifetimeMinutes": 60
  },
  "ApiSettings": {
    "ApiKey": "AIzaSyD-1234567890abcdefghijklmnopqrstuvw",
    "BaseUrl": "https://internal-api.corp.local/v1"
  },
  "Storage": {
    "LocalPath": "C:\\\\Users\\\\Administrator\\\\Data\\\\appsettings.json"
  }
}`,

  sql: `ALTER TABLE dbo.EmployeeRecords 
ADD AttendanceEmployeeId INT NOT NULL DEFAULT(0);

CREATE TABLE dbo.EmployeeAttendance (
    EmployeeAttendanceId INT PRIMARY KEY IDENTITY(1,1),
    UserId NVARCHAR(450) NOT NULL,
    LogDate DATE NOT NULL,
    StartTime DATETIME NULL,
    EndTime DATETIME NULL,
    SyncDateTime DATETIME NOT NULL DEFAULT GETDATE()
);

-- Insert demo attendance entry
INSERT INTO dbo.EmployeeAttendance (UserId, LogDate, StartTime, EndTime)
VALUES ('USR-9921', '2026-09-10', '09:00:00', '17:30:00');

SELECT * FROM dbo.EmployeeAttendance WHERE UserId = 'USR-9921';`,

  other: `// Generic Mixed Environment Script
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_SECRET = "sk_live_51M0abcdef1234567890XYZ";
const INTERNAL_SERVICE_URL = "https://internal-gateway.corp.local/v1/dispatch";
const LOG_FILE = "/var/log/mycompany/service_audit.log";

class TransactionProcessor {
    constructor(authToken) {
        this.authToken = authToken || "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload.sig";
        this.connectionUri = "mongodb+srv://app_user:MongoPass123!@cluster0.internal.mongodb.net/TransactionStore";
    }

    executeDispatch(payload) {
        console.log("Dispatching transaction to", INTERNAL_SERVICE_URL);
    }
}`
};

const FILE_EXTENSIONS = {
  java: 'java',
  csharp: 'cs',
  python: 'py',
  config: 'json',
  sql: 'sql',
  other: 'txt'
};

let currentLanguage = 'java';
let changeIdentifiers = false;
let currentMappings = [];

export function initApp() {
  // Bind Language Tabs
  const tabButtons = document.querySelectorAll('[data-lang-tab]');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const lang = btn.getAttribute('data-lang-tab');
      setLanguage(lang);
    });
  });

  // Bind Change Identifiers Checkbox
  const idCheckbox = document.getElementById('changeIdentifiersCheckbox');
  if (idCheckbox) {
    idCheckbox.checked = changeIdentifiers;
    idCheckbox.addEventListener('change', (e) => {
      changeIdentifiers = e.target.checked;
      runSanitize();
    });
  }

  // Bind Buttons
  document.getElementById('sanitizeBtn')?.addEventListener('click', runSanitize);
  document.getElementById('loadExampleBtn')?.addEventListener('click', loadExample);
  document.getElementById('clearBtn')?.addEventListener('click', clearAll);
  document.getElementById('copyBtn')?.addEventListener('click', copyOutput);
  document.getElementById('downloadBtn')?.addEventListener('click', downloadOutput);

  // Input stats watcher
  const inputEl = document.getElementById('input');
  inputEl?.addEventListener('input', updateInputStats);

  // Set initial state
  setLanguage('csharp');
  loadExample();
}

function setLanguage(lang) {
  if (!SANITIZERS[lang]) return;
  currentLanguage = lang;

  // Update tab UI styles
  const tabButtons = document.querySelectorAll('[data-lang-tab]');
  tabButtons.forEach(btn => {
    const isCurrent = btn.getAttribute('data-lang-tab') === lang;
    if (isCurrent) {
      btn.className = 'lang-tab px-3.5 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white shadow-sm transition-all';
    } else {
      btn.className = 'lang-tab px-3.5 py-1.5 rounded-lg text-xs font-bold text-slate-600 hover:text-slate-900 hover:bg-slate-200/70 transition-all';
    }
  });

  // Update language badge
  const langBadge = document.getElementById('currentLangBadge');
  if (langBadge) {
    const labels = {
      java: 'Java',
      csharp: 'C#',
      python: 'Python',
      config: 'Config',
      other: 'Other',
      sql: 'SQL'
    };
    langBadge.textContent = labels[lang] || lang;
  }
}

export function loadExample() {
  const inputEl = document.getElementById('input');
  if (inputEl) {
    inputEl.value = EXAMPLES[currentLanguage] || '';
    updateInputStats();
    runSanitize();
  }
}

export function clearAll() {
  const inputEl = document.getElementById('input');
  const outputEl = document.getElementById('output');
  if (inputEl) inputEl.value = '';
  if (outputEl) outputEl.value = '';
  currentMappings = [];
  updateInputStats();
  drawMaps([]);
  drawItems([]);
}

export function runSanitize() {
  const inputEl = document.getElementById('input');
  const outputEl = document.getElementById('output');
  if (!inputEl || !outputEl) return;

  const sourceText = inputEl.value || '';
  updateInputStats();

  if (!sourceText.trim()) {
    outputEl.value = '';
    currentMappings = [];
    drawMaps([]);
    drawItems([]);
    return;
  }

  const sanitizer = SANITIZERS[currentLanguage] || SANITIZERS.other;
  const result = sanitizer.sanitize(sourceText, { changeIdentifiers });

  outputEl.value = result.sanitizedText;
  currentMappings = result.mappings || [];
  drawMaps(currentMappings);
  drawItems(result.items || []);
}

export function copyOutput() {
  const outputEl = document.getElementById('output');
  const copyBtn = document.getElementById('copyBtn');
  if (!outputEl || !outputEl.value) return;

  navigator.clipboard?.writeText(outputEl.value).then(() => {
    if (copyBtn) {
      const origText = copyBtn.innerHTML;
      copyBtn.innerHTML = '✓ Copied!';
      copyBtn.classList.add('text-emerald-600');
      setTimeout(() => {
        copyBtn.innerHTML = origText;
        copyBtn.classList.remove('text-emerald-600');
      }, 2000);
    }
  });
}

export function downloadOutput() {
  const outputEl = document.getElementById('output');
  if (!outputEl || !outputEl.value) return;

  const ext = FILE_EXTENSIONS[currentLanguage] || 'txt';
  const filename = `sanitized-code.${ext}`;
  const blob = new Blob([outputEl.value], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function updateInputStats() {
  const inputEl = document.getElementById('input');
  const statsEl = document.getElementById('inStats');
  if (!inputEl || !statsEl) return;

  const text = inputEl.value || '';
  const lines = text ? text.split(/\r?\n/).length : 0;
  const chars = text.length;
  statsEl.textContent = `${lines} lines • ${chars} chars`;
}

function drawMaps(mappings) {
  const body = document.getElementById('mappingBody');
  if (!body) return;

  if (!mappings || mappings.length === 0) {
    body.innerHTML = `<tr><td colspan="3" class="p-5 text-slate-400">Run Sanitization to see mappings.</td></tr>`;
    return;
  }

  body.innerHTML = mappings.map(m => {
    const isSecret = /Secret|Password|Token|Key|Credential/i.test(m.category);
    const categoryBadgeClass = isSecret 
      ? 'bg-rose-100 text-rose-800 border-rose-200'
      : /Database|Server|Connection/i.test(m.category)
      ? 'bg-amber-100 text-amber-800 border-amber-200'
      : 'bg-blue-100 text-blue-800 border-blue-200';

    return `
      <tr class="border-t hover:bg-slate-50/80 transition-colors">
        <td class="p-3 mono text-rose-600 font-medium max-w-[280px] truncate" title="${escapeHtml(m.original)}">${escapeHtml(m.original)}</td>
        <td class="p-3 mono text-emerald-700 font-semibold max-w-[280px] truncate" title="${escapeHtml(m.replacement)}">${escapeHtml(m.replacement)}</td>
        <td class="p-3">
          <span class="inline-flex px-2 py-0.5 text-xs font-semibold rounded-full border ${categoryBadgeClass}">${escapeHtml(m.category)}</span>
        </td>
      </tr>
    `;
  }).join('');
}

function drawItems(items) {
  const el = document.getElementById('detected');
  if (!el) return;

  const icons = {
    key: '🔑',
    database: '🗄️',
    folder: '📁',
    globe: '🌐',
    user: '👤',
    code: '</>'
  };

  if (!items || items.length === 0) {
    el.innerHTML = `<div class="p-5 text-slate-400 text-sm">No sensitive items found yet.</div>`;
    return;
  }

  el.innerHTML = items.map(x => {
    const hasValue = Boolean(x.value);
    const badgeClass = hasValue ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : 'bg-slate-100 text-slate-400 border-slate-200';
    return `
      <div class="flex items-center justify-between gap-4 p-3.5 hover:bg-slate-50 transition-colors">
        <div class="flex items-start gap-3 min-w-0">
          <span class="text-lg leading-none">${icons[x.icon] || '•'}</span>
          <div class="min-w-0">
            <div class="text-xs font-bold text-slate-800">${escapeHtml(x.title)}</div>
            <div class="text-[11px] text-slate-500 mono truncate max-w-[320px]">${escapeHtml(x.value || '—')}</div>
          </div>
        </div>
        <span class="text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${badgeClass} shrink-0">
          ${hasValue ? 'Sanitized' : 'None'}
        </span>
      </div>
    `;
  }).join('');
}

// Auto initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
