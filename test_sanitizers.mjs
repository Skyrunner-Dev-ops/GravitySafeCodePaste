import * as javaSanitizer from './js/java.js';
import * as csharpSanitizer from './js/csharp.js';
import * as pythonSanitizer from './js/python.js';
import * as configSanitizer from './js/config.js';
import * as otherSanitizer from './js/other.js';
import * as sqlSanitizer from './js/sql.js';
import { ReplacementMap } from './js/replacement-map.js';

let totalTests = 0;
let passedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
  }
}

console.log('=== TEST SUITE: Gravity Safe Code Paste Sanitizers ===\n');

// -------------------------------------------------------------
// 0. CASE PRESERVATION & CONSISTENCY TESTS
// -------------------------------------------------------------
console.log('--- 0. ReplacementMap Casing Consistency ---');
const map = new ReplacementMap();
const pascal = map.getOrAddIdentifier('EmployeeAttendance', 'Model');
const camel = map.getOrAddIdentifier('employeeAttendance', 'Model');
const upperSnake = map.getOrAddIdentifier('EMPLOYEE_ATTENDANCE', 'Model');
const lowerSnake = map.getOrAddIdentifier('employee_attendance', 'Model');

assert(pascal === 'SampleModel1' || pascal.includes('Model'), `PascalCase generated: ${pascal}`);
assert(camel.charAt(0) === camel.charAt(0).toLowerCase(), `camelCase starts with lowercase: ${camel}`);
assert(upperSnake.includes('_') && upperSnake === upperSnake.toUpperCase(), `UPPER_SNAKE_CASE preserved: ${upperSnake}`);
assert(lowerSnake.includes('_') && lowerSnake === lowerSnake.toLowerCase(), `lower_snake_case preserved: ${lowerSnake}`);

// -------------------------------------------------------------
// 1. C# SANITIZER TESTS
// -------------------------------------------------------------
console.log('\n--- 1. C# Sanitizer ---');

const csAppsettings1 = `{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=testdb,1983;Database=ProjectManagement;User ID=devteam;Password=devteam;Connect Timeout=30;MultipleActiveResultSets=true;TrustServerCertificate=true;"
  }
}`;

const csAppsettings2 = `{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=PROD-SQL-99;Database=CustomerPortal;User ID=portaladmin;Password=AnotherSecret123;Connect Timeout=60;MultipleActiveResultSets=true;TrustServerCertificate=true;"
  }
}`;

const resCS1_off = csharpSanitizer.sanitize(csAppsettings1, { changeIdentifiers: false });
assert(!resCS1_off.sanitizedText.includes('testdb'), 'C# (OFF) replaces testdb');
assert(!resCS1_off.sanitizedText.includes('devteam'), 'C# (OFF) replaces devteam');
assert(!resCS1_off.sanitizedText.includes('ProjectManagement'), 'C# (OFF) replaces ProjectManagement database name in connection string');

const resCS2_off = csharpSanitizer.sanitize(csAppsettings2, { changeIdentifiers: false });
assert(!resCS2_off.sanitizedText.includes('PROD-SQL-99'), 'C# (OFF) replaces arbitrary server PROD-SQL-99');
assert(!resCS2_off.sanitizedText.includes('CustomerPortal'), 'C# (OFF) replaces arbitrary database CustomerPortal');
assert(!resCS2_off.sanitizedText.includes('portaladmin'), 'C# (OFF) replaces arbitrary user portaladmin');
assert(!resCS2_off.sanitizedText.includes('AnotherSecret123'), 'C# (OFF) replaces arbitrary password AnotherSecret123');

const csCode = `namespace ApexBilling.LedgerProcessing
{
    public class InvoiceRecordDto
    {
        public string InvoiceId { get; set; }
        public string ClientSecret { get; set; } = "sk_live_99887766554433221100";
    }

    public class InvoiceService
    {
        public async Task<InvoiceResponse> ProcessInvoiceAsync(InvoiceRecordDto invoiceDto)
        {
            var serverUrl = "https://internal-billing.corp.local/v1/pay";
            return new InvoiceResponse();
        }
    }
}`;

const resCS_code_off = csharpSanitizer.sanitize(csCode, { changeIdentifiers: false });
assert(!resCS_code_off.sanitizedText.includes('sk_live_99887766554433221100'), 'C# (OFF) removes API secret key');
assert(!resCS_code_off.sanitizedText.includes('https://internal-billing.corp.local/v1/pay'), 'C# (OFF) removes internal endpoint');
assert(resCS_code_off.sanitizedText.includes('InvoiceRecordDto'), 'C# (OFF) preserves class InvoiceRecordDto');
assert(resCS_code_off.sanitizedText.includes('InvoiceService'), 'C# (OFF) preserves class InvoiceService');
assert(resCS_code_off.sanitizedText.includes('InvoiceId'), 'C# (OFF) preserves property InvoiceId');

const resCS_code_on = csharpSanitizer.sanitize(csCode, { changeIdentifiers: true });
assert(!resCS_code_on.sanitizedText.includes('InvoiceRecordDto'), 'C# (ON) renames class InvoiceRecordDto');
assert(!resCS_code_on.sanitizedText.includes('InvoiceService'), 'C# (ON) renames class InvoiceService');
assert(!resCS_code_on.sanitizedText.includes('ApexBilling'), 'C# (ON) renames namespace ApexBilling');
assert(resCS_code_on.sanitizedText.includes('public class'), 'C# (ON) preserves keywords public class');
assert(resCS_code_on.sanitizedText.includes('Task<'), 'C# (ON) preserves .NET types Task');

// -------------------------------------------------------------
// 2. JAVA SANITIZER TESTS
// -------------------------------------------------------------
console.log('\n--- 2. Java Sanitizer ---');

const javaCode = `package org.acmecorp.inventory.service;

import org.springframework.stereotype.Service;

@Service
public class WarehouseStockService {
    private final String dbUrl = "jdbc:postgresql://warehouse-primary.corp.local:5432/InventoryCatalogDB";
    private final String dbPass = "WarehouseDbSecret9988!";
    private final String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.sig123456";

    public StockItemResponseDto checkStockLevel(WarehouseStockItem item) {
        String apiKey = "AKIAIOSFODNN7EXAMPLE";
        return new StockItemResponseDto(item.getSku());
    }
}`;

const resJava_off = javaSanitizer.sanitize(javaCode, { changeIdentifiers: false });
assert(!resJava_off.sanitizedText.includes('WarehouseDbSecret9988!'), 'Java (OFF) sanitizes database password');
assert(!resJava_off.sanitizedText.includes('AKIAIOSFODNN7EXAMPLE'), 'Java (OFF) sanitizes AWS access key');
assert(!resJava_off.sanitizedText.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), 'Java (OFF) sanitizes JWT token');
assert(resJava_off.sanitizedText.includes('WarehouseStockService'), 'Java (OFF) preserves class WarehouseStockService');

const resJava_on = javaSanitizer.sanitize(javaCode, { changeIdentifiers: true });
assert(!resJava_on.sanitizedText.includes('WarehouseStockService'), 'Java (ON) renames class WarehouseStockService');
assert(!resJava_on.sanitizedText.includes('acmecorp'), 'Java (ON) renames custom package acmecorp');
assert(resJava_on.sanitizedText.includes('@Service'), 'Java (ON) preserves @Service annotation');
assert(resJava_on.sanitizedText.includes('public class'), 'Java (ON) preserves public class syntax');

// -------------------------------------------------------------
// 3. PYTHON SANITIZER TESTS
// -------------------------------------------------------------
console.log('\n--- 3. Python Sanitizer ---');

const pyCode = `import os
from pydantic import BaseModel

DATABASE_URL = "postgresql://cluster_admin:SuperSecretPass2026@prod-sql-cluster.internal:5432/EmployeeRecordsDB"
API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
SECRET_KEY = os.getenv("JWT_SIGNING_KEY", "secret_value_12345")

class HealthcareRecordService(BaseModel):
    patient_identifier: str
    hospital_branch_id: int

def calculate_patient_billing(record: HealthcareRecordService) -> float:
    auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
    return 150.00
`;

const resPy_off = pythonSanitizer.sanitize(pyCode, { changeIdentifiers: false });
assert(!resPy_off.sanitizedText.includes('SuperSecretPass2026'), 'Python (OFF) removes DB password');
assert(!resPy_off.sanitizedText.includes('ghp_1234567890abcdefghijklmnopqrstuvwxyzAB'), 'Python (OFF) removes GitHub token');
assert(resPy_off.sanitizedText.includes('HealthcareRecordService'), 'Python (OFF) preserves class HealthcareRecordService');

const resPy_on = pythonSanitizer.sanitize(pyCode, { changeIdentifiers: true });
assert(!resPy_on.sanitizedText.includes('HealthcareRecordService'), 'Python (ON) renames class HealthcareRecordService');
assert(!resPy_on.sanitizedText.includes('calculate_patient_billing'), 'Python (ON) renames function calculate_patient_billing');
assert(resPy_on.sanitizedText.includes('def '), 'Python (ON) preserves def keyword');
assert(resPy_on.sanitizedText.includes('import os'), 'Python (ON) preserves import os');

// -------------------------------------------------------------
// 4. CONFIG SANITIZER TESTS (.env, YAML, TOML, XML, JSON)
// -------------------------------------------------------------
console.log('\n--- 4. Config Sanitizer ---');

const dotEnv = `
DB_HOST=PROD-SQL-01
DB_NAME=HRSystem
DB_USER=databaseadmin
DB_PASSWORD=VerySecretPass7788!
API_KEY=sk_live_11223344556677889900
`;

const resEnv = configSanitizer.sanitize(dotEnv, { changeIdentifiers: false });
assert(!resEnv.sanitizedText.includes('VerySecretPass7788!'), 'Config .env sanitizes password');
assert(!resEnv.sanitizedText.includes('sk_live_11223344556677889900'), 'Config .env sanitizes API key');
assert(!resEnv.sanitizedText.includes('PROD-SQL-01'), 'Config .env sanitizes DB host');
assert(!resEnv.sanitizedText.includes('HRSystem'), 'Config .env sanitizes DB name');
assert(!resEnv.sanitizedText.includes('databaseadmin'), 'Config .env sanitizes DB user');
assert(resEnv.sanitizedText.includes('DB_HOST='), 'Config .env preserves KEY= formatting');

const yamlConfig = `
database:
  host: PROD-SQL-01
  username: databaseadmin
  password: SuperSecretPassword!
services:
  payment_gateway:
    api_key: AIzaSyD-1234567890abcdefghijklmnopqrstuvw
`;

const resYaml = configSanitizer.sanitize(yamlConfig, { changeIdentifiers: false });
assert(!resYaml.sanitizedText.includes('SuperSecretPassword!'), 'Config YAML sanitizes password');
assert(!resYaml.sanitizedText.includes('AIzaSyD-1234567890abcdefghijklmnopqrstuvw'), 'Config YAML sanitizes Google API key');
assert(resYaml.sanitizedText.includes('  host:'), 'Config YAML preserves indentation');

const xmlConfig = `
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" connectionString="Server=SQL-HOST-01;Database=CommerceStore;User Id=dbadmin;Password=SecretXmlPassword!;" />
  </connectionStrings>
  <appSettings>
    <add key="Password" value="SecretXmlPassword!" />
    <add key="ApiKey" value="sk_test_51M0abcdef1234567890XYZ" />
  </appSettings>
</configuration>
`;

const resXml = configSanitizer.sanitize(xmlConfig, { changeIdentifiers: false });
assert(!resXml.sanitizedText.includes('SecretXmlPassword!'), 'Config XML sanitizes password');
assert(!resXml.sanitizedText.includes('sk_test_51M0abcdef1234567890XYZ'), 'Config XML sanitizes API key');
assert(!resXml.sanitizedText.includes('CommerceStore'), 'Config XML sanitizes DB name');
assert(resXml.sanitizedText.includes('<add key="Password"'), 'Config XML preserves XML structure');

// -------------------------------------------------------------
// 5. SQL SANITIZER TESTS
// -------------------------------------------------------------
console.log('\n--- 5. SQL Sanitizer ---');

const sqlCode1 = `ALTER TABLE dbo.EmployeeRecords
ADD AttendanceEmployeeId INT NOT NULL DEFAULT(0)

CREATE TABLE EmployeeAttendance (
    EmployeeAttendanceId INT PRIMARY KEY IDENTITY,
    UserId NVARCHAR(450) NOT NULL,
    LogDate DATE NOT NULL
)`;

const sqlCode2 = `ALTER TABLE dbo.CustomerLedger
ADD CustomerHash INT NOT NULL DEFAULT(0)

CREATE TABLE FinancialTransactions (
    TransactionId INT PRIMARY KEY IDENTITY,
    AccountId NVARCHAR(450) NOT NULL,
    Amount DECIMAL(18,2) NOT NULL
)`;

// SQL 1: Checkbox OFF (preserves table names) vs ON (renames tables/columns)
const resSql1_off = sqlSanitizer.sanitize(sqlCode1, { changeIdentifiers: false });
assert(resSql1_off.sanitizedText.includes('EmployeeRecords'), 'SQL (OFF) preserves EmployeeRecords table');
assert(resSql1_off.sanitizedText.includes('AttendanceEmployeeId'), 'SQL (OFF) preserves AttendanceEmployeeId column');
assert(resSql1_off.sanitizedText.includes('EmployeeAttendance'), 'SQL (OFF) preserves EmployeeAttendance table');

const resSql1_on = sqlSanitizer.sanitize(sqlCode1, { changeIdentifiers: true });
assert(!resSql1_on.sanitizedText.includes('EmployeeRecords'), 'SQL (ON) renames EmployeeRecords table');
assert(!resSql1_on.sanitizedText.includes('AttendanceEmployeeId'), 'SQL (ON) renames AttendanceEmployeeId column');
assert(!resSql1_on.sanitizedText.includes('EmployeeAttendance'), 'SQL (ON) renames EmployeeAttendance table');
assert(resSql1_on.sanitizedText.includes('CREATE TABLE'), 'SQL (ON) preserves CREATE TABLE keywords');
assert(resSql1_on.sanitizedText.includes('INT NOT NULL DEFAULT(0)'), 'SQL (ON) preserves type and constraint syntax');

// SQL 2: Arbitrary different table names
const resSql2_on = sqlSanitizer.sanitize(sqlCode2, { changeIdentifiers: true });
assert(!resSql2_on.sanitizedText.includes('CustomerLedger'), 'SQL (ON) renames arbitrary CustomerLedger table');
assert(!resSql2_on.sanitizedText.includes('FinancialTransactions'), 'SQL (ON) renames arbitrary FinancialTransactions table');
assert(!resSql2_on.sanitizedText.includes('CustomerHash'), 'SQL (ON) renames arbitrary CustomerHash column');
assert(resSql2_on.sanitizedText.includes('CREATE TABLE'), 'SQL (ON) preserves SQL syntax');

// -------------------------------------------------------------
// 6. OTHER SANITIZER TESTS
// -------------------------------------------------------------
console.log('\n--- 6. Other Sanitizer ---');

const mixedCode = `
// Shell & Node script
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export DATABASE_SECRET="SuperSecretToken2026!"
const INTERNAL_ENDPOINT = "https://internal-cluster.corp.local/api/v2";

class CustomPayloadDispatcher {
    constructor() {
        this.token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload.sig";
    }
}
`;

const resOther_off = otherSanitizer.sanitize(mixedCode, { changeIdentifiers: false });
assert(!resOther_off.sanitizedText.includes('AKIAIOSFODNN7EXAMPLE'), 'Other (OFF) removes AWS key');
assert(!resOther_off.sanitizedText.includes('SuperSecretToken2026!'), 'Other (OFF) removes secret token');
assert(!resOther_off.sanitizedText.includes('https://internal-cluster.corp.local/api/v2'), 'Other (OFF) removes internal URL');
assert(resOther_off.sanitizedText.includes('CustomPayloadDispatcher'), 'Other (OFF) preserves CustomPayloadDispatcher');

const resOther_on = otherSanitizer.sanitize(mixedCode, { changeIdentifiers: true });
assert(!resOther_on.sanitizedText.includes('CustomPayloadDispatcher'), 'Other (ON) renames CustomPayloadDispatcher');

console.log(`\n=== RESULTS: ${passedTests} / ${totalTests} tests passed ===`);
if (passedTests === totalTests) {
  console.log('All tests passed successfully! 🎉');
} else {
  process.exit(1);
}
