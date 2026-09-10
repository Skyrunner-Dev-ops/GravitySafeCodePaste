/**
 * Gravity Safe Code Paste — SQL Language Sanitizer
 * Generic DDL/DML parser supporting T-SQL, PostgreSQL, MySQL, Oracle, SQLite.
 */

import { ReplacementMap } from './replacement-map.js';
import { detectSecuritySensitives } from './detector.js';

const SQL_RESERVED = new Set([
  'select', 'from', 'where', 'insert', 'update', 'delete', 'join', 'inner', 'left', 'right',
  'outer', 'cross', 'full', 'on', 'group', 'by', 'order', 'having', 'create', 'alter', 'drop',
  'table', 'view', 'procedure', 'proc', 'function', 'database', 'schema', 'index', 'trigger',
  'add', 'column', 'constraint', 'primary', 'foreign', 'key', 'references', 'not', 'null',
  'default', 'check', 'unique', 'identity', 'auto_increment', 'set', 'values', 'into', 'as',
  'and', 'or', 'in', 'like', 'is', 'between', 'exists', 'case', 'when', 'then', 'else', 'end',
  'cast', 'convert', 'exec', 'execute', 'declare', 'begin', 'commit', 'rollback', 'transaction',
  'go', 'nvarchar', 'varchar', 'int', 'bigint', 'smallint', 'tinyint', 'bit', 'datetime',
  'datetime2', 'date', 'time', 'decimal', 'numeric', 'float', 'real', 'money', 'smallmoney',
  'char', 'nchar', 'text', 'ntext', 'blob', 'clob', 'varbinary', 'image', 'uniqueidentifier',
  'boolean', 'bool', 'timestamp', 'getdate', 'sysdatetime', 'now', 'current_timestamp',
  'count', 'sum', 'avg', 'min', 'max', 'coalesce', 'isnull', 'row_number', 'over', 'partition',
  'top', 'limit', 'offset', 'with', 'nolock', 'union', 'all', 'except', 'intersect', 'truncate',
  'dbo', 'sys', 'master', 'tempdb', 'msdb', 'model', 'information_schema', 'public', 'pg_catalog',
  'returns', 'return', 'as', 'use', 'print', 'raiseerror', 'throw', 'cursor', 'open', 'fetch',
  'close', 'deallocate', 'asc', 'desc', 'clustered', 'nonclustered', 'collate', 'if', 'else',
  'while', 'break', 'continue', 'distinct', 'distinctrow', 'all', 'any', 'some'
]);

export function sanitize(sourceText, options = { changeIdentifiers: false }) {
  const replacementMap = new ReplacementMap();
  const detected = detectSecuritySensitives(sourceText, replacementMap);

  // Detect credentials inside SQL (e.g. sp_addlogin, CREATE LOGIN ... WITH PASSWORD = '...')
  const sqlPasswordRegex = /(?:PASSWORD|PWD)\s*=\s*['"]([^'"]+)['"]/gi;
  let m;
  while ((m = sqlPasswordRegex.exec(sourceText)) !== null) {
    replacementMap.addSensitive(m[1], 'your-password', 'Password');
  }

  // If Change Identifiers is enabled
  if (options && options.changeIdentifiers) {
    // 1. Database & Schema names: CREATE DATABASE [ProjectManagement] / USE [ProjectManagement]
    const dbRegex = /\b(?:DATABASE|SCHEMA)\s+(?:\[dbo\]\.)?\[?([A-Za-z0-9_]+)\]?/gi;
    while ((m = dbRegex.exec(sourceText)) !== null) {
      const dbName = m[1];
      if (!SQL_RESERVED.has(dbName.toLowerCase())) {
        replacementMap.getOrAddIdentifier(dbName, 'Database', 'database');
      }
    }

    // 2. Tables in CREATE/ALTER/DROP: CREATE TABLE [dbo].[EmployeeAttendance] / ALTER TABLE dbo.AspNetUsers
    const tableDeclRegex = /\b(?:TABLE|VIEW|INTO|FROM|JOIN|UPDATE)\s+(?:\[?(?:dbo|public|sys)\]?\.)?\[?([A-Za-z0-9_]+)\]?/gi;
    while ((m = tableDeclRegex.exec(sourceText)) !== null) {
      const tableName = m[1];
      if (!SQL_RESERVED.has(tableName.toLowerCase())) {
        replacementMap.getOrAddIdentifier(tableName, 'Table', 'table');
      }
    }

    // 3. Columns in Column definitions: ADD AttendanceEmployeeId INT / EmployeeAttendanceId INT PRIMARY KEY
    const colDefRegex = /(?:ADD\s+|\(\s*|,\s*)\[?([A-Za-z0-9_]+)\]?\s+(?:NVARCHAR|VARCHAR|INT|BIGINT|SMALLINT|TINYINT|BIT|DATETIME|DATETIME2|DATE|TIME|DECIMAL|NUMERIC|FLOAT|REAL|CHAR|NCHAR|UNIQUEIDENTIFIER|BOOLEAN)/gi;
    while ((m = colDefRegex.exec(sourceText)) !== null) {
      const colName = m[1];
      if (!SQL_RESERVED.has(colName.toLowerCase())) {
        const hint = /id$/i.test(colName) ? 'column' : 'variable';
        replacementMap.getOrAddIdentifier(colName, 'Column', hint);
      }
    }

    // 4. Stored Procedures & Functions: CREATE PROCEDURE [sp_ProcessEmployee]
    const procRegex = /\b(?:PROCEDURE|PROC|FUNCTION)\s+(?:\[?(?:dbo|public)\]?\.)?\[?([A-Za-z0-9_]+)\]?/gi;
    while ((m = procRegex.exec(sourceText)) !== null) {
      const procName = m[1];
      if (!SQL_RESERVED.has(procName.toLowerCase())) {
        replacementMap.getOrAddIdentifier(procName, 'Stored Procedure', 'method');
      }
    }

    // 5. Variables: DECLARE @UserId INT
    const sqlVarRegex = /@([A-Za-z0-9_]+)/g;
    while ((m = sqlVarRegex.exec(sourceText)) !== null) {
      const varName = m[1];
      if (!SQL_RESERVED.has(varName.toLowerCase()) && !varName.startsWith('@')) {
        replacementMap.getOrAddIdentifier(varName, 'SQL Variable', 'variable');
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
