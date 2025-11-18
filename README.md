# Database Forensic Tool

A comprehensive Python CLI tool for forensic analysis of SQLite, MySQL, and MongoDB databases. This tool focuses on evidence extraction, integrity validation, and tampering detection.

## Features

### General Features (All Databases)
- ✅ Export database metadata (version, schema, users where applicable)
- ✅ Audit access logs (when DB supports it)
- ✅ Detect schema changes (added/removed columns/tables)
- ✅ Check for suspicious activity (e.g., DROP TABLE, mass DELETE)
- ✅ Data integrity check (hashing of records/file hash)
- ✅ Timeline reconstruction (track operations history when logs exist)

### SQLite-Specific
- ✅ Parse `.sqlite` file format
- ✅ Extract deleted rows from freelist pages
- ✅ Analyze `sqlite_master` for tampering
- ✅ Journal/WAL recovery detection
- ✅ Compute hash of DB file & pages
- ✅ Integrity validation

### MySQL-Specific
- ✅ Parse binlog & error log
- ✅ Track user login history (if performance_schema enabled)
- ✅ Detect DROP/ALTER/DELETE events
- ✅ Export query history (if general_log enabled)
- ✅ Check for privilege changes
- ✅ Hash tables to detect silent changes

### MongoDB-Specific
- ✅ Parse oplog.rs (replica set log)
- ✅ Track insert/update/delete operations
- ✅ Extract user/role info
- ✅ Check system collections for tampering
- ✅ Check timestamp anomalies

## Installation

1. Clone or download this repository
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### SQLite Analysis

Basic analysis:
```bash
python -m db_forensic_tool sqlite database.db
```

Full analysis with deleted data recovery:
```bash
python -m db_forensic_tool sqlite database.db \
    --recover-deleted \
    --check-journal \
    --page-hash \
    --output report.json
```

### MySQL Analysis

Basic analysis:
```bash
python -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password yourpassword \
    --database testdb
```

With log file analysis:
```bash
python -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password yourpassword \
    --database testdb \
    --binlog /var/log/mysql/binlog.000001 \
    --error-log /var/log/mysql/error.log \
    --general-log /var/log/mysql/general.log \
    --suspicious-ops \
    --output report.json
```

### MongoDB Analysis

Basic analysis:
```bash
python -m db_forensic_tool mongodb \
    --host localhost \
    --port 27017 \
    --database testdb
```

With connection URI:
```bash
python -m db_forensic_tool mongodb \
    --uri "mongodb://user:password@localhost:27017/testdb" \
    --database testdb \
    --check-timestamps
```

Offline oplog analysis:
```bash
python -m db_forensic_tool mongodb \
    --database testdb \
    --oplog /path/to/oplog.json \
    --check-timestamps
```

### Output Options

- `--format json`: Output only JSON report
- `--format text`: Output only text to console
- `--format both`: Output both (default)
- `--output report.json`: Save report to file
- `--verbose`: Enable verbose logging

## Output Format

The tool generates forensic reports in JSON format with the following structure:

```json
{
  "metadata": {
    "timestamp": "2024-01-01T12:00:00",
    "tool": "Database Forensic Tool v1.0.0",
    "db_type": "SQLite",
    "db_name": "database.db"
  },
  "findings": [
    {
      "category": "metadata",
      "severity": "info",
      "title": "Database Metadata Extracted",
      "description": "...",
      "timestamp": "2024-01-01T12:00:00",
      "evidence": {...}
    }
  ]
}
```

### Severity Levels
- `info`: Informational findings
- `warning`: Suspicious but not necessarily malicious
- `critical`: Critical security or integrity issues

## Examples

### Example 1: SQLite Deleted Data Recovery
```bash
python -m db_forensic_tool sqlite evidence.db \
    --recover-deleted \
    --output evidence_report.json
```

### Example 2: MySQL Security Audit
```bash
python -m db_forensic_tool mysql \
    --host 192.168.1.100 \
    --user forensic_user \
    --database production_db \
    --suspicious-ops \
    --general-log /var/log/mysql/general.log \
    --verbose \
    --output security_audit.json
```

### Example 3: MongoDB Oplog Analysis
```bash
python -m db_forensic_tool mongodb \
    --uri "mongodb://admin:pass@localhost:27017" \
    --database appdb \
    --check-timestamps \
    --output mongodb_analysis.json
```

## Limitations

1. **SQLite Deleted Data Recovery**: Full recovery of deleted rows requires binary parsing of SQLite file format. This tool detects freelist pages but full recovery may require specialized tools.

2. **MySQL Binlog Parsing**: Detailed binlog parsing requires `python-mysql-replication` library or `mysqlbinlog` tool. The tool can identify binlog files but detailed parsing is simplified.

3. **MongoDB BSON Oplog**: If oplog files are in BSON format, install `bson` library for full parsing support.

4. **Performance**: Large databases may take significant time to analyze. Consider sampling for very large datasets.

## Security Considerations

- Database credentials may be passed via command line (visible in process lists)
- Consider using environment variables or credential files for production use
- Reports may contain sensitive information - handle appropriately
- Ensure proper permissions before analyzing production databases

## Contributing

This is a forensic tool designed for evidence collection and analysis. Contributions and improvements are welcome.

## License

This tool is provided as-is for forensic and security analysis purposes.

## Disclaimer

This tool is intended for legitimate forensic and security analysis purposes only. Users are responsible for ensuring they have proper authorization before analyzing databases.

