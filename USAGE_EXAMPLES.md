# Usage Examples

Quick reference guide for common forensic analysis scenarios.

## Quick Start

### 1. SQLite Database Analysis

```bash
# Basic analysis
python -m db_forensic_tool sqlite mydatabase.db

# Full forensic analysis with all features
python -m db_forensic_tool sqlite evidence.db \
    --recover-deleted \
    --check-journal \
    --page-hash \
    --output evidence_report.json \
    --verbose
```

**What it does:**
- Extracts database metadata (version, page size, integrity)
- Analyzes schema (tables, indexes, triggers, views)
- Checks sqlite_master for tampering
- Computes file hash
- Attempts to recover deleted rows from freelist pages
- Checks for journal/WAL files
- Computes page-level hashes
- Detects suspicious activity

### 2. MySQL Database Analysis

```bash
# Basic connection (password will be prompted if not provided)
python -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password mypassword \
    --database production_db

# With log file analysis
python -m db_forensic_tool mysql \
    --host 192.168.1.100 \
    --user forensic_user \
    --password securepass \
    --database app_db \
    --binlog /var/log/mysql/binlog.000001 \
    --error-log /var/log/mysql/error.log \
    --general-log /var/log/mysql/general.log \
    --suspicious-ops \
    --output mysql_audit.json \
    --verbose
```

**What it does:**
- Extracts MySQL metadata (version, charset)
- Analyzes schema (tables, columns)
- Audits users and privileges
- Tracks login history (if performance_schema enabled)
- Detects schema changes
- Computes table hashes
- Parses binlog files (if provided)
- Parses error logs for suspicious patterns
- Parses general query logs and detects suspicious queries
- Identifies recent table modifications

### 3. MongoDB Database Analysis

```bash
# Basic connection
python -m db_forensic_tool mongodb \
    --host localhost \
    --port 27017 \
    --database appdb

# With connection URI
python -m db_forensic_tool mongodb \
    --uri "mongodb://admin:password@localhost:27017" \
    --database appdb \
    --check-timestamps \
    --output mongodb_report.json

# Offline oplog analysis
python -m db_forensic_tool mongodb \
    --database appdb \
    --oplog /backup/oplog.json \
    --check-timestamps
```

**What it does:**
- Extracts MongoDB metadata (version, storage engine)
- Analyzes collections (count, size)
- Extracts user and role information
- Checks system collections for tampering
- Analyzes oplog (if replica set)
- Tracks insert/update/delete operations
- Checks for timestamp anomalies in documents
- Parses offline oplog files (JSON format)

## Advanced Scenarios

### Scenario 1: Investigating Data Tampering

```bash
# SQLite - Check for tampering and deleted data
python -m db_forensic_tool sqlite suspect.db \
    --recover-deleted \
    --check-journal \
    --page-hash \
    --output tampering_analysis.json

# MySQL - Check for unauthorized changes
python -m db_forensic_tool mysql \
    --host db-server \
    --user auditor \
    --database critical_db \
    --suspicious-ops \
    --general-log /var/log/mysql/general.log \
    --output unauthorized_changes.json
```

### Scenario 2: Security Audit

```bash
# MySQL - Comprehensive security audit
python -m db_forensic_tool mysql \
    --host production-db \
    --user audit_user \
    --database app_db \
    --error-log /var/log/mysql/error.log \
    --general-log /var/log/mysql/general.log \
    --suspicious-ops \
    --verbose \
    --output security_audit.json

# MongoDB - Security and access audit
python -m db_forensic_tool mongodb \
    --uri "mongodb://audit:pass@db-host:27017" \
    --database appdb \
    --check-timestamps \
    --output security_audit.json
```

### Scenario 3: Incident Response

```bash
# SQLite - Full forensic recovery
python -m db_forensic_tool sqlite incident.db \
    --recover-deleted \
    --check-journal \
    --page-hash \
    --output incident_report.json \
    --verbose

# MySQL - Timeline reconstruction
python -m db_forensic_tool mysql \
    --host incident-server \
    --user responder \
    --database compromised_db \
    --binlog /backup/binlog.* \
    --error-log /var/log/mysql/error.log \
    --general-log /var/log/mysql/general.log \
    --suspicious-ops \
    --output timeline.json
```

### Scenario 4: Compliance Checking

```bash
# Check all databases for compliance
for db in *.db; do
    python -m db_forensic_tool sqlite "$db" \
        --output "compliance_${db%.db}.json"
done

# MySQL compliance audit
python -m db_forensic_tool mysql \
    --host audit-server \
    --user compliance \
    --database regulated_db \
    --output compliance_report.json
```

## Output Formats

### JSON Output (for automation)

```bash
python -m db_forensic_tool sqlite db.db \
    --format json \
    --output report.json
```

### Text Output (for manual review)

```bash
python -m db_forensic_tool sqlite db.db \
    --format text
```

### Both (default)

```bash
python -m db_forensic_tool sqlite db.db \
    --format both \
    --output report.json
```

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Check database credentials
   - Verify network connectivity
   - Ensure database service is running

2. **Permission Errors**
   - Ensure user has necessary privileges
   - For MySQL: SELECT, SHOW DATABASES, etc.
   - For MongoDB: read permissions on database

3. **File Not Found**
   - Verify file paths are correct
   - Use absolute paths if relative paths fail
   - Check file permissions

4. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Getting Help

```bash
python -m db_forensic_tool --help
python -m db_forensic_tool sqlite --help
python -m db_forensic_tool mysql --help
python -m db_forensic_tool mongodb --help
```

## Best Practices

1. **Always save reports**: Use `--output` to save findings
2. **Use verbose mode**: `--verbose` provides detailed logging
3. **Hash files first**: Always compute file hashes before analysis
4. **Work on copies**: Analyze copies of databases, not originals
5. **Document chain of custody**: Keep track of when and how databases were analyzed
6. **Verify findings**: Cross-reference findings with other tools when possible

