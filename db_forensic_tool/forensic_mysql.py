"""
MySQL Forensic Analysis Module
"""

import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

from db_forensic_tool.utils import (
    OutputFormatter, BaselineManager, compute_file_hash, detect_suspicious_queries, 
    validate_file_exists
)


class MySQLForensic:
    """MySQL database forensic analyzer"""
    
    def __init__(self, host: str, port: int, user: str, password: Optional[str],
                 database: str, formatter: Optional[OutputFormatter] = None,
                 baseline_manager: Optional[BaselineManager] = None,
                 create_baseline: bool = False, compare_baseline: bool = False):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.formatter = formatter or OutputFormatter()
        self.baseline_manager = baseline_manager
        self.create_baseline = create_baseline
        self.compare_baseline = compare_baseline
        self.conn = None
        self.logger = logging.getLogger(__name__)
        
        if not PYMYSQL_AVAILABLE:
            raise ImportError("pymysql is required for MySQL analysis. Install with: pip install pymysql")
    
    def _connect(self):
        """Connect to MySQL database"""
        try:
            self.conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                cursorclass=pymysql.cursors.DictCursor
            )
        except Exception as e:
            raise Exception(f"Failed to connect to MySQL database: {e}")
    
    def _disconnect(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def analyze(self, binlog_path: Optional[str] = None,
                error_log_path: Optional[str] = None,
                general_log_path: Optional[str] = None,
                suspicious_ops: bool = False):
        """Perform comprehensive forensic analysis"""
        self.logger.info(f"Starting forensic analysis of MySQL database: {self.database}")
        
        try:
            self._connect()
            
            # Set metadata
            self.formatter.set_metadata(
                db_type="MySQL",
                db_name=self.database,
                host=self.host,
                port=self.port
            )
            
            # 1. Extract metadata
            self._extract_metadata()
            
            # 2. Analyze schema
            self._analyze_schema()
            
            # 2a. Analyze foreign keys and relationships
            self._analyze_relationships()
            
            # 3. Audit users and privileges
            self._audit_users_privileges()
            
            # 4. Track user login history (if available)
            self._track_login_history()
            
            # 5. Detect schema changes
            self._detect_schema_changes()
            
            # 6. Compute table hashes
            table_hashes = self._hash_tables()
            
            # 6a. Hash comparison
            if self.compare_baseline and self.baseline_manager:
                self._compare_hashes(table_hashes)
            
            # 6b. Dropped table detection
            if self.compare_baseline and self.baseline_manager:
                self._detect_dropped_tables()
            
            # 6c. Save baseline if requested
            if self.create_baseline and self.baseline_manager:
                self._save_baseline(table_hashes)
            
            # 7. Parse binlog
            if binlog_path:
                self._parse_binlog(binlog_path, suspicious_ops)
            
            # 8. Parse error log
            if error_log_path:
                self._parse_error_log(error_log_path)
            
            # 9. Parse general query log
            if general_log_path:
                self._parse_general_log(general_log_path, suspicious_ops)
            
            # 10. Detect suspicious operations
            if suspicious_ops:
                self._detect_suspicious_operations()
            
        finally:
            self._disconnect()
        
        # Save report
        self.formatter.save_report()
    
    def _extract_metadata(self):
        """Extract database metadata"""
        try:
            cursor = self.conn.cursor()
            
            # MySQL version
            cursor.execute("SELECT VERSION() as version")
            version = cursor.fetchone()["version"]
            
            # Database charset
            cursor.execute("SELECT @@character_set_database as charset")
            charset = cursor.fetchone()["charset"]
            
            # Current user
            cursor.execute("SELECT USER() as current_user, CURRENT_USER() as effective_user")
            user_info = cursor.fetchone()
            
            metadata = {
                "mysql_version": version,
                "database_charset": charset,
                "current_user": user_info["current_user"],
                "effective_user": user_info["effective_user"]
            }
            
            self.formatter.add_finding(
                category="metadata",
                severity="info",
                title="MySQL Metadata Extracted",
                description=f"MySQL version: {version}, Charset: {charset}",
                evidence=metadata
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {e}")
    
    def _analyze_schema(self):
        """Analyze database schema"""
        try:
            cursor = self.conn.cursor()
            
            # Get all tables
            cursor.execute(f"""
                SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, 
                       DATA_LENGTH, INDEX_LENGTH, CREATE_TIME, UPDATE_TIME
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                ORDER BY TABLE_NAME
            """)
            
            tables = cursor.fetchall()
            
            # Get all columns
            cursor.execute(f"""
                SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, COLUMN_TYPE,
                       IS_NULLABLE, COLUMN_DEFAULT
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = '{self.database}'
                ORDER BY TABLE_NAME, ORDINAL_POSITION
            """)
            
            columns = cursor.fetchall()
            
            schema_info = {
                "table_count": len(tables),
                "column_count": len(columns),
                "tables": [t["TABLE_NAME"] for t in tables],
                "table_details": tables[:10]  # Limit evidence
            }
            
            self.formatter.add_finding(
                category="schema",
                severity="info",
                title="Schema Analysis",
                description=f"Found {len(tables)} tables with {len(columns)} columns",
                evidence=schema_info
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing schema: {e}")
    
    def _analyze_relationships(self):
        """Analyze foreign keys and relationships"""
        try:
            cursor = self.conn.cursor()
            
            # Get foreign key constraints
            cursor.execute(f"""
                SELECT 
                    kcu.TABLE_NAME,
                    kcu.COLUMN_NAME,
                    kcu.CONSTRAINT_NAME,
                    kcu.REFERENCED_TABLE_NAME,
                    kcu.REFERENCED_COLUMN_NAME,
                    rc.UPDATE_RULE,
                    rc.DELETE_RULE
                FROM information_schema.KEY_COLUMN_USAGE kcu
                JOIN information_schema.REFERENTIAL_CONSTRAINTS rc
                    ON kcu.CONSTRAINT_NAME = rc.CONSTRAINT_NAME
                    AND kcu.TABLE_SCHEMA = rc.CONSTRAINT_SCHEMA
                WHERE kcu.TABLE_SCHEMA = '{self.database}'
                    AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
                ORDER BY kcu.TABLE_NAME, kcu.CONSTRAINT_NAME
            """)
            
            foreign_keys = cursor.fetchall()
            
            if foreign_keys:
                fk_list = []
                for fk in foreign_keys:
                    fk_list.append({
                        "table": fk["TABLE_NAME"],
                        "column": fk["COLUMN_NAME"],
                        "references_table": fk["REFERENCED_TABLE_NAME"],
                        "references_column": fk["REFERENCED_COLUMN_NAME"],
                        "on_update": fk.get("UPDATE_RULE", ""),
                        "on_delete": fk.get("DELETE_RULE", "")
                    })
                
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Foreign Key Relationships",
                    description=f"Found {len(foreign_keys)} foreign key relationships",
                    evidence={"foreign_keys": fk_list[:20]}  # Limit evidence
                )
            else:
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Foreign Key Relationships",
                    description="No foreign key relationships found",
                    evidence={"foreign_keys": []}
                )
                
        except Exception as e:
            self.logger.error(f"Error analyzing relationships: {e}")
    
    def _audit_users_privileges(self):
        """Audit users and their privileges"""
        try:
            cursor = self.conn.cursor()
            
            # Get all users
            cursor.execute("""
                SELECT User, Host FROM mysql.user
            """)
            
            users = cursor.fetchall()
            
            # Get current user privileges
            cursor.execute("SHOW GRANTS")
            current_grants = [row[f"Grants for {self.user}@{self.host}"] 
                            if f"Grants for {self.user}@{self.host}" in row 
                            else list(row.values())[0] 
                            for row in cursor.fetchall()]
            
            # Check for privileged operations
            privileged_grants = []
            for grant in current_grants:
                if any(priv in grant.upper() for priv in ["ALL PRIVILEGES", "GRANT OPTION", "SUPER", "PROCESS"]):
                    privileged_grants.append(grant)
            
            user_info = {
                "total_users": len(users),
                "current_user": self.user,
                "user_list": [f"{u['User']}@{u['Host']}" for u in users[:20]],  # Limit
                "current_grants": current_grants[:10],
                "privileged_grants": privileged_grants
            }
            
            self.formatter.add_finding(
                category="security",
                severity="info",
                title="User and Privilege Audit",
                description=f"Found {len(users)} users in database",
                evidence=user_info
            )
            
            if privileged_grants:
                self.formatter.add_finding(
                    category="security",
                    severity="warning",
                    title="Privileged Grants Detected",
                    description=f"Current user has privileged grants",
                    evidence={"privileged_grants": privileged_grants}
                )
            
        except Exception as e:
            self.logger.error(f"Error auditing users: {e}")
    
    def _track_login_history(self):
        """Track user login history (if performance_schema enabled)"""
        try:
            cursor = self.conn.cursor()
            
            # Check if performance_schema is available
            cursor.execute("SELECT @@performance_schema")
            result = cursor.fetchone()
            perf_schema_enabled = result.get(list(result.keys())[0], 0) if result else 0
            
            if perf_schema_enabled:
                try:
                    cursor.execute("""
                        SELECT user, host, event_name, count_star as login_count
                        FROM performance_schema.events_statements_summary_by_user_by_event_name
                        WHERE event_name LIKE '%login%' OR event_name LIKE '%connect%'
                        ORDER BY count_star DESC
                        LIMIT 20
                    """)
                    
                    logins = cursor.fetchall()
                    
                    if logins:
                        self.formatter.add_finding(
                            category="audit",
                            severity="info",
                            title="User Login Activity",
                            description=f"Tracked {len(logins)} login events",
                            evidence={"login_events": logins}
                        )
                except Exception:
                    self.logger.debug("Performance schema login tracking not available")
            else:
                self.formatter.add_finding(
                    category="audit",
                    severity="info",
                    title="Performance Schema Disabled",
                    description="Performance schema is disabled - login history not available"
                )
            
        except Exception as e:
            self.logger.debug(f"Login history tracking not available: {e}")
    
    def _detect_schema_changes(self):
        """Detect schema changes by comparing CREATE_TIME and UPDATE_TIME"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute(f"""
                SELECT TABLE_NAME, CREATE_TIME, UPDATE_TIME, TABLE_ROWS
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                AND UPDATE_TIME IS NOT NULL
                AND UPDATE_TIME != CREATE_TIME
                ORDER BY UPDATE_TIME DESC
            """)
            
            changed_tables = cursor.fetchall()
            
            if changed_tables:
                self.formatter.add_finding(
                    category="schema",
                    severity="warning",
                    title="Potential Schema Changes Detected",
                    description=f"Found {len(changed_tables)} tables with update times different from creation",
                    evidence={"changed_tables": changed_tables[:10]}
                )
            
        except Exception as e:
            self.logger.error(f"Error detecting schema changes: {e}")
    
    def _hash_tables(self) -> Dict[str, str]:
        """Compute hashes of table data to detect silent changes"""
        table_hashes = {}
        try:
            cursor = self.conn.cursor()
            
            cursor.execute(f"""
                SELECT TABLE_NAME FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                AND TABLE_TYPE = 'BASE TABLE'
                LIMIT 10
            """)
            
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table["TABLE_NAME"]
                try:
                    # Hash table structure and row count
                    cursor.execute(f"""
                        SELECT TABLE_NAME, CREATE_TIME, TABLE_ROWS
                        FROM information_schema.TABLES
                        WHERE TABLE_SCHEMA = '{self.database}' AND TABLE_NAME = '{table_name}'
                    """)
                    
                    table_info = cursor.fetchone()
                    hash_string = f"{table_info['TABLE_NAME']}|{table_info['CREATE_TIME']}|{table_info['TABLE_ROWS']}"
                    table_hash = hashlib.sha256(hash_string.encode()).hexdigest()[:16]
                    table_hashes[f"table_{table_name}"] = table_hash
                    
                except Exception as e:
                    self.logger.debug(f"Could not hash table {table_name}: {e}")
            
            if table_hashes:
                self.formatter.add_finding(
                    category="integrity",
                    severity="info",
                    title="Table Hash Analysis",
                    description=f"Computed hashes for {len(table_hashes)} tables",
                    evidence={"table_hashes": table_hashes}
                )
            
        except Exception as e:
            self.logger.error(f"Error hashing tables: {e}")
        
        return table_hashes
    
    def _compare_hashes(self, table_hashes: Dict[str, str]):
        """Compare current hashes with baseline"""
        try:
            comparison = self.baseline_manager.compare_hashes(
                "MySQL", self.database, table_hashes
            )
            
            if comparison["status"] == "no_baseline":
                self.formatter.add_finding(
                    category="integrity",
                    severity="info",
                    title="Hash Comparison",
                    description="No baseline found for comparison. Use --create-baseline to create one.",
                    evidence=comparison
                )
            else:
                if comparison["mismatches"]:
                    self.formatter.add_finding(
                        category="integrity",
                        severity="critical",
                        title="Hash Mismatch Detected",
                        description=f"Found {len(comparison['mismatches'])} hash mismatches - tables may have been modified",
                        evidence=comparison
                    )
                else:
                    self.formatter.add_finding(
                        category="integrity",
                        severity="info",
                        title="Hash Comparison",
                        description=f"All hashes match baseline ({comparison['matches']} items verified)",
                        evidence=comparison
                    )
                    
        except Exception as e:
            self.logger.error(f"Error comparing hashes: {e}")
    
    def _detect_dropped_tables(self):
        """Detect dropped tables by comparing with baseline"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute(f"""
                SELECT TABLE_NAME FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                AND TABLE_TYPE = 'BASE TABLE'
                ORDER BY TABLE_NAME
            """)
            
            current_tables = [row["TABLE_NAME"] for row in cursor.fetchall()]
            
            comparison = self.baseline_manager.compare_tables(
                "MySQL", self.database, current_tables
            )
            
            if comparison["status"] == "no_baseline":
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Dropped Table Detection",
                    description="No baseline found for comparison. Use --create-baseline to create one.",
                    evidence=comparison
                )
            else:
                if comparison["dropped"]:
                    self.formatter.add_finding(
                        category="suspicious",
                        severity="critical",
                        title="Dropped Tables Detected",
                        description=f"Found {len(comparison['dropped'])} dropped tables: {', '.join(comparison['dropped'])}",
                        evidence=comparison
                    )
                
                if comparison["added"]:
                    self.formatter.add_finding(
                        category="schema",
                        severity="info",
                        title="New Tables Detected",
                        description=f"Found {len(comparison['added'])} new tables: {', '.join(comparison['added'])}",
                        evidence=comparison
                    )
                    
        except Exception as e:
            self.logger.error(f"Error detecting dropped tables: {e}")
    
    def _save_baseline(self, table_hashes: Dict[str, str]):
        """Save baseline data"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute(f"""
                SELECT TABLE_NAME FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                AND TABLE_TYPE = 'BASE TABLE'
                ORDER BY TABLE_NAME
            """)
            
            tables = [row["TABLE_NAME"] for row in cursor.fetchall()]
            
            baseline_data = {
                "tables": tables,
                "hashes": table_hashes
            }
            
            self.baseline_manager.save_baseline("MySQL", self.database, baseline_data)
            
            self.formatter.add_finding(
                category="baseline",
                severity="info",
                title="Baseline Created",
                description=f"Baseline saved for {len(tables)} tables",
                evidence={"tables_count": len(tables), "baseline_file": self.baseline_manager.baseline_file}
            )
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")
    
    def _parse_binlog(self, binlog_path: str, suspicious_ops: bool):
        """Parse MySQL binary log"""
        if not validate_file_exists(binlog_path):
            self.logger.warning(f"Binlog file not found: {binlog_path}")
            return
        
        try:
            binlog_hash = compute_file_hash(binlog_path)
            binlog_size = Path(binlog_path).stat().st_size
            
            self.formatter.add_finding(
                category="audit",
                severity="info",
                title="Binary Log File Found",
                description=f"Binlog: {Path(binlog_path).name} ({binlog_size} bytes)",
                evidence={"binlog_path": binlog_path, "binlog_hash": binlog_hash, "size": binlog_size}
            )
            
            # Note: Full binlog parsing requires mysqlbinlog tool or python-mysql-replication library
            self.formatter.add_finding(
                category="audit",
                severity="info",
                title="Binlog Analysis",
                description="Use mysqlbinlog tool or python-mysql-replication for detailed binlog parsing",
                evidence={"note": "Install python-mysql-replication for full binlog parsing support"}
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing binlog: {e}")
    
    def _parse_error_log(self, error_log_path: str):
        """Parse MySQL error log"""
        if not validate_file_exists(error_log_path):
            self.logger.warning(f"Error log file not found: {error_log_path}")
            return
        
        try:
            suspicious_patterns = [
                (r"Access denied", "warning"),
                (r"Unknown user", "warning"),
                (r"Got an error reading communication packets", "info"),
                (r"Forcing close of thread", "warning"),
            ]
            
            findings = []
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for pattern, severity in suspicious_patterns:
                    matches = [line.strip() for line in lines if re.search(pattern, line, re.IGNORECASE)]
                    if matches:
                        findings.append({
                            "pattern": pattern,
                            "severity": severity,
                            "match_count": len(matches),
                            "samples": matches[:5]
                        })
            
            if findings:
                self.formatter.add_finding(
                    category="audit",
                    severity="warning",
                    title="Error Log Analysis",
                    description=f"Found suspicious patterns in error log",
                    evidence={"findings": findings}
                )
            
        except Exception as e:
            self.logger.error(f"Error parsing error log: {e}")
    
    def _parse_general_log(self, general_log_path: str, suspicious_ops: bool):
        """Parse MySQL general query log"""
        if not validate_file_exists(general_log_path):
            self.logger.warning(f"General log file not found: {general_log_path}")
            return
        
        try:
            queries = []
            with open(general_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Extract queries (simplified - actual format may vary)
                    if "Query" in line:
                        query_match = re.search(r'Query\s+(.+)', line)
                        if query_match:
                            queries.append(query_match.group(1))
            
            if queries:
                self.formatter.add_finding(
                    category="audit",
                    severity="info",
                    title="General Query Log Parsed",
                    description=f"Found {len(queries)} queries in log",
                    evidence={"query_count": len(queries), "sample_queries": queries[:10]}
                )
                
                if suspicious_ops:
                    suspicious = detect_suspicious_queries(queries)
                    if suspicious:
                        self.formatter.add_finding(
                            category="suspicious",
                            severity="critical",
                            title="Suspicious Queries Detected",
                            description=f"Found {len(suspicious)} suspicious operations",
                            evidence={"suspicious_operations": suspicious}
                        )
            
        except Exception as e:
            self.logger.error(f"Error parsing general log: {e}")
    
    def _detect_suspicious_operations(self):
        """Detect suspicious operations in database"""
        try:
            cursor = self.conn.cursor()
            
            # Check for tables with suspicious modification times
            cursor.execute(f"""
                SELECT TABLE_NAME, UPDATE_TIME
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '{self.database}'
                AND UPDATE_TIME > DATE_SUB(NOW(), INTERVAL 7 DAY)
                ORDER BY UPDATE_TIME DESC
            """)
            
            recent_changes = cursor.fetchall()
            
            if recent_changes:
                self.formatter.add_finding(
                    category="suspicious",
                    severity="warning",
                    title="Recent Table Modifications",
                    description=f"Found {len(recent_changes)} tables modified in last 7 days",
                    evidence={"recent_changes": recent_changes[:10]}
                )
            
        except Exception as e:
            self.logger.error(f"Error detecting suspicious operations: {e}")


