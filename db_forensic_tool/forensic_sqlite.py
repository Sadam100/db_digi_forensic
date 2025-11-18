"""
SQLite Forensic Analysis Module
"""

import hashlib
import logging
import sqlite3
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from db_forensic_tool.utils import (
    OutputFormatter, BaselineManager, compute_file_hash, compute_string_hash, validate_file_exists
)


class SQLiteForensic:
    """SQLite database forensic analyzer"""
    
    def __init__(self, db_path: str, formatter: Optional[OutputFormatter] = None,
                 baseline_manager: Optional[BaselineManager] = None,
                 create_baseline: bool = False, compare_baseline: bool = False):
        self.db_path = Path(db_path)
        self.formatter = formatter or OutputFormatter()
        self.baseline_manager = baseline_manager
        self.create_baseline = create_baseline
        self.compare_baseline = compare_baseline
        
        if not validate_file_exists(str(self.db_path)):
            raise FileNotFoundError(f"SQLite database not found: {db_path}")
        
        self.conn: Optional[sqlite3.Connection] = None
        self.logger = logging.getLogger(__name__)
    
    def _connect(self):
        """Connect to SQLite database"""
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise Exception(f"Failed to connect to SQLite database: {e}")
    
    def _disconnect(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def analyze(self, recover_deleted: bool = False, check_journal: bool = False, 
                page_hash: bool = False):
        """Perform comprehensive forensic analysis"""
        self.logger.info(f"Starting forensic analysis of {self.db_path}")
        
        try:
            self._connect()
            
            # Set metadata
            self.formatter.set_metadata(
                db_type="SQLite",
                db_name=str(self.db_path),
                db_size=self.db_path.stat().st_size
            )
            
            # 1. Extract metadata
            self._extract_metadata()
            
            # 2. Analyze schema
            self._analyze_schema()
            
            # 2a. Analyze foreign keys and relationships
            self._analyze_relationships()
            
            # 3. Check for tampering in sqlite_master
            self._check_sqlite_master_tampering()
            
            # 4. Compute file hash
            file_hash = self._compute_file_hash()
            
            # 4a. Hash comparison
            if self.compare_baseline and self.baseline_manager:
                self._compare_hashes(file_hash)
            
            # 4b. Dropped table detection
            if self.compare_baseline and self.baseline_manager:
                self._detect_dropped_tables()
            
            # 4c. Save baseline if requested
            if self.create_baseline and self.baseline_manager:
                self._save_baseline(file_hash)
            
            # 5. Recover deleted data
            if recover_deleted:
                self._recover_deleted_rows()
            
            # 6. Check journal/WAL files
            if check_journal:
                self._check_journal_wal()
            
            # 7. Page-level hashing
            if page_hash:
                self._compute_page_hashes()
            
            # 8. Detect suspicious activity
            self._detect_suspicious_activity()
            
        finally:
            self._disconnect()
        
        # Save report
        self.formatter.save_report()
    
    def _extract_metadata(self):
        """Extract database metadata"""
        try:
            cursor = self.conn.execute("PRAGMA quick_check")
            quick_check = cursor.fetchone()[0]
            
            cursor = self.conn.execute("PRAGMA integrity_check")
            integrity_check = cursor.fetchone()[0]
            
            cursor = self.conn.execute("PRAGMA user_version")
            user_version = cursor.fetchone()[0]
            
            # Get SQLite version
            sqlite_version = sqlite3.sqlite_version
            
            metadata = {
                "sqlite_version": sqlite_version,
                "user_version": user_version,
                "quick_check": quick_check,
                "integrity_check": integrity_check,
                "page_size": None,
                "page_count": None
            }
            
            # Get page info
            cursor = self.conn.execute("PRAGMA page_size")
            metadata["page_size"] = cursor.fetchone()[0]
            
            cursor = self.conn.execute("PRAGMA page_count")
            metadata["page_count"] = cursor.fetchone()[0]
            
            self.formatter.add_finding(
                category="metadata",
                severity="info",
                title="Database Metadata Extracted",
                description=f"SQLite version: {sqlite_version}, Page size: {metadata['page_size']}, Pages: {metadata['page_count']}",
                evidence=metadata
            )
            
            if integrity_check != "ok":
                self.formatter.add_finding(
                    category="integrity",
                    severity="critical",
                    title="Database Integrity Check Failed",
                    description=f"Integrity check returned: {integrity_check}",
                    evidence={"integrity_result": integrity_check}
                )
            
        except sqlite3.Error as e:
            self.logger.error(f"Error extracting metadata: {e}")
            self.formatter.add_finding(
                category="error",
                severity="warning",
                title="Metadata Extraction Error",
                description=str(e)
            )
    
    def _analyze_schema(self):
        """Analyze database schema"""
        try:
            cursor = self.conn.execute("""
                SELECT name, type, sql 
                FROM sqlite_master 
                WHERE type IN ('table', 'index', 'trigger', 'view')
                ORDER BY type, name
            """)
            
            schema_info = []
            tables = []
            indexes = []
            triggers = []
            views = []
            
            for row in cursor.fetchall():
                item = {
                    "name": row["name"],
                    "type": row["type"],
                    "sql": row["sql"]
                }
                schema_info.append(item)
                
                if row["type"] == "table":
                    tables.append(row["name"])
                elif row["type"] == "index":
                    indexes.append(row["name"])
                elif row["type"] == "trigger":
                    triggers.append(row["name"])
                elif row["type"] == "view":
                    views.append(row["name"])
            
            self.formatter.add_finding(
                category="schema",
                severity="info",
                title="Schema Analysis",
                description=f"Found {len(tables)} tables, {len(indexes)} indexes, {len(triggers)} triggers, {len(views)} views",
                evidence={
                    "tables": tables,
                    "total_objects": len(schema_info),
                    "schema_items": schema_info[:10]  # Limit evidence size
                }
            )
            
        except sqlite3.Error as e:
            self.logger.error(f"Error analyzing schema: {e}")
    
    def _analyze_relationships(self):
        """Analyze foreign keys and relationships"""
        try:
            # Get all tables
            cursor = self.conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """)
            tables = [row["name"] for row in cursor.fetchall()]
            
            foreign_keys = []
            for table in tables:
                try:
                    # Enable foreign key checking
                    self.conn.execute("PRAGMA foreign_keys")
                    
                    # Get foreign key information
                    cursor = self.conn.execute(f"PRAGMA foreign_key_list({table})")
                    fks = cursor.fetchall()
                    
                    for fk in fks:
                        try:
                            on_update = fk["on_update"]
                        except (KeyError, IndexError):
                            on_update = ""
                        try:
                            on_delete = fk["on_delete"]
                        except (KeyError, IndexError):
                            on_delete = ""
                        try:
                            match = fk["match"]
                        except (KeyError, IndexError):
                            match = ""
                        
                        foreign_keys.append({
                            "table": table,
                            "id": fk["id"],
                            "seq": fk["seq"],
                            "from": fk["from"],
                            "to": fk["to"],
                            "on_update": on_update,
                            "on_delete": on_delete,
                            "match": match
                        })
                except sqlite3.Error:
                    # Table might not exist or FK not enabled
                    pass
            
            if foreign_keys:
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Foreign Key Relationships",
                    description=f"Found {len(foreign_keys)} foreign key relationships",
                    evidence={"foreign_keys": foreign_keys[:20]}  # Limit evidence
                )
            else:
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Foreign Key Relationships",
                    description="No foreign key relationships found",
                    evidence={"foreign_keys": []}
                )
                
        except sqlite3.Error as e:
            self.logger.error(f"Error analyzing relationships: {e}")
    
    def _check_sqlite_master_tampering(self):
        """Check for tampering in sqlite_master table"""
        try:
            # Check if sqlite_master has been modified
            cursor = self.conn.execute("SELECT COUNT(*) as cnt FROM sqlite_master")
            count = cursor.fetchone()["cnt"]
            
            # Compute hash of sqlite_master structure
            cursor = self.conn.execute("""
                SELECT type, name, tbl_name, sql 
                FROM sqlite_master 
                ORDER BY type, name
            """)
            
            schema_string = ""
            for row in cursor.fetchall():
                try:
                    tbl_name = row['tbl_name']
                except (KeyError, IndexError):
                    tbl_name = ''
                try:
                    sql = row['sql']
                except (KeyError, IndexError):
                    sql = ''
                schema_string += f"{row['type']}|{row['name']}|{tbl_name}|{sql}\n"
            
            schema_hash = compute_string_hash(schema_string)
            
            # Check for suspicious entries
            cursor = self.conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE name LIKE 'sqlite_%' AND name != 'sqlite_master'
            """)
            suspicious = [row["name"] for row in cursor.fetchall()]
            
            if suspicious:
                self.formatter.add_finding(
                    category="tampering",
                    severity="warning",
                    title="Potential SQLite System Table Modification",
                    description=f"Found suspicious system entries: {', '.join(suspicious)}",
                    evidence={"suspicious_entries": suspicious}
                )
            
            self.formatter.add_finding(
                category="integrity",
                severity="info",
                title="SQLite Master Table Analysis",
                description=f"Schema hash: {schema_hash[:16]}..., Objects: {count}",
                evidence={"schema_hash": schema_hash, "object_count": count}
            )
            
        except sqlite3.Error as e:
            self.logger.error(f"Error checking sqlite_master: {e}")
    
    def _compute_file_hash(self) -> Optional[str]:
        """Compute hash of the database file"""
        try:
            file_hash = compute_file_hash(str(self.db_path))
            
            self.formatter.add_finding(
                category="integrity",
                severity="info",
                title="Database File Hash",
                description=f"SHA256: {file_hash}",
                evidence={"file_hash_sha256": file_hash, "file_path": str(self.db_path)}
            )
            
            return file_hash
            
        except Exception as e:
            self.logger.error(f"Error computing file hash: {e}")
            return None
    
    def _compare_hashes(self, file_hash: Optional[str]):
        """Compare current hashes with baseline"""
        if not file_hash:
            return
        
        try:
            current_hashes = {
                "file_hash": file_hash
            }
            
            # Add page hashes if available
            # (This would be populated if page_hash was enabled)
            
            comparison = self.baseline_manager.compare_hashes(
                "SQLite", str(self.db_path), current_hashes
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
                        description=f"Found {len(comparison['mismatches'])} hash mismatches - database may have been modified",
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
            cursor = self.conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            current_tables = [row["name"] for row in cursor.fetchall()]
            
            comparison = self.baseline_manager.compare_tables(
                "SQLite", str(self.db_path), current_tables
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
    
    def _save_baseline(self, file_hash: Optional[str]):
        """Save baseline data"""
        try:
            cursor = self.conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            tables = [row["name"] for row in cursor.fetchall()]
            
            baseline_data = {
                "tables": tables,
                "hashes": {
                    "file_hash": file_hash or ""
                }
            }
            
            self.baseline_manager.save_baseline("SQLite", str(self.db_path), baseline_data)
            
            self.formatter.add_finding(
                category="baseline",
                severity="info",
                title="Baseline Created",
                description=f"Baseline saved for {len(tables)} tables",
                evidence={"tables_count": len(tables), "baseline_file": self.baseline_manager.baseline_file}
            )
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")
    
    def _recover_deleted_rows(self):
        """Attempt to recover deleted rows from freelist pages"""
        try:
            # SQLite stores deleted row data in freelist pages
            # This is a simplified version - full recovery requires parsing binary format
            
            cursor = self.conn.execute("PRAGMA freelist_count")
            freelist_count = cursor.fetchone()[0]
            
            if freelist_count > 0:
                self.formatter.add_finding(
                    category="recovery",
                    severity="warning",
                    title="Freelist Pages Detected",
                    description=f"Found {freelist_count} freelist pages - deleted data may be recoverable",
                    evidence={"freelist_count": freelist_count}
                )
                
                # Attempt to read raw database pages (simplified)
                # Note: Full recovery requires binary parsing of SQLite file format
                self.logger.info(f"Freelist pages detected: {freelist_count}")
                
                # Check for potential recoverable data in unused space
                cursor = self.conn.execute("PRAGMA page_size")
                page_size = cursor.fetchone()[0]
                
                self.formatter.add_finding(
                    category="recovery",
                    severity="info",
                    title="Recovery Analysis",
                    description=f"Page size: {page_size} bytes. Full binary recovery required for deleted data extraction.",
                    evidence={"page_size": page_size, "note": "Use specialized tools for full deleted data recovery"}
                )
            else:
                self.formatter.add_finding(
                    category="recovery",
                    severity="info",
                    title="No Freelist Pages",
                    description="No deleted data found in freelist",
                    evidence={"freelist_count": 0}
                )
                
        except sqlite3.Error as e:
            self.logger.error(f"Error in deleted row recovery: {e}")
    
    def _check_journal_wal(self):
        """Check for journal and WAL files"""
        journal_path = self.db_path.with_suffix(self.db_path.suffix + '-journal')
        wal_path = self.db_path.with_suffix(self.db_path.suffix + '-wal')
        shm_path = self.db_path.with_suffix(self.db_path.suffix + '-shm')
        
        journal_found = journal_path.exists()
        wal_found = wal_path.exists()
        shm_found = shm_path.exists()
        
        findings = []
        
        if journal_found:
            journal_size = journal_path.stat().st_size
            journal_hash = compute_file_hash(str(journal_path))
            findings.append({
                "type": "journal",
                "path": str(journal_path),
                "size": journal_size,
                "hash": journal_hash
            })
            
            self.formatter.add_finding(
                category="recovery",
                severity="info",
                title="Journal File Found",
                description=f"Journal file exists: {journal_path.name} ({journal_size} bytes)",
                evidence={"journal_file": findings[-1]}
            )
        
        if wal_found:
            wal_size = wal_path.stat().st_size
            wal_hash = compute_file_hash(str(wal_path))
            findings.append({
                "type": "wal",
                "path": str(wal_path),
                "size": wal_size,
                "hash": wal_hash
            })
            
            self.formatter.add_finding(
                category="recovery",
                severity="info",
                title="WAL File Found",
                description=f"WAL file exists: {wal_path.name} ({wal_size} bytes)",
                evidence={"wal_file": findings[-1]}
            )
        
        if not journal_found and not wal_found:
            self.formatter.add_finding(
                category="recovery",
                severity="info",
                title="No Journal/WAL Files",
                description="No journal or WAL files found",
                evidence={"journal_found": False, "wal_found": False}
            )
    
    def _compute_page_hashes(self):
        """Compute hashes of individual database pages"""
        try:
            cursor = self.conn.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]
            
            cursor = self.conn.execute("PRAGMA page_count")
            page_count = cursor.fetchone()[0]
            
            page_hashes = {}
            
            with open(self.db_path, 'rb') as f:
                # Skip header (first page)
                f.seek(100)  # SQLite header is 100 bytes
                
                # Read sample pages (limit to first 10 for performance)
                for page_num in range(2, min(12, page_count + 1)):
                    page_data = f.read(page_size)
                    if len(page_data) == page_size:
                        page_hash = hashlib.sha256(page_data).hexdigest()
                        page_hashes[page_num] = page_hash[:16] + "..."
            
            self.formatter.add_finding(
                category="integrity",
                severity="info",
                title="Page-Level Hash Analysis",
                description=f"Computed hashes for sample pages (total pages: {page_count})",
                evidence={"page_hashes": page_hashes, "total_pages": page_count}
            )
            
        except Exception as e:
            self.logger.error(f"Error computing page hashes: {e}")
    
    def _detect_suspicious_activity(self):
        """Detect suspicious activity in database"""
        try:
            # Check for tables with suspicious names
            cursor = self.conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE '%temp%' OR name LIKE '%tmp%'
            """)
            temp_tables = [row["name"] for row in cursor.fetchall()]
            
            if temp_tables:
                self.formatter.add_finding(
                    category="suspicious",
                    severity="warning",
                    title="Temporary Tables Detected",
                    description=f"Found tables with suspicious names: {', '.join(temp_tables)}",
                    evidence={"temp_tables": temp_tables}
                )
            
            # Check for triggers that might indicate tampering
            cursor = self.conn.execute("""
                SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger'
            """)
            triggers = [{"name": row["name"], "table": row["tbl_name"], "sql": row["sql"]} 
                       for row in cursor.fetchall()]
            
            if triggers:
                self.formatter.add_finding(
                    category="suspicious",
                    severity="info",
                    title="Database Triggers Found",
                    description=f"Found {len(triggers)} triggers - review for suspicious behavior",
                    evidence={"triggers": triggers[:5]}  # Limit evidence
                )
            
        except sqlite3.Error as e:
            self.logger.error(f"Error detecting suspicious activity: {e}")

