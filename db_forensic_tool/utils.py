"""
Common utilities for database forensic analysis
"""

import hashlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


class OutputFormatter:
    """Handle formatted output for forensic reports"""
    
    def __init__(self, output_file: Optional[str] = None, format_type: str = "both"):
        self.output_file = output_file
        self.format_type = format_type
        self.report_data: Dict[str, Any] = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "tool": "Database Forensic Tool v1.0.0"
            },
            "findings": []
        }
    
    def add_finding(self, category: str, severity: str, title: str, description: str, 
                   evidence: Optional[Dict[str, Any]] = None):
        """Add a forensic finding to the report"""
        finding = {
            "category": category,
            "severity": severity,  # info, warning, critical
            "title": title,
            "description": description,
            "timestamp": datetime.utcnow().isoformat()
        }
        if evidence:
            finding["evidence"] = evidence
        
        self.report_data["findings"].append(finding)
        
        # Print to console
        if self.format_type in ["text", "both"]:
            severity_symbol = {
                "info": "ℹ",
                "warning": "⚠",
                "critical": "🚨"
            }.get(severity, "•")
            
            print(f"\n{severity_symbol} [{category.upper()}] {title}")
            print(f"   {description}")
            if evidence:
                print(f"   Evidence: {json.dumps(evidence, indent=6)[:200]}...")
    
    def set_metadata(self, db_type: str, db_name: str, **kwargs):
        """Set report metadata"""
        self.report_data["metadata"].update({
            "db_type": db_type,
            "db_name": db_name,
            **kwargs
        })
    
    def save_report(self):
        """Save the report to file"""
        if self.output_file and self.format_type in ["json", "both"]:
            with open(self.output_file, 'w') as f:
                json.dump(self.report_data, f, indent=2, default=str)
            logging.info(f"Report saved to {self.output_file}")


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute hash of a file"""
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def compute_string_hash(data: str, algorithm: str = "sha256") -> str:
    """Compute hash of a string"""
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def detect_suspicious_queries(queries: List[str]) -> List[Dict[str, Any]]:
    """Detect suspicious SQL queries"""
    suspicious_patterns = {
        "DROP TABLE": {"severity": "critical", "pattern": r"(?i)drop\s+table"},
        "DROP DATABASE": {"severity": "critical", "pattern": r"(?i)drop\s+database"},
        "DELETE FROM": {"severity": "warning", "pattern": r"(?i)delete\s+from"},
        "TRUNCATE": {"severity": "warning", "pattern": r"(?i)truncate"},
        "ALTER TABLE": {"severity": "warning", "pattern": r"(?i)alter\s+table"},
        "GRANT": {"severity": "warning", "pattern": r"(?i)grant\s+.*\s+on"},
        "REVOKE": {"severity": "warning", "pattern": r"(?i)revoke\s+.*\s+on"},
    }
    
    import re
    suspicious_findings = []
    
    for query in queries:
        query_lower = query.lower()
        for op_name, op_info in suspicious_patterns.items():
            if re.search(op_info["pattern"], query):
                suspicious_findings.append({
                    "operation": op_name,
                    "severity": op_info["severity"],
                    "query": query[:200]  # Truncate long queries
                })
    
    return suspicious_findings


def format_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format events into a timeline"""
    return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)


def validate_file_exists(file_path: str) -> bool:
    """Validate that a file exists"""
    path = Path(file_path)
    if not path.exists():
        logging.error(f"File not found: {file_path}")
        return False
    if not path.is_file():
        logging.error(f"Path is not a file: {file_path}")
        return False
    return True


class BaselineManager:
    """Manage baseline data for integrity comparison and dropped table detection"""
    
    def __init__(self, baseline_file: Optional[str] = None):
        self.baseline_file = baseline_file or "baseline.json"
        self.baseline_data: Dict[str, Any] = {}
        self.load_baseline()
    
    def load_baseline(self):
        """Load baseline data from file"""
        if Path(self.baseline_file).exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    self.baseline_data = json.load(f)
                logging.info(f"Loaded baseline from {self.baseline_file}")
            except Exception as e:
                logging.warning(f"Could not load baseline: {e}")
                self.baseline_data = {}
        else:
            self.baseline_data = {}
    
    def save_baseline(self, db_type: str, db_name: str, data: Dict[str, Any]):
        """Save baseline data to file"""
        if db_type not in self.baseline_data:
            self.baseline_data[db_type] = {}
        
        self.baseline_data[db_type][db_name] = {
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
        
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline_data, f, indent=2, default=str)
            logging.info(f"Saved baseline to {self.baseline_file}")
        except Exception as e:
            logging.error(f"Could not save baseline: {e}")
    
    def get_baseline(self, db_type: str, db_name: str) -> Optional[Dict[str, Any]]:
        """Get baseline data for a database"""
        return self.baseline_data.get(db_type, {}).get(db_name)
    
    def compare_hashes(self, db_type: str, db_name: str, current_hashes: Dict[str, str]) -> Dict[str, Any]:
        """Compare current hashes with baseline"""
        baseline = self.get_baseline(db_type, db_name)
        if not baseline or "hashes" not in baseline:
            return {"status": "no_baseline", "message": "No baseline found for comparison"}
        
        baseline_hashes = baseline.get("hashes", {})
        mismatches = {}
        matches = {}
        
        for key, current_hash in current_hashes.items():
            baseline_hash = baseline_hashes.get(key)
            if baseline_hash:
                if current_hash != baseline_hash:
                    mismatches[key] = {
                        "baseline": baseline_hash,
                        "current": current_hash
                    }
                else:
                    matches[key] = current_hash
        
        # Check for new hashes not in baseline
        new_items = {k: v for k, v in current_hashes.items() if k not in baseline_hashes}
        
        # Check for missing items (dropped)
        missing_items = {k: v for k, v in baseline_hashes.items() if k not in current_hashes}
        
        return {
            "status": "compared",
            "matches": len(matches),
            "mismatches": mismatches,
            "new_items": new_items,
            "missing_items": missing_items,
            "total_compared": len(baseline_hashes)
        }
    
    def compare_tables(self, db_type: str, db_name: str, current_tables: List[str]) -> Dict[str, Any]:
        """Compare current tables with baseline to detect dropped tables"""
        baseline = self.get_baseline(db_type, db_name)
        if not baseline or "tables" not in baseline:
            return {"status": "no_baseline", "message": "No baseline found for comparison"}
        
        baseline_tables = set(baseline.get("tables", []))
        current_tables_set = set(current_tables)
        
        dropped = list(baseline_tables - current_tables_set)
        added = list(current_tables_set - baseline_tables)
        unchanged = list(baseline_tables & current_tables_set)
        
        return {
            "status": "compared",
            "dropped": dropped,
            "added": added,
            "unchanged": unchanged,
            "baseline_count": len(baseline_tables),
            "current_count": len(current_tables)
        }

