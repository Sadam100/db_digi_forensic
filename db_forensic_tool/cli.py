#!/usr/bin/env python3
"""
Main CLI entry point for Database Forensic Tool
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from db_forensic_tool.forensic_sqlite import SQLiteForensic
from db_forensic_tool.forensic_mysql import MySQLForensic
from db_forensic_tool.forensic_mongodb import MongoDBForensic
from db_forensic_tool.utils import OutputFormatter, BaselineManager, setup_logging


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Database Forensic Tool - Analyze SQLite, MySQL, and MongoDB databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze SQLite database
  python -m db_forensic_tool sqlite database.db --output report.json

  # Analyze MySQL with binlog
  python -m db_forensic_tool mysql --host localhost --user root --database testdb --binlog /var/log/mysql/binlog.000001

  # Analyze MongoDB oplog
  python -m db_forensic_tool mongodb --uri mongodb://localhost:27017 --database testdb
        """
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path for forensic report (JSON format)"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format (default: both)"
    )
    
    parser.add_argument(
        "--baseline-file",
        type=str,
        default="baseline.json",
        help="Path to baseline file for comparison (default: baseline.json)"
    )
    
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="Create a baseline snapshot for future comparisons"
    )
    
    parser.add_argument(
        "--compare-baseline",
        action="store_true",
        help="Compare current state with baseline"
    )
    
    subparsers = parser.add_subparsers(dest="db_type", help="Database type", required=True)
    
    # SQLite parser
    sqlite_parser = subparsers.add_parser("sqlite", help="Analyze SQLite database")
    sqlite_parser.add_argument("database", type=str, help="Path to SQLite database file")
    sqlite_parser.add_argument(
        "--recover-deleted",
        action="store_true",
        help="Attempt to recover deleted rows from freelist pages"
    )
    sqlite_parser.add_argument(
        "--check-journal",
        action="store_true",
        help="Check for journal/WAL files and attempt recovery"
    )
    sqlite_parser.add_argument(
        "--page-hash",
        action="store_true",
        help="Compute hash of individual database pages"
    )
    # Add parent arguments to subparser
    sqlite_parser.add_argument("--output", "-o", type=str, help="Output file path for forensic report (JSON format)")
    sqlite_parser.add_argument("--format", choices=["json", "text", "both"], default="both", help="Output format (default: both)")
    sqlite_parser.add_argument("--baseline-file", type=str, default="baseline.json", help="Path to baseline file for comparison (default: baseline.json)")
    sqlite_parser.add_argument("--create-baseline", action="store_true", help="Create a baseline snapshot for future comparisons")
    sqlite_parser.add_argument("--compare-baseline", action="store_true", help="Compare current state with baseline")
    sqlite_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # MySQL parser
    mysql_parser = subparsers.add_parser("mysql", help="Analyze MySQL database")
    mysql_parser.add_argument("--host", type=str, default="localhost", help="MySQL host")
    mysql_parser.add_argument("--port", type=int, default=3306, help="MySQL port")
    mysql_parser.add_argument("--user", type=str, required=True, help="MySQL username")
    mysql_parser.add_argument("--password", type=str, help="MySQL password")
    mysql_parser.add_argument("--database", type=str, required=True, help="Database name")
    mysql_parser.add_argument("--binlog", type=str, help="Path to binlog file for analysis")
    mysql_parser.add_argument("--error-log", type=str, help="Path to MySQL error log")
    mysql_parser.add_argument("--general-log", type=str, help="Path to MySQL general query log")
    mysql_parser.add_argument(
        "--suspicious-ops",
        action="store_true",
        help="Focus on suspicious operations (DROP, ALTER, DELETE)"
    )
    # Add parent arguments to subparser
    mysql_parser.add_argument("--output", "-o", type=str, help="Output file path for forensic report (JSON format)")
    mysql_parser.add_argument("--format", choices=["json", "text", "both"], default="both", help="Output format (default: both)")
    mysql_parser.add_argument("--baseline-file", type=str, default="baseline.json", help="Path to baseline file for comparison (default: baseline.json)")
    mysql_parser.add_argument("--create-baseline", action="store_true", help="Create a baseline snapshot for future comparisons")
    mysql_parser.add_argument("--compare-baseline", action="store_true", help="Compare current state with baseline")
    mysql_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # MongoDB parser
    mongo_parser = subparsers.add_parser("mongodb", help="Analyze MongoDB database")
    mongo_parser.add_argument("--uri", type=str, help="MongoDB connection URI")
    mongo_parser.add_argument("--host", type=str, default="localhost", help="MongoDB host")
    mongo_parser.add_argument("--port", type=int, default=27017, help="MongoDB port")
    mongo_parser.add_argument("--user", type=str, help="MongoDB username")
    mongo_parser.add_argument("--password", type=str, help="MongoDB password")
    mongo_parser.add_argument("--database", type=str, required=True, help="Database name")
    mongo_parser.add_argument("--oplog", type=str, help="Path to oplog.rs file (if analyzing offline)")
    mongo_parser.add_argument(
        "--check-timestamps",
        action="store_true",
        help="Check for timestamp anomalies"
    )
    # Add parent arguments to subparser
    mongo_parser.add_argument("--output", "-o", type=str, help="Output file path for forensic report (JSON format)")
    mongo_parser.add_argument("--format", choices=["json", "text", "both"], default="both", help="Output format (default: both)")
    mongo_parser.add_argument("--baseline-file", type=str, default="baseline.json", help="Path to baseline file for comparison (default: baseline.json)")
    mongo_parser.add_argument("--create-baseline", action="store_true", help="Create a baseline snapshot for future comparisons")
    mongo_parser.add_argument("--compare-baseline", action="store_true", help="Compare current state with baseline")
    mongo_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    # Initialize output formatter
    formatter = OutputFormatter(output_file=args.output, format_type=args.format)
    
    # Initialize baseline manager if needed
    baseline_manager = None
    if args.create_baseline or args.compare_baseline:
        baseline_manager = BaselineManager(baseline_file=args.baseline_file)
    
    try:
        if args.db_type == "sqlite":
            analyzer = SQLiteForensic(
                args.database,
                formatter=formatter,
                baseline_manager=baseline_manager,
                create_baseline=args.create_baseline,
                compare_baseline=args.compare_baseline
            )
            analyzer.analyze(
                recover_deleted=args.recover_deleted,
                check_journal=args.check_journal,
                page_hash=args.page_hash
            )
            
        elif args.db_type == "mysql":
            analyzer = MySQLForensic(
                host=args.host,
                port=args.port,
                user=args.user,
                password=args.password,
                database=args.database,
                formatter=formatter,
                baseline_manager=baseline_manager,
                create_baseline=args.create_baseline,
                compare_baseline=args.compare_baseline
            )
            analyzer.analyze(
                binlog_path=args.binlog,
                error_log_path=args.error_log,
                general_log_path=args.general_log,
                suspicious_ops=args.suspicious_ops
            )
            
        elif args.db_type == "mongodb":
            analyzer = MongoDBForensic(
                uri=args.uri,
                host=args.host,
                port=args.port,
                user=args.user,
                password=args.password,
                database=args.database,
                formatter=formatter,
                baseline_manager=baseline_manager,
                create_baseline=args.create_baseline,
                compare_baseline=args.compare_baseline
            )
            analyzer.analyze(
                oplog_path=args.oplog,
                check_timestamps=args.check_timestamps
            )
            
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print("\n✓ Forensic analysis completed successfully!")
    if args.output:
        print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()

