"""
MongoDB Forensic Analysis Module
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, OperationFailure
    from bson import ObjectId
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False
    ObjectId = None

from db_forensic_tool.utils import OutputFormatter, BaselineManager, validate_file_exists


class MongoDBForensic:
    """MongoDB database forensic analyzer"""
    
    def __init__(self, uri: Optional[str] = None, host: str = "localhost", 
                 port: int = 27017, user: Optional[str] = None,
                 password: Optional[str] = None, database: str = "",
                 formatter: Optional[OutputFormatter] = None,
                 baseline_manager: Optional[BaselineManager] = None,
                 create_baseline: bool = False, compare_baseline: bool = False):
        self.uri = uri
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database_name = database
        self.formatter = formatter or OutputFormatter()
        self.baseline_manager = baseline_manager
        self.create_baseline = create_baseline
        self.compare_baseline = compare_baseline
        self.client = None
        self.db = None
        self.logger = logging.getLogger(__name__)
        
        if not PYMONGO_AVAILABLE:
            raise ImportError("pymongo is required for MongoDB analysis. Install with: pip install pymongo")
    
    def _connect(self):
        """Connect to MongoDB"""
        try:
            if self.uri:
                self.client = MongoClient(self.uri)
            else:
                if self.user and self.password:
                    self.client = MongoClient(
                        self.host,
                        self.port,
                        username=self.user,
                        password=self.password,
                        authSource='admin'
                    )
                else:
                    self.client = MongoClient(self.host, self.port)
            
            # Test connection
            self.client.admin.command('ping')
            
            if self.database_name:
                self.db = self.client[self.database_name]
            
        except ConnectionFailure as e:
            raise Exception(f"Failed to connect to MongoDB: {e}")
        except Exception as e:
            raise Exception(f"MongoDB connection error: {e}")
    
    def _disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
    
    def analyze(self, oplog_path: Optional[str] = None, check_timestamps: bool = False):
        """Perform comprehensive forensic analysis"""
        self.logger.info(f"Starting forensic analysis of MongoDB database: {self.database_name}")
        
        try:
            if not oplog_path:  # Only connect if not analyzing offline oplog
                self._connect()
            
            # Set metadata
            self.formatter.set_metadata(
                db_type="MongoDB",
                db_name=self.database_name,
                host=self.host,
                port=self.port
            )
            
            # 1. Extract metadata
            if not oplog_path:
                self._extract_metadata()
                
                # 2. Analyze schema (collections)
                collections = self._analyze_collections()
                
                # 2a. Note about relationships (MongoDB doesn't have FK constraints)
                self._analyze_relationships()
                
                # 3. Extract user/role info
                self._extract_user_info()
                
                # 3a. Compute collection hashes
                collection_hashes = self._hash_collections()
                
                # 3b. Hash comparison
                if self.compare_baseline and self.baseline_manager:
                    self._compare_hashes(collection_hashes)
                
                # 3c. Dropped collection detection
                if self.compare_baseline and self.baseline_manager:
                    self._detect_dropped_collections()
                
                # 3d. Save baseline if requested
                if self.create_baseline and self.baseline_manager:
                    self._save_baseline(collection_hashes, collections)
                
                # 4. Check system collections for tampering
                self._check_system_collections()
                
                # 5. Analyze oplog (if connected to replica set)
                self._analyze_oplog_online()
            
            # 6. Parse offline oplog file
            if oplog_path:
                self._parse_oplog_file(oplog_path, check_timestamps)
            
            # 7. Track operations
            if not oplog_path:
                self._track_operations()
            
            # 8. Check timestamp anomalies
            if check_timestamps:
                self._check_timestamp_anomalies()
            
        finally:
            if not oplog_path:
                self._disconnect()
        
        # Save report
        self.formatter.save_report()
    
    def _extract_metadata(self):
        """Extract MongoDB metadata"""
        try:
            server_info = self.client.server_info()
            db_stats = self.db.command("dbStats")
            
            metadata = {
                "mongodb_version": server_info.get("version", "unknown"),
                "storage_engine": server_info.get("storageEngine", {}).get("name", "unknown"),
                "database_size": db_stats.get("dataSize", 0),
                "collections": db_stats.get("collections", 0),
                "objects": db_stats.get("objects", 0)
            }
            
            self.formatter.add_finding(
                category="metadata",
                severity="info",
                title="MongoDB Metadata Extracted",
                description=f"MongoDB version: {metadata['mongodb_version']}, Collections: {metadata['collections']}",
                evidence=metadata
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {e}")
    
    def _analyze_collections(self) -> List[str]:
        """Analyze database collections"""
        try:
            collections = self.db.list_collection_names()
            
            collection_info = []
            for coll_name in collections:
                try:
                    coll = self.db[coll_name]
                    stats = self.db.command("collStats", coll_name)
                    
                    collection_info.append({
                        "name": coll_name,
                        "count": stats.get("count", 0),
                        "size": stats.get("size", 0),
                        "storageSize": stats.get("storageSize", 0)
                    })
                except Exception as e:
                    self.logger.debug(f"Could not get stats for {coll_name}: {e}")
            
            self.formatter.add_finding(
                category="schema",
                severity="info",
                title="Collection Analysis",
                description=f"Found {len(collections)} collections",
                evidence={"collections": collections, "collection_details": collection_info[:10]}
            )
            
            return collections
            
        except Exception as e:
            self.logger.error(f"Error analyzing collections: {e}")
            return []
    
    def _analyze_relationships(self):
        """Note about relationships (MongoDB doesn't have FK constraints)"""
        self.formatter.add_finding(
            category="schema",
            severity="info",
            title="Foreign Key Relationships",
            description="MongoDB is a NoSQL database and does not enforce foreign key constraints. Relationships are maintained at the application level.",
            evidence={"note": "Check application code for relationship logic"}
        )
    
    def _extract_user_info(self):
        """Extract user and role information"""
        try:
            # Get users from admin database
            admin_db = self.client.admin
            
            try:
                users = list(admin_db.command("usersInfo")["users"])
                
                user_info = []
                for user in users:
                    user_info.append({
                        "user": user.get("user", ""),
                        "roles": user.get("roles", []),
                        "db": user.get("db", "")
                    })
                
                self.formatter.add_finding(
                    category="security",
                    severity="info",
                    title="User and Role Information",
                    description=f"Found {len(users)} users",
                    evidence={"users": user_info}
                )
                
            except OperationFailure:
                # User doesn't have permission
                self.logger.debug("Cannot access user information - insufficient permissions")
                self.formatter.add_finding(
                    category="security",
                    severity="warning",
                    title="User Information Unavailable",
                    description="Insufficient permissions to access user information"
                )
            
        except Exception as e:
            self.logger.error(f"Error extracting user info: {e}")
    
    def _check_system_collections(self):
        """Check system collections for tampering"""
        try:
            # Check for system collections
            system_collections = [
                "system.users",
                "system.roles",
                "system.version"
            ]
            
            existing_system = []
            for sys_coll in system_collections:
                try:
                    if sys_coll in self.db.list_collection_names():
                        count = self.db[sys_coll].count_documents({})
                        existing_system.append({
                            "collection": sys_coll,
                            "document_count": count
                        })
                except Exception:
                    pass
            
            if existing_system:
                self.formatter.add_finding(
                    category="tampering",
                    severity="warning",
                    title="System Collections in Database",
                    description=f"Found {len(existing_system)} system collections in user database",
                    evidence={"system_collections": existing_system}
                )
            
        except Exception as e:
            self.logger.error(f"Error checking system collections: {e}")
    
    def _analyze_oplog_online(self):
        """Analyze oplog from connected MongoDB instance"""
        try:
            # Check if this is a replica set
            is_master = self.client.admin.command("isMaster")
            
            if is_master.get("setName"):
                # This is a replica set - oplog should be available
                local_db = self.client.local
                
                if "oplog.rs" in local_db.list_collection_names():
                    oplog = local_db.oplog.rs
                    
                    # Get recent operations
                    recent_ops = list(oplog.find().sort("ts", -1).limit(100))
                    
                    if recent_ops:
                        # Categorize operations
                        op_types = {}
                        for op in recent_ops:
                            op_type = op.get("op", "unknown")
                            op_types[op_type] = op_types.get(op_type, 0) + 1
                        
                        self.formatter.add_finding(
                            category="audit",
                            severity="info",
                            title="Oplog Analysis (Online)",
                            description=f"Found {len(recent_ops)} recent operations in oplog",
                            evidence={
                                "operation_types": op_types,
                                "sample_operations": [
                                    {
                                        "op": op.get("op"),
                                        "ns": op.get("ns"),
                                        "ts": str(op.get("ts", ""))[:50]
                                    } for op in recent_ops[:5]
                                ]
                            }
                        )
                else:
                    self.formatter.add_finding(
                        category="audit",
                        severity="info",
                        title="Oplog Not Available",
                        description="Oplog collection not found (may not be a replica set)"
                    )
            else:
                self.formatter.add_finding(
                    category="audit",
                    severity="info",
                    title="Not a Replica Set",
                    description="Instance is not part of a replica set - oplog not available"
                )
            
        except Exception as e:
            self.logger.debug(f"Oplog analysis not available: {e}")
    
    def _parse_oplog_file(self, oplog_path: str, check_timestamps: bool):
        """Parse oplog from file (BSON or JSON format)"""
        if not validate_file_exists(oplog_path):
            self.logger.warning(f"Oplog file not found: {oplog_path}")
            return
        
        try:
            # Try to parse as JSON first
            operations = []
            
            with open(oplog_path, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    # Try JSON format
                    data = json.load(f)
                    if isinstance(data, list):
                        operations = data
                    elif isinstance(data, dict) and "operations" in data:
                        operations = data["operations"]
                except json.JSONDecodeError:
                    # Not JSON - might be BSON (would need bson library)
                    self.logger.warning("Oplog file is not JSON format. BSON parsing requires additional libraries.")
                    self.formatter.add_finding(
                        category="audit",
                        severity="warning",
                        title="Oplog File Format",
                        description="Oplog file is not in JSON format. Install bson library for BSON parsing.",
                        evidence={"oplog_path": oplog_path}
                    )
                    return
            
            if operations:
                # Categorize operations
                op_types = {}
                timestamp_anomalies = []
                
                for op in operations[:1000]:  # Limit analysis
                    op_type = op.get("op", "unknown")
                    op_types[op_type] = op_types.get(op_type, 0) + 1
                    
                    if check_timestamps:
                        ts = op.get("ts")
                        if ts:
                            # Check for timestamp anomalies
                            # (simplified - would need proper timestamp parsing)
                            pass
                
                self.formatter.add_finding(
                    category="audit",
                    severity="info",
                    title="Oplog File Parsed",
                    description=f"Parsed {len(operations)} operations from oplog file",
                    evidence={
                        "operation_types": op_types,
                        "total_operations": len(operations),
                        "sample_operations": operations[:5]
                    }
                )
            
        except Exception as e:
            self.logger.error(f"Error parsing oplog file: {e}")
    
    def _track_operations(self):
        """Track insert/update/delete operations (from oplog if available)"""
        try:
            local_db = self.client.local
            
            if "oplog.rs" in local_db.list_collection_names():
                oplog = local_db.oplog.rs
                
                # Count operations by type
                op_counts = {
                    "i": oplog.count_documents({"op": "i"}),  # insert
                    "u": oplog.count_documents({"op": "u"}),  # update
                    "d": oplog.count_documents({"op": "d"}),  # delete
                    "c": oplog.count_documents({"op": "c"}),  # command
                }
                
                # Get recent suspicious operations
                suspicious_ops = list(oplog.find({
                    "op": {"$in": ["d", "c"]},
                    "ns": {"$regex": f"^{self.database_name}"}
                }).sort("ts", -1).limit(20))
                
                if suspicious_ops:
                    self.formatter.add_finding(
                        category="suspicious",
                        severity="warning",
                        title="Suspicious Operations Detected",
                        description=f"Found {len(suspicious_ops)} delete/command operations on database",
                        evidence={
                            "operation_counts": op_counts,
                            "suspicious_operations": [
                                {
                                    "op": op.get("op"),
                                    "ns": op.get("ns"),
                                    "ts": str(op.get("ts", ""))[:50]
                                } for op in suspicious_ops[:10]
                            ]
                        }
                    )
            
        except Exception as e:
            self.logger.debug(f"Operation tracking not available: {e}")
    
    def _check_timestamp_anomalies(self):
        """Check for timestamp anomalies in documents"""
        try:
            anomalies = []
            
            for coll_name in self.db.list_collection_names()[:10]:  # Limit to first 10 collections
                coll = self.db[coll_name]
                
                # Sample documents and check timestamps
                sample_docs = list(coll.find().limit(100))
                
                for doc in sample_docs:
                    # Check for _id timestamps (ObjectId contains timestamp)
                    if "_id" in doc and ObjectId:
                        try:
                            if isinstance(doc["_id"], ObjectId):
                                doc_time = doc["_id"].generation_time
                                # Check if timestamp is in future or very old
                                now = datetime.utcnow()
                                if doc_time > now:
                                    anomalies.append({
                                        "collection": coll_name,
                                        "anomaly": "future_timestamp",
                                        "timestamp": str(doc_time)
                                    })
                        except Exception:
                            pass
            
            if anomalies:
                self.formatter.add_finding(
                    category="tampering",
                    severity="warning",
                    title="Timestamp Anomalies Detected",
                    description=f"Found {len(anomalies)} timestamp anomalies",
                    evidence={"anomalies": anomalies[:10]}
                )
            else:
                self.formatter.add_finding(
                    category="integrity",
                    severity="info",
                    title="Timestamp Check",
                    description="No timestamp anomalies detected in sampled documents"
                )
            
        except Exception as e:
            self.logger.error(f"Error checking timestamp anomalies: {e}")
    
    def _hash_collections(self) -> Dict[str, str]:
        """Compute hashes of collections to detect silent changes"""
        collection_hashes = {}
        try:
            collections = self.db.list_collection_names()
            
            for coll_name in collections[:10]:  # Limit to first 10
                try:
                    coll = self.db[coll_name]
                    stats = self.db.command("collStats", coll_name)
                    
                    # Create hash from collection stats
                    hash_string = f"{coll_name}|{stats.get('count', 0)}|{stats.get('size', 0)}|{stats.get('storageSize', 0)}"
                    import hashlib
                    coll_hash = hashlib.sha256(hash_string.encode()).hexdigest()[:16]
                    collection_hashes[f"collection_{coll_name}"] = coll_hash
                    
                except Exception as e:
                    self.logger.debug(f"Could not hash collection {coll_name}: {e}")
            
            if collection_hashes:
                self.formatter.add_finding(
                    category="integrity",
                    severity="info",
                    title="Collection Hash Analysis",
                    description=f"Computed hashes for {len(collection_hashes)} collections",
                    evidence={"collection_hashes": collection_hashes}
                )
            
        except Exception as e:
            self.logger.error(f"Error hashing collections: {e}")
        
        return collection_hashes
    
    def _compare_hashes(self, collection_hashes: Dict[str, str]):
        """Compare current hashes with baseline"""
        try:
            comparison = self.baseline_manager.compare_hashes(
                "MongoDB", self.database_name, collection_hashes
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
                        description=f"Found {len(comparison['mismatches'])} hash mismatches - collections may have been modified",
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
    
    def _detect_dropped_collections(self):
        """Detect dropped collections by comparing with baseline"""
        try:
            current_collections = self.db.list_collection_names()
            
            comparison = self.baseline_manager.compare_tables(
                "MongoDB", self.database_name, current_collections
            )
            
            if comparison["status"] == "no_baseline":
                self.formatter.add_finding(
                    category="schema",
                    severity="info",
                    title="Dropped Collection Detection",
                    description="No baseline found for comparison. Use --create-baseline to create one.",
                    evidence=comparison
                )
            else:
                if comparison["dropped"]:
                    self.formatter.add_finding(
                        category="suspicious",
                        severity="critical",
                        title="Dropped Collections Detected",
                        description=f"Found {len(comparison['dropped'])} dropped collections: {', '.join(comparison['dropped'])}",
                        evidence=comparison
                    )
                
                if comparison["added"]:
                    self.formatter.add_finding(
                        category="schema",
                        severity="info",
                        title="New Collections Detected",
                        description=f"Found {len(comparison['added'])} new collections: {', '.join(comparison['added'])}",
                        evidence=comparison
                    )
                    
        except Exception as e:
            self.logger.error(f"Error detecting dropped collections: {e}")
    
    def _save_baseline(self, collection_hashes: Dict[str, str], collections: List[str]):
        """Save baseline data"""
        try:
            baseline_data = {
                "tables": collections,  # Using 'tables' key for consistency with compare_tables
                "hashes": collection_hashes
            }
            
            self.baseline_manager.save_baseline("MongoDB", self.database_name, baseline_data)
            
            self.formatter.add_finding(
                category="baseline",
                severity="info",
                title="Baseline Created",
                description=f"Baseline saved for {len(collections)} collections",
                evidence={"collections_count": len(collections), "baseline_file": self.baseline_manager.baseline_file}
            )
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")

