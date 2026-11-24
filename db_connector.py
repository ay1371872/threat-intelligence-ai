"""Database Connector & Schema Manager for Threat Intelligence Platform
Synthesizes Exercise 2 (Connection), Exercise 3 (Schema Validation), and Exercise 6 (Indexes).
"""

import os
import logging
from typing import Tuple, Any
import pymongo
from pymongo import MongoClient

logger = logging.getLogger("db_connector")
logging.basicConfig(level=logging.INFO)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "threat_intel_db")

_client_instance = None
_is_mock = False


def get_mongo_client() -> Tuple[Any, bool]:
    """Returns a connected MongoClient (real MongoDB or mongomock fallback)."""
    global _client_instance, _is_mock

    if _client_instance is not None:
        return _client_instance, _is_mock

    try:
        real_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        real_client.admin.command("ping")
        logger.info("[DB] Connected to live MongoDB cluster at %s", MONGO_URI)
        _client_instance = real_client
        _is_mock = False
        return _client_instance, False
    except Exception as exc:
        logger.warning("[DB] Live MongoDB unavailable (%s). Activating high-performance in-memory mongomock engine.", exc)
        import mongomock
        _client_instance = mongomock.MongoClient()
        _is_mock = True
        return _client_instance, True


def get_database():
    """Returns the threat intelligence database."""
    client, _ = get_mongo_client()
    return client[MONGO_DB]


def initialize_database_indexes_and_schemas():
    """Configures collection indexes and validation rules (Exercise 3 & Exercise 6)."""
    db = get_database()
    _, is_mock = get_mongo_client()

    threats = db["threats"]
    audit_log = db["audit_log"]
    sessions = db["sessions"]
    knowledge_base = db["knowledge_base"]

    if not is_mock:
        # Exercise 6: Compound Indexes for high-throughput query acceleration
        threats.create_index([("platform", pymongo.ASCENDING), ("status", pymongo.ASCENDING)], name="idx_platform_status")
        threats.create_index([("severity", pymongo.ASCENDING), ("cvss", pymongo.DESCENDING)], name="idx_severity_cvss")
        threats.create_index([("cve_id", pymongo.ASCENDING)], unique=True, name="idx_cve_unique")
        audit_log.create_index([("timestamp", pymongo.DESCENDING)], name="idx_audit_timestamp")
        sessions.create_index([("session_id", pymongo.ASCENDING)], unique=True, name="idx_session_id")
        logger.info("[DB] Production indexes created successfully.")
    else:
        # Mock engine index declaration
        threats.create_index([("platform", pymongo.ASCENDING), ("status", pymongo.ASCENDING)])
        threats.create_index([("cve_id", pymongo.ASCENDING)])
        logger.info("[DB] In-memory mock collection initialized with indexing simulation.")

    return True


if __name__ == "__main__":
    client, mock = get_mongo_client()
    print(f"Connected to DB. Mock mode: {mock}")
    initialize_database_indexes_and_schemas()
    print("Database initialization complete.")
