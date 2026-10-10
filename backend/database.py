import configparser
import os
import pymysql
import pymysql.cursors

CNF_FILE = os.getenv("MYSQL_CNF_FILE", "/etc/mail-secrets/mysql-vmail.cnf")

def get_db_config():
    # Priority 1: Environment Variables
    if os.getenv("DB_PASSWORD"):
        return {
            "host": os.getenv("DB_HOST", "127.0.0.1"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "vmail"),
            "password": os.getenv("DB_PASSWORD", "").strip("\"'"),
            "database": os.getenv("DB_NAME", "vmail"),
            "charset": "utf8mb4",
            "cursorclass": pymysql.cursors.DictCursor,
            "autocommit": True
        }

    # Priority 2: MySQL client cnf file
    if os.path.exists(CNF_FILE):
        cfg = configparser.ConfigParser()
        cfg.read(CNF_FILE)
        client = cfg["client"]
        return {
            "host": client.get("host", "127.0.0.1"),
            "port": int(client.get("port", "3306")),
            "user": client.get("user", "vmail"),
            "password": client.get("password", "").strip("\"'"),
            "database": client.get("database", "vmail"),
            "charset": "utf8mb4",
            "cursorclass": pymysql.cursors.DictCursor,
            "autocommit": True
        }

    # Fallback default (e.g. local socket or empty pass)
    return {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "user": os.getenv("DB_USER", "vmail"),
        "password": "",
        "database": os.getenv("DB_NAME", "vmail"),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": True
    }

def get_connection():
    config = get_db_config()
    return pymysql.connect(**config)
