import os
import duckdb
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

DEFAULT_DB_PATH = os.getenv("DUCKDB_PATH", "data/golden_seed.duckdb")

def get_db_path() -> str:
    return os.getenv("DUCKDB_PATH", DEFAULT_DB_PATH)

def get_connection(read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """Returns a connection to the DuckDB instance, creating directories if needed."""
    db_path = get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    return duckdb.connect(db_path, read_only=read_only)

def init_db(db_path: str = None) -> None:
    """Initializes tables using schema.sql."""
    target_path = db_path or get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    con = duckdb.connect(target_path)
    con.execute(schema_sql)
    con.close()

if __name__ == "__main__":
    init_db()
    print(f"Database initialized successfully at {get_db_path()}")
