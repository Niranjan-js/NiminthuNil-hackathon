import os
import sys

# Remove existing test DB to ensure a clean schema is recreated
for db_file in ["test_niravan_database.db", "backend/test_niravan_database.db"]:
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass

# Set test database URL before any models or database engines are initialized
os.environ["NIRAVAN_DB_URL"] = "sqlite:///test_niravan_database.db"
os.environ["NIRAVAN_ENV"] = "test"
