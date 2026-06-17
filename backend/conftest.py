import os
import sys

# Set test database URL before any models or database engines are initialized
os.environ["NIRAVAN_DB_URL"] = "sqlite:///test_niravan_database.db"
os.environ["NIRAVAN_ENV"] = "test"
