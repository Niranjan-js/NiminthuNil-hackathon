# PostgreSQL Migration Guide / தரவுத்தள இடம்பெயர்வு வழிகாட்டி

This folder contains the SQL migrations to setup NIRAVAN with a production PostgreSQL database.

---

## 🛠️ Setup Instructions / கட்டமைப்பு வழிமுறைகள்

### Step 1: Create Database
Log into the PostgreSQL CLI and create the user and database:

```sql
CREATE USER niravan_user WITH PASSWORD 'niravan_pass';
CREATE DATABASE niravan_prod OWNER niravan_user;
```

### Step 2: Apply Migrations
Apply the migration scripts in sequence:

```bash
# Apply initial schema tables
psql -U niravan_user -d niravan_prod -f 001_initial_schema.sql

# Seed initial assets and admin profile
psql -U niravan_user -d niravan_prod -f 002_tn_departments.sql
```

### Step 3: Configure environment URL
Update your `/var/www/niravan/backend/.env` file to point to the new PostgreSQL server:

```env
NIRAVAN_DB_URL=postgresql://niravan_user:niravan_pass@localhost:5432/niravan_prod
```
