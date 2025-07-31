#!/bin/bash
# PostgreSQL Audit Script - Bash + psql
# Target: PostgreSQL 11/13/15
# Functions: Users/roles export, authentication check, logs, version

# Configuration
PGUSER=${PGUSER:-postgres}
PGHOST=${PGHOST:-localhost}
PGPORT=${PGPORT:-5432}
PGDATABASE=${PGDATABASE:-postgres}

# Initialize variables
hostname=$(hostname)
os="PostgreSQL"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

# Test PostgreSQL connection
if ! psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "SELECT 1;" >/dev/null 2>&1; then
    echo "Failed to connect to PostgreSQL"
    exit 1
fi

echo "Starting PostgreSQL audit - $date"
echo "Output directory: $outdir"

# 1. PostgreSQL Version
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (SELECT version() as version) TO '$outdir/postgres_version.csv' CSV HEADER" 2>/dev/null

# 2. Export Users and Roles with Permissions
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        rolname as role_name,
        rolsuper as is_superuser,
        rolcreatedb as can_create_db,
        rolcreaterole as can_create_role,
        rolcanlogin as can_login,
        rolreplication as can_replicate,
        rolbypassrls as bypass_rls,
        rolconnlimit as connection_limit,
        CASE WHEN rolvaliduntil IS NULL THEN 'Never' ELSE rolvaliduntil::text END as password_expiry
    FROM pg_roles
    ORDER BY rolname
) TO '$outdir/postgres_roles.csv' CSV HEADER" 2>/dev/null

# 3. Database Privileges
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        datname as database_name,
        datacl as database_acl
    FROM pg_database
    WHERE datname NOT IN ('template0', 'template1')
    ORDER BY datname
) TO '$outdir/postgres_database_privileges.csv' CSV HEADER" 2>/dev/null

# 4. Table Privileges (for current database)
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        schemaname as schema_name,
        tablename as table_name,
        tableowner as table_owner,
        tablespace as table_space
    FROM pg_tables
    WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
    ORDER BY schemaname, tablename
) TO '$outdir/postgres_table_owners.csv' CSV HEADER" 2>/dev/null

# 5. Active Connections
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        datname as database_name,
        usename as username,
        client_addr as client_address,
        client_port,
        backend_start,
        state,
        query_start
    FROM pg_stat_activity
    WHERE state IS NOT NULL
    ORDER BY backend_start
) TO '$outdir/postgres_active_connections.csv' CSV HEADER" 2>/dev/null

# 6. Server Configuration
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        name as parameter_name,
        setting as current_value,
        unit,
        category,
        short_desc as description,
        context,
        source
    FROM pg_settings
    WHERE name IN (
        'log_connections',
        'log_disconnections',
        'log_statement',
        'log_min_duration_statement',
        'ssl',
        'port',
        'listen_addresses',
        'max_connections',
        'shared_preload_libraries',
        'authentication_timeout',
        'password_encryption'
    )
    ORDER BY name
) TO '$outdir/postgres_security_config.csv' CSV HEADER" 2>/dev/null

# 7. Find and copy pg_hba.conf
pg_hba_path=""

# Try common locations
for path in \
    "/etc/postgresql/*/main/pg_hba.conf" \
    "/var/lib/pgsql/*/data/pg_hba.conf" \
    "/usr/local/pgsql/data/pg_hba.conf" \
    "/opt/postgresql/*/data/pg_hba.conf" \
    "$(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SHOW hba_file;" 2>/dev/null | xargs)"; do

    if [ -f "$path" ] && [ -r "$path" ]; then
        pg_hba_path="$path"
        break
    fi
done

if [ -n "$pg_hba_path" ]; then
    cp "$pg_hba_path" "$outdir/pg_hba.conf" 2>/dev/null

    # Parse pg_hba.conf to CSV format
    grep -v "^#" "$pg_hba_path" | grep -v "^$" | while IFS= read -r line; do
        echo "$line"
    done > "$outdir/pg_hba_active_rules.txt" 2>/dev/null
else
    echo "pg_hba.conf not found or not readable" > "$outdir/pg_hba_error.txt"
fi

# 8. Get data directory and log settings
data_dir=$(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SHOW data_directory;" 2>/dev/null | xargs)
log_dir=$(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SHOW log_directory;" 2>/dev/null | xargs)
log_filename=$(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SHOW log_filename;" 2>/dev/null | xargs)

# 9. Logging Configuration
{
    echo "Data Directory: $data_dir"
    echo "Log Directory: $log_dir"
    echo "Log Filename Pattern: $log_filename"
    echo ""
    echo "Logging Settings:"
    psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "
        SELECT name, setting, unit, context
        FROM pg_settings
        WHERE name LIKE 'log_%'
        ORDER BY name;" -A -t 2>/dev/null
} > "$outdir/postgres_logging_config.txt"

# 10. Database Statistics
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        datname as database_name,
        numbackends as active_connections,
        xact_commit as transactions_committed,
        xact_rollback as transactions_rolled_back,
        blks_read as blocks_read,
        blks_hit as blocks_hit,
        tup_returned as tuples_returned,
        tup_fetched as tuples_fetched,
        tup_inserted as tuples_inserted,
        tup_updated as tuples_updated,
        tup_deleted as tuples_deleted,
        stats_reset as stats_reset_time
    FROM pg_stat_database
    WHERE datname NOT IN ('template0', 'template1')
    ORDER BY datname
) TO '$outdir/postgres_database_stats.csv' CSV HEADER" 2>/dev/null

# 11. Installed Extensions
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        extname as extension_name,
        extversion as version,
        extrelocatable as relocatable,
        extnamespace::regnamespace as schema_name
    FROM pg_extension
    ORDER BY extname
) TO '$outdir/postgres_extensions.csv' CSV HEADER" 2>/dev/null

# 12. Superuser Check
psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -c "\copy (
    SELECT
        rolname as superuser_name,
        rolcanlogin as can_login,
        CASE WHEN rolvaliduntil IS NULL THEN 'Never' ELSE rolvaliduntil::text END as password_expiry
    FROM pg_roles
    WHERE rolsuper = true
    ORDER BY rolname
) TO '$outdir/postgres_superusers.csv' CSV HEADER" 2>/dev/null

# 13. Authentication Methods Summary
if [ -f "$outdir/pg_hba.conf" ]; then
    {
        echo "connection_type,database,user,address,auth_method"
        grep -v "^#" "$outdir/pg_hba.conf" | grep -v "^$" | awk '{
            if (NF >= 4) {
                if ($1 == "local") {
                    printf "%s,%s,%s,%s,%s\n", $1, $2, $3, "local", $4
                } else if (NF >= 5) {
                    printf "%s,%s,%s,%s,%s\n", $1, $2, $3, $4, $5
                }
            }
        }'
    } > "$outdir/postgres_auth_methods.csv" 2>/dev/null
fi

# 14. Generate Summary Report
{
    echo "PostgreSQL Security Audit Summary"
    echo "================================="
    echo "Server: $hostname"
    echo "Date: $date"
    echo "PostgreSQL Version: $(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SELECT version();" 2>/dev/null | cut -d',' -f1 | xargs)"
    echo "Data Directory: $data_dir"
    echo ""
    echo "Superusers: $(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true;" 2>/dev/null | xargs)"
    echo "Total Roles: $(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SELECT COUNT(*) FROM pg_roles;" 2>/dev/null | xargs)"
    echo "Login Roles: $(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$PGDATABASE" -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true;" 2>/dev/null | xargs)"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "PostgreSQL audit completed"
echo "Files saved to: $outdir"