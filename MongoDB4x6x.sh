#!/bin/bash
# MongoDB Audit Script - Bash + mongosh
# Target: MongoDB 4.x / 6.x
# Functions: Users/roles export, config check, audit log verification

# Configuration
MONGO_HOST=${MONGO_HOST:-localhost}
MONGO_PORT=${MONGO_PORT:-27017}
MONGO_AUTH_DB=${MONGO_AUTH_DB:-admin}
MONGO_USER=${MONGO_USER:-}
MONGO_PASS=${MONGO_PASS:-}

# Initialize variables
hostname=$(hostname)
os="MongoDB"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

# Build connection string
if [ -n "$MONGO_USER" ] && [ -n "$MONGO_PASS" ]; then
    MONGO_URI="mongodb://$MONGO_USER:$MONGO_PASS@$MONGO_HOST:$MONGO_PORT/$MONGO_AUTH_DB"
    AUTH_OPTS="--username $MONGO_USER --password $MONGO_PASS --authenticationDatabase $MONGO_AUTH_DB"
else
    MONGO_URI="mongodb://$MONGO_HOST:$MONGO_PORT"
    AUTH_OPTS=""
fi

# Test MongoDB connection
if ! mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "db.runCommand('ping')" >/dev/null 2>&1; then
    echo "Failed to connect to MongoDB"
    exit 1
fi

echo "Starting MongoDB audit - $date"
echo "Output directory: $outdir"

# 1. MongoDB Version and Server Info
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    var serverInfo = db.runCommand('buildInfo');
    var serverStatus = db.runCommand('serverStatus');
    print('version,git_version,architecture,uptime_seconds,connections_current,connections_available');
    print(serverInfo.version + ',' +
          serverInfo.gitVersion + ',' +
          serverInfo.buildEnvironment.target_arch + ',' +
          serverStatus.uptime + ',' +
          serverStatus.connections.current + ',' +
          serverStatus.connections.available);
" > "$outdir/mongo_server_info.csv" 2>/dev/null

# 2. Export all users and their roles
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('username,database,roles,custom_data,authentication_restrictions');
    db.adminCommand('listUsers').users.forEach(function(user) {
        var roles = user.roles.map(function(role) {
            return role.role + '@' + role.db;
        }).join(';');
        var customData = user.customData ? JSON.stringify(user.customData).replace(/,/g, ';') : '';
        var authRestrictions = user.authenticationRestrictions ? JSON.stringify(user.authenticationRestrictions).replace(/,/g, ';') : '';
        print(user.user + ',' +
              user.db + ',' +
              '\"' + roles + '\",' +
              '\"' + customData + '\",' +
              '\"' + authRestrictions + '\"');
    });
" > "$outdir/mongo_users.csv" 2>/dev/null

# 3. Export database users for each database
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('database,username,roles');
    db.adminCommand('listDatabases').databases.forEach(function(database) {
        if (database.name !== 'local' && database.name !== 'config') {
            try {
                var dbUsers = db.getSiblingDB(database.name).getUsers();
                dbUsers.forEach(function(user) {
                    var roles = user.roles.map(function(role) {
                        return role.role + '@' + role.db;
                    }).join(';');
                    print(database.name + ',' + user.user + ',\"' + roles + '\"');
                });
            } catch (e) {
                // Skip databases where we don't have permission
            }
        }
    });
" > "$outdir/mongo_database_users.csv" 2>/dev/null

# 4. Database and Collection Statistics
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('database,collections,data_size_bytes,storage_size_bytes,indexes,index_size_bytes');
    db.adminCommand('listDatabases').databases.forEach(function(database) {
        if (database.name !== 'local' && database.name !== 'config') {
            try {
                var dbStats = db.getSiblingDB(database.name).stats();
                print(database.name + ',' +
                      dbStats.collections + ',' +
                      dbStats.dataSize + ',' +
                      dbStats.storageSize + ',' +
                      dbStats.indexes + ',' +
                      dbStats.indexSize);
            } catch (e) {
                print(database.name + ',ERROR,ERROR,ERROR,ERROR,ERROR');
            }
        }
    });
" > "$outdir/mongo_database_stats.csv" 2>/dev/null

# 5. Roles Information
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('role_name,database,is_builtin,privileges,inherited_roles');
    db.runCommand('rolesInfo', {rolesInfo: 1, showPrivileges: true, showBuiltinRoles: true}).roles.forEach(function(role) {
        var privileges = role.privileges ? role.privileges.length : 0;
        var inheritedRoles = role.inheritedRoles ? role.inheritedRoles.map(function(r) { return r.role + '@' + r.db; }).join(';') : '';
        print(role.role + ',' +
              role.db + ',' +
              role.isBuiltin + ',' +
              privileges + ',' +
              '\"' + inheritedRoles + '\"');
    });
" > "$outdir/mongo_roles.csv" 2>/dev/null

# 6. Server Configuration Parameters
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('parameter,value');
    var params = db.runCommand('getCmdLineOpts');
    if (params.parsed) {
        if (params.parsed.net) {
            if (params.parsed.net.bindIp) print('bindIp,' + params.parsed.net.bindIp);
            if (params.parsed.net.port) print('port,' + params.parsed.net.port);
            if (params.parsed.net.tls) {
                print('tls.mode,' + (params.parsed.net.tls.mode || 'disabled'));
                if (params.parsed.net.tls.certificateKeyFile) print('tls.certificateKeyFile,' + params.parsed.net.tls.certificateKeyFile);
            }
        }
        if (params.parsed.security) {
            if (params.parsed.security.authorization) print('authorization,' + params.parsed.security.authorization);
            if (params.parsed.security.keyFile) print('keyFile,' + params.parsed.security.keyFile);
        }
        if (params.parsed.auditLog) {
            print('auditLog.destination,' + (params.parsed.auditLog.destination || 'none'));
            if (params.parsed.auditLog.path) print('auditLog.path,' + params.parsed.auditLog.path);
            if (params.parsed.auditLog.format) print('auditLog.format,' + params.parsed.auditLog.format);
        }
    }
" > "$outdir/mongo_server_config.csv" 2>/dev/null

# 7. Security Settings Check
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('setting,status,value');
    try {
        var serverStatus = db.runCommand('serverStatus');
        var cmdLineOpts = db.runCommand('getCmdLineOpts');

        // Check authentication
        var authEnabled = cmdLineOpts.parsed && cmdLineOpts.parsed.security && cmdLineOpts.parsed.security.authorization;
        print('authentication,' + (authEnabled ? 'enabled' : 'disabled') + ',' + (authEnabled || 'none'));

        // Check bind IP
        var bindIp = cmdLineOpts.parsed && cmdLineOpts.parsed.net && cmdLineOpts.parsed.net.bindIp;
        print('bind_ip,' + (bindIp ? 'configured' : 'default') + ',' + (bindIp || '127.0.0.1'));

        // Check TLS
        var tlsMode = cmdLineOpts.parsed && cmdLineOpts.parsed.net && cmdLineOpts.parsed.net.tls && cmdLineOpts.parsed.net.tls.mode;
        print('tls,' + (tlsMode ? 'enabled' : 'disabled') + ',' + (tlsMode || 'none'));

        // Check audit log
        var auditDest = cmdLineOpts.parsed && cmdLineOpts.parsed.auditLog && cmdLineOpts.parsed.auditLog.destination;
        print('audit_log,' + (auditDest ? 'enabled' : 'disabled') + ',' + (auditDest || 'none'));

        // Check if replica set
        var replSetStatus;
        try {
            replSetStatus = db.runCommand('replSetGetStatus');
            print('replica_set,enabled,' + replSetStatus.set);
        } catch (e) {
            print('replica_set,disabled,standalone');
        }

    } catch (e) {
        print('error,failed,' + e.message);
    }
" > "$outdir/mongo_security_settings.csv" 2>/dev/null

# 8. Find and check mongod.conf
mongod_conf_path=""

# Try common locations
for path in \
    "/etc/mongod.conf" \
    "/etc/mongodb.conf" \
    "/usr/local/etc/mongod.conf" \
    "/opt/mongodb/mongod.conf"; do

    if [ -f "$path" ] && [ -r "$path" ]; then
        mongod_conf_path="$path"
        break
    fi
done

if [ -n "$mongod_conf_path" ]; then
    # Copy full config file
    cp "$mongod_conf_path" "$outdir/mongod.conf" 2>/dev/null

    # Extract security-related settings
    {
        echo "Security-related settings from mongod.conf:"
        echo "============================================"
        grep -Ei 'bindip|bind_ip|port|tls|ssl|authorization|keyfile|auditlog|security' "$mongod_conf_path" | grep -v "^#"
    } > "$outdir/mongo_config_security.txt" 2>/dev/null
else
    echo "mongod.conf not found or not readable" > "$outdir/mongo_config_error.txt"
fi

# 9. Current Connections
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('client,active_operations,total_time,wait_time');
    try {
        db.runCommand('currentOp').inprog.forEach(function(op) {
            if (op.client) {
                print(op.client + ',' +
                      (op.active ? '1' : '0') + ',' +
                      (op.microsecs_running || 0) + ',' +
                      (op.waitingForLock ? '1' : '0'));
            }
        });
    } catch (e) {
        print('error,error,error,error');
    }
" > "$outdir/mongo_current_connections.csv" 2>/dev/null

# 10. Profiling Status
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('database,profiling_level,slow_operation_threshold');
    db.adminCommand('listDatabases').databases.forEach(function(database) {
        try {
            var profileStatus = db.getSiblingDB(database.name).runCommand('profile', -1);
            print(database.name + ',' +
                  profileStatus.was + ',' +
                  (profileStatus.slowms || 'N/A'));
        } catch (e) {
            print(database.name + ',error,error');
        }
    });
" > "$outdir/mongo_profiling_status.csv" 2>/dev/null

# 11. Index Information
mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "
    print('database,collection,index_name,keys,unique,sparse');
    db.adminCommand('listDatabases').databases.forEach(function(database) {
        if (database.name !== 'local' && database.name !== 'config') {
            try {
                var collections = db.getSiblingDB(database.name).getCollectionNames();
                collections.forEach(function(collection) {
                    try {
                        var indexes = db.getSiblingDB(database.name).getCollection(collection).getIndexes();
                        indexes.forEach(function(index) {
                            var keys = Object.keys(index.key).join(';');
                            print(database.name + ',' +
                                  collection + ',' +
                                  index.name + ',' +
                                  keys + ',' +
                                  (index.unique ? 'true' : 'false') + ',' +
                                  (index.sparse ? 'true' : 'false'));
                        });
                    } catch (e) {
                        // Skip collections we can't access
                    }
                });
            } catch (e) {
                // Skip databases we can't access
            }
        }
    });
" > "$outdir/mongo_indexes.csv" 2>/dev/null

# 12. Generate Summary Report
{
    echo "MongoDB Security Audit Summary"
    echo "=============================="
    echo "Server: $hostname"
    echo "Date: $date"

    # Get MongoDB version
    mongo_version=$(mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "print(db.version())" 2>/dev/null)
    echo "MongoDB Version: $mongo_version"

    # Get user count
    user_count=$(mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "print(db.adminCommand('listUsers').users.length)" 2>/dev/null)
    echo "Total Users: $user_count"

    # Get database count
    db_count=$(mongosh --quiet --host "$MONGO_HOST" --port "$MONGO_PORT" $AUTH_OPTS --eval "print(db.adminCommand('listDatabases').databases.length)" 2>/dev/null)
    echo "Total Databases: $db_count"

    echo ""
    echo "Configuration File: ${mongod_conf_path:-'Not found'}"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "MongoDB audit completed"
echo "Files saved to: $outdir"