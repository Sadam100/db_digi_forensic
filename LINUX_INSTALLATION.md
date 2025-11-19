# Running Database Forensic Tool on Linux

This guide provides step-by-step instructions for installing and running the Database Forensic Tool on a Linux virtual machine.

## Prerequisites

### System Requirements
- Linux distribution (Ubuntu, Debian, CentOS, RHEL, etc.)
- Python 3.8 or higher
- pip (Python package installer)
- Network access (if analyzing remote databases)

### Check Python Installation

```bash
# Check Python version
python3 --version

# If Python is not installed, install it:
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv

# CentOS/RHEL:
sudo yum install python3 python3-pip
# or for newer versions:
sudo dnf install python3 python3-pip
```

## Installation Steps

### 1. Transfer the Project to Linux VM

If you're working on Windows and need to transfer to Linux:

**Option A: Using SCP (from Windows with OpenSSH or WSL)**
```bash
scp -r db_digi_forensic user@linux-vm-ip:/home/user/
```

**Option B: Using Git (if project is in a repository)**
```bash
git clone <repository-url>
cd db_digi_forensic
```

**Option C: Using shared folder (if using VirtualBox/VMware)**
- Copy the project folder to the shared directory
- Access it from Linux VM

### 2. Navigate to Project Directory

```bash
cd db_digi_forensic
```

### 3. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Your prompt should now show (venv)
```

### 4. Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

This will install:
- `pymysql` (for MySQL support)
- `pymongo` (for MongoDB support)

### 5. (Optional) Install the Package

```bash
# Install the tool as a package (allows using 'db-forensic' command)
pip install -e .

# Or install directly
pip install .
```

## Usage Examples

### SQLite Analysis

**Basic analysis:**
```bash
python3 -m db_forensic_tool sqlite database.db
```

**Full analysis with deleted data recovery:**
```bash
python3 -m db_forensic_tool sqlite database.db \
    --recover-deleted \
    --check-journal \
    --page-hash \
    --output report.json \
    --verbose
```

**Example with actual file:**
```bash
python3 -m db_forensic_tool sqlite chinook/chinook.db \
    --output sqlite_report.json \
    --format both
```

### MySQL Analysis

**Basic analysis:**
```bash
python3 -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password yourpassword \
    --database testdb
```

**With log file analysis (Linux paths):**
```bash
python3 -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password yourpassword \
    --database testdb \
    --binlog /var/log/mysql/mysql-bin.000001 \
    --error-log /var/log/mysql/error.log \
    --general-log /var/log/mysql/general.log \
    --suspicious-ops \
    --output mysql_report.json \
    --verbose
```

**Using environment variable for password (more secure):**
```bash
export MYSQL_PASSWORD="yourpassword"
python3 -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password "$MYSQL_PASSWORD" \
    --database testdb
```

**Remote MySQL server:**
```bash
python3 -m db_forensic_tool mysql \
    --host 192.168.1.100 \
    --port 3306 \
    --user forensic_user \
    --password yourpassword \
    --database production_db \
    --suspicious-ops \
    --output remote_mysql_report.json
```

### MongoDB Analysis

**Basic analysis:**
```bash
python3 -m db_forensic_tool mongodb \
    --host localhost \
    --port 27017 \
    --database testdb
```

**With connection URI:**
```bash
python3 -m db_forensic_tool mongodb \
    --uri "mongodb://user:password@localhost:27017/testdb" \
    --database testdb \
    --check-timestamps \
    --output mongodb_report.json
```

**Remote MongoDB:**
```bash
python3 -m db_forensic_tool mongodb \
    --host 192.168.1.100 \
    --port 27017 \
    --user admin \
    --password yourpassword \
    --database appdb \
    --check-timestamps \
    --output remote_mongodb_report.json
```

## Linux-Specific Considerations

### File Permissions

**If you encounter permission errors:**
```bash
# Make sure you have read permissions for database files
chmod 644 database.db

# For MySQL log files (may require sudo)
sudo chmod 644 /var/log/mysql/*.log
```

### MySQL Log File Locations

Common MySQL log file locations on Linux:
- **Binary logs:** `/var/log/mysql/mysql-bin.*` or `/var/lib/mysql/mysql-bin.*`
- **Error log:** `/var/log/mysql/error.log` or `/var/lib/mysql/hostname.err`
- **General log:** `/var/log/mysql/general.log` (if enabled)

To find MySQL log locations:
```bash
# Check MySQL configuration
mysql -u root -p -e "SHOW VARIABLES LIKE '%log%';"

# Or check my.cnf
cat /etc/mysql/my.cnf | grep log
```

### MongoDB Oplog Access

For MongoDB replica sets, oplog is typically in:
```bash
# Connect to MongoDB and check oplog
mongo --eval "rs.printReplicationInfo()"

# Or access oplog collection directly
python3 -m db_forensic_tool mongodb \
    --host localhost \
    --database local \
    --check-timestamps
```

### Network Connectivity

**Test database connectivity before running analysis:**

For MySQL:
```bash
mysql -h localhost -u root -p -e "SELECT 1;"
```

For MongoDB:
```bash
mongo --host localhost --eval "db.version()"
```

### Running as a Service or Background Process

**Run analysis in background:**
```bash
nohup python3 -m db_forensic_tool mysql \
    --host localhost \
    --user root \
    --password yourpassword \
    --database testdb \
    --output report.json \
    > analysis.log 2>&1 &

# Check status
tail -f analysis.log
```

**Using screen or tmux:**
```bash
# Install screen if not available
sudo apt-get install screen  # Ubuntu/Debian
sudo yum install screen      # CentOS/RHEL

# Start screen session
screen -S forensic

# Run your analysis
python3 -m db_forensic_tool mysql ...

# Detach: Ctrl+A, then D
# Reattach: screen -r forensic
```

## Troubleshooting

### Python Module Not Found

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Connection Errors

**MySQL connection refused:**
```bash
# Check if MySQL is running
sudo systemctl status mysql
# or
sudo service mysql status

# Check if port is open
netstat -tuln | grep 3306
```

**MongoDB connection refused:**
```bash
# Check if MongoDB is running
sudo systemctl status mongod
# or
sudo service mongod status

# Check if port is open
netstat -tuln | grep 27017
```

### Permission Denied Errors

```bash
# Check file permissions
ls -la database.db

# Fix permissions if needed
chmod 644 database.db

# For log files, may need sudo
sudo chmod 644 /var/log/mysql/*.log
```

### Missing Dependencies

```bash
# Install system dependencies if needed
# Ubuntu/Debian:
sudo apt-get install python3-dev libmysqlclient-dev

# CentOS/RHEL:
sudo yum install python3-devel mysql-devel
```

## Security Best Practices

1. **Use environment variables for passwords:**
   ```bash
   export DB_PASSWORD="yourpassword"
   python3 -m db_forensic_tool mysql --password "$DB_PASSWORD" ...
   ```

2. **Use credential files (create a secure script):**
   ```bash
   #!/bin/bash
   # save as run_analysis.sh
   source venv/bin/activate
   export MYSQL_PASSWORD="yourpassword"
   python3 -m db_forensic_tool mysql --password "$MYSQL_PASSWORD" ...
   ```
   ```bash
   chmod 700 run_analysis.sh
   ```

3. **Secure report files:**
   ```bash
   # Set restrictive permissions on reports
   chmod 600 report.json
   ```

## Quick Start Script

Create a helper script for easy execution:

```bash
#!/bin/bash
# save as run_forensic.sh

# Activate virtual environment
source venv/bin/activate

# Run analysis (modify as needed)
python3 -m db_forensic_tool "$@"

# Deactivate
deactivate
```

Make it executable:
```bash
chmod +x run_forensic.sh
```

Usage:
```bash
./run_forensic.sh sqlite database.db --output report.json
```

## Additional Resources

- Check the main `README.md` for detailed feature documentation
- Review `USAGE_EXAMPLES.md` for more examples
- Check tool help: `python3 -m db_forensic_tool --help`

