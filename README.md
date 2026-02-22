# NetApp to Veza Integration Script

## Overview

The `netAppShares.py` script is a comprehensive integration tool that synchronizes NetApp storage resources (volumes, shares, and permissions) with Veza's authorization platform. It supports both NetApp BlueXP cloud deployments and on-premises ONTAP systems, enabling centralized visibility and governance of NetApp storage access.

### Key Features

- **Dual Mode Operation**: Supports both BlueXP (cloud) and ONTAP (on-premises) deployments
- **Multi-Platform Support**: Works with Cloud Volumes ONTAP, Azure NetApp Files, AWS FSx for ONTAP, and Google Cloud Volumes Service
- **CIFS/SMB Share Management**: Retrieves CIFS shares with NTFS permissions and ACLs
- **Identity Integration**: Synchronizes NetApp users and roles with Veza
- **Active Directory Integration**: Queries Veza API to resolve AD group distinguished names
- **Flexible Permission Mapping**: Maps NetApp permissions to Veza's authorization model
- **Domain Normalization**: Optional removal of domain prefixes from user identities

### How It Works

The script performs the following operations:

1. **Authentication**: Authenticates with NetApp BlueXP or ONTAP using OAuth2 client credentials
2. **Data Collection**: 
   - **BlueXP Mode**: Retrieves cloud volumes from specified platform (ONTAP, Azure, AWS, or GCP)
   - **ONTAP Mode**: Retrieves CIFS shares and their NTFS permissions from on-premises SVM
3. **Permission Processing**: Analyzes share ACLs and maps them to Veza's permission model
4. **Identity Resolution**: Distinguishes between users and groups, optionally queries Veza for AD group DNs
5. **Veza Integration**: Pushes processed data to Veza as Custom Applications with proper resource hierarchies

---

## Prerequisites

### System Requirements

- **Operating System**: Red Hat Enterprise Linux 8+ (or compatible Linux distribution)
- **Python Version**: Python 3.7 or higher
- **Network Access**: 
  - Outbound HTTPS access to NetApp BlueXP API endpoints
  - Access to on-premises ONTAP management interfaces (for ONTAP mode)
  - Access to Veza instance API

### NetApp Requirements

- NetApp BlueXP account with API credentials (for cloud mode)
- On-premises ONTAP cluster with API access (for ONTAP mode)
- Working Environment ID and Agent ID (for BlueXP)
- SVM name/address (for ONTAP mode)

### Veza Requirements

- Veza instance URL
- Veza API key with appropriate permissions
- Veza provider configured for NetApp integration

---

## Installation

### One-Command Installer (Linux)

For ONTAP-only deployments, use the installer script directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/pvolu-vz/NetApp/main/install_ontap.sh | bash
```

What it does automatically:

- Runs Linux/RHEL pre-checks similar to `preflight.sh` (system packages, Python, dependencies, connectivity)
- Detects package manager and installs required packages (`git`, `curl`, `python3`, `python3-pip`) using `dnf`, `yum`, `apt`, `zypper`, or `apk`
- Clones/updates this repository into `/opt/netapp-veza/scripts`
- Creates folder structure: `/opt/netapp-veza/scripts`, `/opt/netapp-veza/logs`, `/opt/netapp-veza/configs`, and `/opt/netapp-veza/scripts/logs`
- Creates Python virtual environment and installs `requirements.txt`
- Prompts for **ONTAP + Veza only** values and generates `/opt/netapp-veza/scripts/.env`

Optional flags:

```bash
# Override repository URL/branch/install directory
curl -fsSL https://raw.githubusercontent.com/pvolu-vz/NetApp/main/install_ontap.sh | bash -s -- \
   --repo-url https://github.com/pvolu-vz/NetApp.git \
   --branch main \
   --install-dir /opt/netapp-veza

# Non-interactive mode (CI / automation)
ONTAP_API_BASE_URL=https://ontap.example.com \
ONTAP_USERNAME=svc_netapp \
ONTAP_PASSWORD='secret' \
VEZA_URL=your-company.veza.com \
VEZA_API_KEY='secret' \
curl -fsSL https://raw.githubusercontent.com/pvolu-vz/NetApp/main/install_ontap.sh | bash -s -- --non-interactive --overwrite-env
```

After installation:

```bash
/opt/netapp-veza/scripts/venv/bin/python /opt/netapp-veza/scripts/netAppShares.py \
   --system-type ontap \
   --svm-name YOUR_SVM \
   --protocol cifs \
   --env-file /opt/netapp-veza/scripts/.env
```

### Step 1: Install Python 3

#### On Red Hat Enterprise Linux 8+

```bash
# Install Python 3.9 (recommended for RHEL 8)
sudo dnf install python39 python39-pip python39-devel -y

# Verify installation
python3.9 --version

# Create symbolic link (optional, for convenience)
sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
```

#### Alternative: Install Python 3.11 (if available)

```bash
# Enable additional repositories if needed
sudo dnf install epel-release -y

# Install Python 3.11
sudo dnf install python3.11 python3.11-pip -y

# Verify installation
python3.11 --version
```

### Step 2: Set Up Virtual Environment

```bash
# Navigate to the script directory
cd /path/to/Scripts/NetApp

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Verify installations
pip list
```

### Step 4: Configure Environment Variables

Create a `.env` file in the same directory as the script:

```bash
# Copy the example below and edit with your values
cat > .env << 'EOF'
# NetApp BlueXP Configuration (for cloud mode)
BLUEXP_AUTH_URL=https://netapp-cloud-account.auth0.com/oauth/token
BLUEXP_CLIENT_ID=your_bluexp_client_id
BLUEXP_CLIENT_SECRET=your_bluexp_client_secret
BLUEXP_AUDIENCE=https://api.cloud.netapp.com

# BlueXP API Endpoints
VOLUMES_API_URL_BASE=https://cloudmanager.cloud.netapp.com/occm/api
USERS_API_URL=https://cloudmanager.cloud.netapp.com/iam/users

# BlueXP Environment Details
WORKING_ENVIRONMENT_ID=your_working_environment_id
AGENT_ID=your_agent_id

# On-Premises ONTAP Configuration (for ONTAP mode)
ONTAP_AUTH_URL=https://your-ontap-cluster.example.com/oauth/token
ONTAP_CLIENT_ID=your_ontap_client_id
ONTAP_CLIENT_SECRET=your_ontap_client_secret
ONTAP_AUDIENCE=https://your-ontap-cluster.example.com
ONTAP_API_BASE_URL=https://your-ontap-cluster.example.com

# Veza Configuration
VEZA_URL=your-instance.veza.com
VEZA_API_KEY=your_veza_api_key
EOF

# Secure the .env file
chmod 600 .env
```

### Step 5: Test the Installation

```bash
# Test BlueXP mode (if configured)
python3 netAppShares.py --system-type bluexp --platform azure

# Test ONTAP mode (if configured)
python3 netAppShares.py --system-type ontap --svm-address YOUR_SVM_NAME --protocol cifs
```

---

## Usage

### Command-Line Arguments

The script supports the following command-line arguments:

| Argument | Required | Choices | Default | Description |
|----------|----------|---------|---------|-------------|
| `--system-type` | **Yes** | `bluexp`, `ontap` | None | Deployment mode: bluexp for cloud volumes, ontap for on-premises shares |
| `--platform` | Conditional* | `ontap`, `azure`, `aws`, `gcp` | None | Cloud platform to fetch volumes from (required for BlueXP mode) |
| `--svm-address` | Conditional** | Any string | None | SVM name/address (required for ONTAP mode) |
| `--protocol` | No | `cifs`, `nfs` | `cifs` | Protocol type for ONTAP mode |
| `--remove-domain` | No | Any string | None | Domain prefix to remove from user identities (e.g., "RTI") |
| `--env-file` | No | File path | `.env` | Path to custom .env file (absolute or relative). Useful for managing multiple ONTAP instances |

\* Required when `--system-type bluexp`  
\** Required when `--system-type ontap`

### Usage Examples

#### BlueXP Mode Examples

```bash
# Fetch volumes from Azure NetApp Files
python3 netAppShares.py --system-type bluexp --platform azure

# Fetch volumes from Cloud Volumes ONTAP
python3 netAppShares.py --system-type bluexp --platform ontap

# Fetch volumes from AWS FSx for NetApp ONTAP
python3 netAppShares.py --system-type bluexp --platform aws

# Fetch volumes from Google Cloud Volumes Service
python3 netAppShares.py --system-type bluexp --platform gcp
```

#### ONTAP Mode Examples

```bash
# Fetch CIFS shares from on-premises SVM
python3 netAppShares.py --system-type ontap --svm-address PROD_SVM --protocol cifs

# Fetch CIFS shares and remove domain prefix from identities
python3 netAppShares.py --system-type ontap --svm-address PROD_SVM --remove-domain RTI

# Fetch from test SVM
python3 netAppShares.py --system-type ontap --svm-address TESTCIFSLOW

# Use custom .env file for specific ONTAP instance
python3 netAppShares.py --system-type ontap --svm-address PROD_SVM1 --env-file /etc/netapp/prod-svm1.env
```

---

## Managing Multiple ONTAP Instances

If you have multiple ONTAP systems (clusters or SVMs) in your environment, the `--env-file` argument allows you to manage separate configurations for each instance without maintaining multiple copies of the script.

### Understanding Veza Datasource Behavior

**Key Point:** Each ONTAP SVM creates a **separate datasource** in Veza. Multiple datasources coexist and do not replace each other.

- **Provider Name:** All NetApp integrations share one provider: `NetApp`
- **Datasource Names:** Each SVM gets a unique datasource: `NetApp-ONTAP-{svm_name} (NetApp ONTAP)`

**Example:** With three SVMs (PROD_SVM1, PROD_SVM2, TEST_SVM), you'll see in Veza:
```
Provider: NetApp
  ├── NetApp-ONTAP-PROD_SVM1 (NetApp ONTAP)
  ├── NetApp-ONTAP-PROD_SVM2 (NetApp ONTAP)
  └── NetApp-ONTAP-TEST_SVM (NetApp ONTAP)
```

Each datasource contains its own shares, permissions, and resources. They **do not conflict or replace** each other.

### Setup for Multiple ONTAP Instances

#### Step 1: Create Configuration Files

Create separate `.env` files for each ONTAP instance:

```bash
cd /opt/netapp-veza/scripts

# Create directory for configs (optional)
mkdir -p configs

# Create .env file for each SVM
cp .env.example-ontap configs/prod-svm1.env
cp .env.example-ontap configs/prod-svm2.env
cp .env.example-ontap configs/test-svm.env

# Edit each file with instance-specific settings
vim configs/prod-svm1.env   # Set ONTAP_API_BASE_URL, credentials, etc.
vim configs/prod-svm2.env
vim configs/test-svm.env

# Secure the configuration files
chmod 600 configs/*.env
```

**Minimal ONTAP .env file example:**

```bash
# configs/prod-svm1.env
ONTAP_API_BASE_URL=https://ontap-cluster1.example.com
ONTAP_USERNAME=admin
ONTAP_PASSWORD=your_password
VEZA_URL=your-instance.veza.com
VEZA_API_KEY=your_api_key
DOMAIN_TO_REMOVE=DOMAIN1
```

#### Step 2: Test Each Configuration

```bash
# Test each ONTAP instance individually
python3 netAppShares.py --system-type ontap --svm-name PROD_SVM1 --env-file configs/prod-svm1.env
python3 netAppShares.py --system-type ontap --svm-name PROD_SVM2 --env-file configs/prod-svm2.env
python3 netAppShares.py --system-type ontap --svm-name TEST_SVM --env-file configs/test-svm.env

# Check logs for successful completion
# Verify in Veza UI that separate datasources were created
```

#### Step 3: Automate with Multi-Instance Wrapper

Use the provided `run_multi_ontap_sync.sh` wrapper script to run all ONTAP syncs sequentially:

```bash
# Edit the wrapper script to define your ONTAP instances
vim run_multi_ontap_sync.sh

# In the script, update the ONTAP_INSTANCES array:
# declare -a ONTAP_INSTANCES=(
#     "PROD_SVM1|configs/prod-svm1.env|cifs"
#     "PROD_SVM2|configs/prod-svm2.env|cifs"
#     "TEST_SVM|configs/test-svm.env|cifs"
# )

# Make it executable
chmod +x run_multi_ontap_sync.sh

# Test the wrapper
./run_multi_ontap_sync.sh

# Check the main log
cat logs/multi_sync_*.log
```

#### Step 4: Schedule with Cron

**Option A: Single cron job for all instances (recommended)**

```bash
# Edit crontab
crontab -e

# Add entry to run all ONTAP syncs daily at 2 AM
0 2 * * * /opt/netapp-veza/scripts/run_multi_ontap_sync.sh >> /opt/netapp-veza/logs/cron.log 2>&1
```

**Option B: Individual cron jobs per instance**

```bash
# Run each ONTAP instance at different times to spread load
0 2 * * * cd /opt/netapp-veza/scripts && ./venv/bin/python3 netAppShares.py --system-type ontap --svm-name PROD_SVM1 --env-file configs/prod-svm1.env >> logs/prod-svm1-cron.log 2>&1
15 2 * * * cd /opt/netapp-veza/scripts && ./venv/bin/python3 netAppShares.py --system-type ontap --svm-name PROD_SVM2 --env-file configs/prod-svm2.env >> logs/prod-svm2-cron.log 2>&1
30 2 * * * cd /opt/netapp-veza/scripts && ./venv/bin/python3 netAppShares.py --system-type ontap --svm-name TEST_SVM --env-file configs/test-svm.env >> logs/test-svm-cron.log 2>&1
```

### Directory Structure Example

```
/opt/netapp-veza/
├── scripts/
│   ├── netAppShares.py                 # Main script
│   ├── run_multi_ontap_sync.sh         # Multi-instance wrapper
│   ├── requirements.txt
│   ├── .env.example-ontap              # Template for ONTAP
│   ├── .env.example-bluexp             # Template for BlueXP
│   ├── configs/
│   │   ├── prod-svm1.env              # Production SVM 1 config
│   │   ├── prod-svm2.env              # Production SVM 2 config
│   │   └── test-svm.env               # Test SVM config
│   └── venv/                          # Python virtual environment
└── logs/
    ├── multi_sync_20260220_020000.log # Wrapper execution log
    ├── sync_PROD_SVM1_20260220_020000.log
    ├── sync_PROD_SVM2_20260220_020005.log
    └── sync_TEST_SVM_20260220_020010.log
```

### Best Practices for Multiple Instances

1. **Use descriptive .env file names** - Include environment and SVM identifier
2. **Centralize configuration** - Store all .env files in a `configs/` directory
3. **Use the wrapper script** - Simplifies management and provides centralized logging
4. **Stagger cron schedules** - If running individual jobs, offset start times by 15+ minutes
5. **Monitor all logs** - Each instance logs separately; check for failures
6. **Test before production** - Verify each config file independently before scheduling
7. **Secure credentials** - Set `chmod 600` on all .env files
8. **Document your instances** - Maintain a list of SVMs and their corresponding .env files

---

### Understanding Output

The script provides detailed progress output:

```
====================================================================
PROCESSING VOLUMES
====================================================================

Initializing NetApp BlueXP CustomApplication...
✓ CustomApplication initialized

Authenticating with NetApp BlueXP...
✓ Authentication successful

Fetching volumes from Azure NetApp Files...
✓ Retrieved 15 volume(s)

Processing 15 volumes from AZURE platform...
✓ Created 15 volume resources

Pushing volumes to Veza...
✓ Successfully pushed volumes to Veza

====================================================================
PROCESSING USERS & ROLES
====================================================================
...
```

Exit codes:
- `0`: Success (at least one integration completed)
- `1`: Failure (all integrations failed or error occurred)

---

## Deployment

### Production Deployment

#### 1. Create Dedicated Service Account

```bash
# Create service account for running the script
sudo useradd -r -s /bin/bash -m -d /opt/netapp-veza netapp-veza

# Switch to service account
sudo su - netapp-veza
```

#### 2. Deploy Script Files

```bash
# Create directory structure
mkdir -p /opt/netapp-veza/{scripts,logs}

# Copy script and configuration
cp netAppShares.py /opt/netapp-veza/scripts/
cp run_multi_ontap_sync.sh /opt/netapp-veza/scripts/  # For multiple ONTAP instances
cp .env /opt/netapp-veza/scripts/
cp .env.example-ontap /opt/netapp-veza/scripts/
cp .env.example-bluexp /opt/netapp-veza/scripts/
cp requirements.txt /opt/netapp-veza/scripts/

# Set up virtual environment
cd /opt/netapp-veza/scripts
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Set proper permissions
chmod 700 /opt/netapp-veza/scripts
chmod 600 /opt/netapp-veza/scripts/.env*
chmod 755 /opt/netapp-veza/scripts/netAppShares.py
chmod 755 /opt/netapp-veza/scripts/run_multi_ontap_sync.sh
```

#### 3. Setup Wrapper Script

**For Multiple ONTAP Instances (Recommended):**

The included `run_multi_ontap_sync.sh` wrapper handles multiple ONTAP instances sequentially. See the "Managing Multiple ONTAP Instances" section above for detailed setup instructions.

**For Single Instance (Simple Wrapper):**

If you only have one ONTAP or BlueXP instance, create a simple wrapper `/opt/netapp-veza/scripts/run_netapp_sync.sh`:

```bash
#!/bin/bash
# NetApp-Veza Integration Single Instance Wrapper

SCRIPT_DIR="/opt/netapp-veza/scripts"
LOG_DIR="/opt/netapp-veza/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/netapp_sync_${TIMESTAMP}.log"

# Activate virtual environment
source "${SCRIPT_DIR}/venv/bin/activate"
cd "${SCRIPT_DIR}"

# Option 1: ONTAP mode with default .env
python3 netAppShares.py \
  --system-type ontap \
  --svm-name PROD_SVM \
  --protocol cifs \
  >> "${LOG_FILE}" 2>&1

# Option 2: ONTAP mode with custom .env
# python3 netAppShares.py \
#   --system-type ontap \
#   --svm-name PROD_SVM \
#   --env-file configs/prod-svm.env \
#   >> "${LOG_FILE}" 2>&1

# Option 3: BlueXP mode
# python3 netAppShares.py \
#   --system-type bluexp \
#   --platform azure \
#   >> "${LOG_FILE}" 2>&1

EXIT_CODE=$?
echo "Script completed with exit code: ${EXIT_CODE}" >> "${LOG_FILE}"
find "${LOG_DIR}" -name "netapp_sync_*.log" -mtime +30 -delete
exit ${EXIT_CODE}
```

Make the wrapper executable:

```bash
chmod 755 /opt/netapp-veza/scripts/run_netapp_sync.sh
```

---

## Scheduling with Cron (Red Hat 8+)

### Understanding Cron on Red Hat 8+

Red Hat 8 uses **cronie** as the default cron implementation. It supports:
- User-specific crontabs (`crontab -e`)
- System-wide cron jobs in `/etc/cron.d/`
- Simplified cron directories: `/etc/cron.hourly/`, `/etc/cron.daily/`, etc.

### Cron Job Syntax

```
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of week (0 - 6) (Sunday = 0 or 7)
# │ │ │ │ │
# * * * * * command to execute
```

### Setting Up Cron Jobs

#### Option 1: User Crontab (Recommended for Service Account)

```bash
# Switch to service account
sudo su - netapp-veza

# Edit crontab
crontab -e
```

Add one of the following schedules:

```cron
# For single instance
# Run every 6 hours
0 */6 * * * /opt/netapp-veza/scripts/run_netapp_sync.sh

# Run daily at 2:00 AM
0 2 * * * /opt/netapp-veza/scripts/run_netapp_sync.sh

# For multiple ONTAP instances (using multi-instance wrapper)
# Run all instances daily at 2:00 AM
0 2 * * * /opt/netapp-veza/scripts/run_multi_ontap_sync.sh

# For multiple instances with custom .env files (individual jobs)
0 2 * * * cd /opt/netapp-veza/scripts && ./venv/bin/python3 netAppShares.py --system-type ontap --svm-name PROD_SVM1 --env-file configs/prod-svm1.env >> logs/prod-svm1-cron.log 2>&1
15 2 * * * cd /opt/netapp-veza/scripts && ./venv/bin/python3 netAppShares.py --system-type ontap --svm-name PROD_SVM2 --env-file configs/prod-svm2.env >> logs/prod-svm2-cron.log 2>&1

# Run every Monday at 3:00 AM
0 3 * * 1 /opt/netapp-veza/scripts/run_netapp_sync.sh

# Run every hour
0 * * * * /opt/netapp-veza/scripts/run_netapp_sync.sh

# Run every 30 minutes
*/30 * * * * /opt/netapp-veza/scripts/run_netapp_sync.sh
```

#### Option 2: System Cron Job (Requires Root)

Create `/etc/cron.d/netapp-veza`:

```bash
sudo bash -c 'cat > /etc/cron.d/netapp-veza << EOF
# NetApp-Veza Integration Cron Job
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=admin@example.com

# For single instance - run every 6 hours
0 */6 * * * netapp-veza /opt/netapp-veza/scripts/run_netapp_sync.sh

# For multiple ONTAP instances - run all daily at 2 AM
0 2 * * * netapp-veza /opt/netapp-veza/scripts/run_multi_ontap_sync.sh
EOF'

# Set proper permissions
sudo chmod 644 /etc/cron.d/netapp-veza
```

#### Option 3: Daily Cron Directory

For daily execution, you can place a script in `/etc/cron.daily/`:

```bash
sudo ln -s /opt/netapp-veza/scripts/run_netapp_sync.sh /etc/cron.daily/netapp-veza-sync
```

### Managing Cron Jobs

```bash
# List current user's cron jobs
crontab -l

# List another user's cron jobs (as root)
sudo crontab -u netapp-veza -l

# Edit cron jobs
crontab -e

# Remove all cron jobs (use with caution!)
crontab -r

# Check cron service status
sudo systemctl status crond

# Enable cron service at boot
sudo systemctl enable crond

# Start cron service
sudo systemctl start crond

# View cron logs
sudo journalctl -u crond -f

# View cron execution logs (system logs)
sudo tail -f /var/log/cron
```

### Monitoring Cron Job Execution

#### Check if Cron Jobs Are Running

```bash
# View recent cron executions
sudo grep CRON /var/log/cron | tail -20

# Monitor cron activity in real-time
sudo tail -f /var/log/cron

# Check application logs
tail -f /opt/netapp-veza/logs/netapp_sync_*.log

# View latest log file
ls -lt /opt/netapp-veza/logs/ | head -5
cat /opt/netapp-veza/logs/$(ls -t /opt/netapp-veza/logs/ | head -1)
```

#### Email Notifications

Configure email notifications for cron job results:

```bash
# Install mail utilities if not present
sudo dnf install mailx postfix -y
sudo systemctl enable postfix
sudo systemctl start postfix

# Set MAILTO in crontab
crontab -e
```

Add at the top of your crontab:

```cron
MAILTO=admin@example.com
PATH=/usr/local/bin:/usr/bin:/bin
```

### Troubleshooting Cron Jobs

#### Common Issues and Solutions

1. **Script not executing**
   ```bash
   # Check cron service is running
   sudo systemctl status crond
   
   # Check cron logs for errors
   sudo journalctl -u crond --since "1 hour ago"
   
   # Verify script permissions
   ls -l /opt/netapp-veza/scripts/run_netapp_sync.sh
   ```

2. **Environment variable issues**
   ```bash
   # Cron jobs run with minimal environment
   # Ensure .env file path is absolute in your script
   # Or set variables in crontab:
   VEZA_URL=your-instance.veza.com
   VEZA_API_KEY=your_key
   ```

3. **Permission denied errors**
   ```bash
   # Ensure service account owns the files
   sudo chown -R netapp-veza:netapp-veza /opt/netapp-veza
   
   # Verify executable permissions
   chmod +x /opt/netapp-veza/scripts/run_netapp_sync.sh
   chmod +x /opt/netapp-veza/scripts/netAppShares.py
   ```

4. **Python/module not found**
   ```bash
   # Ensure virtual environment activation in wrapper script
   # Use absolute paths for python and pip
   /opt/netapp-veza/scripts/venv/bin/python3 netAppShares.py
   ```

### Testing Cron Jobs

Before scheduling, test your cron job manually:

```bash
# Test as the service account
sudo su - netapp-veza -c "/opt/netapp-veza/scripts/run_netapp_sync.sh"

# Check exit code
echo $?

# Review log output
cat /opt/netapp-veza/logs/netapp_sync_*.log | tail -50
```

### Best Practices for Production Cron Jobs

1. **Use absolute paths** for all files and commands
2. **Set environment variables** explicitly in wrapper script or crontab
3. **Implement logging** with timestamps and log rotation
4. **Add error handling** in wrapper scripts
5. **Test thoroughly** before scheduling in production
6. **Monitor execution** regularly through logs
7. **Set up alerts** for failures (email or monitoring system)
8. **Document schedule** decisions and rationale
9. **Use flock or lockfile** to prevent concurrent executions:

```bash
#!/bin/bash
# Add to wrapper script to prevent overlapping executions
LOCKFILE=/var/lock/netapp-veza-sync.lock

if [ -e ${LOCKFILE} ] && kill -0 $(cat ${LOCKFILE}); then
    echo "Already running"
    exit
fi

# Make sure lock file is removed when script exits
trap "rm -f ${LOCKFILE}; exit" INT TERM EXIT
echo $$ > ${LOCKFILE}

# Your script logic here...
```

---

## Security Considerations

### File Permissions

Ensure sensitive files are properly secured:

```bash
# Secure .env file (contains credentials)
chmod 600 /opt/netapp-veza/scripts/.env
chown netapp-veza:netapp-veza /opt/netapp-veza/scripts/.env

# Secure script directory
chmod 700 /opt/netapp-veza/scripts

# Secure log directory (if contains sensitive data)
chmod 750 /opt/netapp-veza/logs
```

### SELinux Considerations (Red Hat 8+)

If SELinux is enabled, you may need to configure contexts:

```bash
# Check SELinux status
getenforce

# Set proper context for scripts
sudo semanage fcontext -a -t bin_t "/opt/netapp-veza/scripts/.*\.py"
sudo semanage fcontext -a -t bin_t "/opt/netapp-veza/scripts/.*\.sh"
sudo restorecon -Rv /opt/netapp-veza/scripts

# Allow cron to execute scripts (if needed)
sudo setsebool -P cron_can_relabel 1
```

### API Key Rotation

Implement regular API key rotation:

1. Generate new API keys in NetApp and Veza
2. Update `.env` file with new credentials
3. Test script execution
4. Revoke old API keys

---

## Troubleshooting

### Common Issues

#### Authentication Failures

```bash
# Verify environment variables are loaded
source venv/bin/activate
python3 -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('VEZA_URL'))"

# Test API connectivity
curl -H "Authorization: Bearer YOUR_API_KEY" https://your-instance.veza.com/api/v1/providers
```

#### Module Not Found Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

#### Network Connectivity Issues

```bash
# Test NetApp BlueXP connectivity
curl -I https://cloudmanager.cloud.netapp.com

# Test ONTAP connectivity
curl -Ik https://your-ontap-cluster.example.com

# Test Veza connectivity
curl -I https://your-instance.veza.com
```

---

## Support and Contributions

For issues, questions, or contributions, please contact your organization's NetApp or Veza administrator.

---

## License

This script is proprietary and for internal use only.

---

## Changelog

### Version 1.0
- Initial release with BlueXP and ONTAP support
- CIFS share integration with NTFS permissions
- Active Directory group resolution
- Identity integration for users and roles
