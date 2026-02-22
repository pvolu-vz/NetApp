# NetApp Shares Pre-Flight Validation Script

## Overview

The `preflight.sh` script is a comprehensive validation tool that checks all prerequisites before deploying the `netAppShares.py` script. It validates system requirements, dependencies, configuration, network connectivity, API authentication, and deployment structure.

## Features

- **Menu-driven interface** - Interactive numbered menu for selective testing
- **Automated mode** - Run all checks with `--all` flag for CI/CD pipelines
- **Color-coded output** - Clear visual feedback (✓ success, ✗ failure, ⚠ warning, ℹ info)
- **Comprehensive reporting** - Detailed summary with pass/fail counts
- **Logging** - Timestamped logs saved to preflight_YYYYMMDD_HHMMSS.log

## Quick Start

### Make executable (first time only)
```bash
chmod +x preflight.sh
```

### Interactive mode
```bash
./preflight.sh
```

### Automated mode (run all checks)
```bash
./preflight.sh --all
```

## Menu Options

### Validation Checks

**1. System Requirements**
- Python version (>= 3.7 required)
- pip3 availability
- Virtual environment detection
- OS compatibility check
- curl and jq availability

**2. Python Dependencies**
- Verifies requirements.txt exists
- Checks installed packages:
  - `requests>=2.31.0`
  - `python-dotenv>=1.0.0`
  - `oaaclient>=2.0.0`
- Validates import functionality

**3. Configuration File**
- Checks `.env` file exists
- Validates file permissions (should be 600)
- Verifies all required environment variables:
  - **BlueXP**: AUTH_URL, CLIENT_ID, CLIENT_SECRET, AUDIENCE, VOLUMES_API_URL_BASE, USERS_API_URL, WORKING_ENVIRONMENT_ID, AGENT_ID
  - **ONTAP**: USERNAME, PASSWORD, API_BASE_URL (optional)
  - **Veza**: URL, API_KEY
- Detects placeholder values (e.g., `your_*`)

**4. Network Connectivity**
- Tests HTTPS (port 443) to:
  - `netapp-cloud-account.auth0.com`
  - `cloudmanager.cloud.netapp.com`
  - ONTAP cluster (if configured)
  - Veza instance
- Reports connection time and HTTP status

**5. API Authentication**
- **NetApp BlueXP OAuth2** - Tests client credentials flow with Auth0
- **ONTAP Basic Auth** - Tests username/password authentication (if configured)
- **Veza API** - Validates bearer token authentication
- Displays authentication status and response codes
- Never logs actual passwords or tokens (masked output)

**6. API Endpoint Accessibility**
- Tests authenticated GET requests to:
  - BlueXP Volumes API
  - BlueXP Users API
  - ONTAP CIFS Shares API
  - Veza Query API
- Verifies proper response codes (200-299)
- Detects authorization issues (401, 403)

**7. Deployment Structure**
- Verifies `netAppShares.py` exists and is readable
- Checks script executability
- Validates deployment location
- Checks log directory (if configured)
- Reports current user/service account

**8. Run ALL Checks**
- Executes all validation checks sequentially
- Generates comprehensive summary report
- Returns exit code 0 if all pass, 1 if any fail

### Utilities

**9. Display Current Configuration**
- Shows all environment variables
- Masks sensitive values (secrets, keys)
- Useful for troubleshooting

**10. Generate Template .env File**
- Creates `.env` file with all required variables
- Sets secure permissions (600)
- Includes placeholder values to replace

**11. Install Python Dependencies**
- Installs packages from `requirements.txt`
- Uses pip3 to install in current environment

## Exit Codes

- **0** - All validation checks passed
- **1** - One or more validation checks failed

## What Gets Tested

### Before Running netAppShares.py

The script validates that:

1. **System is ready**
   - Python 3.7+ installed
   - pip3 available
   - curl available for API testing

2. **Dependencies are installed**
   - All required Python packages present
   - Correct versions installed
   - Packages can be imported

3. **Configuration is complete**
   - `.env` file exists with proper permissions
   - All required credentials configured
   - No placeholder values remaining

4. **Network is accessible**
   - HTTPS connectivity to all required endpoints
   - DNS resolution working
   - Firewall allows outbound 443

5. **Authentication works**
   - Can obtain OAuth2 tokens from NetApp
   - Veza API key is valid
   - Tokens have proper permissions

6. **APIs are reachable**
   - Can make authenticated requests
   - Endpoints return expected responses
   - Have proper access permissions

7. **Deployment is correct**
   - Script files in place
   - Proper file permissions
   - Directory structure ready

## Common Issues and Solutions

### Missing .env file
```bash
./preflight.sh
# Select option 10 to generate template
# Edit .env and replace placeholder values
```

### Dependencies not installed
```bash
./preflight.sh
# Select option 11 to install dependencies
# Or manually: pip3 install -r requirements.txt
```

### Insecure .env permissions
```bash
chmod 600 .env
```

### Authentication failures
- Verify CLIENT_ID and CLIENT_SECRET are correct (for BlueXP)
- Verify ONTAP_USERNAME and ONTAP_PASSWORD are correct (for ONTAP)
- Check that credentials haven't expired
- Ensure AUDIENCE matches your environment (for BlueXP)

### Network connectivity issues
- Check firewall allows outbound HTTPS (443)
- Verify DNS resolves endpoint hostnames
- Test with: `curl -v https://cloudmanager.cloud.netapp.com`

### API endpoint 403 errors
- Verify credentials have proper permissions
- Check AGENT_ID is correct
- Ensure WORKING_ENVIRONMENT_ID matches your environment

## Recommended Workflow

1. **Initial setup**
   ```bash
   ./preflight.sh
   # Select option 10 - Generate .env template
   # Edit .env with your credentials
   # Select option 11 - Install dependencies
   ```

2. **Before deployment**
   ```bash
   ./preflight.sh --all
   # Review any failures or warnings
   # Fix issues identified
   # Re-run until all checks pass
   ```

3. **Run netAppShares.py**
   ```bash
   python3 netAppShares.py
   ```

## Automation / CI/CD

For automated deployments:

```bash
#!/bin/bash

# Run preflight checks
./preflight.sh --all

# Exit if checks failed
if [ $? -ne 0 ]; then
    echo "Pre-flight validation failed. Aborting deployment."
    exit 1
fi

# Run the script
python3 netAppShares.py
```

## Production Deployment

For production environments:

1. Create service account:
   ```bash
   sudo useradd -r -s /bin/bash netapp-veza
   ```

2. Deploy to recommended location:
   ```bash
   sudo mkdir -p /opt/netapp-veza/scripts
   sudo mkdir -p /opt/netapp-veza/logs
   sudo cp netAppShares.py preflight.sh requirements.txt /opt/netapp-veza/scripts/
   sudo cp .env /opt/netapp-veza/scripts/
   sudo chown -R netapp-veza:netapp-veza /opt/netapp-veza
   sudo chmod 600 /opt/netapp-veza/scripts/.env
   ```

3. Run preflight validation as service account:
   ```bash
   sudo -u netapp-veza /opt/netapp-veza/scripts/preflight.sh --all
   ```

## Logs

Each run creates a timestamped log file:
```
preflight_20260212_221303.log
```

The log contains all validation output for troubleshooting.

## Requirements

- **Bash** (3.2+)
- **Python** (3.7+)
- **curl** (for API testing)
- **jq** (optional, for enhanced JSON parsing)

## Support

For issues or questions about specific validation failures, review the detailed error messages provided by the script. Each failure includes:
- What was tested
- Why it failed
- How to fix it (when applicable)
