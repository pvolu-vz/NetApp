#!/bin/bash
################################################################################
# NetApp Multi-ONTAP Sync Wrapper Script
#
# This script runs the NetApp to Veza integration for multiple ONTAP instances
# sequentially. Each ONTAP instance uses its own .env configuration file.
#
# Usage:
#   ./run_multi_ontap_sync.sh
#
# Cron Setup:
#   # Run daily at 2 AM
#   0 2 * * * /opt/netapp-veza/scripts/run_multi_ontap_sync.sh >> /opt/netapp-veza/logs/multi_sync.log 2>&1
#
################################################################################

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="netAppShares.py"
SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"
VENV_PATH="${SCRIPT_DIR}/venv"
LOG_DIR="${SCRIPT_DIR}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAIN_LOG="${LOG_DIR}/multi_sync_${TIMESTAMP}.log"

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

# Ensure only one instance runs at a time
LOCKFILE="/var/lock/netapp-multi-sync.lock"
exec 200>"${LOCKFILE}"
flock -n 200 || {
    echo "[$(date)] Another instance is already running. Exiting." | tee -a "${MAIN_LOG}"
    exit 1
}

# Trap to ensure lockfile cleanup on exit
trap 'rm -f ${LOCKFILE}; exit' INT TERM EXIT

################################################################################
# Logging Functions
################################################################################

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${MAIN_LOG}"
}

log_section() {
    echo "" | tee -a "${MAIN_LOG}"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "${MAIN_LOG}"
    echo "$*" | tee -a "${MAIN_LOG}"
    echo "═══════════════════════════════════════════════════════════════" | tee -a "${MAIN_LOG}"
}

################################################################################
# ONTAP Instance Configuration
#
# Define your ONTAP instances here. Each entry should have:
#   - SVM_NAME: The name/address of the SVM
#   - ENV_FILE: Path to the .env file (relative to script directory or absolute)
#   - PROTOCOL: cifs or nfs (optional, defaults to cifs)
################################################################################

# Array of ONTAP instances to sync
# Format: "SVM_NAME|ENV_FILE|PROTOCOL"
declare -a ONTAP_INSTANCES=(
    "PROD_SVM1|.env.prod-svm1|cifs"
    "PROD_SVM2|.env.prod-svm2|cifs"
    "TEST_SVM|.env.test-svm|cifs"
    # Add more instances as needed
    # "DEV_SVM|configs/dev-svm.env|cifs"
)

################################################################################
# Main Execution
################################################################################

log_section "NetApp Multi-ONTAP Sync Started"
log "Script: ${SCRIPT_PATH}"
log "Log Directory: ${LOG_DIR}"
log "Main Log: ${MAIN_LOG}"
log "Total ONTAP Instances: ${#ONTAP_INSTANCES[@]}"

# Check if virtual environment exists
if [ ! -d "${VENV_PATH}" ]; then
    log "ERROR: Virtual environment not found at ${VENV_PATH}"
    log "Please run: python3 -m venv ${VENV_PATH} && source ${VENV_PATH}/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
log "Activating virtual environment..."
source "${VENV_PATH}/bin/activate" || {
    log "ERROR: Failed to activate virtual environment"
    exit 1
}

# Verify Python script exists
if [ ! -f "${SCRIPT_PATH}" ]; then
    log "ERROR: NetApp script not found at ${SCRIPT_PATH}"
    exit 1
fi

# Make script executable if needed
chmod +x "${SCRIPT_PATH}" 2>/dev/null

# Track results
TOTAL=0
SUCCESS=0
FAILED=0
declare -a FAILED_SVMS=()

# Process each ONTAP instance
for instance in "${ONTAP_INSTANCES[@]}"; do
    # Parse instance configuration
    IFS='|' read -r SVM_NAME ENV_FILE PROTOCOL <<< "$instance"
    
    # Set default protocol if not specified
    PROTOCOL=${PROTOCOL:-cifs}
    
    # Skip empty lines
    [ -z "${SVM_NAME}" ] && continue
    
    TOTAL=$((TOTAL + 1))
    
    log_section "Processing ONTAP Instance: ${SVM_NAME}"
    log "SVM Name: ${SVM_NAME}"
    log "Config File: ${ENV_FILE}"
    log "Protocol: ${PROTOCOL}"
    
    # Resolve env file path
    if [[ "${ENV_FILE}" = /* ]]; then
        # Absolute path
        ENV_FILE_PATH="${ENV_FILE}"
    else
        # Relative to script directory
        ENV_FILE_PATH="${SCRIPT_DIR}/${ENV_FILE}"
    fi
    
    # Check if env file exists
    if [ ! -f "${ENV_FILE_PATH}" ]; then
        log "ERROR: Configuration file not found: ${ENV_FILE_PATH}"
        log "Skipping ${SVM_NAME}"
        FAILED=$((FAILED + 1))
        FAILED_SVMS+=("${SVM_NAME} (config missing)")
        continue
    fi
    
    # Create instance-specific log file
    INSTANCE_LOG="${LOG_DIR}/sync_${SVM_NAME}_${TIMESTAMP}.log"
    log "Instance Log: ${INSTANCE_LOG}"
    
    # Run the sync
    log "Starting sync..."
    
    python3 "${SCRIPT_PATH}" \
        --system-type ontap \
        --svm-name "${SVM_NAME}" \
        --protocol "${PROTOCOL}" \
        --env-file "${ENV_FILE_PATH}" \
        > "${INSTANCE_LOG}" 2>&1
    
    EXIT_CODE=$?
    
    if [ ${EXIT_CODE} -eq 0 ]; then
        log "✓ SUCCESS: ${SVM_NAME} synced successfully"
        SUCCESS=$((SUCCESS + 1))
    else
        log "✗ FAILED: ${SVM_NAME} sync failed with exit code ${EXIT_CODE}"
        log "   See log: ${INSTANCE_LOG}"
        FAILED=$((FAILED + 1))
        FAILED_SVMS+=("${SVM_NAME} (exit code: ${EXIT_CODE})")
        
        # Show last 10 lines of error log
        log "   Last 10 lines of error log:"
        tail -10 "${INSTANCE_LOG}" | sed 's/^/      /' | tee -a "${MAIN_LOG}"
    fi
    
    # Small delay between instances to avoid API rate limiting
    if [ ${TOTAL} -lt ${#ONTAP_INSTANCES[@]} ]; then
        log "Waiting 5 seconds before next instance..."
        sleep 5
    fi
done

################################################################################
# Summary
################################################################################

log_section "Multi-ONTAP Sync Completed"
log "Total Instances: ${TOTAL}"
log "Successful: ${SUCCESS}"
log "Failed: ${FAILED}"

if [ ${FAILED} -gt 0 ]; then
    log ""
    log "Failed SVMs:"
    for failed_svm in "${FAILED_SVMS[@]}"; do
        log "  - ${failed_svm}"
    done
fi

log ""
log "Main log saved to: ${MAIN_LOG}"
log "Individual logs in: ${LOG_DIR}"

# Deactivate virtual environment
deactivate

# Exit with appropriate code
if [ ${FAILED} -eq 0 ]; then
    log "All syncs completed successfully!"
    exit 0
else
    log "Some syncs failed. Please review logs."
    exit 1
fi
