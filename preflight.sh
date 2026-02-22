#!/bin/bash

#####################################################################
# NetApp Shares Pre-Flight Validation Script
# Purpose: Validate all prerequisites before deploying netAppShares.py
# Author: Auto-generated
# Date: 2026-02-12
#####################################################################

set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
NETAPP_SCRIPT="${SCRIPT_DIR}/netAppShares.py"
LOG_FILE="${SCRIPT_DIR}/preflight_$(date +%Y%m%d_%H%M%S).log"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

#####################################################################
# Utility Functions
#####################################################################

print_header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((TESTS_WARNING++))
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_output() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

#####################################################################
# Validation Functions
#####################################################################

validate_system_requirements() {
    print_header "System Requirements Validation"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
        PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
        
        if [[ "$PYTHON_MAJOR" -ge 3 ]] && [[ "$PYTHON_MINOR" -ge 7 ]]; then
            print_success "Python version $PYTHON_VERSION (>= 3.7 required)"
        else
            print_fail "Python version $PYTHON_VERSION is too old (>= 3.7 required)"
        fi
    else
        print_fail "Python 3 not found. Please install Python 3.7 or higher"
        return 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        PIP_VERSION=$(pip3 --version 2>&1 | awk '{print $2}')
        print_success "pip3 version $PIP_VERSION installed"
    else
        print_fail "pip3 not found. Please install pip3"
        echo -e "  ${YELLOW}Install with: python3 -m ensurepip --upgrade${NC}"
    fi
    
    # Check if in virtual environment
    if [[ -n "$VIRTUAL_ENV" ]]; then
        print_success "Running in virtual environment: $VIRTUAL_ENV"
    else
        print_warning "Not running in virtual environment (recommended but not required)"
        echo -e "  ${YELLOW}Create one with: python3 -m venv venv && source venv/bin/activate${NC}"
    fi
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            OS_NAME=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
            OS_VERSION=$(grep "^VERSION=" /etc/os-release | cut -d'"' -f2)
            print_info "Operating System: $OS_NAME $OS_VERSION"
        else
            print_info "Operating System: Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_info "Operating System: macOS"
    else
        print_warning "Operating System: $OSTYPE (RHEL 8+ recommended for production)"
    fi
    
    # Check curl availability
    if command -v curl &> /dev/null; then
        print_success "curl installed (required for API tests)"
    else
        print_fail "curl not found. Please install curl"
    fi
    
    # Check jq availability (optional)
    if command -v jq &> /dev/null; then
        print_success "jq installed (optional, for enhanced JSON parsing)"
    else
        print_warning "jq not found (optional). Will use Python for JSON parsing"
    fi
}

validate_dependencies() {
    print_header "Python Dependencies Validation"
    
    # Check requirements.txt exists
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        print_fail "requirements.txt not found at $REQUIREMENTS_FILE"
        return 1
    fi
    print_success "requirements.txt found"
    
    # Check if dependencies are installed
    echo -e "\n${BOLD}Checking installed packages:${NC}"
    
    # Check requests
    if python3 -c "import requests" 2>/dev/null; then
        REQUESTS_VER=$(python3 -c "import requests; print(requests.__version__)" 2>/dev/null)
        print_success "requests==$REQUESTS_VER installed"
    else
        print_fail "requests not installed"
    fi
    
    # Check python-dotenv
    if python3 -c "import dotenv" 2>/dev/null; then
        DOTENV_VER=$(python3 -c "import dotenv; print(dotenv.__version__)" 2>/dev/null)
        print_success "python-dotenv==$DOTENV_VER installed"
    else
        print_fail "python-dotenv not installed"
    fi
    
    # Check oaaclient
    if python3 -c "import oaaclient" 2>/dev/null; then
        print_success "oaaclient installed"
    else
        print_fail "oaaclient not installed"
    fi
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "\n${YELLOW}Install dependencies with: pip3 install -r $REQUIREMENTS_FILE${NC}"
    fi
}

validate_configuration() {
    print_header "Configuration File Validation"
    
    # Check .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        print_fail ".env file not found at $ENV_FILE"
        echo -e "  ${YELLOW}Create one using: Option 10 from main menu${NC}"
        return 1
    fi
    print_success ".env file exists"
    
    # Check file permissions
    PERMS=$(stat -f "%OLp" "$ENV_FILE" 2>/dev/null || stat -c "%a" "$ENV_FILE" 2>/dev/null)
    if [[ "$PERMS" == "600" ]]; then
        print_success ".env file permissions are secure (600)"
    else
        print_warning ".env file permissions are $PERMS (should be 600 for security)"
        echo -e "  ${YELLOW}Fix with: chmod 600 $ENV_FILE${NC}"
    fi
    
    # Source .env and validate required variables
    echo -e "\n${BOLD}Validating environment variables:${NC}"
    
    source "$ENV_FILE"
    
    # BlueXP variables
    echo -e "\n${BOLD}BlueXP Configuration:${NC}"
    check_env_var "BLUEXP_AUTH_URL" "$BLUEXP_AUTH_URL"
    check_env_var "BLUEXP_CLIENT_ID" "$BLUEXP_CLIENT_ID"
    check_env_var "BLUEXP_CLIENT_SECRET" "$BLUEXP_CLIENT_SECRET"
    check_env_var "BLUEXP_AUDIENCE" "$BLUEXP_AUDIENCE"
    check_env_var "VOLUMES_API_URL_BASE" "$VOLUMES_API_URL_BASE"
    check_env_var "USERS_API_URL" "$USERS_API_URL"
    check_env_var "WORKING_ENVIRONMENT_ID" "$WORKING_ENVIRONMENT_ID"
    check_env_var "AGENT_ID" "$AGENT_ID"
    
    # ONTAP variables
    echo -e "\n${BOLD}ONTAP Configuration:${NC}"
    check_env_var "ONTAP_USERNAME" "$ONTAP_USERNAME" "optional"
    check_env_var "ONTAP_PASSWORD" "$ONTAP_PASSWORD" "optional"
    check_env_var "ONTAP_API_BASE_URL" "$ONTAP_API_BASE_URL" "optional"
    
    # Veza variables
    echo -e "\n${BOLD}Veza Configuration:${NC}"
    check_env_var "VEZA_URL" "$VEZA_URL"
    check_env_var "VEZA_API_KEY" "$VEZA_API_KEY"
    
    # Domain variables
    echo -e "\n${BOLD}Domain Configuration:${NC}"
    check_env_var "DOMAIN_TO_REMOVE" "$DOMAIN_TO_REMOVE" "optional"
    check_env_var "DOMAIN_SUFFIX" "$DOMAIN_SUFFIX" "optional"
}

check_env_var() {
    local var_name=$1
    local var_value=$2
    local optional=$3
    
    if [[ -z "$var_value" ]]; then
        if [[ "$optional" == "optional" ]]; then
            print_info "$var_name not set (optional for ONTAP mode)"
        else
            print_fail "$var_name is not set"
        fi
    elif [[ "$var_value" =~ ^your_.*|^https://your-.* ]]; then
        print_warning "$var_name contains placeholder value"
    else
        # Mask sensitive values
        if [[ "$var_name" =~ SECRET|KEY|TOKEN ]]; then
            print_success "$var_name set (${var_value:0:8}...)"
        else
            print_success "$var_name set"
        fi
    fi
}

validate_network_connectivity() {
    print_header "Network Connectivity Tests"
    
    source "$ENV_FILE" 2>/dev/null || true
    
    echo -e "${BOLD}Testing HTTPS connectivity to required endpoints:${NC}\n"
    
    # Test NetApp Auth0
    test_connectivity "NetApp Auth0" "netapp-cloud-account.auth0.com" 443
    
    # Test NetApp BlueXP API
    test_connectivity "NetApp BlueXP API" "cloudmanager.cloud.netapp.com" 443
    
    # Test ONTAP if configured
    if [[ -n "$ONTAP_API_BASE_URL" && ! "$ONTAP_API_BASE_URL" =~ your-.* ]]; then
        ONTAP_HOST=$(echo "$ONTAP_API_BASE_URL" | sed -E 's|https?://||' | cut -d'/' -f1)
        test_connectivity "ONTAP Cluster" "$ONTAP_HOST" 443
    else
        print_info "ONTAP_API_BASE_URL not configured, skipping ONTAP connectivity test"
    fi
    
    # Test Veza
    if [[ -n "$VEZA_URL" && ! "$VEZA_URL" =~ your-.* ]]; then
        VEZA_HOST=$(echo "$VEZA_URL" | sed -E 's|https?://||' | cut -d'/' -f1)
        test_connectivity "Veza Instance" "$VEZA_HOST" 443
    else
        print_warning "VEZA_URL not configured properly, skipping Veza connectivity test"
    fi
}

test_connectivity() {
    local name=$1
    local host=$2
    local port=$3
    
    # Try curl first
    if command -v curl &> /dev/null; then
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" -m 10 "https://${host}" 2>/dev/null)
        HTTP_CODE=$(echo "$RESPONSE" | cut -d'|' -f1)
        TIME=$(echo "$RESPONSE" | cut -d'|' -f2)
        
        if [[ -n "$HTTP_CODE" && "$HTTP_CODE" != "000" ]]; then
            TIME_MS=$(echo "$TIME * 1000" | bc 2>/dev/null || echo "$TIME")
            print_success "$name ($host:$port) - HTTP $HTTP_CODE - ${TIME_MS}ms"
        else
            print_fail "$name ($host:$port) - Connection failed"
        fi
    else
        # Fall back to nc if available
        if command -v nc &> /dev/null; then
            if nc -zv -w 5 "$host" "$port" 2>&1 | grep -q "succeeded\|open"; then
                print_success "$name ($host:$port) - Port is open"
            else
                print_fail "$name ($host:$port) - Port is closed or unreachable"
            fi
        else
            print_warning "$name ($host:$port) - Cannot test (curl and nc not available)"
        fi
    fi
}

validate_api_authentication() {
    print_header "API Authentication Tests"
    
    source "$ENV_FILE" 2>/dev/null || true
    
    # Test NetApp BlueXP OAuth2 - DISABLED
    echo -e "${BOLD}Testing NetApp BlueXP Authentication:${NC}"
    print_info "BlueXP authentication tests disabled (skipped)"
    
    # Test ONTAP Basic Auth
    echo -e "\n${BOLD}Testing ONTAP Authentication:${NC}"
    if [[ -n "$ONTAP_API_BASE_URL" && -n "$ONTAP_USERNAME" && -n "$ONTAP_PASSWORD" && ! "$ONTAP_API_BASE_URL" =~ your-.* ]]; then
        echo -e "${BLUE}[DEBUG] Request: GET ${ONTAP_API_BASE_URL}/api/protocols/cifs/shares${NC}"
        echo -e "${BLUE}[DEBUG] Authentication: Basic Auth (username: ${ONTAP_USERNAME})${NC}"
        
        RESPONSE_BODY=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "${ONTAP_API_BASE_URL}/api/protocols/cifs/shares" \
            -u "$ONTAP_USERNAME:$ONTAP_PASSWORD" \
            -H "Content-Type: application/json" \
            2>/dev/null)
        
        HTTP_CODE=$(echo "$RESPONSE_BODY" | grep "HTTP_CODE:" | cut -d: -f2)
        BODY=$(echo "$RESPONSE_BODY" | sed '/HTTP_CODE:/d')
        
        if [[ "$HTTP_CODE" == "200" ]]; then
            print_success "ONTAP Basic Authentication successful (HTTP 200)"
            echo -e "${BLUE}[DEBUG] Response successful${NC}"
        elif [[ "$HTTP_CODE" == "401" ]]; then
            print_fail "ONTAP Basic Authentication failed (HTTP 401 - Invalid credentials)"
            echo -e "${RED}[DEBUG] Check username and password${NC}"
        else
            print_warning "ONTAP authentication response: HTTP $HTTP_CODE"
            echo -e "${YELLOW}[DEBUG] Response body:${NC}"
            echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
        fi
    else
        print_info "ONTAP credentials not configured, skipping ONTAP authentication test"
    fi
    
    # Test Veza API
    echo -e "\n${BOLD}Testing Veza API Authentication:${NC}"
    if [[ -n "$VEZA_URL" && -n "$VEZA_API_KEY" && ! "$VEZA_URL" =~ your-.* ]]; then
        VEZA_BASE_URL="https://${VEZA_URL}"
        echo -e "${BLUE}[DEBUG] Request: GET ${VEZA_BASE_URL}/api/v1/providers${NC}"
        echo -e "${BLUE}[DEBUG] Authorization: Bearer ${VEZA_API_KEY:0:8}...${NC}"
        
        RESPONSE_BODY=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "${VEZA_BASE_URL}/api/v1/providers" \
            -H "Authorization: Bearer $VEZA_API_KEY" \
            -H "Content-Type: application/json" \
            2>/dev/null)
        
        HTTP_CODE=$(echo "$RESPONSE_BODY" | grep "HTTP_CODE:" | cut -d: -f2)
        BODY=$(echo "$RESPONSE_BODY" | sed '/HTTP_CODE:/d')
        
        if [[ "$HTTP_CODE" == "200" ]]; then
            print_success "Veza API authentication successful (HTTP 200)"
            echo -e "${BLUE}[DEBUG] Response successful${NC}"
        elif [[ "$HTTP_CODE" == "401" ]]; then
            print_fail "Veza API authentication failed (HTTP 401 - Invalid API key)"
            echo -e "${RED}[DEBUG] Full response body:${NC}"
            echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
        elif [[ "$HTTP_CODE" == "403" ]]; then
            print_fail "Veza API authentication failed (HTTP 403 - Access forbidden)"
            echo -e "${RED}[DEBUG] Full response body:${NC}"
            echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
        else
            print_warning "Veza API response: HTTP $HTTP_CODE"
            echo -e "${YELLOW}[DEBUG] Full response body:${NC}"
            echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
        fi
    else
        print_warning "Veza credentials not configured, skipping Veza authentication test"
    fi
}

validate_api_endpoints() {
    print_header "API Endpoint Accessibility Tests"
    
    source "$ENV_FILE" 2>/dev/null || true
    
    echo -e "${BOLD}Testing authenticated API endpoint access:${NC}\n"
    
    # BlueXP endpoint tests - DISABLED
    print_info "BlueXP endpoint tests disabled (skipped)"
    
    # Test Veza query endpoint
    echo ""
    if [[ -n "$VEZA_URL" && -n "$VEZA_API_KEY" && ! "$VEZA_URL" =~ your-.* ]]; then
        VEZA_BASE_URL="https://${VEZA_URL}"
        test_veza_endpoint "Veza Query API" "${VEZA_BASE_URL}/api/v1/assessments/query_spec:nodes" "$VEZA_API_KEY"
    fi
}

test_api_endpoint() {
    local name=$1
    local url=$2
    local token=$3
    local agent_id=$4
    
    local HEADERS="-H 'Authorization: Bearer $token'"
    if [[ -n "$agent_id" ]]; then
        HEADERS="$HEADERS -H 'x-agent-id: $agent_id'"
    fi
    
    RESPONSE=$(eval curl -s -o /dev/null -w "%{http_code}" -X GET "$url" $HEADERS 2>/dev/null)
    
    if [[ "$RESPONSE" == "200" ]]; then
        print_success "$name accessible (HTTP 200)"
    elif [[ "$RESPONSE" == "401" ]]; then
        print_fail "$name failed (HTTP 401 - Unauthorized)"
    elif [[ "$RESPONSE" == "403" ]]; then
        print_fail "$name failed (HTTP 403 - Forbidden)"
    elif [[ "$RESPONSE" == "404" ]]; then
        print_warning "$name returned HTTP 404 (endpoint may not exist or no data)"
    else
        print_warning "$name returned HTTP $RESPONSE"
    fi
}

test_veza_endpoint() {
    local name=$1
    local url=$2
    local api_key=$3
    
    # Minimal valid query to test endpoint
    local QUERY='{"query":"nodes{InstanceId first:1}"}'
    
    echo -e "${BLUE}[DEBUG] Request: POST $url${NC}"
    echo -e "${BLUE}[DEBUG] Query: $QUERY${NC}"
    
    RESPONSE_BODY=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$url" \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d "$QUERY" \
        2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE_BODY" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$RESPONSE_BODY" | sed '/HTTP_CODE:/d')
    
    if [[ "$HTTP_CODE" == "200" ]]; then
        print_success "$name accessible (HTTP 200)"
        echo -e "${BLUE}[DEBUG] Response successful${NC}"
    elif [[ "$HTTP_CODE" == "401" ]]; then
        print_fail "$name failed (HTTP 401 - Invalid API key)"
        echo -e "${RED}[DEBUG] Full response body:${NC}"
        echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        print_fail "$name failed (HTTP 403 - Insufficient permissions)"
        echo -e "${RED}[DEBUG] Full response body:${NC}"
        echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
    else
        print_warning "$name returned HTTP $HTTP_CODE"
        echo -e "${YELLOW}[DEBUG] Full response body:${NC}"
        echo "$BODY" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null || echo "$BODY"
    fi
}

validate_deployment_structure() {
    print_header "Deployment Structure Validation"
    
    # Check main script exists
    if [ -f "$NETAPP_SCRIPT" ]; then
        print_success "netAppShares.py exists at $NETAPP_SCRIPT"
        
        # Check if readable
        if [ -r "$NETAPP_SCRIPT" ]; then
            print_success "netAppShares.py is readable"
        else
            print_fail "netAppShares.py exists but is not readable"
        fi
        
        # Check if executable (if it has shebang)
        if head -n 1 "$NETAPP_SCRIPT" | grep -q "^#!"; then
            if [ -x "$NETAPP_SCRIPT" ]; then
                print_success "netAppShares.py is executable"
            else
                print_warning "netAppShares.py has shebang but is not executable"
                echo -e "  ${YELLOW}Fix with: chmod +x $NETAPP_SCRIPT${NC}"
            fi
        fi
    else
        print_fail "netAppShares.py not found at $NETAPP_SCRIPT"
        return 1
    fi
    
    # Check working directory structure
    echo -e "\n${BOLD}Current deployment location:${NC}"
    print_info "Script directory: $SCRIPT_DIR"
    
    # Check if in recommended location
    if [[ "$SCRIPT_DIR" =~ /opt/netapp-veza/scripts ]]; then
        print_success "Deployed in recommended location (/opt/netapp-veza/scripts)"
    else
        print_info "Not in recommended production location (/opt/netapp-veza/scripts)"
    fi
    
    # Check log directory
    if [ -d "${SCRIPT_DIR}/logs" ]; then
        if [ -w "${SCRIPT_DIR}/logs" ]; then
            print_success "logs/ directory exists and is writable"
        else
            print_warning "logs/ directory exists but is not writable"
        fi
    else
        print_info "logs/ directory does not exist (optional)"
    fi
    
    # Check if running as service account
    CURRENT_USER=$(whoami)
    if [[ "$CURRENT_USER" == "netapp-veza" ]]; then
        print_success "Running as dedicated service account (netapp-veza)"
    else
        print_info "Running as user: $CURRENT_USER"
    fi
}

run_all_checks() {
    print_header "Running Complete Pre-Flight Validation"
    
    echo -e "${BOLD}Starting comprehensive validation at $(date)${NC}\n"
    
    # Reset counters
    TESTS_PASSED=0
    TESTS_FAILED=0
    TESTS_WARNING=0
    
    # Run all validation functions
    validate_system_requirements
    echo ""
    validate_dependencies
    echo ""
    validate_configuration
    echo ""
    validate_network_connectivity
    echo ""
    validate_api_authentication
    echo ""
    validate_api_endpoints
    echo ""
    validate_deployment_structure
    
    # Print summary
    print_summary
}

print_summary() {
    print_header "Validation Summary"
    
    echo -e "${GREEN}Passed:${NC}   $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}   $TESTS_FAILED"
    echo -e "${YELLOW}Warnings:${NC} $TESTS_WARNING"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}✓ All critical checks passed! NetApp deployment is ready.${NC}"
        echo -e "\nTo run netAppShares.py:"
        echo -e "  ${BLUE}cd $SCRIPT_DIR${NC}"
        echo -e "  ${BLUE}python3 netAppShares.py${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}✗ Some checks failed. Please address the issues above before deployment.${NC}"
        return 1
    fi
}

display_current_config() {
    print_header "Current Configuration"
    
    if [ ! -f "$ENV_FILE" ]; then
        print_fail ".env file not found"
        return 1
    fi
    
    source "$ENV_FILE" 2>/dev/null
    
    echo -e "${BOLD}BlueXP Configuration:${NC}"
    echo "  BLUEXP_AUTH_URL: ${BLUEXP_AUTH_URL:-<not set>}"
    echo "  BLUEXP_CLIENT_ID: ${BLUEXP_CLIENT_ID:0:20}${BLUEXP_CLIENT_ID:+...}"
    echo "  BLUEXP_CLIENT_SECRET: ${BLUEXP_CLIENT_SECRET:+<set>}${BLUEXP_CLIENT_SECRET:-<not set>}"
    echo "  BLUEXP_AUDIENCE: ${BLUEXP_AUDIENCE:-<not set>}"
    echo "  VOLUMES_API_URL_BASE: ${VOLUMES_API_URL_BASE:-<not set>}"
    echo "  USERS_API_URL: ${USERS_API_URL:-<not set>}"
    echo "  WORKING_ENVIRONMENT_ID: ${WORKING_ENVIRONMENT_ID:-<not set>}"
    echo "  AGENT_ID: ${AGENT_ID:-<not set>}"
    
    echo -e "\n${BOLD}ONTAP Configuration:${NC}"
    echo "  ONTAP_API_BASE_URL: ${ONTAP_API_BASE_URL:-<not set>}"
    echo "  ONTAP_USERNAME: ${ONTAP_USERNAME:-<not set>}"
    
    echo -e "\n${BOLD}Domain Configuration:${NC}"
    echo "  DOMAIN_TO_REMOVE: ${DOMAIN_TO_REMOVE:-<not set>}"
    echo "  DOMAIN_SUFFIX: ${DOMAIN_SUFFIX:-<not set>}"
    echo "  ONTAP_PASSWORD: ${ONTAP_PASSWORD:+<set>}${ONTAP_PASSWORD:-<not set>}"
    
    echo -e "\n${BOLD}Veza Configuration:${NC}"
    echo "  VEZA_URL: ${VEZA_URL:-<not set>}"
    echo "  VEZA_API_KEY: ${VEZA_API_KEY:+<set>}${VEZA_API_KEY:-<not set>}"
}

generate_env_template() {
    print_header "Generate .env Template"
    
    if [ -f "$ENV_FILE" ]; then
        echo -e "${YELLOW}Warning: .env file already exists at $ENV_FILE${NC}"
        read -p "Overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Cancelled."
            return 0
        fi
    fi
    
    cat > "$ENV_FILE" << 'EOF'
# NetApp BlueXP Configuration (Cloud Mode)
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

# On-Premises ONTAP Configuration (ONTAP Mode)
ONTAP_API_BASE_URL=https://your-ontap-cluster.example.com
ONTAP_USERNAME=your_ontap_service_account_username
ONTAP_PASSWORD=your_ontap_service_account_password

# Veza Configuration
VEZA_URL=your-instance.veza.com
VEZA_API_KEY=your_veza_api_key

# Domain Configuration (Optional)
# Remove domain suffix from usernames (e.g., @EXAMPLE.COM)
DOMAIN_TO_REMOVE=
# Add domain suffix to usernames if not present (e.g., example.com)
DOMAIN_SUFFIX=
EOF
    
    chmod 600 "$ENV_FILE"
    print_success "Template .env file created at $ENV_FILE"
    print_success "File permissions set to 600"
    echo -e "\n${YELLOW}Please edit the file and replace all placeholder values with actual credentials.${NC}"
}

install_dependencies() {
    print_header "Install Python Dependencies"
    
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        print_fail "requirements.txt not found at $REQUIREMENTS_FILE"
        return 1
    fi
    
    echo -e "${BOLD}Installing dependencies from requirements.txt...${NC}\n"
    
    if pip3 install -r "$REQUIREMENTS_FILE"; then
        print_success "All dependencies installed successfully"
    else
        print_fail "Failed to install some dependencies"
        return 1
    fi
}

#####################################################################
# Main Menu
#####################################################################

show_menu() {
    echo -e "\n${BOLD}${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║       NetApp Shares Pre-Flight Validation Menu            ║${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BOLD}Validation Checks:${NC}"
    echo "  1) System Requirements (Python, pip, OS)"
    echo "  2) Python Dependencies (packages)"
    echo "  3) Configuration File (.env validation)"
    echo "  4) Network Connectivity (HTTPS ports)"
    echo "  5) API Authentication (Basic Auth / OAuth2)"
    echo "  6) API Endpoint Accessibility"
    echo "  7) Deployment Structure"
    echo ""
    echo -e "${BOLD}Comprehensive Tests:${NC}"
    echo "  8) Run ALL Checks (recommended)"
    echo ""
    echo -e "${BOLD}Utilities:${NC}"
    echo "  9) Display Current Configuration"
    echo "  10) Generate Template .env File"
    echo "  11) Install Python Dependencies"
    echo ""
    echo "  0) Exit"
    echo ""
}

main() {
    # Check if --all flag is passed for automated runs
    if [[ "$1" == "--all" ]]; then
        run_all_checks
        exit $?
    fi
    
    # Interactive menu
    while true; do
        show_menu
        read -p "Select option: " choice
        
        case $choice in
            1) validate_system_requirements ;;
            2) validate_dependencies ;;
            3) validate_configuration ;;
            4) validate_network_connectivity ;;
            5) validate_api_authentication ;;
            6) validate_api_endpoints ;;
            7) validate_deployment_structure ;;
            8) run_all_checks ;;
            9) display_current_config ;;
            10) generate_env_template ;;
            11) install_dependencies ;;
            0) 
                echo -e "\n${BLUE}Exiting. Logs saved to: $LOG_FILE${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo -e "\n${BOLD}Press Enter to continue...${NC}"
        read
    done
}

# Run main function
main "$@"
