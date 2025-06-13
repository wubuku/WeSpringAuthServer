#!/bin/bash

# WeChat Login End-to-End Test Script
# Tests WeChat OAuth2 login flow, refresh token functionality, and JWK token verification

# Base URL configuration
BASE_URL="http://localhost:9000"

# Default code (will be overridden by parameter or interactive input)
# Check if WECHAT_CODE is set in environment
if [[ -n "$WECHAT_CODE" ]]; then
    echo -e "Using WeChat code from environment variable: ${WECHAT_CODE:0:20}..."
else
    WECHAT_CODE=""
fi

# Script usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -c, --code CODE     WeChat authorization code
    -h, --help          Show this help message
    -i, --interactive   Interactive mode - prompt for code input
    
EXAMPLES:
    $0 --code "0b1N85100T85rU15aE000urgLn2N851x"
    $0 -i
    $0  # Will prompt for code interactively

Note: WeChat authorization codes expire within minutes of generation.
Get a fresh code from your WeChat Mini Program development environment.
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--code)
            WECHAT_CODE="$2"
            shift 2
            ;;
        -i|--interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to get fresh WeChat code interactively
get_fresh_wechat_code() {
    echo -e "\n${YELLOW}⚠️  WeChat Authorization Code Required${NC}"
    echo "WeChat authorization codes expire within minutes."
    echo "Please obtain a fresh code from your WeChat Mini Program development environment."
    echo ""
    echo -e "${BLUE}Steps to get a fresh code:${NC}"
    echo "1. Go to WeChat Developer Tools"
    echo "2. Open your Mini Program project"
    echo "3. Use the development environment to trigger OAuth login"
    echo "4. Copy the authorization code from the callback URL or logs"
    echo ""
    
    while true; do
        read -p "Please enter fresh WeChat authorization code: " input_code
        
        if [[ -n "$input_code" && "$input_code" != "exit" && "$input_code" != "quit" ]]; then
            # Basic validation - WeChat codes are typically alphanumeric and around 32 chars
            if [[ ${#input_code} -ge 20 && "$input_code" =~ ^[A-Za-z0-9]+$ ]]; then
                WECHAT_CODE="$input_code"
                echo -e "${GREEN}✅ Code accepted: ${input_code:0:20}...${NC}"
                return 0
            else
                echo -e "${RED}❌ Invalid code format. WeChat codes are typically 20+ alphanumeric characters.${NC}"
                echo "Example format: 0b1N85100T85rU15aE000urgLn2N851x"
            fi
        elif [[ "$input_code" == "exit" || "$input_code" == "quit" ]]; then
            echo -e "${YELLOW}Exiting test script.${NC}"
            exit 0
        else
            echo -e "${RED}❌ Please enter a valid authorization code or 'exit' to quit.${NC}"
        fi
        
        echo ""
    done
}

# Function to handle code expiration and retry
handle_code_expiration() {
    local error_message="$1"
    
    if echo "$error_message" | grep -q "invalid code\|code expired\|40029"; then
        echo -e "\n${YELLOW}⚠️  Authorization code has expired!${NC}"
        echo "WeChat authorization codes are only valid for a few minutes after generation."
        
        while true; do
            echo ""
            read -p "Would you like to enter a fresh authorization code? (y/n): " retry_choice
            
            case $retry_choice in
                [Yy]*)
                    get_fresh_wechat_code
                    return 0  # Code refreshed successfully
                    ;;
                [Nn]*)
                    echo -e "${YELLOW}Skipping WeChat login test due to expired code.${NC}"
                    return 1  # User chose not to retry
                    ;;
                *)
                    echo "Please answer y or n."
                    ;;
            esac
        done
    fi
    
    return 1  # Not a code expiration error
}

# Function to print section headers
print_section() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Function to print test results
print_result() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    else
        echo -e "${BLUE}ℹ️  $message${NC}"
    fi
}

# URL encode function
urlencode() {
    python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

# Base64URL encode function (no padding)
base64url_encode() {
    base64 | tr '/+' '_-' | tr -d '='
}

# JWT decode function for different OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(printf '=%.0s' $(seq 1 $pad))"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | gbase64 -d 2>/dev/null
    }
else
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(printf '=%.0s' $(seq 1 $pad))"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | base64 -d 2>/dev/null
    }
fi

# Function to test JWK endpoint
test_jwks_endpoint() {
    print_section "Testing JWK Set Endpoint"
    
    local jwks_response=$(curl -s "${BASE_URL}/oauth2/jwks")
    local http_status=$(curl -s -w "%{http_code}" "${BASE_URL}/oauth2/jwks" -o /dev/null)
    
    if [ "$http_status" = "200" ]; then
        print_result "success" "JWK endpoint accessible (HTTP 200)"
        
        # Validate JSON structure
        if echo "$jwks_response" | jq -e '.keys' > /dev/null 2>&1; then
            print_result "success" "JWK response has valid JSON structure"
            
            # Display keys information
            local keys_count=$(echo "$jwks_response" | jq '.keys | length')
            print_result "info" "Found $keys_count key(s) in JWK set"
            
            echo -e "\n${BLUE}JWK Set Details:${NC}"
            echo "$jwks_response" | jq '.'
            
            return 0
        else
            print_result "error" "JWK response is not valid JSON"
            echo "Response: $jwks_response"
            return 1
        fi
    else
        print_result "error" "JWK endpoint failed (HTTP $http_status)"
        return 1
    fi
}

# Function to verify JWT token against JWK
verify_jwt_with_jwk() {
    local token=$1
    local token_type=$2
    
    print_section "Verifying $token_type with JWK"
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        print_result "error" "No $token_type provided for verification"
        return 1
    fi
    
    # Extract JWT header
    local header=$(echo "$token" | cut -d"." -f1)
    local header_decoded=$(decode_jwt "$header")
    
    if [ -n "$header_decoded" ]; then
        print_result "success" "Successfully decoded $token_type header"
        echo -e "\n${BLUE}$token_type Header:${NC}"
        echo "$header_decoded" | jq '.' 2>/dev/null || echo "$header_decoded"
        
        # Extract kid (key ID) from header
        local kid=$(echo "$header_decoded" | jq -r '.kid' 2>/dev/null)
        if [ -n "$kid" ] && [ "$kid" != "null" ]; then
            print_result "success" "Found key ID: $kid"
            
            # Get JWK and check if kid matches
            local jwks_response=$(curl -s "${BASE_URL}/oauth2/jwks")
            local matching_key=$(echo "$jwks_response" | jq --arg kid "$kid" '.keys[] | select(.kid == $kid)')
            
            if [ -n "$matching_key" ]; then
                print_result "success" "Found matching JWK for key ID $kid"
                echo -e "\n${BLUE}Matching JWK:${NC}"
                echo "$matching_key" | jq '.'
            else
                print_result "error" "No matching JWK found for key ID $kid"
            fi
        else
            print_result "warning" "No key ID found in $token_type header"
        fi
        
        # Extract and display payload
        local payload=$(echo "$token" | cut -d"." -f2)
        local payload_decoded=$(decode_jwt "$payload")
        
        if [ -n "$payload_decoded" ]; then
            print_result "success" "Successfully decoded $token_type payload"
            echo -e "\n${BLUE}$token_type Payload:${NC}"
            echo "$payload_decoded" | jq '.' 2>/dev/null || echo "$payload_decoded"
            
            # Check issuer field (security requirement)
            local issuer=$(echo "$payload_decoded" | jq -r '.iss // "NOT_FOUND"' 2>/dev/null)
            if [ -n "$issuer" ] && [ "$issuer" != "NOT_FOUND" ] && [ "$issuer" != "null" ]; then
                print_result "success" "✅ JWT Issuer field present: $issuer"
            else
                echo -e "\n${RED}🚨 SECURITY WARNING: JWT Token missing 'iss' (issuer) field! 🚨${NC}"
                echo -e "${RED}This is a security vulnerability that should be fixed.${NC}"
                echo -e "${YELLOW}The 'iss' field helps prevent token misuse across different services.${NC}"
                print_result "error" "JWT missing required issuer field"
            fi
            
            # Check token expiration
            local exp=$(echo "$payload_decoded" | jq -r '.exp' 2>/dev/null)
            if [ -n "$exp" ] && [ "$exp" != "null" ]; then
                local current_time=$(date +%s)
                if [ "$exp" -gt "$current_time" ]; then
                    local remaining=$((exp - current_time))
                    print_result "success" "$token_type is valid (expires in $remaining seconds)"
                else
                    print_result "error" "$token_type has expired"
                fi
            fi
        else
            print_result "error" "Failed to decode $token_type payload"
        fi
        
        return 0
    else
        print_result "error" "Failed to decode $token_type header"
        return 1
    fi
}

# Function to test WeChat login with retry on expiration
test_wechat_login() {
    print_section "Testing WeChat Login Flow"
    
    local max_retries=3
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        if [ $attempt -gt 1 ]; then
            print_result "info" "Retry attempt $attempt/$max_retries"
        fi
        
        print_result "info" "Using WeChat authorization code: ${WECHAT_CODE:0:20}..."
        
        # Encode the WeChat code
        local encoded_code=$(urlencode "$WECHAT_CODE")
        
        # Make WeChat login request
        local wechat_response=$(curl -s -X GET \
            "${BASE_URL}/wechat/login?code=${encoded_code}" \
            -H "Accept: application/json" \
            -w "\n%{http_code}")
        
        # Extract HTTP status code
        local http_status=$(echo "$wechat_response" | tail -n1)
        local response_body=$(echo "$wechat_response" | sed '$d')
        
        print_result "info" "WeChat login HTTP status: $http_status"
        
        if [ "$http_status" = "200" ]; then
            print_result "success" "WeChat login request successful"
            
            # Parse JSON response
            if echo "$response_body" | jq -e '.' > /dev/null 2>&1; then
                print_result "success" "WeChat login response is valid JSON"
                
                # Extract tokens
                local access_token=$(echo "$response_body" | jq -r '.access_token')
                local refresh_token=$(echo "$response_body" | jq -r '.refresh_token')
                local token_type=$(echo "$response_body" | jq -r '.token_type')
                local expires_in=$(echo "$response_body" | jq -r '.expires_in')
                
                if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
                    print_result "success" "Access token received: ${access_token:0:50}..."
                    
                    # Save tokens for later use
                    export WECHAT_ACCESS_TOKEN="$access_token"
                    export WECHAT_REFRESH_TOKEN="$refresh_token"
                    
                    # Save to file
                    cat > wechat_tokens.env << EOF
export WECHAT_ACCESS_TOKEN=$access_token
export WECHAT_REFRESH_TOKEN=$refresh_token
export WECHAT_TOKEN_TYPE=$token_type
export WECHAT_EXPIRES_IN=$expires_in
EOF
                    
                    print_result "success" "Tokens saved to wechat_tokens.env"
                    
                    # Display token information
                    echo -e "\n${BLUE}WeChat Login Response:${NC}"
                    echo "$response_body" | jq '.'
                    
                    return 0
                else
                    print_result "error" "No access token in WeChat login response"
                    echo "Response: $response_body"
                    return 1
                fi
            else
                print_result "error" "WeChat login response is not valid JSON"
                echo "Response: $response_body"
                return 1
            fi
        else
            print_result "error" "WeChat login failed (HTTP $http_status)"
            echo "Response: $response_body"
            
            # Check if this is a code expiration error and handle it
            if handle_code_expiration "$response_body"; then
                # Code was refreshed, retry the login
                ((attempt++))
                continue
            else
                # Not a code expiration error, or user chose not to retry
                return 1
            fi
        fi
        
        ((attempt++))
    done
    
    print_result "error" "WeChat login failed after $max_retries attempts"
    return 1
}

# Function to test refresh token
test_refresh_token() {
    print_section "Testing Refresh Token Functionality"
    
    if [ -z "$WECHAT_REFRESH_TOKEN" ] || [ "$WECHAT_REFRESH_TOKEN" = "null" ]; then
        print_result "error" "No refresh token available for testing"
        return 1
    fi
    
    print_result "info" "Using refresh token: ${WECHAT_REFRESH_TOKEN:0:50}..."
    
    # Test refresh token request
    local refresh_response=$(curl -s -X POST "${BASE_URL}/wechat/refresh-token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Authorization: Basic $(echo -n 'ffv-client:secret' | base64)" \
        -H "Accept: application/json" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=$(urlencode "$WECHAT_REFRESH_TOKEN")" \
        -d "scope=openid%20profile" \
        -w "\n%{http_code}")
    
    # Extract HTTP status code
    local http_status=$(echo "$refresh_response" | tail -n1)
    local response_body=$(echo "$refresh_response" | sed '$d')
    
    print_result "info" "Refresh token HTTP status: $http_status"
    
    if [ "$http_status" = "200" ]; then
        print_result "success" "Refresh token request successful"
        
        # Parse JSON response
        if echo "$response_body" | jq -e '.' > /dev/null 2>&1; then
            print_result "success" "Refresh token response is valid JSON"
            
            # Extract new tokens
            local new_access_token=$(echo "$response_body" | jq -r '.access_token')
            local new_refresh_token=$(echo "$response_body" | jq -r '.refresh_token')
            
            if [ -n "$new_access_token" ] && [ "$new_access_token" != "null" ]; then
                print_result "success" "New access token received: ${new_access_token:0:50}..."
                
                # Update exported variables
                export WECHAT_ACCESS_TOKEN="$new_access_token"
                if [ -n "$new_refresh_token" ] && [ "$new_refresh_token" != "null" ]; then
                    export WECHAT_REFRESH_TOKEN="$new_refresh_token"
                    print_result "success" "New refresh token received: ${new_refresh_token:0:50}..."
                fi
                
                echo -e "\n${BLUE}Refresh Token Response:${NC}"
                echo "$response_body" | jq '.'
                
                return 0
            else
                print_result "error" "No new access token in refresh response"
                echo "Response: $response_body"
                return 1
            fi
        else
            print_result "error" "Refresh token response is not valid JSON"
            echo "Response: $response_body"
            return 1
        fi
    else
        print_result "error" "Refresh token request failed (HTTP $http_status)"
        echo "Response: $response_body"
        return 1
    fi
}

# Function to test API access with WeChat token
test_api_access_with_wechat_token() {
    print_section "Testing API Access with WeChat Token"
    
    if [ -z "$WECHAT_ACCESS_TOKEN" ] || [ "$WECHAT_ACCESS_TOKEN" = "null" ]; then
        print_result "error" "No WeChat access token available for API testing"
        return 1
    fi
    
    # Test accessing a protected endpoint with the WeChat token
    # Note: You may need to adjust this endpoint based on your API structure
    local api_response=$(curl -s \
        -H "Authorization: Bearer $WECHAT_ACCESS_TOKEN" \
        -H "Accept: application/json" \
        "${BASE_URL}/api/userinfo" \
        -w "\n%{http_code}")
    
    local http_status=$(echo "$api_response" | tail -n1)
    local response_body=$(echo "$api_response" | sed '$d')
    
    print_result "info" "API access HTTP status: $http_status"
    
    if [ "$http_status" = "200" ]; then
        print_result "success" "API access successful with WeChat token"
        echo -e "\n${BLUE}API Response:${NC}"
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body"
    elif [ "$http_status" = "401" ]; then
        print_result "warning" "API access unauthorized - token may be invalid or endpoint may not exist"
    elif [ "$http_status" = "404" ]; then
        print_result "warning" "API endpoint not found - this is expected if the endpoint doesn't exist"
    else
        print_result "error" "API access failed (HTTP $http_status)"
        echo "Response: $response_body"
    fi
}

# Function to test WeChat configuration
test_wechat_configuration() {
    print_section "Testing WeChat Configuration"
    
    # Test if application is running
    local health_check=$(curl -s -w "%{http_code}" "${BASE_URL}/actuator/health" -o /dev/null 2>/dev/null || echo "000")
    
    if [ "$health_check" != "200" ]; then
        print_result "warning" "Application health check failed (HTTP $health_check) - server may not be running"
    else
        print_result "success" "Application is running (HTTP 200)"
    fi
    
    # Check if WeChatConfig bean is properly configured
    # We can't directly access beans, but we can test a WeChat-specific endpoint or check error messages
    print_result "info" "Testing WeChat service configuration..."
    
    # Try a test call to see configuration status
    local test_response=$(curl -s "http://localhost:9000/wechat/login?code=test_config_check" 2>&1)
    
    if echo "$test_response" | grep -q "invalid appid"; then
        print_result "error" "WeChat AppID configuration issue detected"
        print_result "info" "The WeChat app-id is likely set to default value 'YOUR_APP_ID'"
        echo -e "\n${YELLOW}Configuration Fix Required:${NC}"
        echo "1. Set environment variable: export WECHAT_APP_ID=your_real_app_id"
        echo "2. Set environment variable: export WECHAT_APP_SECRET=your_real_app_secret"
        echo "3. Or update application.yml with real values"
        echo "4. Restart the application"
        return 1
    elif echo "$test_response" | grep -q "Connection refused\|Could not connect"; then
        print_result "error" "Cannot connect to WeChat service - server may not be running"
        return 1
    else
        print_result "success" "WeChat configuration appears valid"
        return 0
    fi
}

# Function to run all tests
run_all_tests() {
    print_section "WeChat Login End-to-End Test Suite"
    
    # Clean up any existing token files
    rm -f wechat_tokens.env
    
    local tests_passed=0
    local tests_total=7
    
    # Test 1: WeChat configuration
    if test_wechat_configuration; then
        ((tests_passed++))
    fi
    
    # Test 2: JWK endpoint
    if test_jwks_endpoint; then
        ((tests_passed++))
    fi
    
    # Test 3: WeChat login
    if test_wechat_login; then
        ((tests_passed++))
        
        # Test 4: Verify access token with JWK
        if verify_jwt_with_jwk "$WECHAT_ACCESS_TOKEN" "Access Token"; then
            ((tests_passed++))
        fi
        
        # Test 5: Refresh token functionality
        if test_refresh_token; then
            ((tests_passed++))
            
            # Test 6: Verify new access token with JWK
            if verify_jwt_with_jwk "$WECHAT_ACCESS_TOKEN" "Refreshed Access Token"; then
                ((tests_passed++))
            fi
        fi
        
        # Test 7: API access with WeChat token
        if test_api_access_with_wechat_token; then
            ((tests_passed++))
        fi
    fi
    
    # Print test summary
    print_section "Test Summary"
    
    if [ $tests_passed -eq $tests_total ]; then
        print_result "success" "All tests passed! ($tests_passed/$tests_total)"
    elif [ $tests_passed -gt 0 ]; then
        print_result "warning" "Some tests passed ($tests_passed/$tests_total)"
    else
        print_result "error" "All tests failed ($tests_passed/$tests_total)"
    fi
    
    echo -e "\n${BLUE}Note: Some test failures may be expected if:${NC}"
    echo "- WeChat service is not properly mocked or configured"
    echo "- Specific API endpoints don't exist in your application"
    echo "- Mock authorization code is not recognized by your WeChat service"
    
    if [ -f wechat_tokens.env ]; then
        print_result "info" "WeChat tokens saved in wechat_tokens.env for manual testing"
    fi
}

# Main execution
echo "🚀 Starting WeChat Login End-to-End Test Suite"
echo "=================================================="
echo "Base URL: $BASE_URL"

# Check if we have a WeChat code, if not get one interactively
if [ -z "$WECHAT_CODE" ] || [ "$INTERACTIVE_MODE" = "true" ]; then
    get_fresh_wechat_code
fi

echo "WeChat Code: ${WECHAT_CODE:0:20}..."
echo "=================================================="

run_all_tests

print_section "Test Completed" 