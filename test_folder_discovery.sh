#!/bin/bash
# Test script for NetApp folder discovery feature

echo "========================================="
echo "NetApp Folder Discovery Test Script"
echo "========================================="
echo ""

# Check if MockAPI is running
if ! curl -s http://localhost:5001/api/protocols/cifs/shares > /dev/null 2>&1; then
    echo "⚠️  MockAPI is not running on port 5001"
    echo "Please start the MockAPI first:"
    echo "  python3 NetApp_MockAPI.py"
    echo ""
    exit 1
fi

echo "✓ MockAPI is running"
echo ""

# Test 1: Verify volumes endpoint
echo "Test 1: Fetching volumes..."
curl -s -u test-client:test-client \
  "http://localhost:5001/api/storage/volumes?svm.name=TESTCIFSLOW" | \
  python3 -m json.tool | head -20
echo ""

# Test 2: Verify folder discovery for CIFSTEST share
echo "Test 2: Fetching folders for CIFSTEST share..."
VOLUME_UUID="c9339406-93b4-4ea7-821a-d2a25ab36abd"
curl -s -u test-client:test-client \
  "http://localhost:5001/api/storage/volumes/${VOLUME_UUID}/files/CIFSTEST?type=directory" | \
  python3 -m json.tool
echo ""

# Test 3: Verify folder permissions
echo "Test 3: Fetching folder permissions..."
SVM_UUID="d0d5f340-1c54-11e6-a188-a0369f33bdb4"
curl -s -u test-client:test-client \
  "http://localhost:5001/api/protocols/file-security/permissions/${SVM_UUID}/CIFSTEST/Subfolder1" | \
  python3 -m json.tool | head -40
echo ""

echo "========================================="
echo "All API tests completed"
echo "========================================="
echo ""
echo "Next step: Run the integration script"
echo "  python3 netAppShares.py --system-type ontap --svm-name TESTCIFSLOW --protocol cifs"
