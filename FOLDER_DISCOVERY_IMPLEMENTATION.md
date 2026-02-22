# NetApp Folder Discovery - Implementation Summary

## Overview
Extended the NetApp ONTAP integration to discover folders within CIFS shares (one level deep) and retrieve NTFS permissions for each folder, linking them in Veza as sub-resources of shares.

## Files Modified

### 1. netAppShares.py
**New Functions Added:**
- `get_storage_volumes(base_url, svm_name)`: Fetches storage volumes from ONTAP API using `/api/storage/volumes?svm.name={svm_name}`
- `get_volume_folders(base_url, volume_uuid, path)`: Retrieves immediate child folders using `/api/storage/volumes/{volume_uuid}/files/{path}?type=directory`

**Modified Functions:**
- `create_ontap_application()`: 
  - Added parameters: `volumes_data`, `base_url`
  - Added folder property definitions (path, parent_share, folder_name, security_style, owner, group)
  - Implemented folder discovery loop within share processing
  - Added folder permission retrieval and ACL processing
  - Updated statistics tracking (folders discovered, folders with permissions)

- `main()`: 
  - Added volume discovery step before application creation
  - Passes volumes and base_url to `create_ontap_application()`

**Resource Hierarchy:**
```
SVM (Resource)
├── Share 1 (Sub-Resource)
│   ├── Folder 1.1 (Sub-Resource of Share)
│   ├── Folder 1.2 (Sub-Resource of Share)
│   └── Folder 1.3 (Sub-Resource of Share)
├── Share 2 (Sub-Resource)
│   ├── Folder 2.1 (Sub-Resource of Share)
│   └── Folder 2.2 (Sub-Resource of Share)
└── Share 3 (Sub-Resource)
```

**Unique ID Pattern:**
- Share: `{svm_uuid}/{share_name}`
- Folder: `{svm_uuid}/{share_name}/{folder_name}`

### 2. NetApp_MockAPI.py
**Enhanced Endpoints:**
- `/api/protocols/file-security/permissions/{SVM_UUID}/{path}`: Now handles folder paths (e.g., `CIFSTEST/Subfolder1`)
- `/api/storage/volumes/<volume_uuid>/files/<path>`: Returns folders for multiple shares (CIFSTEST, Archive, Hello)

**New Mock Data:**
- Folder permissions with different ACL configurations
- Multiple folders per share for testing
- Realistic permission variations (Full Control, Read/Write, ReadOnly)

### 3. Test Script
**Created:** `test_folder_discovery.sh`
- Validates MockAPI endpoints
- Tests volume discovery
- Tests folder discovery
- Tests folder permission retrieval

## API Flow

```
1. GET /api/storage/volumes?svm.name={SVM_NAME}
   └─> Returns: List of volumes with UUIDs

2. GET /api/protocols/cifs/shares?svm.name={SVM_NAME}
   └─> Returns: List of shares

3. For each share:
   a. GET /api/protocols/file-security/permissions/{SVM_UUID}/{SHARE_NAME}
      └─> Share permissions

   b. For each volume UUID:
      GET /api/storage/volumes/{VOLUME_UUID}/files/{SHARE_NAME}?type=directory
      └─> List of folders in share (try until successful)

   c. For each discovered folder:
      GET /api/protocols/file-security/permissions/{SVM_UUID}/{SHARE_NAME}/{FOLDER_NAME}
      └─> Folder permissions
```

## Key Features

### Error Handling
- Continues processing if volume discovery fails (returns empty list)
- Tries folder discovery against each volume until successful
- Logs errors for individual folder permission failures but continues
- Doesn't block share processing if folder discovery fails

### Permission Mapping
Folder permissions use the same mapping as shares:
- `full_control=True` → "Full Control"
- `delete=True && write_data=True` → "Read", "Write", "Delete"
- `write_data=True || append_data=True` → "Read", "Write"
- `read_data=True` → "Read"

### Identity Management
- Reuses the same identity cache for groups/users across shares and folders
- Queries Veza API for group distinguished names (cached)
- Normalizes NTFS identities with optional domain stripping

### Statistics Tracking
New metrics added to output:
- Number of volumes discovered
- Number of folders discovered across all shares
- Number of folders with permissions successfully retrieved
- Per-share folder counts with volume information

## Testing

### Start MockAPI:
```bash
cd /Users/pedrovolu/Documents/Scripts/NetApp
python3 NetApp_MockAPI.py
# Runs on http://localhost:5001
```

### Run Test Script:
```bash
./test_folder_discovery.sh
```

### Run Integration (requires Veza credentials):
```bash
# Set environment variables in .env:
# ONTAP_API_BASE_URL=http://localhost:5001
# ONTAP_USERNAME=test-client
# ONTAP_PASSWORD=test-client
# VEZA_URL=https://your-veza-instance.com
# VEZA_API_KEY=your-api-key

python3 netAppShares.py --system-type ontap --svm-name TESTCIFSLOW --protocol cifs
```

## Expected Output Example

```
Fetching storage volumes for SVM 'TESTCIFSLOW'...
✓ Retrieved 2 storage volume(s)

Fetching CIFS shares for SVM 'TESTCIFSLOW'...
✓ Retrieved 12 CIFS share(s)

Fetching permissions for 12 share(s)...
  ✓ CIFSTEST: 7 ACL(s)
  ✓ Archive: 5 ACL(s)
  ...

Creating ONTAP application for SVM 'TESTCIFSLOW'...
✓ Created SVM resource: TESTCIFSLOW

  Found 3 folder(s) in share 'CIFSTEST' (volume: TESTTEST)
  Found 2 folder(s) in share 'Archive' (volume: ARCHIVE01)
  ...

✓ Created 12 share sub-resources
✓ Discovered 15 folder(s) across all shares
✓ Retrieved permissions for 15 folder(s)
✓ Assigned 487 permissions
```

## Veza Payload Structure

Folders appear as sub-resources with properties:
```json
{
  "name": "Subfolder1",
  "resource_type": "folder",
  "unique_id": "d0d5f340-1c54-11e6-a188-a0369f33bdb4/CIFSTEST/Subfolder1",
  "custom_properties": {
    "path": "/CIFSTEST/Subfolder1",
    "parent_share": "CIFSTEST",
    "folder_name": "Subfolder1",
    "security_style": "ntfs",
    "owner": "RTI\\Domain Admins",
    "group": "RTI\\Domain Users"
  }
}
```

## Implementation Notes

1. **Volume-Share Mapping**: The script tries each volume UUID for folder discovery since the share-to-volume relationship isn't explicit in the shares API response. This ensures folders are found regardless of which volume contains the share.

2. **One Level Deep Only**: As specified, the implementation only discovers immediate child folders of shares, not recursive traversal.

3. **Backward Compatible**: All existing functionality preserved. The script works with or without volume discovery success.

4. **Performance**: For large environments with many shares and folders, consider the number of API calls:
   - 1 call for volumes
   - 1 call for shares
   - n calls for share permissions (n = number of shares)
   - Up to n × m calls for folder discovery (n shares × m volumes)
   - k calls for folder permissions (k = total folders discovered)

## Future Enhancements

Potential improvements not implemented:
- Configurable recursion depth (currently hardcoded to 1 level)
- Parallel folder discovery for performance
- Caching of volume-to-share relationships
- Support for NFS exports folder discovery
- Filtering of administrative shares (admin$, c$, ipc$)
