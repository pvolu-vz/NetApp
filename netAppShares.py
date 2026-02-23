#!/usr/bin/env python3
"""
NetApp BlueXP REST API - Volume Reader
Authenticates and retrieves volumes from NetApp BlueXP
"""

import requests
import urllib3
import json
import sys
import os
import logging
import argparse
import base64

# Suppress SSL certificate warnings for ONTAP connections with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType, IdPProviderType

# Load environment variables
load_dotenv()

# Configuration from environment
VOLUMES_API_URL_BASE = os.getenv("VOLUMES_API_URL_BASE", "https://cloudmanager.cloud.netapp.com/occm/api")
USERS_API_URL = os.getenv("USERS_API_URL")
ONTAP_API_BASE_URL = os.getenv("ONTAP_API_BASE_URL")

# Volume API endpoints for different platforms
VOLUME_ENDPOINTS = {
    "ontap": "protocols/ontap/volumes",
    "azure": "/azure/anf/volumes",
    "aws": "/aws/fsx/volumes",
    "gcp": "/gcp/cvs/volumes"
}

# BlueXP Authentication credentials from environment
BLUEXP_AUTH_URL = os.getenv("BLUEXP_AUTH_URL")
BLUEXP_CLIENT_ID = os.getenv("BLUEXP_CLIENT_ID")
BLUEXP_CLIENT_SECRET = os.getenv("BLUEXP_CLIENT_SECRET")
BLUEXP_AUDIENCE = os.getenv("BLUEXP_AUDIENCE")

# ONTAP Authentication credentials from environment
ONTAP_USERNAME = os.getenv("ONTAP_USERNAME")
ONTAP_PASSWORD = os.getenv("ONTAP_PASSWORD")

# Working Environment ID from environment
WORKING_ENVIRONMENT_ID = os.getenv("WORKING_ENVIRONMENT_ID")

# Agent ID from environment
AGENT_ID = os.getenv("AGENT_ID")

# Veza configuration from environment
VEZA_URL = os.getenv("VEZA_URL")
VEZA_API_KEY = os.getenv("VEZA_API_KEY")

# Domain configuration from environment
DOMAIN_TO_REMOVE = os.getenv("DOMAIN_TO_REMOVE")
DOMAIN_SUFFIX = os.getenv("DOMAIN_SUFFIX")


def initialize_custom_app():
    """
    Initialize CustomApplication for NetApp BlueXP with permissions and properties
    """
    print("Initializing NetApp BlueXP CustomApplication...")
    
    app = CustomApplication(name='NetApp-BlueXP', application_type='NetApp BlueXP')
    
    # Define custom permissions
    app.add_custom_permission('volume_read', permissions=[
        OAAPermission.DataRead,
        OAAPermission.MetadataRead
    ])
    app.add_custom_permission('volume_write', permissions=[
        OAAPermission.DataWrite,
        OAAPermission.DataRead,
        OAAPermission.MetadataRead
    ])
    app.add_custom_permission('volume_admin', permissions=[
        OAAPermission.DataWrite,
        OAAPermission.DataRead,
        OAAPermission.DataDelete,
        OAAPermission.MetadataRead,
        OAAPermission.MetadataWrite
    ])
    
    # Define resource properties for volumes
    app.property_definitions.define_resource_property('volume', 'size', OAAPropertyType.NUMBER)
    app.property_definitions.define_resource_property('volume', 'sizeUnit', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'svmName', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'aggregateName', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'volumeType', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'protocols', OAAPropertyType.STRING_LIST)
    app.property_definitions.define_resource_property('volume', 'providerVolumeType', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'junctionPath', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('volume', 'state', OAAPropertyType.STRING)
    
    print("✓ CustomApplication initialized\n")
    return app


def normalize_ntfs_identity(full_identity, remove_domain=None):
    """
    Normalize NTFS user/group identity by optionally stripping domain prefix
    
    Args:
        full_identity: Full identity like "RTI\\username" or "BUILTIN\\Administrators"
        remove_domain: Domain prefix to remove (e.g., "RTI"). If None, keeps full identity
    
    Returns:
        Normalized identity name (e.g., "username" if domain removed, or full identity if kept)
    """
    if not full_identity:
        return ""
    
    # If no domain removal specified, return full identity
    if remove_domain is None:
        return full_identity
    
    # Remove specific domain prefix (case-insensitive)
    import re
    # Match domain\username pattern and extract username if domain matches
    pattern = rf'^{re.escape(remove_domain)}\\(.+)$'
    match = re.match(pattern, full_identity, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Domain doesn't match or no domain prefix found, return as-is
    return full_identity


def is_group_identity(identity_name):
    """
    Heuristic to determine if an identity is a group or user
    
    Args:
        identity_name: Normalized identity name
    
    Returns:
        Boolean indicating if identity appears to be a group
    """
    if not identity_name:
        return False
    
    # Common group keywords and patterns
    group_patterns = [
        'administrators', 'admins', 'users', 'operators', 'guests',
        'domain', 'enterprise', 'schema', 'server', 'backup',
        'power users', 'remote desktop', 'replicator'
    ]
    
    identity_lower = identity_name.lower()
    
    # Check for plural forms (likely groups)
    if identity_lower.endswith('s') and len(identity_name) > 3:
        return True
    
    # Check for known group keywords
    for pattern in group_patterns:
        if pattern in identity_lower:
            return True
    
    return False


def query_veza_group_dn(group_name, veza_url, veza_api_key, cache):
    """
    Query Veza API to find Active Directory group distinguished name by group name
    
    Args:
        group_name: Name of the AD group to search for
        veza_url: Veza instance URL (without https://)
        veza_api_key: Veza API key for authentication
        cache: Dictionary to cache results {group_name: dn_or_none}
    
    Returns:
        str: Distinguished name (idp_unique_id) if found, None otherwise
    """
    # Check cache first
    if group_name in cache:
        return cache[group_name]
    
    url = f"https://{veza_url}/api/v1/assessments/query_spec:nodes"
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {veza_api_key}'
    }
    
    payload = {
        "no_relation": False,
        "include_nodes": True,
        "query_type": "SOURCE_TO_DESTINATION",
        "source_node_types": {
            "nodes": [
                {
                    "node_type": "ActiveDirectoryGroup",
                    "tags_to_get": [],
                    "condition_expression": {
                        "operator": "AND",
                        "specs": [],
                        "tag_specs": [],
                        "child_expressions": [
                            {
                                "specs": [
                                    {
                                        "fn": "EQ",
                                        "property": "name",
                                        "value": group_name,
                                        "not": False,
                                        "value_property_name": "",
                                        "value_property_from_other_node": False,
                                        "source_property": ""
                                    }
                                ],
                                "tag_specs": [],
                                "child_expressions": []
                            }
                        ]
                    },
                    "direct_relationship_only": False
                }
            ]
        },
        "node_relationship_type": "EFFECTIVE_ACCESS",
        "result_value_type": "SOURCE_NODES_WITH_COUNTS",
        "include_all_source_tags_in_results": False,
        "include_all_destination_tags_in_results": False,
        "include_sub_permissions": False,
        "include_permissions_summary": True
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        values = result.get('values', [])
        
        if len(values) == 0:
            print(f"  ⚠ Group '{group_name}' not found in Veza AD")
            cache[group_name] = None
            return None
        elif len(values) > 1:
            print(f"  ⚠ Multiple groups found for '{group_name}' ({len(values)} results), using first match")
        
        # Extract idp_unique_id (distinguished name) from first result
        entity = values[0]
        dn = entity.get('properties', {}).get('idp_unique_id')
        
        if dn:
            print(f"  ✓ Found DN for '{group_name}': {dn}")
            cache[group_name] = dn
            return dn
        else:
            print(f"  ⚠ Group '{group_name}' found but has no idp_unique_id")
            cache[group_name] = None
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error querying Veza API for group '{group_name}': {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"    Response: {e.response.text}")
        cache[group_name] = None
        return None


def define_cifs_share_permissions():
    """
    Define custom permissions for CIFS shares based on NTFS advanced rights
    
    Permission Mapping:
    - Create (C): The data create permission, e.g., permission to create a database table
    - Write (W): The data write permission, e.g., write permission to a database table
    - Delete (D): The data delete permission, e.g., delete permission to a database table
    - Read (R): The data read permission, e.g., read permission from a database table
    - Metadata (M): The metadata read, create, write or delete permission
    
    Returns:
        Dict of permission definitions
    """
    return {
        'Read': [OAAPermission.DataRead],
        'Write': [OAAPermission.DataWrite],
        'Create': [OAAPermission.DataCreate],
        'Delete': [OAAPermission.DataDelete],
        'Modify': [OAAPermission.NonData],
        'Full Control': [OAAPermission.DataCreate, OAAPermission.DataDelete, OAAPermission.DataRead, OAAPermission.DataWrite]
    }


def get_access_token():
    """
    Authenticate with NetApp BlueXP and retrieve access token
    """
    print("Authenticating with NetApp BlueXP...")
    
    headers = {
        "Content-Type": "application/json"
    }
    
    payload = {
        "audience": BLUEXP_AUDIENCE,
        "client_id": BLUEXP_CLIENT_ID,
        "client_secret": BLUEXP_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    
    try:
        response = requests.post(BLUEXP_AUTH_URL, headers=headers, json=payload)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if access_token:
            print("✓ Authentication successful\n")
            return access_token
        else:
            print("✗ Failed to retrieve access token")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Authentication error: {e}")
        return None


def create_basic_auth_header():
    """
    Create Basic Authentication header from username and password
    
    Returns:
        str: Base64-encoded Basic Auth credentials
    """
    credentials = f"{ONTAP_USERNAME}:{ONTAP_PASSWORD}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f"Basic {encoded_credentials}"


def get_cifs_shares(base_url, svm_name):
    """
    Retrieve CIFS shares from on-premises ONTAP for specified SVM
    
    Args:
        base_url: ONTAP API base URL
        svm_name: SVM name to query
    
    Returns:
        tuple: (shares_list, svm_uuid) or (None, None) on failure
    """
    print(f"Fetching CIFS shares for SVM '{svm_name}'...")
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": create_basic_auth_header()
    }
    
    # Build URL with SVM name parameter
    url = f"{base_url}/api/protocols/cifs/shares"
    params = {"svm.name": svm_name}
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract shares and SVM UUID from response
        num_records = data.get('num_records', 0)
        shares = data.get('records', [])
        
        if num_records == 0 or not shares:
            print(f"⚠ No CIFS shares found for SVM '{svm_name}'")
            return [], None
        
        # Extract SVM UUID from first record
        svm_uuid = shares[0].get('svm', {}).get('uuid') if shares else None
        
        print(f"✓ Retrieved {num_records} CIFS share(s)\n")
        return shares, svm_uuid
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching CIFS shares: {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None, None


def get_nfs_exports(base_url, svm_name):
    """
    Placeholder: Retrieve NFS exports from on-premises ONTAP for specified SVM
    
    Args:
        base_url: ONTAP API base URL
        svm_name: SVM name to query
    
    Returns:
        list: NFS exports (currently empty - placeholder for future implementation)
    """
    print(f"NFS export retrieval not yet implemented for SVM '{svm_name}'")
    # TODO: Implement NFS export retrieval
    # URL would be: {base_url}/api/protocols/nfs/export-policies
    return []


def get_share_permissions(base_url, svm_uuid, share_name):
    """
    Retrieve NTFS permissions for a specific CIFS share
    
    Args:
        base_url: ONTAP API base URL
        svm_uuid: SVM UUID
        share_name: Share name
    
    Returns:
        dict: File security data including ACLs, or None on failure
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": create_basic_auth_header()
    }
    
    # Build URL with SVM UUID and share name in path
    url = f"{base_url}/api/protocols/file-security/permissions/{svm_uuid}/{share_name}"
    
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        
        data = response.json()
        return data.get('file_security', {})
        
    except requests.exceptions.RequestException as e:
        print(f"⚠ Error fetching permissions for share '{share_name}': {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None


def get_storage_volumes(base_url, svm_name):
    """
    Retrieve storage volumes from on-premises ONTAP for specified SVM
    
    Args:
        base_url: ONTAP API base URL
        svm_name: SVM name to query
    
    Returns:
        list: List of volume dictionaries with name and uuid, or empty list on failure
    """
    print(f"Fetching storage volumes for SVM '{svm_name}'...")
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": create_basic_auth_header()
    }
    
    # Build URL with SVM name parameter
    url = f"{base_url}/api/storage/volumes"
    params = {"svm.name": svm_name}
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract volumes from response
        num_records = data.get('num_records', 0)
        volumes = data.get('records', [])
        
        if num_records == 0 or not volumes:
            print(f"⚠ No storage volumes found for SVM '{svm_name}'")
            return []
        
        print(f"✓ Retrieved {num_records} storage volume(s)\n")
        return volumes
        
    except requests.exceptions.RequestException as e:
        print(f"⚠ Error fetching storage volumes: {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return []


def get_volume_folders(base_url, volume_uuid, path="/"):
    """
    Retrieve immediate child folders within a volume path
    
    Args:
        base_url: ONTAP API base URL
        volume_uuid: Volume UUID
        path: Path within the volume (default: "/")
    
    Returns:
        list: List of folder dictionaries with name and path, or empty list on failure
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": create_basic_auth_header()
    }
    
    # Build URL for files endpoint with directory filter
    # Remove leading slash from path for URL construction
    clean_path = path.lstrip('/')
    if not clean_path:
        clean_path = "/"
    
    url = f"{base_url}/api/storage/volumes/{volume_uuid}/files/{clean_path}"
    params = {"type": "directory"}
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract folders from response
        folders = data.get('records', [])
        return folders
        
    except requests.exceptions.RequestException as e:
        # Gracefully fail - folder may not exist, have no children, or be inaccessible
        return []


def discover_folders_recursive(base_url, volume_uuid, parent_path, current_level, max_depth, svm_uuid, share_name):
    """
    Recursively discover folders up to a specified depth
    
    Args:
        base_url: ONTAP API base URL
        volume_uuid: Volume UUID
        parent_path: Current path to discover folders within (e.g., "/share" or "/share/folder1")
        current_level: Current depth level (0 = directly under share)
        max_depth: Maximum depth to traverse
        svm_uuid: SVM UUID for unique ID generation
        share_name: Share name for unique ID generation
    
    Returns:
        list: List of tuples (folder_full_path, folder_metadata, folder_level)
    """
    # Base case: reached max depth
    if current_level >= max_depth:
        return []
    
    discovered_folders = []
    
    # Get folders at current path
    folders = get_volume_folders(base_url, volume_uuid, parent_path)
    
    # If no folders found, gracefully return (folder may be leaf or inaccessible)
    if not folders:
        return []
    
    # Process each folder at this level
    for folder in folders:
        folder_name = folder.get('name', '')
        if not folder_name:
            continue
        
        # Build full path for this folder
        folder_full_path = f"{parent_path}/{folder_name}" if parent_path != "/" else f"/{folder_name}"
        
        # Add this folder to results with its level
        discovered_folders.append((folder_full_path, folder, current_level))
        
        # Recursively discover subfolders if we haven't reached max depth
        if current_level + 1 < max_depth:
            try:
                subfolders = discover_folders_recursive(
                    base_url=base_url,
                    volume_uuid=volume_uuid,
                    parent_path=folder_full_path,
                    current_level=current_level + 1,
                    max_depth=max_depth,
                    svm_uuid=svm_uuid,
                    share_name=share_name
                )
                discovered_folders.extend(subfolders)
            except Exception as e:
                # Gracefully continue if subfolder discovery fails
                logging.warning(f"Failed to discover subfolders in {folder_full_path}: {e}")
                continue
    
    return discovered_folders


def get_volumes(access_token, platform=None):
    """
    Retrieve volumes from NetApp BlueXP for specified platform(s)
    
    Args:
        access_token: Authentication token
        platform: Cloud platform ('ontap', 'azure', 'aws', 'gcp') or None for all
    
    Returns:
        tuple: (volumes_data, platform_name) or None if all fail
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-agent-id": AGENT_ID
    }
    
    params = {
        "workingEnvironmentId": WORKING_ENVIRONMENT_ID
    }
    
    # If platform specified, try only that platform
    if platform:
        platforms_to_try = [platform.lower()]
    else:
        # Try all platforms
        platforms_to_try = list(VOLUME_ENDPOINTS.keys())
        print("No platform specified, will try all endpoints...\n")
    
    for platform_name in platforms_to_try:
        if platform_name not in VOLUME_ENDPOINTS:
            print(f"✗ Unknown platform: {platform_name}")
            print(f"Valid options: {', '.join(VOLUME_ENDPOINTS.keys())}\n")
            continue
        
        endpoint = VOLUME_ENDPOINTS[platform_name]
        volumes_url = f"{VOLUMES_API_URL_BASE}{endpoint}"
        
        print(f"Fetching {platform_name.upper()} volumes from {volumes_url}...")
        
        try:
            response = requests.get(volumes_url, headers=headers, params=params)
            response.raise_for_status()
            
            volumes_data = response.json()
            print(f"✓ Volumes retrieved successfully from {platform_name.upper()}\n")
            return volumes_data, platform_name
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error fetching {platform_name.upper()} volumes: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            
            # If specific platform requested, return None
            if platform:
                return None, None
            # Otherwise continue trying other platforms
            print(f"Trying next platform...\n")
            continue
    
    # If we tried all platforms and none worked
    print("✗ Failed to retrieve volumes from any platform\n")
    return None, None


def process_volumes(app, volumes_data):
    """
    Process volume data and add as resources to the CustomApplication
    """
    print("Processing volumes and creating resources...")
    
    volumes_list = []
    
    # Handle different response formats
    if isinstance(volumes_data, list):
        volumes_list = volumes_data
    elif isinstance(volumes_data, dict) and 'volumes' in volumes_data:
        volumes_list = volumes_data['volumes']
    else:
        print("⚠ Unexpected volumes data format")
        return 0
    
    resources_created = 0
    
    for volume in volumes_list:
        try:
            volume_name = volume.get('name', 'Unknown')
            volume_uuid = volume.get('uuid', volume.get('id', volume_name))
            
            # Create resource for the volume
            resource = app.add_resource(
                name=volume_name,
                resource_type='volume',
                unique_id=volume_uuid
            )
            
            # Set description
            if volume.get('comment'):
                resource.description = volume['comment']
            
            # Set properties from volume data
            if 'size' in volume and 'size' in volume['size']:
                resource.set_property('size', volume['size']['size'])
            if 'size' in volume and 'unit' in volume['size']:
                resource.set_property('sizeUnit', volume['size']['unit'])
            
            if 'svmName' in volume:
                resource.set_property('svmName', volume['svmName'])
            if 'aggregateName' in volume:
                resource.set_property('aggregateName', volume['aggregateName'])
            if 'volumeType' in volume:
                resource.set_property('volumeType', volume['volumeType'])
            if 'providerVolumeType' in volume:
                resource.set_property('providerVolumeType', volume['providerVolumeType'])
            if 'junctionPath' in volume:
                resource.set_property('junctionPath', volume['junctionPath'])
            if 'state' in volume:
                resource.set_property('state', volume['state'])
            
            # Handle protocols as list
            if 'enabledProtocols' in volume:
                protocols = volume['enabledProtocols']
                if isinstance(protocols, list):
                    resource.set_property('protocols', protocols)
                elif isinstance(protocols, str):
                    resource.set_property('protocols', [protocols])
            
            resources_created += 1
            
        except Exception as e:
            print(f"⚠ Error processing volume {volume.get('name', 'Unknown')}: {e}")
            continue
    
    print(f"✓ Created {resources_created} volume resources\n")
    return resources_created


def push_to_veza(app):
    """
    Create Veza provider and push CustomApplication to Veza
    """
    print("Connecting to Veza and pushing application...")
    
    try:
        # Connect to Veza
        veza_con = OAAClient(url=VEZA_URL, api_key=VEZA_API_KEY)
        
        provider_name = "NetApp"
        data_source_name = f"{app.name} ({app.application_type})"
        
        # Get or create provider
        print(f"Getting or creating provider '{provider_name}'...")
        provider = veza_con.get_provider(provider_name)
        
        if not provider:
            print(f"Creating new provider '{provider_name}'...")
            provider = veza_con.create_provider(provider_name, 'application')
            print("✓ Provider created")
        else:
            print("✓ Provider found")
        
        # Push application to Veza
        print(f"Pushing data source '{data_source_name}'...")
        response = veza_con.push_application(
            provider_name=provider_name,
            data_source_name=data_source_name,
            application_object=app,
            save_json=False
        )
        
        print("✓ Successfully pushed to Veza\n")
        
        # Handle warnings
        if response.get("warnings"):
            print("⚠ Push succeeded with warnings:")
            for warning in response['warnings']:
                print(f"  - {warning}")
            print()
        
        # Print success details
        if response.get("id"):
            print(f"Data Source ID: {response['id']}")
        
        return True
        
    except OAAClientError as e:
        print(f"✗ Veza API error: {e}")
        print(f"Error Type: {type(e).__name__}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
        if hasattr(e, 'message'):
            print(f"Message: {e.message}")
        if hasattr(e, 'details'):
            print(f"Details: {e.details}")
        if hasattr(e, 'response'):
            print(f"Response: {e.response}")
        print("\nFull traceback:")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"✗ Unexpected error pushing to Veza: {e}")
        print(f"Error Type: {type(e).__name__}")
        print("\nFull traceback:")
        import traceback
        traceback.print_exc()
        return False


def initialize_identity_app():
    """
    Initialize CustomApplication for NetApp BlueXP Identity with user and group properties
    """
    print("Initializing NetApp BlueXP Identity Application...")
    
    app = CustomApplication(name='NetApp-BlueXP-Identity', application_type='NetApp BlueXP Identity')
    
    # Define user properties
    app.property_definitions.define_local_user_property('email', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('firstName', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('lastName', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('username', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('roleId', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('roleName', OAAPropertyType.STRING)
    
    # Define group properties
    app.property_definitions.define_local_group_property('roleId', OAAPropertyType.STRING)
    
    print("✓ Identity Application initialized\n")
    return app


def get_users(access_token):
    """
    Retrieve users from NetApp BlueXP Console
    """
    print("Fetching users...")
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-agent-id": AGENT_ID
    }
    
    try:
        response = requests.get(USERS_API_URL, headers=headers)
        response.raise_for_status()
        
        users_data = response.json()
        print("✓ Users retrieved successfully\n")
        return users_data
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching users: {e}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None


def process_users_and_roles(app, users_data):
    """
    Process user data, create role-based groups, and add users to groups
    """
    print("Processing users and creating role-based groups...")
    
    users_list = []
    
    # Handle different response formats
    if isinstance(users_data, list):
        users_list = users_data
    elif isinstance(users_data, dict) and 'users' in users_data:
        users_list = users_data['users']
    else:
        print("⚠ Unexpected users data format")
        return 0
    
    # First pass: collect unique roles and create groups
    roles_map = {}  # roleId -> roleName
    
    for user in users_list:
        role_id = user.get('roleId')
        role_name = user.get('roleName', user.get('role', role_id))
        
        if role_id and role_id not in roles_map:
            roles_map[role_id] = role_name
    
    # Create groups for each unique role
    for role_id, role_name in roles_map.items():
        try:
            group = app.add_local_group(
                name=role_name,
                unique_id=role_id
            )
            group.set_property('roleId', role_id)
            print(f"  Created group: {role_name} ({role_id})")
        except Exception as e:
            print(f"⚠ Error creating group {role_name}: {e}")
    
    print(f"✓ Created {len(roles_map)} role groups\n")
    
    # Second pass: create users and assign to groups
    users_created = 0
    
    for user in users_list:
        try:
            user_id = user.get('userId', user.get('id', user.get('email')))
            username = user.get('username', user.get('email', user_id))
            email = user.get('email', '')
            first_name = user.get('firstName', '')
            last_name = user.get('lastName', '')
            role_id = user.get('roleId')
            role_name = user.get('roleName', user.get('role', role_id))
            
            # Create full name
            if first_name and last_name:
                full_name = f"{first_name} {last_name}"
            else:
                full_name = username
            
            # Add user with email as identity for linking
            identities = [email] if email else []
            new_user = app.add_local_user(
                username,
                unique_id=user_id,
                identities=identities
            )
            new_user.set_source_identity(
                provider_type=IdPProviderType.ANY,
                identity=email  # Set source identity to email for better linking in Veza
            )
            
            # Set user properties
            if email:
                new_user.set_property('email', email)
            if first_name:
                new_user.set_property('firstName', first_name)
            if last_name:
                new_user.set_property('lastName', last_name)
            new_user.set_property('username', username)
            if role_id:
                new_user.set_property('roleId', role_id)
            if role_name:
                new_user.set_property('roleName', role_name)
            
            # Set active status
            is_active = user.get('active', user.get('isActive', True))
            new_user.is_active = is_active
            
            # Add user to role group
            if role_id:
                new_user.add_group(role_id)
            
            users_created += 1
            
        except Exception as e:
            print(f"⚠ Error processing user {user.get('email', 'Unknown')}: {e}")
            continue
    
    print(f"✓ Created {users_created} user accounts\n")
    return users_created


def push_identity_to_veza(app):
    """
    Create Veza provider and push Identity Application to Veza
    """
    print("Connecting to Veza and pushing identity application...")
    
    try:
        # Connect to Veza
        veza_con = OAAClient(url=VEZA_URL, api_key=VEZA_API_KEY)
        
        provider_name = "NetApp"
        data_source_name = f"{app.name} ({app.application_type})"
        
        # Get or create provider
        print(f"Getting or creating provider '{provider_name}'...")
        provider = veza_con.get_provider(provider_name)
        
        if not provider:
            print(f"Creating new provider '{provider_name}'...")
            provider = veza_con.create_provider(provider_name, 'application')
            print("✓ Provider created")
        else:
            print("✓ Provider found")
        
        # Push application to Veza
        print(f"Pushing data source '{data_source_name}'...")
        response = veza_con.push_application(
            provider_name=provider_name,
            data_source_name=data_source_name,
            application_object=app,
            save_json=False
        )
        
        print("✓ Successfully pushed identity data to Veza\n")
        
        # Handle warnings
        if response.get("warnings"):
            print("⚠ Push succeeded with warnings:")
            for warning in response['warnings']:
                print(f"  - {warning}")
            print()
        
        # Print success details
        if response.get("id"):
            print(f"Data Source ID: {response['id']}")
        
        return True
        
    except OAAClientError as e:
        print(f"✗ Veza API error: {e}")
        print(f"Error Type: {type(e).__name__}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
        if hasattr(e, 'message'):
            print(f"Message: {e.message}")
        if hasattr(e, 'details'):
            print(f"Details: {e.details}")
        if hasattr(e, 'response'):
            print(f"Response: {e.response}")
        print("\nFull traceback:")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"✗ Unexpected error pushing to Veza: {e}")
        print(f"Error Type: {type(e).__name__}")
        print("\nFull traceback:")
        import traceback
        traceback.print_exc()
        return False


def parse_arguments():
    """
    Parse command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='NetApp to Veza Integration - Volume and Share Reader',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Platforms (BlueXP mode):
  ontap    - Cloud Volumes ONTAP
  azure    - Azure NetApp Files
  aws      - Amazon FSx for NetApp ONTAP
  gcp      - Google Cloud Volumes Service

Supported Protocols (ONTAP mode):
  cifs     - CIFS/SMB shares with NTFS permissions (default)
  nfs      - NFS exports (placeholder for future implementation)

Examples:
  # BlueXP mode - fetch cloud volumes
  %(prog)s --system-type bluexp --platform azure
  %(prog)s --system-type bluexp --platform ontap
  %(prog)s --system-type bluexp
  
  # ONTAP mode - fetch on-premises shares
  %(prog)s --system-type ontap --svm-name TESTCIFSLOW --protocol cifs
  %(prog)s --system-type ontap --svm-name TESTCIFSLOW
  
  # Multiple ONTAP instances with custom .env files
  %(prog)s --system-type ontap --svm-name PROD_SVM1 --env-file /etc/netapp/prod-svm1.env
  %(prog)s --system-type ontap --svm-name PROD_SVM2 --env-file configs/prod-svm2.env
  %(prog)s --system-type bluexp --platform azure --env-file ~/.netapp/azure-prod.env
        """
    )
    
    parser.add_argument(
        '--system-type',
        type=str,
        required=True,
        choices=['bluexp', 'ontap'],
        help='Deployment mode: bluexp (cloud volumes) or ontap (on-premises shares)'
    )
    
    parser.add_argument(
        '--platform',
        type=str,
        choices=['ontap', 'azure', 'aws', 'gcp'],
        help='Cloud platform to fetch volumes from (BlueXP mode only)'
    )
    
    parser.add_argument(
        '--svm-name',
        type=str,
        help='SVM name for ONTAP mode (required when system-type=ontap)'
    )
    
    parser.add_argument(
        '--protocol',
        type=str,
        choices=['cifs', 'nfs'],
        default='cifs',
        help='Protocol type for ONTAP mode (default: cifs)'
    )
    
    parser.add_argument(
        '--no-remove-domain',
        action='store_false',
        dest='remove_domain',
        default=True,
        help='Disable domain prefix removal from identities (domain removal is enabled by default using DOMAIN_TO_REMOVE from .env)'
    )
    
    parser.add_argument(
        '--env-file',
        type=str,
        help='Path to custom .env file (absolute or relative). If not specified, uses .env in current directory. Useful for managing multiple ONTAP instances with different configurations.'
    )
    
    parser.add_argument(
        '--folder-depth',
        type=int,
        default=1,
        help='Maximum folder depth to traverse (default: 1). Level 0 = folders directly under share, level 1 = subfolders, etc. Use higher values to discover nested folder hierarchies.'
    )
    
    args = parser.parse_args()
    
    # Validate folder-depth
    if args.folder_depth < 0:
        parser.error('--folder-depth must be >= 0')
    
    return args


def create_ontap_application(provider_name, svm_name, svm_uuid, shares_data, permissions_data, volumes_data, base_url, remove_domain=None, folder_depth=1):
    """
    Create CustomApplication for on-premises ONTAP with SVM and share modeling
    
    Args:
        provider_name: Name of the Veza provider
        svm_name: SVM name
        svm_uuid: SVM UUID
        shares_data: List of share dictionaries from ONTAP API
        permissions_data: Dictionary mapping share names to their permission data
        volumes_data: List of volume dictionaries from ONTAP API
        base_url: ONTAP API base URL for making additional requests
        remove_domain: Optional domain prefix to remove from identities
        folder_depth: Maximum folder depth to traverse (default: 1)
    
    Returns:
        CustomApplication object
    """
    print(f"Creating ONTAP application for SVM '{svm_name}'...")
    
    # Create application with SVM-specific name
    app = CustomApplication(
        name=f'NetApp-ONTAP-{svm_name}',
        application_type='NetApp ONTAP'
    )
    
    # Define CIFS share permissions
    cifs_permissions = define_cifs_share_permissions()
    for perm_name, perm_list in cifs_permissions.items():
        app.add_custom_permission(perm_name, permissions=perm_list)
    
    # Define resource properties for SVM
    app.property_definitions.define_resource_property('svm', 'num_shares', OAAPropertyType.NUMBER)
    app.property_definitions.define_resource_property('svm', 'svm_uuid', OAAPropertyType.STRING)
    
    # Define resource properties for shares
    app.property_definitions.define_resource_property('share', 'path', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('share', 'security_style', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('share', 'owner', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('share', 'group', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('share', 'effective_style', OAAPropertyType.STRING)
    
    # Define resource properties for folders
    app.property_definitions.define_resource_property('folder', 'path', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'parent_share', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'folder_name', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'security_style', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'owner', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'group', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('folder', 'folder_level', OAAPropertyType.NUMBER)
    
    # Create SVM as main resource
    svm_resource = app.add_resource(
        name=svm_name,
        resource_type='svm',
        unique_id=svm_uuid
    )
    svm_resource.set_property('num_shares', len(shares_data))
    svm_resource.set_property('svm_uuid', svm_uuid)
    
    print(f"✓ Created SVM resource: {svm_name}\\n")
    
    # Build volume name to UUID mapping
    volume_name_to_uuid = {vol.get('name'): vol.get('uuid') for vol in volumes_data if vol.get('name') and vol.get('uuid')}
    
    # Initialize cache for Veza API group DN lookups
    group_dn_cache = {}
    
    # Process each share as sub-resource
    shares_created = 0
    permissions_assigned = 0
    folders_discovered = 0
    folders_with_permissions = 0
    
    # Track created folder resources by their full path for parent-child relationships
    folder_resources_by_path = {}
    
    for share in shares_data:
        share_name = share.get('name', 'Unknown')
        
        try:
            # Create share as sub-resource of SVM
            share_resource = svm_resource.add_sub_resource(
                name=share_name,
                resource_type='share',
                unique_id=f"{svm_uuid}/{share_name}"
            )
            
            # Get permissions for this share
            share_perms = permissions_data.get(share_name, {})
            
            # Set share properties from permissions data
            if share_perms:
                if 'path' in share_perms:
                    share_resource.set_property('path', share_perms['path'])
                if 'security_style' in share_perms:
                    share_resource.set_property('security_style', share_perms['security_style'])
                if 'effective_style' in share_perms:
                    share_resource.set_property('effective_style', share_perms['effective_style'])
                if 'owner' in share_perms:
                    share_resource.set_property('owner', share_perms['owner'])
                if 'group' in share_perms:
                    share_resource.set_property('group', share_perms['group'])
            
            shares_created += 1
            
            # Process ACLs for this share
            acls = share_perms.get('acls', [])
            
            for acl in acls:
                # Only process allow entries
                if acl.get('access') != 'access_allow':
                    continue
                
                user_full = acl.get('user', '')
                if not user_full:
                    continue
                
                # Normalize the identity (optionally strip domain prefix)
                normalized_identity = normalize_ntfs_identity(user_full, remove_domain)
                
                
                # Determine if this is a group or user
                is_group = is_group_identity(normalized_identity)
                
                # Create local identity if not already exists
                if is_group:
                    if normalized_identity not in app.local_groups:
                        # Build identities list dynamically
                        identities = [normalized_identity]
                        
                        # Query Veza API for AD group distinguished name using normalized identity (without domain)
                        dn = query_veza_group_dn(normalized_identity, VEZA_URL, VEZA_API_KEY, group_dn_cache)
                        if dn:
                            identities.append(dn)
                        
                        group = app.add_local_group(
                            name=normalized_identity,
                            unique_id=normalized_identity,
                            identities=identities
                        )
                        
                else:
                    if normalized_identity not in app.local_users:
                        # Build user identities with email suffix if configured
                        user_identities = [normalized_identity]
                        #if DOMAIN_SUFFIX:
                        #    user_identities.insert(0, normalized_identity + '@' + DOMAIN_SUFFIX)
                        
                        user = app.add_local_user(
                            name=normalized_identity, 
                            unique_id=normalized_identity,
                            identities=user_identities
                        )
                
                # Determine permission level from advanced rights
                advanced_rights = acl.get('advanced_rights', {})
                
                # Map advanced rights to permission level(s)
                permissions_to_assign = []
                
                if advanced_rights.get('full_control'):
                    # FULL_CONTROL grants Read, Write, Create, and Delete
                    permissions_to_assign = ['Full Control']
                elif advanced_rights.get('delete') and advanced_rights.get('write_data'):
                    permissions_to_assign = ['Read','Write','Delete']
                elif advanced_rights.get('write_data') or advanced_rights.get('append_data'):
                    permissions_to_assign = ['Read','Write']
                elif advanced_rights.get('read_data'):
                    permissions_to_assign = ['Read']
                else:
                    # Skip if no clear permission mapping
                    continue
                
                # Assign permission(s) to the identity for this share sub-resource
                for permission in permissions_to_assign:
                    if is_group:
                        if normalized_identity in app.local_groups:
                            app.local_groups[normalized_identity].add_permission(
                                permission=permission,
                                resources=[share_resource]
                            )
                            permissions_assigned += 1
                    else:
                        if normalized_identity in app.local_users:
                            app.local_users[normalized_identity].add_permission(
                                permission=permission,
                                resources=[share_resource]
                            )
                            permissions_assigned += 1
            
            # Step 2: Discover folders within this share (up to specified depth)
            # Try each volume to find which one contains this share
            all_discovered_folders = []
            volume_found = None
            volume_uuid_found = None
            
            for volume_uuid in volume_name_to_uuid.values():
                # Try to discover folders recursively from this volume
                discovered = discover_folders_recursive(
                    base_url=base_url,
                    volume_uuid=volume_uuid,
                    parent_path=f"/{share_name}",
                    current_level=0,
                    max_depth=folder_depth,
                    svm_uuid=svm_uuid,
                    share_name=share_name
                )
                
                if discovered:
                    all_discovered_folders = discovered
                    volume_uuid_found = volume_uuid
                    # Find volume name for logging
                    for vol_name, vol_uuid in volume_name_to_uuid.items():
                        if vol_uuid == volume_uuid:
                            volume_found = vol_name
                            break
                    break
            
            if all_discovered_folders:
                depth_info = f"max depth: {folder_depth}" if folder_depth > 1 else "1 level deep"
                print(f"  Found {len(all_discovered_folders)} folder(s) in share '{share_name}' ({depth_info}, volume: {volume_found})")
                folders_discovered += len(all_discovered_folders)
                
                # Process each folder as sub-resource of the share
                # all_discovered_folders contains tuples: (folder_full_path, folder_metadata, folder_level)
                for folder_full_path, folder_metadata, folder_level in all_discovered_folders:
                    folder_name = folder_metadata.get('name', '')
                    
                    if not folder_name:
                        continue
                    
                    try:
                        # Extract relative path from full path (remove leading /share_name/)
                        relative_path = folder_full_path.replace(f"/{share_name}/", "", 1)
                        
                        # For nested folders, use relative path as display name for clarity
                        # Level 0: "folder1", Level 1+: "folder1/subfolder"
                        display_name = relative_path
                        
                        # Determine parent resource based on folder level
                        if folder_level == 0:
                            # Level 0 folders are direct children of the share
                            parent_resource = share_resource
                        else:
                            # Level 1+ folders are children of their parent folder
                            # Extract parent path by removing the last folder component
                            parent_folder_path = '/'.join(folder_full_path.rsplit('/', 1)[:-1])
                            parent_resource = folder_resources_by_path.get(parent_folder_path)
                            
                            # Safety check: if parent not found, fall back to share (should never happen due to ordering)
                            if parent_resource is None:
                                print(f"    ⚠ Warning: Parent folder not found for '{folder_full_path}', using share as parent")
                                parent_resource = share_resource
                        
                        print(f"    Creating folder: '{display_name}' (level {folder_level}, unique_id: {svm_uuid}/{share_name}/{relative_path})")
                        
                        # Create folder as sub-resource of parent (share for level 0, parent folder for level 1+)
                        # Use relative path for both name and unique_id to support nested folders
                        folder_resource = parent_resource.add_sub_resource(
                            name=display_name,
                            resource_type='folder',
                            unique_id=f"{svm_uuid}/{share_name}/{relative_path}"
                        )
                        
                        # Set folder properties
                        folder_resource.set_property('path', folder_full_path)
                        folder_resource.set_property('parent_share', share_name)
                        folder_resource.set_property('folder_name', display_name)
                        folder_resource.set_property('folder_level', folder_level)
                        
                        # Store this folder resource for potential child folders
                        folder_resources_by_path[folder_full_path] = folder_resource
                        
                        # Get permissions for this folder
                        # Construct path for permissions API: share_name/relative_path (supports nested folders)
                        folder_perms_path = f"{share_name}/{relative_path}"
                        
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": create_basic_auth_header()
                        }
                        
                        perms_url = f"{base_url}/api/protocols/file-security/permissions/{svm_uuid}/{folder_perms_path}"
                        
                        try:
                            response = requests.get(perms_url, headers=headers, verify=False)
                            response.raise_for_status()
                            
                            folder_perms_data = response.json().get('file_security', {})
                            
                            # Set folder security properties
                            if folder_perms_data.get('security_style'):
                                folder_resource.set_property('security_style', folder_perms_data['security_style'])
                            if folder_perms_data.get('owner'):
                                folder_resource.set_property('owner', folder_perms_data['owner'])
                            if folder_perms_data.get('group'):
                                folder_resource.set_property('group', folder_perms_data['group'])
                            
                            folders_with_permissions += 1
                            
                            # Process ACLs for this folder
                            folder_acls = folder_perms_data.get('acls', [])
                            
                            for acl in folder_acls:
                                # Only process allow entries
                                if acl.get('access') != 'access_allow':
                                    continue
                                
                                user_full = acl.get('user', '')
                                if not user_full:
                                    continue
                                
                                # Normalize the identity
                                normalized_identity = normalize_ntfs_identity(user_full, remove_domain)
                                
                                # Determine if this is a group or user
                                is_group = is_group_identity(normalized_identity)
                                
                                # Create local identity if not already exists
                                if is_group:
                                    if normalized_identity not in app.local_groups:
                                        #identities = [normalized_identity]
                                        # Query Veza API for AD group using normalized identity (without domain)
                                        dn = query_veza_group_dn(normalized_identity, VEZA_URL, VEZA_API_KEY, group_dn_cache)
                                        #if dn:
                                            #identities.append(dn)
                                        app.add_local_group(
                                            name=normalized_identity,
                                            unique_id=normalized_identity,
                                            identities=dn
                                        )
                                        
                                else:
                                    if normalized_identity not in app.local_users:
                                        # Build user identities with email suffix if configured
                                        user_identities = [normalized_identity]
                                        if DOMAIN_SUFFIX:
                                            user_identities.insert(0, normalized_identity + '@' + DOMAIN_SUFFIX)
                                        
                                        app.add_local_user(
                                            name=normalized_identity,
                                            unique_id=normalized_identity,
                                            identities=user_identities
                                        )
                                
                                # Determine permission level from advanced rights
                                advanced_rights = acl.get('advanced_rights', {})
                                
                                # Map advanced rights to permission level(s)
                                permissions_to_assign = []
                                
                                if advanced_rights.get('full_control'):
                                    permissions_to_assign = ['Full Control']
                                elif advanced_rights.get('delete') and advanced_rights.get('write_data'):
                                    permissions_to_assign = ['Read','Write','Delete']
                                elif advanced_rights.get('write_data') or advanced_rights.get('append_data'):
                                    permissions_to_assign = ['Read','Write']
                                elif advanced_rights.get('read_data'):
                                    permissions_to_assign = ['Read']
                                else:
                                    continue
                                
                                # Assign permission(s) to the identity for this folder
                                for permission in permissions_to_assign:
                                    if is_group:
                                        if normalized_identity in app.local_groups:
                                            app.local_groups[normalized_identity].add_permission(
                                                permission=permission,
                                                resources=[folder_resource]
                                            )
                                            permissions_assigned += 1
                                    else:
                                        if normalized_identity in app.local_users:
                                            app.local_users[normalized_identity].add_permission(
                                                permission=permission,
                                                resources=[folder_resource]
                                            )
                                            permissions_assigned += 1
                        
                        except requests.exceptions.RequestException as e:
                            # Log error but continue processing other folders
                            print(f"    ⚠ Error fetching permissions for folder '{folder_name}': {e}")
                            continue
                    
                    except Exception as e:
                        print(f"    ⚠ Error processing folder '{folder_name}': {e}")
                        continue
        
        except Exception as e:
            print(f"⚠ Error processing share '{share_name}': {e}")
            continue
    
    print(f"\n✓ Created {shares_created} share sub-resources")
    print(f"✓ Discovered {folders_discovered} folder(s) across all shares")
    print(f"✓ Retrieved permissions for {folders_with_permissions} folder(s)")
    print(f"✓ Assigned {permissions_assigned} permissions\\n")
    
    # Print Veza API query statistics
    total_groups_queried = len(group_dn_cache)
    successful_lookups = sum(1 for dn in group_dn_cache.values() if dn is not None)
    failed_lookups = total_groups_queried - successful_lookups
    
    if total_groups_queried > 0:
        print(f"✓ Queried {total_groups_queried} unique group(s) from Veza: {successful_lookups} found, {failed_lookups} not found\n")
    
    return app


def main():
    """
    Main execution function
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    # Reload environment from custom .env file if specified
    if args.env_file:
        env_file_path = args.env_file
        if not os.path.isfile(env_file_path):
            print(f"✗ Error: Specified .env file not found: {env_file_path}")
            sys.exit(1)
        
        print(f"Loading environment from: {env_file_path}")
        load_dotenv(dotenv_path=env_file_path, override=True)
        print("✓ Custom environment loaded\n")
        
        # Reload global configuration variables after loading custom .env
        global VOLUMES_API_URL_BASE, USERS_API_URL, ONTAP_API_BASE_URL
        global BLUEXP_AUTH_URL, BLUEXP_CLIENT_ID, BLUEXP_CLIENT_SECRET, BLUEXP_AUDIENCE
        global ONTAP_USERNAME, ONTAP_PASSWORD
        global WORKING_ENVIRONMENT_ID, AGENT_ID
        global VEZA_URL, VEZA_API_KEY
        global DOMAIN_TO_REMOVE, DOMAIN_SUFFIX
        
        VOLUMES_API_URL_BASE = os.getenv("VOLUMES_API_URL_BASE", "https://cloudmanager.cloud.netapp.com/occm/api")
        USERS_API_URL = os.getenv("USERS_API_URL")
        ONTAP_API_BASE_URL = os.getenv("ONTAP_API_BASE_URL")
        BLUEXP_AUTH_URL = os.getenv("BLUEXP_AUTH_URL")
        BLUEXP_CLIENT_ID = os.getenv("BLUEXP_CLIENT_ID")
        BLUEXP_CLIENT_SECRET = os.getenv("BLUEXP_CLIENT_SECRET")
        BLUEXP_AUDIENCE = os.getenv("BLUEXP_AUDIENCE")
        ONTAP_USERNAME = os.getenv("ONTAP_USERNAME")
        ONTAP_PASSWORD = os.getenv("ONTAP_PASSWORD")
        WORKING_ENVIRONMENT_ID = os.getenv("WORKING_ENVIRONMENT_ID")
        AGENT_ID = os.getenv("AGENT_ID")
        VEZA_URL = os.getenv("VEZA_URL")
        VEZA_API_KEY = os.getenv("VEZA_API_KEY")
        DOMAIN_TO_REMOVE = os.getenv("DOMAIN_TO_REMOVE")
        DOMAIN_SUFFIX = os.getenv("DOMAIN_SUFFIX")
    
    # Validate Veza configuration
    if not VEZA_URL or not VEZA_API_KEY:
        print("✗ Error: VEZA_URL and VEZA_API_KEY must be set in environment variables")
        if args.env_file:
            print(f"   (Loaded from: {args.env_file})")
        sys.exit(1)
    
    # Branch based on system type
    if args.system_type == 'ontap':
        # ===== ON-PREMISES ONTAP MODE =====
        print("=" * 60)
        print("NetApp ONTAP to Veza Integration (On-Premises)")
        print(f"SVM: {args.svm_name}")
        print(f"Protocol: {args.protocol.upper()}")
        print("=" * 60 + "\n")
        
        # Validate ONTAP-specific arguments
        if not args.svm_name:
            print("✗ Error: --svm-name is required when system-type=ontap")
            sys.exit(1)
        
        if not ONTAP_API_BASE_URL:
            print("✗ Error: ONTAP_API_BASE_URL must be set in environment variables")
            sys.exit(1)
        
        try:
            # Step 1: Validate credentials
            if not ONTAP_USERNAME or not ONTAP_PASSWORD:
                print("✗ Error: ONTAP_USERNAME and ONTAP_PASSWORD must be set in environment variables")
                sys.exit(1)
            
            # Step 2: Fetch shares based on protocol
            if args.protocol == 'cifs':
                print("\n" + "=" * 60)
                print("PROCESSING CIFS SHARES")
                print("=" * 60 + "\n")
                
                # Get CIFS shares
                shares, svm_uuid = get_cifs_shares(
                    ONTAP_API_BASE_URL,
                    args.svm_name
                )
                
                if not shares or not svm_uuid:
                    print("✗ Failed to retrieve CIFS shares")
                    sys.exit(1)
                
                # Step 3: Get permissions for each share
                print(f"Fetching permissions for {len(shares)} share(s)...\n")
                permissions_data = {}
                
                for share in shares:
                    share_name = share.get('name')
                    if share_name:
                        perms = get_share_permissions(
                            ONTAP_API_BASE_URL,
                            svm_uuid,
                            share_name
                        )
                        if perms:
                            permissions_data[share_name] = perms
                            print(f"  ✓ {share_name}: {len(perms.get('acls', []))} ACL(s)")
                
                print(f"\n✓ Retrieved permissions for {len(permissions_data)} share(s)\n")
                
                # Step 3.5: Get storage volumes for folder discovery
                volumes = get_storage_volumes(
                    ONTAP_API_BASE_URL,
                    args.svm_name
                )
                
                # Step 4: Create ONTAP application and model data
                # Use DOMAIN_TO_REMOVE if domain removal is enabled, otherwise None
                domain_to_strip = DOMAIN_TO_REMOVE if args.remove_domain else None
                ontap_app = create_ontap_application(
                    "NetApp ONTAP",
                    args.svm_name,
                    svm_uuid,
                    shares,
                    permissions_data,
                    volumes,
                    ONTAP_API_BASE_URL,
                    domain_to_strip,
                    args.folder_depth
                )
                
                # Step 5: Push to Veza
                print("=" * 60)
                print("PUSHING TO VEZA")
                print("=" * 60 + "\n")
                
                success = push_to_veza(ontap_app)
                
                if success:
                    print("\n" + "=" * 60)
                    print("✓ ONTAP INTEGRATION COMPLETED SUCCESSFULLY")
                    print("=" * 60)
                    sys.exit(0)
                else:
                    print("\n" + "=" * 60)
                    print("✗ ONTAP INTEGRATION FAILED")
                    print("=" * 60)
                    sys.exit(1)
            
            elif args.protocol == 'nfs':
                print("\n" + "=" * 60)
                print("PROCESSING NFS EXPORTS")
                print("=" * 60 + "\n")
                
                # NFS placeholder
                exports = get_nfs_exports(
                    ONTAP_API_BASE_URL,
                    args.svm_name,
                    access_token
                )
                
                print("\n⚠ NFS protocol support is not yet implemented")
                print("=" * 60)
                sys.exit(1)
            
        except KeyboardInterrupt:
            print("\n\n✗ Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n✗ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    else:  # args.system_type == 'bluexp'
        # ===== BLUEXP CLOUD MODE =====
        print("=" * 60)
        print("NetApp BlueXP to Veza Integration (Cloud)")
        if args.platform:
            print(f"Platform: {args.platform.upper()}")
        else:
            print("Platform: ALL (will try all available endpoints)")
        print("=" * 60 + "\n")
        
        volumes_success = False
        identity_success = False
        
        try:
            # ===== VOLUMES INTEGRATION =====
            print("\n" + "=" * 60)
            print("PROCESSING VOLUMES")
            print("=" * 60 + "\n")
            
            # Step 1: Initialize CustomApplication for volumes
            volumes_app = initialize_custom_app()
            
            # Step 2: Get access token
            access_token = get_access_token()
            
            if not access_token:
                print("\n⚠ Skipping volumes due to authentication failure")
            else:
                # Step 3: Get volumes from NetApp BlueXP
                volumes, platform_name = get_volumes(access_token, args.platform)
                
                if not volumes:
                    print("\n⚠ Skipping volumes due to retrieval failure")
                else:
                    print(f"Retrieved volumes from {platform_name.upper()} platform\n")
                    
                    # Step 4: Process volumes and create resources
                    resources_count = process_volumes(volumes_app, volumes)
                    
                    if resources_count == 0:
                        print("⚠ No volume resources created, skipping Veza push")
                    else:
                        # Step 5: Push volumes to Veza
                        volumes_success = push_to_veza(volumes_app)
            
            # ===== IDENTITY INTEGRATION =====
            print("\n" + "=" * 60)
            print("PROCESSING USERS & ROLES")
            print("=" * 60 + "\n")
            
            # Step 1: Initialize Identity Application
            identity_app = initialize_identity_app()
            
            # Step 2: Reuse access token or get new one if needed
            if not access_token:
                access_token = get_access_token()
            
            if not access_token:
                print("\n⚠ Skipping users due to authentication failure")
            else:
                # Step 3: Get users from NetApp BlueXP
                users = get_users(access_token)
                
                if not users:
                    print("\n⚠ Skipping users due to retrieval failure")
                else:
                    # Step 4: Process users and roles
                    users_count = process_users_and_roles(identity_app, users)
                    
                    if users_count == 0:
                        print("⚠ No users created, skipping Veza push")
                    else:
                        # Step 5: Push identity to Veza
                        identity_success = push_identity_to_veza(identity_app)
            
            # ===== SUMMARY =====
            print("\n" + "=" * 60)
            print("INTEGRATION SUMMARY")
            print("=" * 60)
            
            if volumes_success:
                print("✓ Volumes integration completed successfully")
            else:
                print("✗ Volumes integration failed or skipped")
            
            if identity_success:
                print("✓ Identity integration completed successfully")
            else:
                print("✗ Identity integration failed or skipped")
            
            print("=" * 60)
            
            # Exit with appropriate code
            if volumes_success or identity_success:
                sys.exit(0)
            else:
                sys.exit(1)
                
        except KeyboardInterrupt:
            print("\n\n✗ Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n✗ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
