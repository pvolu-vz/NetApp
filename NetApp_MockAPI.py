from flask import Flask, jsonify, request, abort
import base64

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Mock Basic Authentication credentials
MOCK_USERNAME = "test-client"
MOCK_PASSWORD = "test-client"

def require_basic_auth(f):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            abort(401)
        
        try:
            # Decode base64 credentials
            encoded_credentials = auth.split(" ", 1)[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(":", 1)
            
            # Validate credentials
            if username != MOCK_USERNAME or password != MOCK_PASSWORD:
                abort(401)
        except (IndexError, ValueError, UnicodeDecodeError):
            abort(401)
            
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


@app.route('/api/protocols/cifs/shares')
@require_basic_auth
def get_items():
    # Get the svm.name query parameter
    svm_name = request.args.get('svm.name', '')
    
    # Return shares for the specified SVM
    if svm_name == 'TESTCIFSLOW' or not svm_name:
        return jsonify({
            "records": [
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "admin$"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "Archive"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "Ari"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "c$"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "CIFSTEST"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "Download"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "Hello"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "ipc$"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "RESTORE"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "Seclogs"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "TESTCIFSLOW_ARCHIVE_T2_Vol"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "name": "XCP"
                }
            ],
            "num_records": 12
        })
        # Return shares for the specified SVM
    elif svm_name == 'RANDOMSVM' or not svm_name:
        return jsonify({
            "records": [
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "RANDOMSVM"
                    },
                    "name": "randomFolder$"
                },
                {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "RANDOMSVM"
                    },
                    "name": "Archive_random"
                }
            ],
            "num_records": 2
        })
    else:
        # Return empty result for other SVM names
        return jsonify({
            "records": [],
            "num_records": 0
        })

@app.route('/api/protocols/cifs/shares/<SVM_UUID>/<SHARE_NAME>/acl')
@require_basic_auth
def get_users_and_groups(SVM_UUID, SHARE_NAME):
    return jsonify(
      {
        "users_and_groups": {
          "records": [
            {
              "user_or_group": "RTI\\Domain Users",
              "type": "windows"
            },
            {
              "user_or_group": "RTI\\ITS-Server-Admins",
              "type": "windows"
            }
          ],
          "num_records": 2
        }
      }
    )


@app.route('/api/protocols/file-security/permissions/<SVM_UUID>/<path:PATH>')
@require_basic_auth
def get_permissions(SVM_UUID, PATH):
    # Normalize path by stripping leading slash for comparison
    normalized_path = PATH.lstrip('/')
    
    # Return different permissions based on the path
    if normalized_path == "CIFSTEST":
        # CIFSTEST share permissions
        return jsonify({
            "file_security": {
                "svm": {
                    "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                    "name": "TESTCIFSLOW"
                },
                "path": "/CIFSTEST",
                "owner": "BUILTIN\\Administrators",
                "group": "BUILTIN\\Administrators",
                "control_flags": "0x9504",
                "acls": [
                    {
                        "user": "NT AUTHORITY\\SYSTEM",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\ITS-Server-Admins",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\Linux-server-administrators",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\ayfox",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\ayfoxprv",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\Domain Users",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "read_data": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\svcITSLinuxSpotter",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    }
                ],
                "inode": 64,
                "security_style": "ntfs",
                "effective_style": "ntfs",
                "dos_attributes": "10",
                "text_dos_attr": "----D---",
                "user_id": "0",
                "group_id": "0",
                "mode_bits": 777,
                "text_mode_bits": "rwxrwxrwx"
            }
        })
    
    elif normalized_path == "Hello":
        # Hello share permissions
        return jsonify({
            "file_security": {
                "svm": {
                    "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                    "name": "TESTCIFSLOW"
                },
                "path": "/Hello",
                "owner": "BUILTIN\\Administrators",
                "group": "RTI\\Domain Users",
                "control_flags": "0x9504",
                "acls": [
                    {
                        "user": "RTI\\cifstesthello_users",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\cifstesthello_read",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "execute_file": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\ITS-Server-Admins",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    }
                ],
                "inode": 30051,
                "security_style": "ntfs",
                "effective_style": "ntfs",
                "dos_attributes": "10",
                "text_dos_attr": "----D---",
                "user_id": "10015",
                "group_id": "49985",
                "mode_bits": 777,
                "text_mode_bits": "rwxrwxrwx"
            }
        })
    
    elif normalized_path.startswith("CIFSTEST/") or normalized_path.startswith("Archive/"):
        # Folder permissions (subfolder of a share)
        folder_name = normalized_path.split('/')[-1]
        return jsonify({
            "file_security": {
                "svm": {
                    "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                    "name": "TESTCIFSLOW"
                },
                "path": f"/{PATH}",
                "owner": "RTI\\Domain Admins",
                "group": "RTI\\Domain Users",
                "control_flags": "0x9504",
                "acls": [
                    {
                        "user": "RTI\\ITS-Server-Admins",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "delete_child": True,
                            "execute_file": True,
                            "full_control": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "write_owner": True,
                            "synchronize": True,
                            "write_perm": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\Domain Users",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "write_data": True,
                            "read_data": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_ea": True,
                            "read_perm": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    },
                    {
                        "user": "RTI\\FolderReadOnly",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": True,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "read_data": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_ea": True,
                            "read_perm": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                    }
                ],
                "inode": 64,
                "security_style": "ntfs",
                "effective_style": "ntfs",
                "dos_attributes": "10",
                "text_dos_attr": "----D---",
                "user_id": "0",
                "group_id": "0",
                "mode_bits": 777,
                "text_mode_bits": "rwxrwxrwx"
            }
        })
    
    elif normalized_path.startswith("Hello/MaybeSubFolder"):
            # Folder permissions (subfolder of a share)
            folder_name = normalized_path.split('/')[-1]
            return jsonify({
                "file_security": {
                    "svm": {
                        "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                        "name": "TESTCIFSLOW"
                    },
                    "path": f"/{PATH}",
                    "owner": "RTI\\Domain Admins",
                    "group": "RTI\\Domain Users",
                    "control_flags": "0x9504",
                    "acls": [
                        {
                        "user": "RTI\\ayfox",
                        "access": "access_allow",
                        "apply_to": {
                            "files": True,
                            "sub_folders": False,
                            "this_folder": True
                        },
                        "advanced_rights": {
                            "append_data": True,
                            "delete": True,
                            "execute_file": True,
                            "read_attr": True,
                            "read_data": True,
                            "read_ea": True,
                            "read_perm": True,
                            "write_attr": True,
                            "write_data": True,
                            "write_ea": True,
                            "synchronize": True
                        },
                        "access_control": "file_directory"
                        },
                        {
                            "user": "RTI\\FolderReadOnly",
                            "access": "access_allow",
                            "apply_to": {
                                "files": True,
                                "sub_folders": True,
                                "this_folder": True
                            },
                            "advanced_rights": {
                                "read_data": True,
                                "execute_file": True,
                                "read_attr": True,
                                "read_ea": True,
                                "read_perm": True,
                                "synchronize": True
                            },
                            "access_control": "file_directory"
                        }
                    ],
                    "inode": 64,
                    "security_style": "ntfs",
                    "effective_style": "ntfs",
                    "dos_attributes": "10",
                    "text_dos_attr": "----D---",
                    "user_id": "0",
                    "group_id": "0",
                    "mode_bits": 777,
                    "text_mode_bits": "rwxrwxrwx"
                }
            })

    else:
        # Default fallback - return CIFSTEST data for unknown paths
        return jsonify({
            "file_security": {
                "svm": {
                    "uuid": "d0d5f340-1c54-11e6-a188-a0369f33bdb4",
                    "name": "TESTCIFSLOW"
                },
                "path": f"/{PATH}",
                "owner": "BUILTIN\\Administrators",
                "group": "BUILTIN\\Administrators",
                "control_flags": "0x9504",
                "acls": [],
                "inode": 64,
                "security_style": "ntfs",
                "effective_style": "ntfs",
                "dos_attributes": "10",
                "text_dos_attr": "----D---",
                "user_id": "0",
                "group_id": "0",
                "mode_bits": 777,
                "text_mode_bits": "rwxrwxrwx"
            }
        })


@app.route('/api/storage/volumes')
@require_basic_auth
def get_volumes():
    # Get the svm.name query parameter
    svm_name = request.args.get('svm.name', '')
    
    # Return volumes for the specified SVM
    if svm_name == 'TESTCIFSLOW':
        return jsonify({
            "records": [
                {
                    "uuid": "c9339406-93b4-4ea7-821a-d2a25ab36abd",
                    "name": "TESTTEST",
                    "svm": {
                        "name": "TESTCIFSLOW"
                    }
                },
                {
                    "uuid": "a1b2c3d4-5678-4f90-aaaa-bbbbccccdddd",
                    "name": "ARCHIVE01",
                    "svm": {
                        "name": "TESTCIFSLOW"
                    }
                },
                {
                    "uuid": "d7fbc685-f4f3-48b0-ad7d-aae17d4065f3",
                    "name": "ARCHIVE_T2_Vol",
                    "svm": {
                        "name": "TESTCIFSLOW"
                    }
                }
            ],
            "num_records": 3
        })
    elif not svm_name:
        # Return default volume when no svm.name parameter is provided
        return jsonify({
            "records": [
                {
                    "uuid": "d7fbc685-f4f3-48b0-ad7d-aae17d4065f3",
                    "name": "ARCHIVE_T2_Vol"
                }
            ],
            "num_records": 1
        })
    else:
        # Return empty result for other SVM names
        return jsonify({
            "records": [],
            "num_records": 0
        })


@app.route('/api/storage/volumes/<volume_uuid>/files/<path:file_path>')
@require_basic_auth
def get_volume_files(volume_uuid, file_path):
    # Get the type query parameter
    file_type = request.args.get('type', '')
    
    # Normalize file_path by removing leading slashes
    normalized_path = file_path.lstrip('/')
    
    # Return folders based on volume UUID and path
    if file_type == 'directory':
        # For CIFSTEST share - return some test folders
        if normalized_path == 'CIFSTEST' and volume_uuid == 'd7fbc685-f4f3-489b-ad7d-aae17d4065fY':
            return jsonify({
                "records": [
                    {
                        "name": "Subfolder1",
                        "path": "/CIFSTEST/Subfolder1",
                        "type": "directory"
                    },
                    {
                        "name": "Subfolder2",
                        "path": "/CIFSTEST/Subfolder2",
                        "type": "directory"
                    },
                    {
                        "name": "Documents",
                        "path": "/CIFSTEST/Documents",
                        "type": "directory"
                    }
                ],
                "num_records": 3
            })
        
        # For Archive share - return different folders (in ARCHIVE01 volume)
        elif normalized_path == 'Archive' and volume_uuid == 'a1b2c3d4-5678-4f90-aaaa-bbbbccccdddd':
            return jsonify({
                "records": [
                    {
                        "name": "2024",
                        "path": "/Archive/2024",
                        "type": "directory"
                    },
                    {
                        "name": "2025",
                        "path": "/Archive/2025",
                        "type": "directory"
                    }
                ],
                "num_records": 2
            })
        
        # For Hello share (only in ARCHIVE_T2_Vol volume)
        elif normalized_path == 'Hello' and volume_uuid == 'd7fbc685-f4f3-48b0-ad7d-aae17d4065f3':
            return jsonify({
                "records": [
                    {
                        "name": "ThisIsdefinitelyASubFolder",
                        "path": "/Hello/ThisIsdefinitelyASubFolder",
                        "type": "directory"
                    },
                    {
                        "name": "MaybeSubFolder",
                        "path": "/Hello/MaybeSubFolder",
                        "type": "directory"
                    }
                ],
                "num_records": 2
            })
        # For Hello share (only in ARCHIVE_T2_Vol volume)
        elif normalized_path == 'Hello/ThisIsdefinitelyASubFolder' and volume_uuid == 'd7fbc685-f4f3-48b0-ad7d-aae17d4065f3':
            return jsonify({
                "records": [
                    {
                        "name": "ChildLevel1",
                        "path": "/Hello/ThisIsdefinitelyASubFolder/ChildLevel1",
                        "type": "directory"
                    },
                    {
                        "name": "ChildLevel2",
                        "path": "/Hello/ThisIsdefinitelyASubFolder/ChildLevel2",
                        "type": "directory"
                    }
                ],
                "num_records": 2
            })
        else:
            # Return empty result for other paths
            return jsonify({
                "records": [],
                "num_records": 0
            })
    else:
        # Return empty result for non-directory types
        return jsonify({
            "records": [],
            "num_records": 0
        })


if __name__ == '__main__':
    app.run(port=5001)