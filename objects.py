# fa26cnt5410 project - objects.py

import os
import json
import secrets

class Objects:
    @staticmethod
    def new_id():
        """Generate a new random object ID as hex string."""
        return secrets.token_hex(16)  # 16 bytes -> 32 hex chars

    @staticmethod
    def get_path(object_id, storage_root):
        """
        Get file paths for object data and its JSON sidecar.
        Returns (data_path, sidecar_path) relative to storage_root.
        """
        assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
        assert isinstance(storage_root, str) and len(storage_root) > 0, "Storage root must be non-empty string"
        # Use first 2 chars of object_id as subdirectory to spread files
        subdir = object_id[:2]
        data_dir = os.path.join(storage_root, 'objects', subdir)
        data_path = os.path.join(data_dir, object_id)
        sidecar_path = data_path + '.json'
        return data_path, sidecar_path

    @staticmethod
    def get_data(object_id_or_path):
        """
        Read raw object data from disk.
        Accepts either object_id (requires storage_root from context) or full path.
        For simplicity in this boilerplate, we assume path is provided.
        """
        assert isinstance(object_id_or_path, str) and len(object_id_or_path) > 0, "Path must be non-empty string"
        assert os.path.exists(object_id_or_path), f"File not found: {object_id_or_path}"
        # In real implementation, would need storage_root to convert object_id to path
        # This is a placeholder - actual implementation would depend on context
        with open(object_id_or_path, 'rb') as f:
            return f.read()

    @staticmethod
    def write_data(object_id_or_path, data):
        """
        Write raw object data to disk.
        Creates directories as needed.
        """
        assert isinstance(object_id_or_path, str) and len(object_id_or_path) > 0, "Path must be non-empty string"
        assert isinstance(data, bytes), "Data must be bytes"
        # For placeholder, assume object_id_or_path is a full path
        os.makedirs(os.path.dirname(object_id_or_path), exist_ok=True)
        with open(object_id_or_path, 'wb') as f:
            f.write(data)

    @staticmethod
    def is_valid_id(object_id):
        if not isinstance(object_id, str) or len(object_id) != 32:
            return False
        if any(c not in "0123456789abcdef" for c in object_id):
            return False
        return True
            