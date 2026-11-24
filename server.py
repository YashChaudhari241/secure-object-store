# fa26cnt5410 project - server.py

import socket
import threading
import json
import os
import time

import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


from objects import Objects
import utils
import crypto


# Fixed thread pool size
THREAD_POOL_SIZE = 10

SIGNUP_LOCK = threading.RLock()
OBJECT_LOCK = threading.Lock()


def handle_client(conn, addr, storage_root):
    """Handle a single client connection."""
    assert conn is not None, "Connection must not be None"
    assert addr is not None, "Address must not be None"
    assert isinstance(storage_root, str) and len(storage_root) > 0, "Storage root must be non-empty string"
    try:
        while True:
            # we'll know the length
            data = utils.recv_message(conn)
            if data is None:
                break
            
            try:
                # Retrieve dict command
                command = decode_and_verify_command(data)

                # Dispatch based on command type
                cmd_type = command.get('cmd')
                assert cmd_type is not None, "Command must have 'cmd' field"
                if cmd_type == 'signup':
                    response = handle_signup(command, storage_root)
                elif cmd_type == 'info':
                    response = handle_info(command, storage_root)
                elif cmd_type == 'read':
                    response = handle_read(command, storage_root)
                elif cmd_type == 'write':
                    response = handle_write(command, storage_root)
                elif cmd_type == 'share':
                    response = handle_share(command, storage_root)
                elif cmd_type == 'new':
                    response = handle_new(command, storage_root)
                elif cmd_type == 'delete':
                    response = handle_delete(command, storage_root)
                else:
                    response = {'status': 'error', 'message': 'Unknown command'}
            except Exception as e:
                response = {'status': 'error', 'message': f'Invalid command: {str(e)}'}
            
            # Send response
            response_bytes = json.dumps(response).encode("utf-8")
            utils.send_message(conn, response_bytes)
            
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def _get_users(storage_root):
    registry_path = os.path.join(storage_root, "users.json")
    # Need a lock for this to avoid concurrency issues
    with SIGNUP_LOCK:
        users = (utils.read_json(registry_path) if os.path.exists(registry_path) else {})
        if not isinstance(users, dict):
            raise ValueError("Invalid user registry")
        return users

def _create_ownership_index(owner, storage_root):
    list_id = Objects.new_id()
    data_path, sidecar_path = Objects.get_path(list_id, storage_root)
    os.makedirs(os.path.dirname(data_path), exist_ok=True)

    metadata = {
        "object_id": list_id,
        "created_at": int(time.time()),
        "kind": "ownership_index",
        "owner_public_key_b64": owner,
        "acl": {owner: ["info", "list"]},
    }

    created = []
    try:
        with open(data_path, "x", encoding="utf-8") as f:
            created.append(data_path)
            json.dump({"object_ids": []}, f)

        with open(sidecar_path, "x", encoding="utf-8") as f:
            created.append(sidecar_path)
            json.dump(metadata, f, indent=2)
    except Exception:
        for path in reversed(created):
            os.unlink(path)
        raise

    return list_id, created


def handle_signup(command, storage_root):
    assert isinstance(command, dict), "Command must be dictionary"

    username = command.get("username")
    public_key_bytes = command.get("public_key")

    if not isinstance(username, str) or not username.strip():
        return {"status": "error", "message": "Username must be non-empty"}

    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        return {"status": "error", "message": "Invalid signing public key"}

    public_key_b64 = utils.bytes_to_b64(public_key_bytes)
    
    registry_path = os.path.join(storage_root, "users.json")
    with SIGNUP_LOCK:
        users = _get_users(storage_root)

        if username in users:
            record = users[username]

            if (not isinstance(record, dict) or not Objects.is_valid_id(record.get("list_object_id"))):
                raise ValueError("Invalid user registry entry")

            if record.get("public_key_b64") != public_key_b64:
                return {"status": "error", "message": "Username already registered",}

            # Same username and key: return the existing index.
            list_id = record["list_object_id"]

        else:
            with OBJECT_LOCK:
                list_id, created = _create_ownership_index(public_key_b64, storage_root)

                users[username] = {"public_key_b64": public_key_b64, "list_object_id": list_id,}

                try:
                    utils.write_json_atomic(registry_path, users)
                except Exception:
                    for path in reversed(created):
                        os.unlink(path)
                    raise

    return {"status": "ok", "username": username, "list_object_id": list_id}


def handle_info(command, storage_root):
    """Handle info command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"
    assert 'object_id' in command, "Info command requires object_id"
    object_id = command.get("object_id")

    if not Objects.is_valid_id(object_id):
        return {"status": "error", "message": "Invalid object ID"}

    caller = utils.bytes_to_b64(command["public_key"])
    data_path, sidecar_path = Objects.get_path(object_id, storage_root)

    with OBJECT_LOCK:
        if not os.path.isfile(data_path) or not os.path.isfile(sidecar_path):
            return {"status": "error", "message": "Object not found"}

        metadata = utils.read_json(sidecar_path)
        permissions = metadata.get("acl", {}).get(caller, [])

        if "info" not in permissions: 
            # purposefully return "Invalid object ID" instead of access denied to not leak existence
            return {"status": "error", "message": "Invalid object ID"}

        info = {
            "object_id": object_id,
            "created_at": metadata["created_at"],
            "size_bytes": os.path.getsize(data_path),
            "permissions": permissions,
        }

    return {"status": "ok", "info": info}


def handle_read(command, storage_root):
    """Handle read command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"
    assert 'object_id' in command, "Read command requires object_id"
    # TODO: Implement actual read logic with access control and decryption
    return {'status': 'ok', 'data': ''}

def handle_write(command, storage_root):
    """Handle write command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"
    assert 'object_id' in command, "Write command requires object_id"
    assert 'data' in command, "Write command requires data"
    # TODO: Implement actual write logic with quota check and encryption
    return {'status': 'ok'}

def handle_share(command, storage_root):
    """Handle share command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"
    assert 'user_publickey' in command, "Share command requires user_publickey"
    assert 'object_id' in command, "Share command requires object_id"
    assert 'access_rights' in command, "Share command requires access_rights"
    assert 'expiration' in command, "Share command requires expiration"
    # TODO: Implement actual share logic (create capability token)
    return {'status': 'ok'}

def handle_new(command, storage_root):
    """Handle new command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"

    owner = utils.bytes_to_b64(command["public_key"])

    users = _get_users(storage_root)
    user = next(
        (
            record
            for record in users.values()
            if isinstance(record, dict)
            and record.get("public_key_b64") == owner
            and record.get("list_object_id")
        ),
        None,
    )

    if user is None:
        return {"status": "error", "message": "Signup required"}

    with OBJECT_LOCK:
        object_id = Objects.new_id()
        data_path, sidecar_path = Objects.get_path(object_id, storage_root)

        if os.path.exists(data_path) or os.path.exists(sidecar_path):
            return {"status": "error", "message": "Object ID collision; retry"}

        os.makedirs(os.path.dirname(data_path), exist_ok=True)

        metadata = {
            "object_id": object_id,
            "created_at": int(time.time()),
            "owner_public_key_b64": owner,
            "acl": { owner: ["info", "read", "write", "share", "delete"], },
        }

        created = []
        try:
            with open(data_path, "xb"):
                pass
            created.append(data_path)

            with open(sidecar_path, "x", encoding="utf-8") as f:
                created.append(sidecar_path)
                json.dump(metadata, f, indent=2)

            index_path, _ = Objects.get_path(user["list_object_id"], storage_root)
            index = utils.read_json(index_path)

            if (not isinstance(index, dict) or not isinstance(index.get("object_ids"), list)):
                raise ValueError("Invalid ownership index")

            index["object_ids"].append(object_id)
            utils.write_json_atomic(index_path, index)
        
        except Exception:
            for path in reversed(created):
                os.unlink(path)
            raise

    return {"status": "ok", "object_id": object_id}

def handle_delete(command, storage_root):
    """Handle delete command - placeholder."""
    assert isinstance(command, dict), "Command must be dictionary"
    assert 'object_id' in command, "Delete command requires object_id"
    # TODO: Implement actual delete logic
    return {'status': 'ok'}



def decode_and_verify_command(data):
    command = utils.deserialize_command(data.decode("utf-8"))

    # Exclude authenticator when reproducing the command hash.
    authenticator = command.get('authenticator')
    if not isinstance(authenticator, dict):
        raise ValueError("Missing or invalid authenticator")

    del command['authenticator'] # remove it so we can compute the hash

    public_key_bytes = command.get("public_key")
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("Invalid public key")

    command_bytes = utils.serialize_command(command).encode("utf-8")
    command_hash = hashlib.sha256(command_bytes).digest()

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    if not crypto.verify_authenticator(command_hash, authenticator, public_key):
        raise ValueError("Invalid authenticator")

    # Preserve metadata for the server's replay check.
    command["authenticator"] = authenticator
    return command


def main(config_path):
    """Main server entry point."""
    assert isinstance(config_path, str) and len(config_path) > 0, "Config path must be non-empty string"
    assert os.path.exists(config_path), f"Config file not found: {config_path}"
    config = utils.read_json(config_path)
    assert 'storage_root' in config, "Config must contain storage_root"
    assert 'bind_ip' in config, "Config must contain bind_ip"
    assert 'port' in config, "Config must contain port"
    storage_root = config['storage_root']
    bind_ip = config['bind_ip']
    port = config['port']
    assert isinstance(storage_root, str) and len(storage_root) > 0, "Storage root must be non-empty string"
    assert isinstance(bind_ip, str) and len(bind_ip) > 0, "Bind IP must be non-empty string"
    assert isinstance(port, int) and 0 < port < 65536, "Port must be valid integer"
    
    # Ensure storage directories exist
    objects_dir = os.path.join(storage_root, 'objects')
    os.makedirs(objects_dir, exist_ok=True)
    assert os.path.isdir(objects_dir), f"Objects directory must exist: {objects_dir}"
    
    # Create socket and listen
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((bind_ip, port))
    server_socket.listen(5)
    print(f"Server listening on {bind_ip}:{port}")
    
    # Simple thread pool implementation (not robust, but meets requirement)
    active_threads = []
    
    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr}")
            
            # Clean up finished threads
            active_threads = [t for t in active_threads if t.is_alive()]
            
            # If at thread limit, wait for a slot (simple approach)
            if len(active_threads) >= THREAD_POOL_SIZE:
                # Wait for oldest thread to finish (not ideal but simple)
                active_threads[0].join()
                active_threads = active_threads[1:]
            
            # Start new thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, storage_root),
                daemon=True
            )
            client_thread.start()
            active_threads.append(client_thread)
            
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    import sys
    assert len(sys.argv) == 2, "Usage: python server.py <config_file>"
    main(sys.argv[1])
