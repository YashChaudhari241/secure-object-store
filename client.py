# fa26cnt5410 project - client.py

import socket
import json
import os
import sys
import secrets
import getpass
import hashlib

import crypto
import utils

def load_config(config_path):
    """Load client configuration."""
    assert isinstance(config_path, str) and len(config_path) > 0, "Config path must be non-empty string"
    if os.path.exists(config_path):
        return utils.read_json(config_path)
    return {}

def save_config(config_path, config):
    """Save client configuration."""
    assert isinstance(config_path, str) and len(config_path) > 0, "Config path must be non-empty string"
    assert isinstance(config, dict), "Config must be dictionary"
    utils.write_json(config_path, config)

def get_keypair_from_config(config):
    """
    Get or create keypair from config.
    If password in config, use it; otherwise prompt.
    Stores private keys in config (in practice, should be more secure).
    """
    assert isinstance(config, dict), "Config must be dictionary"

    username = config.get('username')
    if not username :
        username = input("Enter username: ")
        assert isinstance(username , str) and len(username ) > 0, "Username must be non-empty string"
        config['username'] = username 

    password = config.get('password')
    if not password:
        password = getpass.getpass("Enter password: ")
        assert password, "Password must be non-empty string"
    
    # Generate or retrieve salt
    salt = config.get('salt')
    if not salt:
        salt = utils.bytes_to_b64(secrets.token_bytes(16))
        config['salt'] = salt
    else:
        assert isinstance(salt, str), "Salt must be string if present"
    
    # Derive keypair
    signing_key, encryption_key = crypto.get_keypair(username, password, salt)
    return signing_key, encryption_key


def send_command(sock, command_dict, signing_key):
    """
    Send a command dictionary as JSON and receive response.
    Commands always include a fresh authenticator (produced using signing_key).
    """
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(command_dict, dict), "Command must be dictionary"

    if 'authenticator' in command_dict:
        del command_dict['authenticator'] # remove if there since we need to hash thhe command

    public_key_bytes = signing_key.public_key().public_bytes_raw()
    command_dict['public_key'] = public_key_bytes

    # Hash every request field except the authenticator.
    command_bytes = utils.serialize_command(command_dict).encode("utf-8")
    command_hash_bytes = hashlib.sha256(command_bytes).digest()

    authenticator = crypto.create_authenticator(command_hash_bytes, signing_key)

    # now add the authenticator stuff
    command_dict['authenticator'] = authenticator

    serialized_bytes = utils.serialize_command(command_dict).encode("utf-8")
    try:
        utils.send_message(sock, serialized_bytes)

        response_data = utils.recv_message(sock)
        if response_data is None:
            raise ConnectionError("Server closed without a response")

        return json.loads(response_data.decode("utf-8"))
    except Exception as e:
        return {'status': 'error', 'message': f'Communication error: {str(e)}'}
    


def cmd_signup(sock, config, signing_key):
    """Send signup command - server will get the public key."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(config, dict), "Config must be dictionary"

    # note: public key will be added by send_command() automatically
    command = { "cmd": "signup", "username": config['username'],} 

    response = send_command(sock, command, signing_key)
    if response.get("status") == "ok":
        config["list_object_id"] = response["list_object_id"]

    return response


def cmd_list(sock, config, signing_key):
    """Handle list command - retrieve file list from server."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(config, dict), "Config must be dictionary"
    # The object_id for the file list should be stored in config after signup

    list_object_id = config.get('list_object_id')
    if not list_object_id:
        return {"status": "error", "message": "No list object ID; signup first"}
    
    command = {
        'cmd': 'list',
        'object_id': list_object_id,
        # ...
    }
    # TODO
    
    response = send_command(sock, command, signing_key)
    return response


def cmd_info(sock, object_id, signing_key):
    """Handle info command."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
    command = {
        'cmd': 'info',
        'object_id': object_id,
        # ...
    }
    # TODO

    response = send_command(sock, command, signing_key)
    return response

def cmd_read(sock, object_id, signing_key):
    """Handle read command."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
    command = {
        'cmd': 'read',
        'object_id': object_id,
        # ...
    }
    # TODO
    
    response = send_command(sock, command, signing_key)
    return response

def cmd_write(sock, object_id, data, signing_key):
    """Handle write command."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
    assert isinstance(data, str), "Data must be string (would be b64 encoded in real implementation)"
    command = {
        'cmd': 'write',
        'object_id': object_id,
                # ...
    }
    # TODO
    
    response = send_command(sock, command, signing_key)
    return response

def cmd_share(sock, user_publickey, object_id, access_rights, expiration, signing_key):
    """Handle share command."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(user_publickey, str) and len(user_publickey) > 0, "User public key must be non-empty string"
    assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
    assert isinstance(access_rights, str) and len(access_rights) > 0, "Access rights must be non-empty string"
    assert isinstance(expiration, str) and len(expiration) > 0, "Expiration must be non-empty string"
    command = {
        'cmd': 'share',
        'user_publickey': user_publickey,
        'object_id': object_id,
        'access_rights': access_rights,
        'expiration': expiration,
                # ...
    }
    # TODO
    
    response = send_command(sock, command, signing_key)
    return response

def cmd_delete(sock, object_id, signing_key):
    """Handle delete command."""
    assert isinstance(sock, socket.socket), "Socket must be socket object"
    assert isinstance(object_id, str) and len(object_id) > 0, "Object ID must be non-empty string"
    command = {
        'cmd': 'delete',
        'object_id': object_id,
            # ...
    }
    # TODO
    
    response = send_command(sock, command, signing_key)
    return response


def main(config_path):
    """Main client entry point."""
    assert isinstance(config_path, str) and len(config_path) > 0, "Config path must be non-empty string"
    config = load_config(config_path)
    
    # Get server connection info from config
    server_ip = config.get('server_ip', '127.0.0.1')
    server_port = config.get('server_port', 8282)
    assert isinstance(server_ip, str) and len(server_ip) > 0, "Server IP must be non-empty string"
    assert isinstance(server_port, int) and 0 < server_port < 65536, "Server port must be valid integer"
    
    # Connect to server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, server_port))
        print(f"Connected to server at {server_ip}:{server_port}")
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        return
    
    # Parse command line arguments
    assert len(sys.argv) >= 3, "Usage: python client.py <config_file> <command> [args...]"
    command = sys.argv[2]

    signing_key, encryption_key = get_keypair_from_config(config)
    save_config(config_path, config)
    
    if command == 'signup':
        response = cmd_signup(sock, config, signing_key)        
        if response.get("status") == "ok":
            save_config(config_path, config)

    elif command == 'list':
        response = cmd_list(sock, config, signing_key)
    elif command == 'info':
        assert len(sys.argv) >= 4, "Usage: info <object_id>"
        response = cmd_info(sock, sys.argv[3], signing_key)
    elif command == 'read':
        assert len(sys.argv) >= 4, "Usage: read <object_id>"
        response = cmd_read(sock, sys.argv[3], signing_key)
    elif command == 'write':
        assert len(sys.argv) >= 5, "Usage: write <object_id> <data>"
        response = cmd_write(sock, sys.argv[3], sys.argv[4], signing_key)
    elif command == 'share':
        assert len(sys.argv) >= 7, "Usage: share <user_publickey> <object_id> <access_rights> <expiration>"
        response = cmd_share(sock, sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], signing_key)
    elif command == 'delete':
        assert len(sys.argv) >= 4, "Usage: delete <object_id>"
        response = cmd_delete(sock, sys.argv[3], signing_key)
    else:
        print(f"Unknown command: {command}")

    if response.get("status") == "ok":
        print(f"{command} successful")
    else:
        print(f"{command} failed: {response.get('message')}")
    
    sock.close()

if __name__ == '__main__':
    assert len(sys.argv) >= 2, "Usage: python client.py <config_file>"
    main(sys.argv[1])

