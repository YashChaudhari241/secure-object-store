# fa26cnt5410 project - utils.py

import json
import base64
import os

MAX_MESSAGE_BYTES = 32 * 1024 * 1024 

def read_json(filepath):
    assert os.path.exists(filepath), f"File not found: {filepath}"
    with open(filepath, 'r') as f:
        return json.load(f)

def write_json(filepath, data):
    assert isinstance(data, dict), "Data must be a dictionary"
    with open(filepath, 'w', encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def write_json_atomic(filepath, data):
    temp_path = filepath + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, filepath)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

def bytes_to_b64(data):
    assert isinstance(data, bytes), "Input must be bytes"
    return base64.b64encode(data).decode('utf-8')

def b64_to_bytes(data):
    assert isinstance(data, str), "Input must be string"
    return base64.b64decode(data.encode('utf-8'), validate=True)


def serialize_command(command_dc):
    def _recurse_b64(value):
        if isinstance(value, dict):
            result = {}

            for key, item in value.items():
                if key.endswith("_b64"):
                    raise ValueError("Keys ending in _b64 are reserved")
                
                if isinstance(item, bytes):
                    result[f"{key}_b64"] = bytes_to_b64(item)
                else:
                    result[key] = _recurse_b64(item)

            return result

        if isinstance(value, list):
            return [_recurse_b64(item) for item in value]

        if isinstance(value, bytes):
            raise TypeError("Bytes must be stored under a dictionary key")

        return value
    
    command_dc_b64 = _recurse_b64(command_dc)
    return json.dumps(command_dc_b64, sort_keys=True, allow_nan=False)


def deserialize_command(text):
    def _decode_object(pairs):
        result = {}

        for key, value in pairs:
            if key.endswith("_b64"):
                key = key[:-4]

                if not isinstance(value, str):
                    raise ValueError("Base64 field must contain a string")
                value = b64_to_bytes(value)

            if key in result:
                raise ValueError("Duplicate or conflicting field")
            result[key] = value

        return result
    
    command = json.loads(text, object_pairs_hook=_decode_object)
    if not isinstance(command, dict):
        raise ValueError("Command must be a dictionary")

    return command





# strategy: prefix length to every message that ways we know how much to expect
def send_message(sock, payload):
    if not isinstance(payload, bytes):
        raise TypeError("Payload must be bytes")

    if not 1 <= len(payload) <= MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message size")

    sock.sendall(len(payload).to_bytes(8, "big"))
    sock.sendall(payload)

def recv_message(sock):
    header = recv_exact(sock, 8, allow_eof=True)

    if header is None:
        return None

    size = int.from_bytes(header, "big")

    if not 1 <= size <= MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message size")

    return recv_exact(sock, size)

def recv_exact(sock, size, allow_eof=False):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(min(size - len(result), 64 * 1024))

        if not chunk:
            if allow_eof and not result:
                return None
            raise ConnectionError("Connection closed during a message")

        result.extend(chunk)

    return bytes(result)