# fa26cnt5410 project - crypto.py

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519 
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.exceptions import InvalidSignature, InvalidTag

import secrets
import time

import utils

MAX_TIMESTAMP_GAP_AUTHENTICATOR = 120

SECURE_STORAGE_AUTH_PREFIX = b"secure-storage-auth-v1\x00"
SECURE_STORAGE_PAYLOAD_PREFIX = b"secure-storage-payload-v1\x00"
SECURE_STORAGE_OBJECT_PREFIX = b"secure-storage-object-v1\x00"
SECURE_STORAGE_CEK_WRAP_PREFIX = b"secure-storage-cek-wrap-v1\x00"

def get_keypair(username, password, salt, iterations=100000):
    """
    Derive Ed25519 and X25519 key pairs from password using PBKDF2.
    Returns (signing_private_key, encryption_private_key)
    """
    assert isinstance(username, str) and len(username) > 0, "Username must be non-empty string"
    assert isinstance(password, str) and len(password) > 0, "Password must be non-empty string"
    assert isinstance(salt, str) and len(salt) >= 12, "Salt must be non-empty string"

    # note: library wants bytes so we need to encode these strings
    salt_bytes = utils.b64_to_bytes(salt) # salt arrives as b64
    assert len(salt_bytes) >= 16
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=iterations)

    username_bytes = username.encode('utf-8')
    password_bytes = password.encode('utf-8')
    # adding length makes it unambiguous (no colliding pairs of username,passwords)
    userpass_bytes = (len(username_bytes).to_bytes(4, "big") + username_bytes + password_bytes)
    master_seed = kdf.derive(userpass_bytes) # derive master (step 1)

    # derive ed25519 and x25519 seeds for keys from master_seed (step 2)

    ed25519_seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ed25519-signing").derive(master_seed)
    x25519_seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-encryption").derive(master_seed)

    # derive private keys (step 3)
    ed25519_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    x25519_priv = x25519.X25519PrivateKey.from_private_bytes(x25519_seed )

    return ed25519_priv, x25519_priv 


def sign_encrypt(object_id_bytes, data, private_key):
    """
    Sign the plaintext with Ed25519 private key, then
    encrypt data with a randomly generated CEK using AES-GCM.
    Returns (ciphertext, cek)
    """
    assert isinstance(data, bytes) and len(data) > 0, "Data must be bytes"
    assert isinstance(object_id_bytes, bytes) and len(object_id_bytes) > 0, "Object id must be bytes"
    assert private_key is not None, "Private key must not be None"

    # 0. associated_data
    associated_data = SECURE_STORAGE_OBJECT_PREFIX + object_id_bytes

    # 1. Sign and pack the payload
    signature = private_key.sign(SECURE_STORAGE_PAYLOAD_PREFIX + data)
    payload_bytes = data + signature
    
    # 2. Generate a fresh Content Encryption Key (CEK) and a nonce
    cek = AESGCM.generate_key(bit_length=256)
    nonce_bytes = secrets.token_bytes(12)

    # 3. Encrypt payload once using AES-GCM
    ciphertext_bytes = AESGCM(cek).encrypt(nonce_bytes, payload_bytes, associated_data=associated_data)
    
    return (nonce_bytes + ciphertext_bytes), cek


def decrypt_verify(object_id_bytes, ciphertext, cek, public_key):
    """
    Decrypt ciphertext using CEK with AES-GCM,
    then verify signature with Ed25519 public key.
    Returns plaintext on success or None and an error message on failure.
    """
    assert isinstance(object_id_bytes, bytes) and len(object_id_bytes) > 0, "Object id must be bytes"
    assert isinstance(ciphertext, bytes) and len(ciphertext) > 0, "Ciphertext must be bytes"
    assert isinstance(cek, bytes) and len(cek) > 0, "CEK must be bytes"
    assert public_key is not None, "Public key must not be None"

    associated_data = SECURE_STORAGE_OBJECT_PREFIX + object_id_bytes

    if len(ciphertext) < 92: # 12 (nonce) + 16 (GCM) + 64 (sig)
        return None, "invalid ciphertext!"

    if len(cek) != 32:
        return None, "invalid cek!"

    # extract nonce and ciphertext bytes
    nonce_bytes = ciphertext[:12]
    ciphertext_bytes = ciphertext[12:]

    try:
        decrypted_payload_bytes = AESGCM(cek).decrypt(nonce_bytes, ciphertext_bytes, associated_data=associated_data)
    except InvalidTag:
        return None, "invalid tag!"
    
    if len(decrypted_payload_bytes) < 64:
        return None, "missing or truncated signature!"

    data = decrypted_payload_bytes[:-64]
    signature = decrypted_payload_bytes[-64:]

    try:
        public_key.verify(signature, SECURE_STORAGE_PAYLOAD_PREFIX + data)
    except InvalidSignature:
        return None, "invalid signature!"
    
    return data, "ok"

def wrap_cek(object_id_bytes, cek, recipient_public_keys):
    """
    For each recipient public key:
      - Generate ephemeral X25519 key pair
      - Derive shared secret via ECDH
      - Derive wrapping key from shared secret
      - Encrypt CEK with wrapping key
    Returns headers, a list per recipient
    """
    assert isinstance(object_id_bytes, bytes) and len(object_id_bytes) > 0, "Object id must be bytes"
    assert isinstance(cek, bytes) and len(cek) > 0, "CEK must be bytes"
    assert isinstance(recipient_public_keys, list), "Recipient public keys must be list"
    assert all(pk is not None for pk in recipient_public_keys), "All public keys must not be None"

    headers = []
    for recipient_public_key in recipient_public_keys:
        ephemeral_private_key = x25519.X25519PrivateKey.generate()

        recipient_bytes = recipient_public_key.public_bytes_raw()
        ephemeral_bytes = ephemeral_private_key.public_key().public_bytes_raw()

        context = (SECURE_STORAGE_CEK_WRAP_PREFIX + ephemeral_bytes + 
                   recipient_bytes + object_id_bytes)

        # ephemeral key exchange
        shared_secret = ephemeral_private_key.exchange(recipient_public_key)

        wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context,).derive(shared_secret)

        nonce_bytes = secrets.token_bytes(12)
        wrapped_cek = AESGCM(wrapping_key).encrypt(nonce_bytes, cek, associated_data=context,)

        recipient_dc = {'recipient_public_key': recipient_bytes,
                        'ephemeral_public_key': ephemeral_bytes,
                        'nonce': nonce_bytes,
                        'wrapped_cek': wrapped_cek}
        headers.append(recipient_dc)
    
    return headers


def unwrap_cek(object_id_bytes, headers, private_key):
    """
    Find header matching private key, derive shared secret, unwrap CEK
    Returns cek on success or None and a failure message.
    """
    assert isinstance(object_id_bytes, bytes) and len(object_id_bytes) > 0, "Object id must be bytes"
    
    assert isinstance(headers, list), "Headers must be list"
    assert private_key is not None, "Private key must not be None"
    
    # grab the public key
    public_key = private_key.public_key()
    recipient_bytes = public_key.public_bytes_raw()

    for header in headers:
        if not isinstance(header, dict):
            return None, "invalid header"

        if header.get('recipient_public_key') != recipient_bytes:
            continue

        # if we get here we must have found the right key
        ephemeral_bytes = header.get('ephemeral_public_key')
        if not isinstance(ephemeral_bytes, bytes) or len(ephemeral_bytes) != 32:
            return None, "invalid ephemeral bytes"
        try:
            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_bytes)
            shared_secret = private_key.exchange(ephemeral_public_key)
        except ValueError:
            return None, "invalid ephemeral key"
        
        nonce_bytes = header.get('nonce')
        if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 12:
            return None, "invalid nonce"
        
        # wrapped cek is 32 byte CEK + 16 bytes AESGMC tag
        wrapped_cek = header.get('wrapped_cek')
        if not isinstance(wrapped_cek, bytes) or len(wrapped_cek) != 48:
            return None, "invalid wrapped cek"

        context = (SECURE_STORAGE_CEK_WRAP_PREFIX + ephemeral_bytes + 
                   recipient_bytes + object_id_bytes)

        # attempt to re-derived the wrapping key from shared secret and decrypt cek
        try:
            wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context,).derive(shared_secret)

            cek = AESGCM(wrapping_key).decrypt(nonce_bytes, wrapped_cek, associated_data=context,)
        except InvalidTag:
            return None, "invalid tag"

        return cek, "ok"
    
    return None, "wrapped cek not found or unauthorized recipient"


def create_authenticator(command_hash_bytes, private_key):
    """
    Create a signature of the command hash using the private key.
    Returns signature.
    """
    assert isinstance(command_hash_bytes, bytes), "Command hash must be bytes"
    assert private_key is not None, "Private key must not be None"
    
    timestamp = int(time.time())
    nonce_bytes = secrets.token_bytes(16)

    message_bytes = (b"secure-storage-auth-v1\x00" +
               timestamp.to_bytes(8, "big") + nonce_bytes + command_hash_bytes)

    signature = private_key.sign(message_bytes)

    return {'timestamp': timestamp, 'nonce': nonce_bytes, 'signature': signature}

def verify_authenticator(command_hash_bytes, authenticator, public_key):
    """
    Verify the signature of the command hash using public key.
    Returns True if valid.
    """
    assert isinstance(command_hash_bytes, bytes), "Command hash must be bytes"
    assert isinstance(authenticator, dict), "Authenticator must be dict"
    assert public_key is not None, "Public key must not be None"
    
    timestamp = int(time.time())
    signature_timestamp = authenticator.get('timestamp')
    if type(signature_timestamp) is not int or not (0 <= signature_timestamp < 2**64):
        return False
    
    nonce_bytes = authenticator.get('nonce')
    if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 16:
        return False


    message_bytes = (SECURE_STORAGE_AUTH_PREFIX +
               signature_timestamp.to_bytes(8, "big") + nonce_bytes + command_hash_bytes)

    if abs(timestamp - signature_timestamp) > MAX_TIMESTAMP_GAP_AUTHENTICATOR:
       return False

    signature = authenticator.get('signature')
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    
    try:
        public_key.verify(signature, message_bytes)
    except InvalidSignature:
        return False

    return True

