import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a SECP256R1 (P-256) ECDH private key.

    Returns:
        ec.EllipticCurvePrivateKey: The generated private key.
    """
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    return private_key


def serialize_public_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize a private key's public key to PEM format.

    Args:
        private_key: The private key whose public key will be serialized.

    Returns:
        bytes: The public key in PEM-encoded bytes format.
    """
    public_key = private_key.public_key()
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes


def deserialize_public_key(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Load a public key from PEM-encoded bytes.

    Args:
        pem_bytes: The PEM-encoded public key bytes.

    Returns:
        ec.EllipticCurvePublicKey: The loaded public key object.
    """
    public_key = serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )
    return public_key


def derive_shared_key(private_key: ec.EllipticCurvePrivateKey, remote_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Derive a 32-byte symmetric key from the ECDH shared secret using HKDF.

    Args:
        private_key: This side's private key.
        remote_public_key: The remote peer's public key.

    Returns:
        bytes: A 32-byte (256-bit) symmetric key.
    """
    shared_secret = private_key.exchange(ec.ECDH(), remote_public_key)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"p2p-file-transfer-v1",
    )
    return kdf.derive(shared_secret)


def encrypt_chunk(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext chunk using ChaCha20-Poly1305.

    Args:
        key: A 32-byte symmetric key.
        plaintext: The plaintext data to encrypt.

    Returns:
        bytes: nonce (12 bytes) + ciphertext (encrypted data).
    """
    nonce = os.urandom(12)
    cpaead = ChaCha20Poly1305(key)
    ciphertext = cpaead.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_chunk(key: bytes, payload: bytes) -> bytes:
    """Decrypt a ChaCha20-Poly1305 payload.

    Args:
        key: A 32-byte symmetric key.
        payload: nonce (12 bytes) + ciphertext.

    Returns:
        bytes: The decrypted plaintext.
    """
    nonce = payload[:12]
    ciphertext = payload[12:]
    cpaead = ChaCha20Poly1305(key)
    return cpaead.decrypt(nonce, ciphertext, None)
