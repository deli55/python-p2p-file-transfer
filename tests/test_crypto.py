import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from p2p_transfer.crypto import (
    derive_shared_key,
    encrypt_chunk,
    decrypt_chunk,
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
)


def test_keypair_generation():
    """Test that a keypair can be generated, serialized, and deserialized correctly."""
    # Generate a keypair
    private_key = generate_keypair()

    # Serialize the public key to PEM
    pem_bytes = serialize_public_key(private_key)

    # Deserialize the public key back from PEM
    loaded_public_key = deserialize_public_key(pem_bytes)

    # Assert the deserialized key is valid
    assert loaded_public_key is not None
    assert isinstance(loaded_public_key, type(private_key.public_key()))


def test_derive_shared_key():
    """Test that Alice and Bob derive the same shared key by exchanging public keys."""
    # Generate keypairs for Alice and Bob
    alice_private = generate_keypair()
    bob_private = generate_keypair()

    # Exchange public keys
    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    # Each side derives the shared key using their own private key and the other's public key
    alice_derived = derive_shared_key(alice_private, bob_public)
    bob_derived = derive_shared_key(bob_private, alice_public)

    # Both sides must derive the same key
    assert alice_derived == bob_derived
    assert len(alice_derived) == 32


def test_chunk_encryption():
    """Test ChaCha20-Poly1305 chunk encryption and decryption."""
    # Generate a random 32-byte key
    key = os.urandom(32)

    # Sample plaintext
    plaintext = b"Hello, this is a secret chunk of data!"

    # Encrypt
    payload = encrypt_chunk(key, plaintext)

    # Decrypt
    decrypted = decrypt_chunk(key, payload)
    assert decrypted == plaintext

    # Verify that decrypting with an invalid key raises InvalidTag
    wrong_key = os.urandom(32)
    with pytest.raises(InvalidTag):
        decrypt_chunk(wrong_key, payload)
