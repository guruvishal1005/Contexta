"""
Contexta Backend - Digital Signature Module

RSA-based digital signatures for actor verification in the blockchain ledger.
Ensures that SOC events cannot be forged - only the real actor's key can sign.
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import structlog

logger = structlog.get_logger()


def generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA keypair for an actor.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    logger.debug("Generated new RSA keypair")
    
    return private_key, public_key


def sign_data(private_key: rsa.RSAPrivateKey, message: str) -> str:
    """
    Sign a message using RSA-PSS with SHA256.
    
    Args:
        private_key: RSA private key
        message: String message to sign
        
    Returns:
        Base64-encoded signature string
    """
    signature_bytes = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature_bytes).decode('utf-8')


def verify_signature(
    public_key: rsa.RSAPublicKey,
    message: str,
    signature: str
) -> bool:
    """
    Verify a signature using RSA-PSS with SHA256.
    
    Args:
        public_key: RSA public key
        message: Original message that was signed
        signature: Base64-encoded signature string
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        
        public_key.verify(
            signature_bytes,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.warning("Signature verification failed", error=str(e))
        return False


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    """
    Serialize public key to PEM format string.
    
    Args:
        public_key: RSA public key
        
    Returns:
        PEM-encoded public key string
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def deserialize_public_key(pem_string: str) -> rsa.RSAPublicKey:
    """
    Deserialize PEM string to public key.
    
    Args:
        pem_string: PEM-encoded public key string
        
    Returns:
        RSA public key object
    """
    return serialization.load_pem_public_key(
        pem_string.encode('utf-8'),
        backend=default_backend()
    )


def serialize_private_key(
    private_key: rsa.RSAPrivateKey,
    password: Optional[bytes] = None
) -> str:
    """
    Serialize private key to PEM format string.
    
    Args:
        private_key: RSA private key
        password: Optional password for encryption
        
    Returns:
        PEM-encoded private key string
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    return pem_bytes.decode('utf-8')


def deserialize_private_key(
    pem_string: str,
    password: Optional[bytes] = None
) -> rsa.RSAPrivateKey:
    """
    Deserialize PEM string to private key.
    
    Args:
        pem_string: PEM-encoded private key string
        password: Password if key is encrypted
        
    Returns:
        RSA private key object
    """
    return serialization.load_pem_private_key(
        pem_string.encode('utf-8'),
        password=password,
        backend=default_backend()
    )
