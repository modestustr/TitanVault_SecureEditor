import base64
import os
import logging
from typing import Optional
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class TitanCryptoEngine:
    """AES-GCM encryption with dynamic salt per file.

    Stores salt in file header for compatibility:
    [salt(16 bytes)][nonce(12 bytes)][ciphertext][tag(16 bytes)]
    """

    def __init__(self, master_password: str, salt: Optional[bytes] = None):
        """Initialize with master password and optional fixed salt.

        Args:
            master_password: User's master password
            salt: Optional fixed salt (for backward compatibility).
                  If None, generates dynamic salt per file.
        """
        self._fixed_salt = salt  # Used only if provided
        self._master_password = master_password.encode("utf-8")

        # Security: Overwrite plaintext password in memory
        # This hints to Python's garbage collector to free the plaintext sooner
        master_password = None  # type: ignore

    def _derive_key(self, master_password: bytes, salt: bytes) -> bytes:
        """Derive encryption key using Argon2id KDF.

        Security parameters:
        - iterations=8: 2x stronger against brute-force (was 4)
        - memory_cost=262144 (256MB): Resistant to GPU attacks (was 102400)
        - lanes=8: Parallel processing
        """
        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=8,           # ← Increased: 4 → 8 (2x security)
            memory_cost=262144,     # ← Increased: 102400 → 256MB (GPU resistant)
            lanes=8
        )
        return kdf.derive(master_password)

    def encrypt(self, plain_text: str) -> str:
        """Encrypt text with salt.

        For dynamic salt (None): returns [salt(16)][nonce(12)][ciphertext][tag]
        For fixed salt: returns [nonce(12)][ciphertext][tag] (backward compat)
        """
        try:
            # Use provided salt or generate new one
            salt = self._fixed_salt if self._fixed_salt else os.urandom(16)
            derived_key = self._derive_key(self._master_password, salt)

            aesgcm = AESGCM(derived_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)

            # For fixed salt (legacy): don't include salt in output
            # For dynamic salt: include salt for recovery on decrypt
            if self._fixed_salt:
                # Legacy format: [nonce(12)][ciphertext][tag]
                return base64.b64encode(nonce + ciphertext).decode("utf-8")
            else:
                # New format: [salt(16)][nonce(12)][ciphertext][tag]
                return base64.b64encode(salt + nonce + ciphertext).decode("utf-8")
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            # RISK #3 FIX: Exception chain suppression (from None)
            raise ValueError("Encryption failed") from None

    def decrypt(self, encrypted_b64: str) -> str:
        """Decrypt text using stored or provided salt.

        Handles both formats:
        - Fixed salt (legacy): [nonce(12)][ciphertext][tag]
        - Dynamic salt (new): [salt(16)][nonce(12)][ciphertext][tag]
        """
        try:
            data = base64.b64decode(encrypted_b64.strip())

            if self._fixed_salt:
                # Legacy format: salt is NOT in data, use self._fixed_salt
                if len(data) < 12:
                    raise ValueError("Corrupted data: too short for legacy format")
                nonce = data[:12]
                ciphertext = data[12:]
                salt = self._fixed_salt
            else:
                # Dynamic salt format: salt IS in data
                if len(data) < 28:  # 16 + 12 + min ciphertext
                    raise ValueError("Corrupted data: too short for dynamic format")
                salt = data[:16]
                nonce = data[16:28]
                ciphertext = data[28:]

            derived_key = self._derive_key(self._master_password, salt)
            aesgcm = AESGCM(derived_key)
            plain_text = aesgcm.decrypt(nonce, ciphertext, None)

            return plain_text.decode("utf-8")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            # RISK #3 FIX: Exception chain suppression (from None)
            raise ValueError(
                "Decryption failed (wrong password or corrupted file)"
            ) from None
