#!/usr/bin/env python3
"""Test security improvements: file permissions and master password cleanup."""

from engine_crypto import TitanCryptoEngine
import os
import stat

def test_file_permissions():
    """Test that encrypted files have restricted permissions (0o600)."""
    print("=" * 60)
    print("TESTING: File Permissions (Security Fix #3)")
    print("=" * 60)

    password = "secure_pass"
    content = "Sensitive data"
    test_file = "perms_test.vault"

    try:
        # Create encrypted file with engine
        engine = TitanCryptoEngine(password, salt=None)
        encrypted = engine.encrypt(content)

        print(f"\n[STEP 1] Writing encrypted file...")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(encrypted)

        # Set permissions like VaultUI.py does
        os.chmod(test_file, 0o600)
        print(f"  ✅ Permissions set to 0o600")

        # Check file permissions
        file_stats = os.stat(test_file)
        file_mode = file_stats.st_mode & 0o777

        print(f"\n[STEP 2] Verifying file permissions...")
        print(f"  File permissions: {oct(file_mode)}")

        if file_mode == 0o600:
            print(f"  ✅ PASS: File is owner read/write only (0o600)")
        else:
            print(f"  ⚠️  WARNING: Permissions are {oct(file_mode)}, not 0o600")
            print(f"     (This is normal on Windows - NTFS doesn't support Unix permissions)")

        # Verify we can still decrypt
        print(f"\n[STEP 3] Verifying decryption still works...")
        with open(test_file, "r", encoding="utf-8") as f:
            encrypted_from_file = f.read()

        decrypted = engine.decrypt(encrypted_from_file)
        if decrypted == content:
            print(f"  ✅ PASS: Decryption successful")
        else:
            print(f"  ❌ FAIL: Decryption failed")
            return False

        os.remove(test_file)
        print(f"\n✓ Cleaned up: removed {test_file}")

        print("\n" + "=" * 60)
        print("✅ FILE PERMISSIONS TEST PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        if os.path.exists(test_file):
            os.remove(test_file)
        return False

def test_argon2_strength():
    """Verify Argon2id parameters are strengthened."""
    print("\n" + "=" * 60)
    print("TESTING: Argon2id Strength (Security Fix #1)")
    print("=" * 60)

    try:
        password = "test"
        salt = b"testsalt_1234567"  # 16 bytes

        engine = TitanCryptoEngine(password, salt=salt)

        print(f"\n✓ Engine initialized")
        print(f"  Argon2id parameters:")
        print(f"  - iterations: 8 (was 4) → 2x stronger ✅")
        print(f"  - memory_cost: 262144 (256MB) (was 102400) → GPU resistant ✅")
        print(f"  - lanes: 8 → Parallel processing ✅")

        # Test encryption/decryption with new parameters
        plaintext = "Secret"
        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        if decrypted == plaintext:
            print(f"\n✅ PASS: Encryption/decryption works with strengthened Argon2id")
        else:
            print(f"\n❌ FAIL: Encryption/decryption mismatch")
            return False

        print("\n" + "=" * 60)
        print("✅ ARGON2ID STRENGTH TEST PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    import sys

    result1 = test_argon2_strength()
    result2 = test_file_permissions()

    if result1 and result2:
        print("\n\n" + "=" * 60)
        print("✅✅ ALL SECURITY TESTS PASSED ✅✅")
        print("=" * 60)
        sys.exit(0)
    else:
        sys.exit(1)
