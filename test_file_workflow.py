#!/usr/bin/env python3
"""Test file encryption/decryption workflow."""

from engine_crypto import TitanCryptoEngine
import os

def test_file_workflow():
    """Test full file encryption/decryption workflow."""
    print("=" * 60)
    print("TESTING: File Encryption/Decryption Workflow")
    print("=" * 60)

    # Test data
    test_content = """Gizli Dosya

Bu dosya önemli bilgiler içeriyor:
- Örnek kullanıcı adı: example
- Örnek parola: placeholder
- Örnek API anahtarı: not-a-real-key

Kimse bunu göremez!"""

    password = "my_secure_password"
    test_file = "test_encrypted.vault"

    try:
        # Initialize engine
        engine = TitanCryptoEngine(password, salt=None)
        print(f"\n✓ Engine initialized with dynamic salt")

        # Encrypt and save
        print(f"\n[STEP 1] Encrypting and saving to file...")
        encrypted_data = engine.encrypt(test_content)
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(encrypted_data)

        file_size = os.path.getsize(test_file)
        print(f"  ✅ File created: {test_file} ({file_size} bytes)")
        print(f"  Original size: {len(test_content)} bytes")
        print(f"  Encrypted size: {file_size} bytes")

        # Read and decrypt
        print(f"\n[STEP 2] Reading and decrypting from file...")
        with open(test_file, "r", encoding="utf-8") as f:
            encrypted_from_file = f.read()

        decrypted_data = engine.decrypt(encrypted_from_file)
        print(f"  ✅ File decrypted successfully")

        # Verify content
        if decrypted_data == test_content:
            print(f"  ✅ Content verified: matches original")
        else:
            print(f"  ❌ Content mismatch!")
            print(f"  Expected: {repr(test_content[:50])}")
            print(f"  Got: {repr(decrypted_data[:50])}")
            return False

        # Test with wrong password
        print(f"\n[STEP 3] Testing wrong password...")
        wrong_engine = TitanCryptoEngine("wrong_password", salt=None)
        try:
            wrong_engine.decrypt(encrypted_from_file)
            print(f"  ❌ Should have failed with wrong password")
            return False
        except ValueError:
            print(f"  ✅ Correctly rejected wrong password")

        # Cleanup
        os.remove(test_file)
        print(f"\n✓ Cleaned up: removed {test_file}")

        print("\n" + "=" * 60)
        print("✅ FILE WORKFLOW TEST PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        # Cleanup on error
        if os.path.exists(test_file):
            os.remove(test_file)
        return False

if __name__ == "__main__":
    import sys
    success = test_file_workflow()
    sys.exit(0 if success else 1)
