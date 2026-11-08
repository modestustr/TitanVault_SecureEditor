#!/usr/bin/env python3
"""Quick test for engine_crypto with dynamic salt."""

from engine_crypto import TitanCryptoEngine
import sys

def test_dynamic_salt():
    """Test encryption/decryption with dynamic salt."""
    print("=" * 60)
    print("TESTING: Dynamic Salt Encryption")
    print("=" * 60)

    password = "test_password_123"
    plaintext = "This is a secret message that should be encrypted."

    # Initialize with dynamic salt (None)
    engine = TitanCryptoEngine(password, salt=None)

    print(f"\n✓ Password: {password}")
    print(f"✓ Plaintext: {plaintext}")

    # Encrypt twice - should produce DIFFERENT ciphertexts due to unique salt/nonce
    print("\n[TEST 1] Encrypting same plaintext twice (should produce different outputs)...")
    encrypted1 = engine.encrypt(plaintext)
    encrypted2 = engine.encrypt(plaintext)

    print(f"  Encrypted #1 length: {len(encrypted1)} chars")
    print(f"  Encrypted #2 length: {len(encrypted2)} chars")

    if encrypted1 != encrypted2:
        print(f"  ✅ PASS: Different ciphertexts (unique salt/nonce)")
    else:
        print(f"  ❌ FAIL: Same ciphertexts (should be different)")
        return False

    # Decrypt both and verify they match plaintext
    print("\n[TEST 2] Decrypting both ciphertexts...")
    decrypted1 = engine.decrypt(encrypted1)
    decrypted2 = engine.decrypt(encrypted2)

    if decrypted1 == plaintext and decrypted2 == plaintext:
        print(f"  ✅ PASS: Both decrypt to original plaintext")
    else:
        print(f"  ❌ FAIL: Decryption mismatch")
        return False

    # Test wrong password
    print("\n[TEST 3] Testing wrong password...")
    wrong_engine = TitanCryptoEngine("wrong_password", salt=None)
    try:
        wrong_engine.decrypt(encrypted1)
        print(f"  ❌ FAIL: Should have raised error for wrong password")
        return False
    except ValueError as e:
        print(f"  ✅ PASS: Correctly raised error: {e}")

    # Test empty input
    print("\n[TEST 4] Testing empty plaintext...")
    empty_encrypted = engine.encrypt("")
    empty_decrypted = engine.decrypt(empty_encrypted)
    if empty_decrypted == "":
        print(f"  ✅ PASS: Empty string handled correctly")
    else:
        print(f"  ❌ FAIL: Empty string not preserved")
        return False

    # Test special characters
    print("\n[TEST 5] Testing special characters...")
    special = "Türkçe çeviri ✓ [!@#$%^&*()]"
    special_encrypted = engine.encrypt(special)
    special_decrypted = engine.decrypt(special_encrypted)
    if special_decrypted == special:
        print(f"  ✅ PASS: Special characters preserved: {special}")
    else:
        print(f"  ❌ FAIL: Special characters corrupted")
        return False

    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED")
    print("=" * 60)
    return True

if __name__ == "__main__":
    try:
        success = test_dynamic_salt()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
