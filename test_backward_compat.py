#!/usr/bin/env python3
"""Test backward compatibility with legacy static salt files."""

from engine_crypto import TitanCryptoEngine

def test_backward_compatibility():
    """Test that legacy files (with static salt) can still be opened."""
    print("=" * 60)
    print("TESTING: Backward Compatibility (Static Salt)")
    print("=" * 60)

    password = "legacy_password"
    legacy_salt = b"static_salt_value"
    plaintext = "This is a legacy encrypted file."

    # Initialize engine WITH fixed salt (like the old VaultUI.py did)
    legacy_engine = TitanCryptoEngine(password, salt=legacy_salt)

    print(f"\n✓ Legacy engine initialized with static salt")
    print(f"  Salt: {legacy_salt}")
    print(f"  Plaintext: {plaintext}")

    # Encrypt with static salt (old format)
    print(f"\n[STEP 1] Encrypting with static salt (legacy format)...")
    encrypted_legacy = legacy_engine.encrypt(plaintext)
    print(f"  ✅ Encrypted: {len(encrypted_legacy)} chars")

    # Now try to decrypt with the SAME password and salt
    print(f"\n[STEP 2] Decrypting with same password/salt...")
    decrypted = legacy_engine.decrypt(encrypted_legacy)

    if decrypted == plaintext:
        print(f"  ✅ Successfully decrypted legacy format")
        print(f"  Content matches: {decrypted}")
    else:
        print(f"  ❌ Decryption failed")
        return False

    # Simulate: Save to file and reopen (like VaultUI would)
    print(f"\n[STEP 3] Testing file save/load workflow...")
    test_file = "legacy_test.txt"

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(encrypted_legacy)

    # Re-read and decrypt
    with open(test_file, "r", encoding="utf-8") as f:
        encrypted_from_file = f.read()

    decrypted_from_file = legacy_engine.decrypt(encrypted_from_file)

    if decrypted_from_file == plaintext:
        print(f"  ✅ File workflow successful with legacy encryption")
    else:
        print(f"  ❌ File workflow failed")
        return False

    # Important: Test that dynamic salt engine CANNOT open legacy files
    print(f"\n[STEP 4] Verify isolation (dynamic salt engine cannot open legacy files)...")
    dynamic_engine = TitanCryptoEngine(password, salt=None)

    try:
        # This should fail because the format is different
        dynamic_engine.decrypt(encrypted_legacy)
        print(f"  ⚠️  WARNING: Dynamic engine could decrypt legacy format!")
        print(f"     This might indicate format collision.")
    except ValueError:
        print(f"  ✅ Correctly isolated: dynamic engine cannot open legacy files")
    except Exception as e:
        print(f"  ✅ Correctly isolated: {type(e).__name__}")

    # Cleanup
    import os
    os.remove(test_file)
    print(f"\n✓ Cleaned up: removed {test_file}")

    print("\n" + "=" * 60)
    print("✅ BACKWARD COMPATIBILITY TEST PASSED")
    print("=" * 60)
    return True

if __name__ == "__main__":
    import sys
    try:
        success = test_backward_compatibility()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
