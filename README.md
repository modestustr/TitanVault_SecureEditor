# TitanVault Secure Editor

TitanVault is a desktop text editor that encrypts files with AES-GCM. It derives
an encryption key from the master password using Argon2id and generates a
random salt and nonce for each encrypted file.

## Requirements

- Python 3.10 or newer
- The dependencies listed in `requirements.txt`

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run

```powershell
python VaultUI.py
```

The application asks for a master password at startup. Use the same password
to decrypt a file. If the password is lost, the encrypted data cannot be
recovered.

## Encryption format

The current engine stores each file as Base64-encoded data containing a
16-byte random salt, a 12-byte random nonce, and the AES-GCM ciphertext and
authentication tag. The key is derived with Argon2id.

Keep the master password private and make backups of encrypted files. Do not
commit passwords, encryption keys, salts, or encrypted personal data.

## Tests

```powershell
$env:PYTHONIOENCODING = "utf-8"
python test_crypto.py
python test_file_workflow.py
python test_backward_compat.py
python test_security_fixes.py
```
