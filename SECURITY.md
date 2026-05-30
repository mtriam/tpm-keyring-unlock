# Security

This is a local-only helper for unlocking GNOME Keyring with a TPM2-sealed
secret.

Please do not include keyring passwords, sealed blob contents, private logs, or
machine-specific recovery material in public issues.

This project does not modify LUKS slots, Secure Boot keys, or GNOME Keyring
passwords. It stores only TPM2 sealed state plus a SHA256 integrity checksum.
