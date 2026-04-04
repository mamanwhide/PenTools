"""
Custom Django model fields — transparent Fernet encryption.

EncryptedCharField stores any string value encrypted in the database.
On read (from_db_value), the stored ciphertext is decrypted transparently.
On write (get_prep_value), the plaintext is encrypted before INSERT/UPDATE.

The underlying DB column type is TEXT (no max-length restriction), so existing
CharField/URLField columns are widened via migration — safe in PostgreSQL.
"""
from django.db import models
from pentools.crypto import fernet_encrypt, fernet_decrypt


class EncryptedCharField(models.TextField):
    """
    A Django TextField that transparently encrypts values with Fernet before
    storing them and decrypts them when loading from the database.

    Drop-in replacement for CharField / URLField for sensitive strings.
    Pre-existing plaintext rows are returned as-is (fernet_decrypt falls back
    gracefully) and are re-encrypted the next time the record is saved.
    """

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        return fernet_decrypt(value)

    def get_prep_value(self, value):
        if not value:
            return value
        return fernet_encrypt(str(value))

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # Store as our custom field path so migrations reference this class
        return name, "pentools.encrypted_fields.EncryptedCharField", args, kwargs
