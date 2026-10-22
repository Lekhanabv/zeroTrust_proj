
from dotenv import load_dotenv

load_dotenv()

from app.crypto_utils import encrypt_text, decrypt_text

original = "Confidential file: Project report"

encrypted = encrypt_text(original)
decrypted = decrypt_text(encrypted)

print("Original:", original)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)

assert encrypted != original
assert decrypted == original

print("SUCCESS: Encryption and decryption work.")
