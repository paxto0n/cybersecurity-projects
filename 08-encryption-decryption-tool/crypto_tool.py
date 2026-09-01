import sys
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
CHUNK_SIZE = 64 * 1024
RSA_KEY_SIZE = 2048

# Fixed-size header fields for the hybrid file format:
# [4 bytes: RSA blob length][RSA-encrypted AES key][IV][AES ciphertext]
RSA_LEN_HEADER_SIZE = 4


def derive_key(password, salt, iterations=PBKDF2_ITERATIONS):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt_text(plaintext, password):
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    blob = salt + iv + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def aes_decrypt_text(encoded_blob, password):
    try:
        blob = base64.b64decode(encoded_blob)
    except Exception:
        raise ValueError("Input is not valid base64 — was it encrypted with this tool?")

    if len(blob) < SALT_SIZE + IV_SIZE:
        raise ValueError("Input is too short to contain valid salt/IV/ciphertext")

    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = blob[SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
    except (ValueError, Exception):
        raise ValueError("Decryption failed — wrong password, or the data is corrupted/tampered with")

    return plaintext.decode("utf-8")


def aes_encrypt_file(input_path, password, output_path=None):
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"No such file: {input_path}")

    if output_path is None:
        output_path = input_path + ".enc"

    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        outfile.write(salt)
        outfile.write(iv)

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            padded_chunk = padder.update(chunk)
            outfile.write(encryptor.update(padded_chunk))

        final_padded = padder.finalize()
        outfile.write(encryptor.update(final_padded) + encryptor.finalize())

    return output_path


def aes_decrypt_file(input_path, password, output_path=None):
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"No such file: {input_path}")

    if output_path is None:
        if input_path.endswith(".enc"):
            output_path = input_path[:-4]
        else:
            output_path = input_path + ".dec"

    with open(input_path, "rb") as infile:
        salt = infile.read(SALT_SIZE)
        iv = infile.read(IV_SIZE)
        ciphertext = infile.read()

    if len(salt) < SALT_SIZE or len(iv) < IV_SIZE:
        raise ValueError("File is too short to contain a valid salt/IV — is this an encrypted file?")

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
    except (ValueError, Exception):
        raise ValueError("Decryption failed — wrong password, or the file is corrupted/tampered with")

    with open(output_path, "wb") as outfile:
        outfile.write(plaintext)

    return output_path


def generate_rsa_keypair(output_dir, key_name="rsa_key"):
    os.makedirs(output_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    private_path = os.path.join(output_dir, f"{key_name}_private.pem")
    public_path = os.path.join(output_dir, f"{key_name}_public.pem")

    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return private_path, public_path


def rsa_encrypt_text(plaintext, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt_text(encoded_ciphertext, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    try:
        ciphertext = base64.b64decode(encoded_ciphertext)
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError("RSA decryption failed — wrong private key, or data is corrupted")


def hybrid_encrypt_file(input_path, public_key_path, output_path=None):
    """
    Hybrid (RSA + AES) file encryption:
    1. Generate a random one-time AES-256 key
    2. Encrypt the file with that AES key (fast, handles any size)
    3. Encrypt the small AES key itself with RSA
    4. Write: [4-byte RSA blob length][RSA-encrypted AES key][IV][AES ciphertext]

    This is the same pattern used by TLS, PGP, and every real-world system
    that combines RSA and AES — RSA alone cannot handle file-sized data.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"No such file: {input_path}")

    if output_path is None:
        output_path = input_path + ".henc"

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    aes_key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        outfile.write(len(encrypted_aes_key).to_bytes(RSA_LEN_HEADER_SIZE, "big"))
        outfile.write(encrypted_aes_key)
        outfile.write(iv)

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            outfile.write(encryptor.update(padder.update(chunk)))

        final_padded = padder.finalize()
        outfile.write(encryptor.update(final_padded) + encryptor.finalize())

    return output_path


def hybrid_decrypt_file(input_path, private_key_path, output_path=None):
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"No such file: {input_path}")

    if output_path is None:
        if input_path.endswith(".henc"):
            output_path = input_path[:-5]
        else:
            output_path = input_path + ".dec"

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(input_path, "rb") as infile:
        rsa_len = int.from_bytes(infile.read(RSA_LEN_HEADER_SIZE), "big")
        encrypted_aes_key = infile.read(rsa_len)
        iv = infile.read(IV_SIZE)
        ciphertext = infile.read()

    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    except Exception:
        raise ValueError("Hybrid decryption failed — wrong private key, or file is corrupted")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
    except (ValueError, Exception):
        raise ValueError("Hybrid decryption failed — AES layer corrupted or tampered with")

    with open(output_path, "wb") as outfile:
        outfile.write(plaintext)

    return output_path


def sha256_file(filepath):
    """Computes SHA-256 hash of a file for integrity verification (not encryption)."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"No such file: {filepath}")

    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage (AES text):")
        print("  python3 crypto_tool.py encrypt <password> <text> [--quiet]")
        print("  python3 crypto_tool.py decrypt <password> <encrypted_blob> [--quiet]")
        print("Usage (AES file):")
        print("  python3 crypto_tool.py encrypt-file <password> <filepath>")
        print("  python3 crypto_tool.py decrypt-file <password> <filepath>")
        print("Usage (RSA text):")
        print("  python3 crypto_tool.py genkeys <output_dir> [key_name]")
        print("  python3 crypto_tool.py rsa-encrypt <public_key_path> <text> [--quiet]")
        print("  python3 crypto_tool.py rsa-decrypt <private_key_path> <encrypted_blob> [--quiet]")
        print("Usage (hybrid RSA+AES file):")
        print("  python3 crypto_tool.py hybrid-encrypt-file <public_key_path> <filepath>")
        print("  python3 crypto_tool.py hybrid-decrypt-file <private_key_path> <filepath>")
        print("Usage (hashing):")
        print("  python3 crypto_tool.py hash-file <filepath>")
        print("  python3 crypto_tool.py hash-text <text>")
        sys.exit(1)

    quiet = "--quiet" in sys.argv
    if quiet:
        sys.argv.remove("--quiet")

    mode = sys.argv[1]

    if mode == "genkeys":
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        key_name = sys.argv[3] if len(sys.argv) > 3 else "rsa_key"
        priv, pub = generate_rsa_keypair(output_dir, key_name)
        print(f"\nPrivate key: {priv}\nPublic key:  {pub}\n")

    elif mode == "rsa-encrypt":
        public_key_path, text = sys.argv[2], sys.argv[3]
        try:
            result = rsa_encrypt_text(text, public_key_path)
            print(result if quiet else f"\nRSA Encrypted (base64):\n{result}\n")
        except ValueError as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "rsa-decrypt":
        private_key_path, blob = sys.argv[2], sys.argv[3]
        try:
            result = rsa_decrypt_text(blob, private_key_path)
            print(result if quiet else f"\nRSA Decrypted:\n{result}\n")
        except ValueError as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "hybrid-encrypt-file":
        public_key_path, filepath = sys.argv[2], sys.argv[3]
        try:
            output = hybrid_encrypt_file(filepath, public_key_path)
            print(f"\nHybrid-encrypted file written to: {output}\n")
        except (FileNotFoundError, ValueError) as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "hybrid-decrypt-file":
        private_key_path, filepath = sys.argv[2], sys.argv[3]
        try:
            output = hybrid_decrypt_file(filepath, private_key_path)
            print(f"\nHybrid-decrypted file written to: {output}\n")
        except (FileNotFoundError, ValueError) as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "hash-file":
        filepath = sys.argv[2]
        try:
            digest = sha256_file(filepath)
            print(digest if quiet else f"\nSHA-256: {digest}\n")
        except FileNotFoundError as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "hash-text":
        text = sys.argv[2]
        digest = sha256_text(text)
        print(digest if quiet else f"\nSHA-256: {digest}\n")

    elif mode == "encrypt":
        password, data = sys.argv[2], sys.argv[3]
        result = aes_encrypt_text(data, password)
        print(result if quiet else f"\nEncrypted (base64):\n{result}\n")

    elif mode == "decrypt":
        password, data = sys.argv[2], sys.argv[3]
        try:
            result = aes_decrypt_text(data, password)
            print(result if quiet else f"\nDecrypted:\n{result}\n")
        except ValueError as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "encrypt-file":
        password, filepath = sys.argv[2], sys.argv[3]
        try:
            output = aes_encrypt_file(filepath, password)
            print(f"\nEncrypted file written to: {output}\n")
        except (FileNotFoundError, ValueError) as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    elif mode == "decrypt-file":
        password, filepath = sys.argv[2], sys.argv[3]
        try:
            output = aes_decrypt_file(filepath, password)
            print(f"\nDecrypted file written to: {output}\n")
        except (FileNotFoundError, ValueError) as e:
            print(f"\nError: {e}\n")
            sys.exit(1)

    else:
        print(f"Unknown mode '{mode}'.")
        sys.exit(1)
