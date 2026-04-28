import os, sys, hashlib, hmac, platform, subprocess
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type

try:
    from Crypto.Cipher import ChaCha20_Poly1305

    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

FORMAT_VERSION = b'\x03'
MAGIC = b'ATC3'

DEBUG = True


def debug_print(*args):
    if DEBUG:
        print("[DEBUG]", *args)


class HardwareFingerprint:
    @staticmethod
    def _wmi_query(query: str) -> str:
        try:
            out = subprocess.check_output(["wmic"] + query.split(), stderr=subprocess.DEVNULL, timeout=3).decode(
                errors="replace").strip()
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            return lines[-1] if lines else ""
        except Exception:
            return ""

    @staticmethod
    def collect() -> bytes:
        parts = []
        if platform.system() == "Windows":
            parts.append(HardwareFingerprint._wmi_query("cpu get ProcessorId"))
            parts.append(HardwareFingerprint._wmi_query("baseboard get SerialNumber"))
            parts.append(HardwareFingerprint._wmi_query("bios get SerialNumber"))
            parts.append(HardwareFingerprint._wmi_query("diskdrive get SerialNumber"))
            try:
                import uuid as _uuid
                parts.append(hex(_uuid.getnode())[2:])
            except:
                pass
        elif platform.system() == "Linux":
            try:
                parts.append(Path("/etc/machine-id").read_text().strip())
            except:
                pass
            try:
                out = subprocess.check_output("ip link show | grep ether | head -1 | awk '{print $2}'", shell=True,
                                              timeout=2).decode().strip()
                parts.append(out)
            except:
                pass
        else:
            parts.append(platform.node())
            parts.append(platform.processor())

        raw = "|".join(p for p in parts if p).encode()
        return raw if raw else b"atomic_fallback_no_hw"

    @staticmethod
    def derive(salt: bytes) -> bytes:
        raw = HardwareFingerprint.collect()
        return hash_secret_raw(raw, salt, time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)


class AtomicCipherV3:
    KDF_SALT_LEN, HW_SALT_LEN, NONCE_LEN, TAG_LEN, HMAC_LEN = 32, 16, 12, 16, 64
    MIN_KEY_LEN = 16
    FLAG_LOCKED, FLAG_ARGON2, FLAG_CHACHA = 0x01, 0x02, 0x04

    @staticmethod
    def _derive_key(password: str, kdf_salt: bytes, hw_fingerprint: bytes | None) -> bytes:
        pwd_bytes = password.encode('utf-8')
        master = hash_secret_raw(pwd_bytes, kdf_salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
                                 type=Type.ID)
        combined = master + (hw_fingerprint or b"")
        result = hashlib.blake2b(combined, digest_size=32).digest()
        return result

    @staticmethod
    def encrypt(data: bytes, password: str, use_hw_lock: bool = True) -> bytes:
        if len(password) < AtomicCipherV3.MIN_KEY_LEN:
            _ = hash_secret_raw(b"dummy", os.urandom(32), time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
                                type=Type.ID)
            raise ValueError(f"Ключ минимум {AtomicCipherV3.MIN_KEY_LEN} символов")

        kdf_salt = os.urandom(AtomicCipherV3.KDF_SALT_LEN)
        hw_salt = os.urandom(AtomicCipherV3.HW_SALT_LEN)
        nonce = os.urandom(AtomicCipherV3.NONCE_LEN)

        flags = AtomicCipherV3.FLAG_CHACHA | AtomicCipherV3.FLAG_ARGON2
        hw_fingerprint = None
        if use_hw_lock:
            flags |= AtomicCipherV3.FLAG_LOCKED
            hw_fingerprint = HardwareFingerprint.derive(hw_salt)

        key = AtomicCipherV3._derive_key(password, kdf_salt, hw_fingerprint)
        aad = MAGIC + FORMAT_VERSION + bytes([flags]) + kdf_salt + hw_salt + nonce

        debug_print(f"ENCRYPT - AAD length: {len(aad)}")
        debug_print(f"ENCRYPT - AAD hex: {aad.hex()}")

        if CRYPTO_OK:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(data)
        else:
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(data)

        packet = aad + ciphertext + tag
        debug_print(f"ENCRYPT - Packet (aad+ciphertext+tag) length: {len(packet)}")
        debug_print(f"ENCRYPT - Packet hex (first 100): {packet[:100].hex()}")

        mac = hmac.new(key, packet, hashlib.blake2b).digest()
        debug_print(f"ENCRYPT - MAC length: {len(mac)}")
        debug_print(f"ENCRYPT - MAC hex: {mac.hex()}")

        result = packet + mac
        debug_print(f"ENCRYPT - Total result length: {len(result)}")

        return result

    @staticmethod
    def decrypt(data: bytes, password: str) -> bytes:
        if len(password) < AtomicCipherV3.MIN_KEY_LEN:
            _ = hash_secret_raw(b"dummy", os.urandom(32), time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
                                type=Type.ID)
            raise ValueError(f"Ключ минимум {AtomicCipherV3.MIN_KEY_LEN} символов")

        debug_print(f"\nDECRYPT - Input data length: {len(data)}")
        debug_print(f"DECRYPT - Input data hex (first 100): {data[:100].hex()}")

        header_len = 4 + 1 + 1 + AtomicCipherV3.KDF_SALT_LEN + AtomicCipherV3.HW_SALT_LEN + AtomicCipherV3.NONCE_LEN
        min_len = header_len + AtomicCipherV3.TAG_LEN + AtomicCipherV3.HMAC_LEN

        debug_print(f"DECRYPT - Header length: {header_len}")
        debug_print(f"DECRYPT - Min total length: {min_len}")

        if len(data) < min_len:
            raise ValueError("Данные повреждены или слишком короткие")

        # Парсим заголовок
        off = 0
        magic = data[off:off + 4]
        off += 4
        debug_print(f"DECRYPT - Magic: {magic}")
        if magic != MAGIC:
            raise ValueError("Неверный формат — не ATC3")

        version = data[off]
        off += 1
        debug_print(f"DECRYPT - Version: {version}")
        if version != FORMAT_VERSION[0]:
            raise ValueError(f"Неподдерживаемая версия: {version}")

        flags = data[off]
        off += 1
        debug_print(f"DECRYPT - Flags: {hex(flags)}")

        kdf_salt = data[off:off + AtomicCipherV3.KDF_SALT_LEN]
        off += AtomicCipherV3.KDF_SALT_LEN
        debug_print(f"DECRYPT - kdf_salt hex: {kdf_salt.hex()}")

        hw_salt = data[off:off + AtomicCipherV3.HW_SALT_LEN]
        off += AtomicCipherV3.HW_SALT_LEN
        debug_print(f"DECRYPT - hw_salt hex: {hw_salt.hex()}")

        nonce = data[off:off + AtomicCipherV3.NONCE_LEN]
        off += AtomicCipherV3.NONCE_LEN
        debug_print(f"DECRYPT - nonce hex: {nonce.hex()}")

        # AAD = весь заголовок
        aad = data[:off]
        debug_print(f"DECRYPT - AAD length: {len(aad)}")
        debug_print(f"DECRYPT - AAD hex: {aad.hex()}")

        # Теперь data[off:] содержит ciphertext + tag + mac
        # Находим mac (последние HMAC_LEN байт)
        mac_received = data[-AtomicCipherV3.HMAC_LEN:]
        debug_print(f"DECRYPT - Received MAC hex: {mac_received.hex()}")

        # Перед mac находится tag (TAG_LEN байт)
        tag_start = len(data) - AtomicCipherV3.HMAC_LEN - AtomicCipherV3.TAG_LEN
        tag_end = len(data) - AtomicCipherV3.HMAC_LEN
        tag = data[tag_start:tag_end]
        debug_print(f"DECRYPT - Tag hex: {tag.hex()}")

        # Всё между off и tag_start — это ciphertext
        ciphertext = data[off:tag_start]
        debug_print(f"DECRYPT - Ciphertext length: {len(ciphertext)}")
        debug_print(f"DECRYPT - Ciphertext hex: {ciphertext.hex()}")

        # Проверяем, что размеры соответствуют
        expected_size = off + len(ciphertext) + AtomicCipherV3.TAG_LEN + AtomicCipherV3.HMAC_LEN
        debug_print(f"DECRYPT - Expected total size: {expected_size}, Actual: {len(data)}")

        # Вычисляем HW fingerprint если нужно
        hw_fingerprint = None
        if flags & AtomicCipherV3.FLAG_LOCKED:
            hw_fingerprint = HardwareFingerprint.derive(hw_salt)
            debug_print(f"DECRYPT - HW fingerprint computed")

        key = AtomicCipherV3._derive_key(password, kdf_salt, hw_fingerprint)
        debug_print(f"DECRYPT - Derived key hex: {key.hex()}")

        # Проверяем HMAC
        packet = data[:-AtomicCipherV3.HMAC_LEN]
        debug_print(f"DECRYPT - Packet for HMAC length: {len(packet)}")
        debug_print(f"DECRYPT - Packet for HMAC hex (first 100): {packet[:100].hex()}")

        mac_expected = hmac.new(key, packet, hashlib.blake2b).digest()
        debug_print(f"DECRYPT - Expected MAC hex: {mac_expected.hex()}")

        if not hmac.compare_digest(mac_received, mac_expected):
            debug_print("DECRYPT - HMAC MISMATCH!")
            debug_print(f"  Received: {mac_received.hex()}")
            debug_print(f"  Expected: {mac_expected.hex()}")
            raise ValueError("Неверный ключ или данные повреждены (и HW lock если был)")

        debug_print("DECRYPT - HMAC verified successfully!")

        # Расшифровка
        if CRYPTO_OK and (flags & AtomicCipherV3.FLAG_CHACHA):
            debug_print("DECRYPT - Using ChaCha20-Poly1305")
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            debug_print("DECRYPT - Using AES-GCM")
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        debug_print(f"DECRYPT - Success! Plaintext: {plaintext}")
        return plaintext

    @staticmethod
    def to_base64(data: bytes) -> str:
        import base64
        return base64.b64encode(data).decode()

    @staticmethod
    def from_base64(s: str) -> bytes:
        import base64
        return base64.b64decode(s.strip())