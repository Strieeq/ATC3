from src.crypto import AtomicCipherV3
from pathlib import Path

password = "1234567890123456"
text = b"Hello World"

print("\n" + "="*60)
print("TEST START")
print("="*60)

print("\n1. Шифруем...")
encrypted = AtomicCipherV3.encrypt(text, password, use_hw_lock=False)
print(f"   Зашифровано: {len(encrypted)} байт")

# Сохраняем
Path("test.atc3").write_bytes(encrypted)

print("\n2. Сохранено в test.atc3")

# Читаем и расшифровываем
print("\n3. Читаем файл...")
raw = Path("test.atc3").read_bytes()
print(f"   Прочитано: {len(raw)} байт")

print("\n4. Расшифровываем...")
decrypted = AtomicCipherV3.decrypt(raw, password)
print(f"   Расшифровано: {decrypted}")

if decrypted == text:
    print("\n✅ УСПЕХ! Крипто-ядро работает корректно")
else:
    print("\n❌ ОШИБКА: данные не совпадают")