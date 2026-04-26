from PyQt6.QtCore import QThread, pyqtSignal
from src.crypto import AtomicCipherV3

class CryptoWorker(QThread):
    finished = pyqtSignal(bool, str, bytes)
    status   = pyqtSignal(str)

    def __init__(self, mode: str, data: bytes | str, password: str, use_hw: bool):
        super().__init__()
        self.mode = mode
        self.data = data
        self.password = password
        self.use_hw = use_hw

    def run(self):
        try:
            if self.mode == 'encrypt':
                self.status.emit("Генерация солей и шифрование...")
                raw = AtomicCipherV3.encrypt(self.data, self.password, self.use_hw)
                self.finished.emit(True, AtomicCipherV3.to_base64(raw), b'')
            else:
                self.status.emit("Проверка подписи и расшифровка...")
                raw = AtomicCipherV3.from_base64(self.data if isinstance(self.data, str) else self.data.decode())
                plaintext = AtomicCipherV3.decrypt(raw, self.password)
                self.finished.emit(True, '', plaintext)
        except PermissionError as e:
            self.finished.emit(False, f"🔒 {e}", b'')
        except Exception as e:
            self.finished.emit(False, str(e), b'')