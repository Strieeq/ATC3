from PyQt6.QtCore import QThread, pyqtSignal
from src.crypto import AtomicCipherV3


class CryptoWorker(QThread):
    finished = pyqtSignal(bool, str, bytes)
    status = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, mode: str, data: bytes | str, password: str, use_hw: bool, file_path: str = None):
        super().__init__()
        self.mode = mode
        self.data = data
        self.password = password
        self.use_hw = use_hw
        self.file_path = file_path

    def run(self):
        try:
            if self.mode == 'encrypt':
                self.status.emit("Шифрование...")
                if isinstance(self.data, str):
                    self.data = self.data.encode('utf-8')
                raw = AtomicCipherV3.encrypt(self.data, self.password, self.use_hw)
                self.finished.emit(True, AtomicCipherV3.to_base64(raw), b'')

            elif self.mode == 'decrypt':
                self.status.emit("Расшифровка Base64...")
                raw = AtomicCipherV3.from_base64(self.data if isinstance(self.data, str) else self.data.decode())
                plaintext = AtomicCipherV3.decrypt(raw, self.password)
                self.finished.emit(True, '', plaintext)

            elif self.mode == 'decrypt_raw':
                self.status.emit("Расшифровка ATC3 файла...")
                plaintext = AtomicCipherV3.decrypt(self.data, self.password)
                self.finished.emit(True, '', plaintext)

        except Exception as e:
            self.finished.emit(False, str(e), b'')