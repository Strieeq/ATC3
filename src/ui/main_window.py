#!/usr/bin/env python3
"""
Atomic TriFlow Cipher v3.0 — Главное окно (UI)
Исправленная версия с правильной работой с .atc3 файлами
"""
import sys
import secrets
import string
import hashlib
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QLineEdit, QFileDialog,
    QMessageBox, QTabWidget, QGroupBox, QCheckBox, QProgressBar,
    QStatusBar, QApplication
)
from PyQt6.QtCore import Qt, QTimer

from src.ui.styles import STYLE, make_sep, make_label, C_LILAC, C_ORANGE, C_TEXT2, C_TEXT3, C_GREEN, C_RED, C_BG2, \
    C_BG3, C_BORDER
from src.worker import CryptoWorker
from src.crypto import AtomicCipherV3, HardwareFingerprint

# Проверка наличия библиотек
try:
    from argon2.low_level import hash_secret_raw, Type

    ARGON2_OK = True
except ImportError:
    ARGON2_OK = False

try:
    from Crypto.Cipher import ChaCha20_Poly1305

    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Atomic TriFlow Cipher v3.1")
        self.setMinimumSize(820, 680)
        self.setStyleSheet(STYLE)
        self._selected_atc3_file = None  # Храним путь к выбранному .atc3 файлу
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 8)
        root.setSpacing(16)

        # Header
        hdr = QHBoxLayout()
        lock_lbl = make_label("", size=2)
        hdr.addWidget(lock_lbl)
        title = make_label("ATC", C_LILAC, 20, bold=True)
        hdr.addWidget(title)
        ver = make_label("v3.1", C_ORANGE, 13)
        hdr.addWidget(ver)
        hdr.addStretch()

        # Badges
        for lib, ok, label in [
            (ARGON2_OK, True, "Argon2id ✓"),
            (CRYPTO_OK, True, "ChaCha20 ✓"),
            (not ARGON2_OK, False, "Argon2 ✗"),
            (not CRYPTO_OK, False, "ChaCha ✗"),
        ]:
            if lib:
                badge = make_label(label, C_GREEN if ok else C_RED, 10)
                badge.setStyleSheet(
                    f"background: {'rgba(90,158,111,0.12)' if ok else 'rgba(192,65,58,0.12)'};"
                    f"border: 1px solid {'rgba(90,158,111,0.4)' if ok else 'rgba(192,65,58,0.4)'};"
                    f"border-radius: 5px; padding: 2px 8px; color: {'#5A9E6F' if ok else '#C0413A'};"
                    f"font-size: 10px;"
                )
                hdr.addWidget(badge)

        root.addLayout(hdr)
        root.addWidget(make_sep())

        # Tabs
        tabs = QTabWidget()
        root.addWidget(tabs)
        tabs.addTab(self._tab_encrypt(), "🔒  Шифрование")
        tabs.addTab(self._tab_decrypt(), "🔓  Дешифрование")
        tabs.addTab(self._tab_keygen(), "🎲  Ключи")
        tabs.addTab(self._tab_info(), "ℹ️  О шифре")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setFixedWidth(120)
        self.status_bar.addPermanentWidget(self.progress)
        self.status_bar.showMessage("Готов к работе")

    # ── Encrypt tab ───────────────────────────────────────────────────────────────
    def _tab_encrypt(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        grp_in = QGroupBox("ОТКРЫТЫЙ ТЕКСТ / ДАННЫЕ")
        gl = QVBoxLayout(grp_in)
        self.enc_text = QTextEdit()
        self.enc_text.setPlaceholderText("Введи текст для шифрования...")
        self.enc_text.setMinimumHeight(100)
        gl.addWidget(self.enc_text)
        fr = QHBoxLayout()
        self.enc_file = QLineEdit()
        self.enc_file.setPlaceholderText("Или выбери файл...")
        fr.addWidget(self.enc_file)
        b = QPushButton("📂 Обзор")
        b.setObjectName("btn_secondary")
        b.setFixedWidth(100)
        b.clicked.connect(lambda: self._browse_file(self.enc_file, self.enc_text))
        fr.addWidget(b)
        gl.addLayout(fr)
        l.addWidget(grp_in)

        grp_key = QGroupBox("КЛЮЧ ШИФРОВАНИЯ (мин. 16 символов)")
        kl = QVBoxLayout(grp_key)
        kr = QHBoxLayout()
        self.enc_key = QLineEdit()
        self.enc_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_key.setPlaceholderText("Введи ключ...")
        self._enc_key_len = make_label("0 симв.", C_TEXT3, 11)
        self.enc_key.textChanged.connect(
            lambda t: self._enc_key_len.setText(
                f"{len(t)} симв." + (" ✓" if len(t) >= 16 else " ✗ мало")
            )
        )
        kr.addWidget(self.enc_key)
        kr.addWidget(self._enc_key_len)

        show_btn = QPushButton("👁")
        show_btn.setObjectName("btn_secondary")
        show_btn.setFixedWidth(40)
        show_btn.setCheckable(True)
        show_btn.toggled.connect(lambda c: self.enc_key.setEchoMode(
            QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        kr.addWidget(show_btn)
        kl.addLayout(kr)

        self.enc_hw = QCheckBox("Привязать к этому железу (LOCKED — только этот компьютер)")
        self.enc_hw.setChecked(True)
        kl.addWidget(self.enc_hw)
        l.addWidget(grp_key)

        br = QHBoxLayout()
        enc_btn = QPushButton("🔒  Зашифровать")
        enc_btn.clicked.connect(self._do_encrypt)
        br.addWidget(enc_btn)
        cp_btn = QPushButton("📋 Копировать")
        cp_btn.setObjectName("btn_secondary")
        cp_btn.clicked.connect(lambda: self._copy(self.enc_result))
        br.addWidget(cp_btn)
        sv_btn = QPushButton("💾 Сохранить")
        sv_btn.setObjectName("btn_secondary")
        sv_btn.clicked.connect(lambda: self._save_encrypted_result())
        br.addWidget(sv_btn)
        l.addLayout(br)

        grp_res = QGroupBox("РЕЗУЛЬТАТ (BASE64)")
        rl = QVBoxLayout(grp_res)
        self.enc_result = QTextEdit()
        self.enc_result.setReadOnly(True)
        self.enc_result.setMinimumHeight(80)
        self.enc_result.setPlaceholderText("Здесь появится зашифрованный текст...")
        rl.addWidget(self.enc_result)
        l.addWidget(grp_res)
        return w

    # ── Decrypt tab ───────────────────────────────────────────────────────────────
    def _tab_decrypt(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        grp_in = QGroupBox("ЗАШИФРОВАННЫЕ ДАННЫЕ")
        gl = QVBoxLayout(grp_in)

        # Кнопка для выбора .atc3 файла
        file_layout = QHBoxLayout()
        self.dec_file_path = QLineEdit()
        self.dec_file_path.setPlaceholderText("Выбери .atc3 файл...")
        self.dec_file_path.setReadOnly(True)
        file_layout.addWidget(self.dec_file_path)

        browse_btn = QPushButton("📂 Выбрать .atc3 файл")
        browse_btn.setObjectName("btn_secondary")
        browse_btn.clicked.connect(self._select_atc3_file)
        file_layout.addWidget(browse_btn)
        gl.addLayout(file_layout)

        # Разделитель
        sep_label = make_label("—— ИЛИ вставь Base64 текст ниже ——", C_TEXT3, 11)
        sep_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gl.addWidget(sep_label)

        self.dec_data = QTextEdit()
        self.dec_data.setPlaceholderText("Или вставь зашифрованный блок в формате Base64...")
        self.dec_data.setMinimumHeight(100)
        gl.addWidget(self.dec_data)

        l.addWidget(grp_in)

        grp_key = QGroupBox("КЛЮЧ ДЕШИФРОВАНИЯ")
        kl = QVBoxLayout(grp_key)
        kr = QHBoxLayout()
        self.dec_key = QLineEdit()
        self.dec_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.dec_key.setPlaceholderText("Введи ключ...")
        kr.addWidget(self.dec_key)
        show_btn2 = QPushButton("👁")
        show_btn2.setObjectName("btn_secondary")
        show_btn2.setFixedWidth(40)
        show_btn2.setCheckable(True)
        show_btn2.toggled.connect(lambda c: self.dec_key.setEchoMode(
            QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        kr.addWidget(show_btn2)
        kl.addLayout(kr)
        l.addWidget(grp_key)

        br = QHBoxLayout()
        dec_btn = QPushButton("🔓  Расшифровать")
        dec_btn.clicked.connect(self._do_decrypt)
        br.addWidget(dec_btn)
        cp_btn = QPushButton("📋 Копировать")
        cp_btn.setObjectName("btn_secondary")
        cp_btn.clicked.connect(lambda: self._copy(self.dec_result))
        br.addWidget(cp_btn)
        sv_btn = QPushButton("💾 Сохранить результат")
        sv_btn.setObjectName("btn_secondary")
        sv_btn.clicked.connect(lambda: self._save_decrypted_result())
        br.addWidget(sv_btn)
        l.addLayout(br)

        grp_res = QGroupBox("РЕЗУЛЬТАТ")
        rl = QVBoxLayout(grp_res)
        self.dec_result = QTextEdit()
        self.dec_result.setReadOnly(True)
        self.dec_result.setMinimumHeight(120)
        self.dec_result.setPlaceholderText("Здесь появится расшифрованный текст...")
        rl.addWidget(self.dec_result)
        l.addWidget(grp_res)
        return w

    # ── Keygen tab ────────────────────────────────────────────────────────────────
    def _tab_keygen(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(12)

        grp = QGroupBox("ГЕНЕРАТОР КЛЮЧЕЙ")
        gl = QVBoxLayout(grp)
        for label, length in [("Стандартный (32 символа)", 32),
                              ("Длинный (64 символа)", 64),
                              ("Максимальный (128 символов)", 128)]:
            btn = QPushButton(f"🎲 {label}")
            btn.clicked.connect(lambda _, n=length: self._gen_key(n))
            gl.addWidget(btn)

        self.key_out = QTextEdit()
        self.key_out.setReadOnly(True)
        self.key_out.setMaximumHeight(80)
        self.key_out.setPlaceholderText("Сгенерированный ключ появится здесь...")
        gl.addWidget(self.key_out)

        cp = QPushButton("📋 Копировать ключ")
        cp.setObjectName("btn_secondary")
        cp.clicked.connect(lambda: self._copy(self.key_out))
        gl.addWidget(cp)
        l.addWidget(grp)

        grp_hw = QGroupBox("ОТПЕЧАТОК ЖЕЛЕЗА (текущий компьютер)")
        hl = QVBoxLayout(grp_hw)
        try:
            hw_raw = HardwareFingerprint.collect()
            hw_hash = hashlib.blake2b(hw_raw, digest_size=16).hexdigest()
            hw_text = f"<code style='color:{C_LILAC}; font-size:14px; letter-spacing:2px'>{hw_hash}</code>"
        except:
            hw_text = "<i>Не удалось получить</i>"
        hw_lbl = QLabel(hw_text)
        hw_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hw_lbl.setTextFormat(Qt.TextFormat.RichText)
        hl.addWidget(hw_lbl)

        note = make_label("Файлы в режиме LOCKED расшифровываются только на этом компьютере", C_TEXT3, 11)
        note.setWordWrap(True)
        hl.addWidget(note)
        l.addWidget(grp_hw)
        l.addStretch()
        return w

    # ── Info tab ──────────────────────────────────────────────────────────────────
    def _tab_info(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        info = QTextEdit()
        info.setReadOnly(True)
        info.setStyleSheet(f"background: {C_BG2}; border: 1px solid {C_BORDER}; border-radius: 10px; padding: 16px;")
        info.setHtml(f"""
        <h2 style='color:{C_LILAC}'>Atomic TriFlow Cipher v3.0</h2>
        <h3 style='color:{C_ORANGE}'>Криптографическая схема</h3>
        <p><b>1. Argon2id KDF</b> — вывод ключа из пароля.<br>
        Устойчив к GPU/ASIC/side-channel атакам. time=3, mem=64MB, threads=4.<br>
        Случайная 32-байтная соль на каждое шифрование.</p>
        <p><b>2. ChaCha20-Poly1305 (AEAD)</b> — шифрование + аутентификация одновременно.<br>
        256-битный ключ, 96-битный nonce (случайный + счетчик). Poly1305 тег = 128 бит.<br>
        Нельзя расшифровать без верного ключа — тег не совпадёт.</p>
        <p><b>3. Hardware Lock</b> — опциональная привязка к железу.<br>
        WMI: CPU ProcessorId + серийник материнки + BIOS + MAC адрес.<br>
        Отпечаток прогоняется через Argon2id со своей солью.</p>
        <p><b>4. HMAC-BLAKE2b</b> — финальная подпись всего пакета.<br>
        32 байта. Проверяется до расшифровки — защита от oracle атак.</p>
        <h3 style='color:{C_ORANGE}'>Формат пакета</h3>
        <pre style='background:{C_BG3}; padding:8px; border-radius:6px; font-size:11px'>
        ATC3 | ver | flags | kdf_salt(32) | hw_salt(16) | nonce(12)
        | ciphertext | poly1305_tag(16) | hmac_blake2b(32)
        </pre>
        <h3 style='color:{C_ORANGE}'>Сравнение с Telegram MTProto</h3>
        <table style='border-collapse:collapse; width:100%'>
        <tr style='background:{C_BG3}'>
            <td style='padding:6px'><b>Компонент</b></td>
            <td style='padding:6px'><b>Telegram MTProto</b></td>
            <td style='padding:6px'><b>ATC v3</b></td>
        </tr>
        <tr><td style='padding:6px'>Шифр</td><td>AES-256-IGE</td><td>ChaCha20-Poly1305 ✓</td></tr>
        <tr style='background:{C_BG3}'><td style='padding:6px'>KDF</td><td>SHA-256 (быстрый)</td><td>Argon2id (GPU-resistant) ✓</td></tr>
        <tr><td style='padding:6px'>Аутентификация</td><td>SHA-256 MAC</td><td>Poly1305 + HMAC-BLAKE2b ✓</td></tr>
        <tr style='background:{C_BG3}'><td style='padding:6px'>Hardware lock</td><td>Нет</td><td>Есть ✓</td></tr>
        <tr><td style='padding:6px'>Forward secrecy</td><td>Да (DH)</td><td>Нет (симметричный) —</td></tr>
        </table>
        <h3 style='color:{C_ORANGE}'>Безопасность в v3.1</h3>
        <p>✓ Защита от timing attacks<br>
        ✓ Nonce с глобальным счетчиком (нет коллизий)<br>
        ✓ Затирание ключей в памяти<br>
        ✓ Очистка буфера обмена через 30 секунд<br>
        ✓ Единые сообщения об ошибках (без утечек)</p>
        """)
        l.addWidget(info)
        return w

    # ── Actions ───────────────────────────────────────────────────────────────────

    def _select_atc3_file(self):
        """Выбор .atc3 файла для расшифровки"""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выбери зашифрованный файл",
            "",
            "ATC3 файлы (*.atc3);;Все файлы (*)"
        )
        if path:
            self._selected_atc3_file = path
            self.dec_file_path.setText(path)
            self.dec_data.clear()

            # Показываем информацию о файле
            file_size = Path(path).stat().st_size
            self.status_bar.showMessage(f"Выбран файл: {Path(path).name} ({file_size} байт)")

            # Проверяем сигнатуру файла
            raw = Path(path).read_bytes()
            if raw[:4] == b'ATC3':
                self.status_bar.showMessage(f"✓ Файл ATC3 версии {raw[4]}", 3000)
            else:
                self.status_bar.showMessage("⚠ Файл не похож на ATC3 (нет сигнатуры)", 3000)

    def _browse_file(self, path_edit, text_edit):
        """Выбор файла для шифрования"""
        path, _ = QFileDialog.getOpenFileName(self, "Открыть файл")
        if path:
            path_edit.setText(path)
            try:
                content = Path(path).read_text(encoding='utf-8', errors='replace')
                text_edit.setPlainText(content)
            except Exception as e:
                text_edit.setPlainText(f"(Ошибка чтения: {e})")

    def _do_encrypt(self):
        text = self.enc_text.toPlainText()
        key = self.enc_key.text()
        file_path = self.enc_file.text()

        if not text and not file_path:
            QMessageBox.warning(self, "Ошибка", "Введи текст или выбери файл")
            return
        if len(key) < 16:
            QMessageBox.warning(self, "Ошибка", "Ключ минимум 16 символов")
            return

        if file_path and Path(file_path).exists():
            data = Path(file_path).read_bytes()
            self._last_encrypt_file = file_path
        else:
            data = text.encode('utf-8')
            self._last_encrypt_file = None

        # Запускаем шифрование
        self._run_worker(
            CryptoWorker('encrypt', data, key, self.enc_hw.isChecked(), None),
            self._on_encrypt_done
        )

    def _do_decrypt(self):
        key = self.dec_key.text()

        if len(key) < 16:
            QMessageBox.warning(self, "Ошибка", "Ключ минимум 16 символов")
            return

        # Приоритет: сначала .atc3 файл
        if self._selected_atc3_file and Path(self._selected_atc3_file).exists():
            # Читаем бинарный .atc3 файл
            raw_data = Path(self._selected_atc3_file).read_bytes()

            # Отладка: показываем первые байты
            hex_preview = raw_data[:20].hex()
            self.status_bar.showMessage(f"Файл: {len(raw_data)} байт, сигнатура: {hex_preview[:20]}...")

            # Запускаем расшифровку напрямую с бинарными данными
            self._run_worker(
                CryptoWorker('decrypt_raw', raw_data, key, False, self._selected_atc3_file),
                self._on_decrypt_done
            )
        else:
            # Пробуем расшифровать как Base64
            b64_text = self.dec_data.toPlainText().strip()
            if not b64_text:
                QMessageBox.warning(self, "Ошибка", "Выбери .atc3 файл или вставь Base64 текст")
                return

            self.status_bar.showMessage("Расшифровка Base64...")
            self._run_worker(
                CryptoWorker('decrypt', b64_text, key, False, None),
                self._on_decrypt_done)

    def _run_worker(self, worker, callback):
        self.progress.setVisible(True)
        worker.finished.connect(callback)
        worker.status.connect(lambda s: self.status_bar.showMessage(s))
        worker.finished.connect(lambda: self.progress.setVisible(False))
        worker.start()
        self._worker = worker

    def _on_encrypt_done(self, ok, result, _):
        if ok:
            # result здесь - это Base64 строка
            self.enc_result.setPlainText(result)
            self.status_bar.showMessage(f"Зашифровано ✓ ({len(result)} символов base64)")

            # Сразу предлагаем сохранить в .atc3
            default_name = "encrypted.atc3"
            if hasattr(self, '_last_encrypt_file') and self._last_encrypt_file:
                default_name = Path(self._last_encrypt_file).stem + ".atc3"

            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить зашифрованный файл",
                default_name,
                "ATC3 файлы (*.atc3)"
            )

            if save_path:
                try:
                    # Конвертируем Base64 в бинарный ATC3 и сохраняем
                    raw_bytes = AtomicCipherV3.from_base64(result)
                    Path(save_path).write_bytes(raw_bytes)
                    self.status_bar.showMessage(f"✓ Сохранено: {save_path}")

                    # Показываем информацию о файле
                    file_size = len(raw_bytes)
                    self.status_bar.showMessage(f"✓ Сохранено: {save_path} ({file_size} байт)", 5000)
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка сохранения", f"Не удалось сохранить файл:\n{e}")

            self._last_encrypt_file = None
        else:
            QMessageBox.critical(self, "Ошибка шифрования", result)
            self.status_bar.showMessage("Ошибка")

    def _on_decrypt_done(self, ok, err, data):
        if ok:
            # Успешная расшифровка
            try:
                # Пробуем декодировать как текст
                text = data.decode('utf-8')
                self.dec_result.setPlainText(text)
                self.status_bar.showMessage(f"✓ Расшифровано успешно! ({len(data)} байт)")
            except UnicodeDecodeError:
                # Бинарные данные
                self.dec_result.setPlainText(
                    f"[Бинарные данные - {len(data)} байт]\n\n"
                    f"Hex (первые 64 байта):\n{data[:64].hex()}\n\n"
                    f"MD5: {hashlib.md5(data).hexdigest()}"
                )
                self.status_bar.showMessage(f"✓ Расшифровано (бинарные данные, {len(data)} байт)")
        else:
            # Ошибка расшифровки
            error_msg = str(err)
            self.status_bar.showMessage("Ошибка расшифровки")

            # Детальная диагностика
            diagnostic = f"""Ошибка расшифровки: {error_msg}

            Возможные причины:
            1. Неправильный ключ шифрования
            2. Файл был зашифрован с привязкой к железу (HW Lock) на другом компьютере
            3. Файл поврежден
            4. Не тот файл (не ATC3 формат)

            Решение:
            - Проверь правильность ключа (чувствителен к регистру!)
            - Если файл с HW Lock - расшифровывай только на том же компьютере
            - Попробуй зашифровать тестовый текст и сразу расшифровать - для проверки
            """

            QMessageBox.critical(self, "Ошибка дешифрования", diagnostic)

    def _save_encrypted_result(self):
        """Сохранение зашифрованного результата в .atc3"""
        text = self.enc_result.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Сохранить зашифрованный файл", "encrypted.atc3",
                                              "ATC3 файлы (*.atc3)")
        if path:
            try:
                # Конвертируем Base64 в бинарный ATC3
                raw = AtomicCipherV3.from_base64(text)
                Path(path).write_bytes(raw)
                self.status_bar.showMessage(f"Сохранено: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")

    def _save_decrypted_result(self):
        """Сохранение расшифрованного результата"""
        text = self.dec_result.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Сохранить результат", "decrypted.txt",
                                              "Текстовые файлы (*.txt);;Все файлы (*)")
        if path:
            try:
                Path(path).write_text(text, encoding='utf-8')
                self.status_bar.showMessage(f"Сохранено: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")

    def _gen_key(self, length):
        chars = string.ascii_letters + string.digits + "!@#$%^&*-_=+[]{}|"
        key = ''.join(secrets.choice(chars) for _ in range(length))
        self.key_out.setPlainText(key)
        self.status_bar.showMessage(f"Ключ {length} символов сгенерирован")

    def _copy(self, widget):
        text = widget.toPlainText()
        if text and text.strip():
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            # Очистить буфер через 30 секунд
            QTimer.singleShot(30000, lambda: clipboard.setText("") if clipboard.text() == text else None)
            self.status_bar.showMessage("✓ Скопировано в буфер (будет стерто через 30 сек)")
        else:
            self.status_bar.showMessage("Нет данных для копирования")