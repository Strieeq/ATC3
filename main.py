#!/usr/bin/env python3
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

try:
    from PyQt6.QtWidgets import QApplication
    from src.ui.main_window import MainWindow
except ImportError as e:
    print("❌ Ошибка импорта. Убедись, что установлены зависимости:")
    print("   pip install -r requirements.txt")
    sys.exit(1)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Atomic TriFlow Cipher")
    app.setApplicationVersion("3.0.1")
    
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()