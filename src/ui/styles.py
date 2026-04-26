from PyQt6.QtWidgets import QFrame, QLabel
from PyQt6.QtCore import Qt

C_BG, C_BG2, C_BG3, C_BORDER = "#F5F0EB", "#EDE6DD", "#E2D9CE", "#D4C8BA"
C_LILAC, C_LILAC2 = "#9B7FBD", "#B99DD4"
C_ORANGE, C_ORANGE2 = "#E07A3A", "#F0A060"
C_TEXT, C_TEXT2, C_TEXT3 = "#3D2E20", "#7A6555", "#A89080"
C_GREEN, C_RED = "#5A9E6F", "#C0413A"

STYLE = f"""
* {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: {C_TEXT}; }}
QMainWindow, QWidget {{ background: {C_BG}; }}
QTabWidget::pane {{ border: 1px solid {C_BORDER}; border-radius: 10px; background: {C_BG}; }}
QTabBar::tab {{ background: {C_BG2}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 8px 18px; margin: 2px; color: {C_TEXT2}; }}
QTabBar::tab:selected {{ background: {C_LILAC}; color: white; font-weight: bold; }}
QTabBar::tab:hover {{ background: {C_LILAC2}; color: white; }}
QGroupBox {{ border: 1.5px solid {C_BORDER}; border-radius: 10px; margin-top: 14px; padding: 10px; font-weight: bold; color: {C_TEXT2}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {C_LILAC}; font-size: 11px; letter-spacing: 1px; }}
QTextEdit, QLineEdit {{ background: white; border: 1.5px solid {C_BORDER}; border-radius: 8px; padding: 8px 12px; color: {C_TEXT}; selection-background-color: {C_LILAC2}; }}
QTextEdit:focus, QLineEdit:focus {{ border-color: {C_LILAC}; }}
QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {C_LILAC}, stop:1 {C_ORANGE}); border: none; border-radius: 9px; color: white; font-weight: bold; padding: 10px 18px; letter-spacing: 0.5px; }}
QPushButton:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {C_LILAC2}, stop:1 {C_ORANGE2}); }}
QPushButton:pressed {{ background: {C_BG3}; color: {C_LILAC}; }}
QPushButton#btn_secondary {{ background: transparent; border: 1.5px solid {C_BORDER}; color: {C_TEXT2}; }}
QPushButton#btn_secondary:hover {{ border-color: {C_LILAC}; color: {C_LILAC}; background: rgba(155,127,189,0.07); }}
QCheckBox {{ spacing: 8px; color: {C_TEXT2}; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border: 2px solid {C_BORDER}; border-radius: 4px; background: white; }}
QCheckBox::indicator:checked {{ background: {C_LILAC}; border-color: {C_LILAC}; }}
QProgressBar {{ border: none; border-radius: 4px; background: {C_BG3}; height: 6px; text-align: center; }}
QProgressBar::chunk {{ background: {C_LILAC}; border-radius: 4px; }}
QScrollBar:vertical {{ background: {C_BG2}; width: 6px; border-radius: 3px; }}
QScrollBar::handle:vertical {{ background: {C_BORDER}; border-radius: 3px; min-height: 24px; }}
QStatusBar {{ background: {C_BG2}; border-top: 1px solid {C_BORDER}; color: {C_TEXT3}; }}
"""

def make_sep():
    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"background: {C_BORDER}; max-height: 1px;")
    return sep

def make_label(text, color=None, size=None, bold=False):
    lbl = QLabel(text)
    css = f"color: {color or C_TEXT2};"
    if size: css += f" font-size: {size}px;"
    if bold: css += " font-weight: bold;"
    lbl.setStyleSheet(css)
    return lbl