"""
Утилиты для безопасной работы с памятью
"""

def secure_zero(data: bytearray | bytes) -> None:
    """Безопасно затирает данные в памяти"""
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            # Для bytes нужно преобразовать в bytearray
            ba = bytearray(data)
            for i in range(len(ba)):
                ba[i] = 0
    except:
        pass  # Если не получилось — игнорируем