from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_aes_key():
    """Генерирует случайный AES ключ (256 бит)"""
    return get_random_bytes(32)  # 32 байта = 256 бит


def encrypt_message(plaintext, key):
    """Шифрует данные через AES-256-CBC"""
    try:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Генерируем случайный IV
        iv = get_random_bytes(16)

        # Создаём шифр
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Дополняем данные до блока 16 байт
        padded_data = pad(plaintext, AES.block_size)

        # Шифруем
        encrypted = cipher.encrypt(padded_data)

        # Возвращаем IV + зашифрованные данные
        return iv + encrypted
    except Exception as e:
        print(f"Encryption error: {e}")
        return None


def decrypt_message(ciphertext, key):
    """Расшифровывает данные через AES-256-CBC"""
    try:
        # Извлекаем IV (первые 16 байт)
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]

        # Создаём шифр
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Расшифровываем
        decrypted = cipher.decrypt(encrypted_data)

        # Убираем padding
        unpadded = unpad(decrypted, AES.block_size)

        # Возвращаем байты (для файлов) или строку (для текста)
        return unpadded
    except Exception as e:
        print(f"Decryption error: {e}")
        return None