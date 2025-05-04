import base64
import re


def encode_or_decode_base64_utf32(text):
    """
    Detecta se o texto está em base64 codificado com UTF-32 e decodifica.
    Caso contrário, codifica o texto para base64 usando UTF-32.
    """
    if is_base64(text):
        try:
            return base64.b64decode(text.encode('utf-8')).decode('utf-32')
        except Exception:
            return base64.b64encode(text.encode('utf-32')).decode('utf-8')
    else:
        return base64.b64encode(text.encode('utf-32')).decode('utf-8')


def is_base64(s):
    """
    Verifica se a string parece estar em base64.
    """
    if not isinstance(s, str) or len(s) % 4 != 0:
        return False
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    return re.fullmatch(pattern, s) is not None
