from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from typing import Tuple, Any
from ..interfaces import ICipher

class RSACipher(ICipher):
    """
    Implementação do algoritmo RSA (Assimétrico) - Épico 3.
    Referência: HU-11 (Cifrar com Pública), HU-12 (Decifrar com Privada).
    """

    def __init__(self, key_content: bytes):
        """
        Recebe o conteúdo da chave (PEM) em bytes.
        Pode ser chave PÚBLICA (para encriptar) ou PRIVADA (para decriptar).
        """
        try:
            self.key = RSA.import_key(key_content)
            self.cipher = PKCS1_OAEP.new(self.key)
        except Exception as e:
            raise ValueError(f"Chave RSA inválida: {e}")

    def encriptar(self, texto_claro: str) -> Tuple[Any, bytes]:
        """
        Retorna (None, ciphertext).
        RSA OAEP não gera nonce externo, então retornamos None.
        """
        if not self.key.can_encrypt():
            raise ValueError("Esta chave não pode encriptar (provavelmente é uma chave privada sem a parte pública ou formato incorreto).")
            
        ciphertext = self.cipher.encrypt(texto_claro.encode('utf-8'))
        return None, ciphertext

    def decriptar(self, nonce: Any, texto_cifrado: bytes) -> str:
        """
        O parâmetro 'nonce' é ignorado no RSA, mas mantido pela interface.
        """
        if not self.key.has_private():
            raise ValueError("É necessária uma chave PRIVADA para decriptar.")
            
        try:
            data = self.cipher.decrypt(texto_cifrado)
            return data.decode('utf-8')
        except Exception:
            return "[ERRO] Falha na decriptação RSA (Chave errada ou dados corrompidos)."