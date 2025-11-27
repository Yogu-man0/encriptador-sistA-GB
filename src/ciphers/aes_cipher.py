# src/ciphers/aes_cipher.py
from Crypto.Cipher import AES
from typing import Tuple
from ..interfaces import ICipher

class AESCipher(ICipher):
    """
    Implementação do algoritmo AES (Simétrico).
    Referência PDF: HU-08, HU-10.
    """

    def __init__(self, chave_bytes: bytes, modo=AES.MODE_EAX):
        """
        Recebe a chave JÁ formatada (bytes).
        O 'modo' prepara o terreno para a HU-10.
        """
        self.chave = chave_bytes
        self.modo = modo

    def encriptar(self, texto_claro: str) -> Tuple[bytes, bytes]:
        """
        Retorna (nonce, ciphertext).
        O nonce é crucial para o modo EAX/CTR.
        """
        cipher = AES.new(self.chave, self.modo)
        ciphertext, tag = cipher.encrypt_and_digest(texto_claro.encode('utf-8'))
        
        # Retornamos o nonce pois ele é necessário para decriptar
        return cipher.nonce, ciphertext

    def decriptar(self, nonce: bytes, texto_cifrado: bytes) -> str:
        """
        Requer o nonce gerado na encriptação.
        """
        try:
            cipher = AES.new(self.chave, self.modo, nonce=nonce)
            data = cipher.decrypt(texto_cifrado)
            return data.decode('utf-8')
        except ValueError:
            return "[ERRO] Decriptação falhou (Chave incorreta ou dados corrompidos)."