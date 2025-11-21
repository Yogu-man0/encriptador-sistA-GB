# src/interfaces.py
from abc import ABC, abstractmethod
from typing import Tuple, Any

class ICipher(ABC):
    """
    Interface abstrata para garantir que todas as cifras (AES, RSA, etc.)
    sigam o mesmo padrão no futuro.
    """
    @abstractmethod
    def encriptar(self, dados: str) -> Tuple[Any, bytes]:
        """Deve retornar (metadados/nonce, texto_cifrado)"""
        pass
    @abstractmethod 
    def decriptar(self, metadados: Any, texto_cifrado: bytes) -> str:
        """Deve retornar o texto original"""
        pass
