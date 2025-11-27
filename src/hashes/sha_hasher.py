# src/hashes/sha_hasher.py
import hashlib

class SHA256Hasher:
    """
    Implementação do Épico 5: Hashing (SHA-256).
    Responsável por garantir a integridade dos dados.
    Referência: HU-16.
    """

    @staticmethod
    def gerar_hash(dados: bytes) -> str:
        """
        Recebe o conteúdo em bytes (seja texto ou arquivo) e retorna
        a assinatura digital (hash) em formato Hexadecimal.
        """
        # Cria o objeto SHA-256
        sha_signature = hashlib.sha256(dados).hexdigest()
        return sha_signature

    @staticmethod
    def verificar_integridade(dados: bytes, hash_original: str) -> bool:
        """
        Recalcula o hash dos dados e compara com um hash fornecido.
        Retorna True se forem idênticos (dados íntegros).
        """
        hash_calculado = hashlib.sha256(dados).hexdigest()
        # A comparação é case-insensitive (minúscula/maiúscula não importa no hex)
        return hash_calculado.lower() == hash_original.lower()