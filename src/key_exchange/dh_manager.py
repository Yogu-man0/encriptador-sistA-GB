# src/key_exchange/dh_manager.py
from Crypto.Util import number
from Crypto.Random import random
import os

class DHManager:
    """
    Implementação do Protocolo Diffie-Hellman (DFH).
    Objetivo: Permitir que duas partes derivem a mesma chave secreta (para usar no AES).
    """

    # Parâmetros padrão (RFC 3526 - Grupo 5 - 1536 bits) para evitar lentidão na geração de primos
    # Em produção real, usam-se grupos maiores ou Curvas Elípticas (ECDH).
    PRIME_MODULUS = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
                        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
                        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
                        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
                        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
                        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
                        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
                        '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16)
    GENERATOR = 2

    def __init__(self):
        self.p = self.PRIME_MODULUS
        self.g = self.GENERATOR
        self.private_key = None
        self.public_key = None

    def gerar_chaves(self):
        """
        Gera a chave privada (a) e a pública (A = g^a mod p).
        """
        # Chave privada: número aleatório entre 2 e p-2
        self.private_key = random.randint(2, self.p - 2)
        
        # Chave pública: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        return self.private_key, self.public_key

    def calcular_segredo_compartilhado(self, minha_chave_privada: int, chave_publica_outro: int) -> str:
        """
        Calcula o segredo S = (B)^a mod p.
        Retorna o segredo como string numérica (que pode ser formatada para virar chave AES).
        """
        segredo_int = pow(chave_publica_outro, minha_chave_privada, self.p)
        return str(segredo_int)

    @staticmethod
    def salvar_param(caminho, valor):
        with open(caminho, 'w') as f:
            f.write(str(valor))

    @staticmethod
    def carregar_param(caminho):
        if not os.path.exists(caminho):
            raise FileNotFoundError(f"Arquivo não encontrado: {caminho}")
        with open(caminho, 'r') as f:
            return int(f.read().strip())