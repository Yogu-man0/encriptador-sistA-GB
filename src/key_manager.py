# src/key_manager.py
from Crypto.PublicKey import RSA
import os

class KeyManager:
    """
    Gerencia chaves Simétricas (AES) e Assimétricas (RSA).
    Histórico:
    - Sprint 2: HU-09 (Formatação de chave simétrica).
    - Sprint 3: HU-13, HU-14, HU-15 (Geração e carregamento de RSA).
    """

    @staticmethod
    def formatar_chave_simetrica(chave_input: str) -> bytes:
        """
        [HU-09] Ajusta string para 128 bits (16 bytes).
        Usado para o algoritmo AES.
        """
        TAMANHO_ALVO = 16  # 128 bits
        
        # Garante que é string antes de manipular
        if not isinstance(chave_input, str):
            chave_input = str(chave_input)

        # Regra 1: Truncamento (se maior que 16)
        if len(chave_input) > TAMANHO_ALVO:
            chave_formatada = chave_input[:TAMANHO_ALVO]
        
        # Regra 2: Padding com zeros à esquerda (se menor que 16)
        else:
            chave_formatada = chave_input.zfill(TAMANHO_ALVO)
            
        return chave_formatada.encode('ascii')

    @staticmethod
    def gerar_par_chaves_rsa(tamanho=2048):
        """
        [HU-14] Gera um par de chaves RSA (Privada e Pública).
        Retorna as chaves em formato bytes (PEM).
        """
        key = RSA.generate(tamanho)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def salvar_chave(caminho: str, dados_chave: bytes):
        """
        [HU-15] Salva a chave gerada em um arquivo no disco.
        """
        # Garante que o diretório existe (opcional, mas boa prática)
        diretorio = os.path.dirname(caminho)
        if diretorio and not os.path.exists(diretorio):
            os.makedirs(diretorio)

        with open(caminho, 'wb') as f:
            f.write(dados_chave)

    @staticmethod
    def carregar_chave_arquivo(caminho: str) -> bytes:
        """
        [HU-13] Carrega uma chave de um arquivo PEM para usar no RSA.
        """
        if not os.path.exists(caminho):
            raise FileNotFoundError(f"Arquivo de chave não encontrado: {caminho}")
        
        with open(caminho, 'rb') as f:
            return f.read()