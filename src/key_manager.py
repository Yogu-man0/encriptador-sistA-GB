# src/key_manager.py

class KeyManager:
    """
    Gerencia o tratamento de chaves simétricas e (futuramente) assimétricas.
    Referência PDF: HU-09, HU-13, HU-14.
    """

    @staticmethod
    def formatar_chave_simetrica(chave_input: str) -> bytes:
        """
        Implementa a HU-09: Ajusta string para 128 bits (16 bytes).
        
        Regras:
        1. < 16 chars: Preenche com zeros à esquerda (zfill).
        2. > 16 chars: Trunca para os primeiros 16 chars.
        """
        TAMANHO_ALVO = 16  # 128 bits
        
        if not isinstance(chave_input, str):
            # Garante robustez para entradas inválidas
            chave_input = str(chave_input)

        if len(chave_input) > TAMANHO_ALVO:
            # Truncamento (Critério HU-09)
            chave_formatada = chave_input[:TAMANHO_ALVO]
        else:
            # Padding com zeros à esquerda (Critério HU-09)
            chave_formatada = chave_input.zfill(TAMANHO_ALVO)
            
        return chave_formatada.encode('ascii')

    # TODO: Futura implementação da HU-13 (Carregar Chave de Arquivo)
    # def carregar_chave_arquivo(self, caminho: str):
    #     pass