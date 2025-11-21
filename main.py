# main.py
import argparse
import sys
import random
import string
import binascii

# Importações dos módulos da pasta src
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher

def rodar_teste_criterio_conclusao():
    """
    Executa a validação automática solicitada:
    1. Lê uma frase do teclado (Mudança solicitada).
    2. Gera 5 chaves aleatórias diferentes.
    3. Criptografa a MESMA frase com cada chave.
    4. Valida se a saída é visualmente aleatória e se decripta corretamente.
    """
    print("\n>>> MODO DE TESTE AUTOMÁTICO (Critérios HU-08 e HU-09) <<<")
    
    # --- ALTERAÇÃO AQUI: Leitura do teclado ---
    print("Este teste encriptará sua frase 5 vezes com chaves aleatórias.")
    frase_original = input("Digite a frase para o teste: ").strip()
    
    # Fallback caso o usuário dê Enter sem digitar nada
    if not frase_original:
        frase_original = "Engenharia de Sistemas A - Teste Padrão"
        print(f" Nenhum texto digitado. Usando frase padrão: '{frase_original}'")
    
    print(f"\nFrase Base: '{frase_original}'\n")

    # Loop para validar o critério HU-08 (Mesma frase, chaves diferentes)
    for i in range(1, 6):
        # 1. Gera string aleatória (simulando HU-09 com tamanhos variados de input)
        # Algumas chaves serão curtas (precisam de padding), outras longas (precisam de corte)
        tamanho_random = random.randint(5, 25)
        chave_raw = ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho_random))
        
        # 2. Formata a chave para 128 bits usando o KeyManager (HU-09)
        chave_ajustada = KeyManager.formatar_chave_simetrica(chave_raw)
        
        # 3. Cifra usando o motor AES (HU-08)
        motor_aes = AESCipher(chave_ajustada)
        nonce, cifrado = motor_aes.encriptar(frase_original)
        
        # 4. Decifra para provar que o processo é reversível
        texto_recuperado = motor_aes.decriptar(nonce, cifrado)
        
        # Validações visuais e lógicas
        cifrado_hex = binascii.hexlify(cifrado).decode('utf-8')
        status = "SUCESSO" if texto_recuperado == frase_original else "FALHA"
        
        print(f"[Teste #{i}]")
        print(f"  Entrada Chave (Random): '{chave_raw}' ({len(chave_raw)} chars)")
        print(f"  Chave Ajustada (HU-09): {chave_ajustada} (16 bytes)")
        print(f"  Ciphertext (HU-08):     {cifrado_hex[:256]} (Visualmente Aleatório)")
        print(f"  Decriptação:            {status}")
        print("-" * 60)

def main():
    # Configuração da CLI (Argumentos de Linha de Comando - HU-01)
    parser = argparse.ArgumentParser(description="O Encriptador - CLI")
    
    parser.add_argument("--test", action="store_true", help="Roda os testes de critério de aceitação (HU-08/09)")
    parser.add_argument("--text", type=str, help="Texto para encriptar (Uso único)")
    parser.add_argument("--key", type=str, help="Chave de encriptação")
    
    args = parser.parse_args()

    # Lógica de Controle
    if args.test:
        rodar_teste_criterio_conclusao()
        sys.exit(0)
    
    # Modo CLI Direto (ex: python main.py --text "Ola" --key "123")
    if args.text and args.key:
        chave = KeyManager.formatar_chave_simetrica(args.key)
        motor = AESCipher(chave)
        nonce, cifrado = motor.encriptar(args.text)
        print(f"Texto Cifrado (hex): {binascii.hexlify(cifrado).decode()}")
        print(f"Nonce (hex):         {binascii.hexlify(nonce).decode()}")
    else:
        # Se rodar sem argumentos, cai no modo interativo de teste por padrão
        print("Nenhum argumento passado via CLI.")
        rodar_teste_criterio_conclusao()

if __name__ == "__main__":
    main()