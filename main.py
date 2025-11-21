# main.py
import argparse
import sys
import random
import string
import binascii

# Importações dos módulos criados
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher

def rodar_teste_criterio_conclusao():
    """
    Executa a validação automática solicitada no prompt.
    Critério HU-08: 5 chaves aleatórias, saídas aleatórias, reversibilidade.
    """
    print("\n>>> MODO DE TESTE AUTOMÁTICO (Critérios HU-08 e HU-09) <<<")
    frase_original = "Engenharia de Sistemas A - Sprint Review"
    print(f"Frase Base: '{frase_original}'\n")

    for i in range(1, 6):
        # 1. Gera string aleatória (simulando HU-09 com tamanhos variados)
        tamanho_random = random.randint(5, 25)
        chave_raw = ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho_random))
        
        # 2. Formata (HU-09)
        chave_ajustada = KeyManager.formatar_chave_simetrica(chave_raw)
        
        # 3. Cifra (HU-08)
        motor_aes = AESCipher(chave_ajustada)
        nonce, cifrado = motor_aes.encriptar(frase_original)
        
        # 4. Decifra (Prova Real)
        texto_recuperado = motor_aes.decriptar(nonce, cifrado)
        
        # Visualização
        cifrado_hex = binascii.hexlify(cifrado).decode('utf-8')
        status = "SUCESSO" if texto_recuperado == frase_original else "FALHA"
        
        print(f"[Teste #{i}]")
        print(f"  Entrada Chave: '{chave_raw}'")
        print(f"  Chave 128-bit: {chave_ajustada}")
        print(f"  Ciphertext:    {cifrado_hex[:30]}... (Visualmente Aleatório)")
        print(f"  Status Decrypt: {status}")
        print("-" * 50)

def main():
    # Configuração Inicial do Épico 1 (CLI com argparse)
    # Referência PDF: HU-01 a HU-06
    parser = argparse.ArgumentParser(description="O Encriptador - CLI")
    
    # Argumentos futuros (preparação para HU-02, HU-07, HU-09)
    parser.add_argument("--test", action="store_true", help="Roda os testes de critério de aceitação")
    parser.add_argument("--text", type=str, help="Texto para encriptar (HU-02)")
    parser.add_argument("--key", type=str, help="Chave de encriptação (HU-09)")
    # parser.add_argument("--cipher", type=str, default="AES", help="Algoritmo (HU-07)") # Futuro
    
    args = parser.parse_args()

    # Lógica de Controle
    if args.test:
        rodar_teste_criterio_conclusao()
        sys.exit(0)
    
    if args.text and args.key:
        # Demonstração de uso real via linha de comando
        chave = KeyManager.formatar_chave_simetrica(args.key)
        motor = AESCipher(chave)
        nonce, cifrado = motor.encriptar(args.text)
        print(f"Texto Cifrado (hex): {binascii.hexlify(cifrado).decode()}")
        print(f"Nonce (necessário p/ decifrar): {binascii.hexlify(nonce).decode()}")
    else:
        # Se não passar argumentos, roda o teste padrão solicitado
        print("Nenhum argumento passado via CLI. Executando testes de validação...\n")
        rodar_teste_criterio_conclusao()
        print("\nDica: Use 'python main.py --help' para ver as opções futuras.")

if __name__ == "__main__":
    main()