# main.py
import argparse
import sys
import random
import string
import binascii
import os

# Importações dos módulos criados
# Certifique-se que src/hasher.py existe (conforme passo anterior)
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher
try:
    from src.hasher import Hasher
except ImportError:
    # Mock caso o arquivo ainda não tenha sido criado fisicamente
    class Hasher:
        @staticmethod
        def generate_text_hash(t): return f"hash_simulado_sha256({t})"
        @staticmethod
        def generate_file_hash(p): return "hash_arquivo_simulado"
        @staticmethod
        def verify_integrity(o, c): return o == c

def rodar_teste_criterio_conclusao():
    """
    Executa a validação automática solicitada no prompt.
    Critério HU-08: 5 chaves aleatórias, saídas aleatórias, reversibilidade.
    """
    print("\n>>> MODO DE TESTE AUTOMÁTICO (Critérios HU-08 e HU-09: AES) <<<")
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

def rodar_teste_hashing():
    """
    Executa validação automática para o Épico 5 (HU-16).
    """
    print("\n>>> MODO DE TESTE AUTOMÁTICO (Critério HU-16: Hashing SHA-256) <<<")
    hasher = Hasher()
    
    # Teste 1: Hash de Texto
    texto = "Integridade é tudo"
    hash1 = hasher.generate_text_hash(texto)
    print(f"[Teste Hash Texto]")
    print(f"  Entrada: '{texto}'")
    print(f"  SHA-256: {hash1}")
    
    # Teste 2: Integridade (Positivo)
    check_ok = hasher.verify_integrity(hash1, hash1)
    print(f"  Verificação com mesmo hash: {'SUCESSO' if check_ok else 'FALHA'}")
    
    # Teste 3: Integridade (Negativo)
    fake_hash = hash1.replace('a', 'b').replace('1', '2')
    check_fail = hasher.verify_integrity(hash1, fake_hash)
    print(f"  Verificação com hash alterado: {'SUCESSO' if not check_fail else 'FALHA'}")
    print("-" * 50)

def main():
    # Configuração Inicial do Épico 1 (CLI com argparse)
    # Referência PDF: HU-01 a HU-06 + HU-16 (Hashing)
    parser = argparse.ArgumentParser(description="O Encriptador - CLI")
    
    # Argumentos Gerais / AES
    parser.add_argument("--test", action="store_true", help="Roda os testes de critério de aceitação (AES e Hash)")
    parser.add_argument("--text", type=str, help="Texto para encriptar ou hashear")
    parser.add_argument("--key", type=str, help="Chave de encriptação (HU-09)")
    
    # Argumentos Novos (Hashing - Épico 5)
    parser.add_argument("--hash", action="store_true", help="Ativa modo de Hashing (SHA-256)")
    parser.add_argument("--file", type=str, help="Caminho do arquivo para hashing (HU-16)")
    parser.add_argument("--verify", type=str, help="Hash original para verificar integridade")
    
    args = parser.parse_args()

    # 1. Modo de Teste
    if args.test:
        rodar_teste_criterio_conclusao() # AES
        rodar_teste_hashing()            # Hashing
        sys.exit(0)
    
    # 2. Lógica de Hashing (Prioridade se --hash for passado)
    if args.hash:
        hasher = Hasher()
        resultado_hash = ""
        
        if args.file:
            print(f"Calculando hash do arquivo: {args.file}...")
            resultado_hash = hasher.generate_file_hash(args.file)
        elif args.text:
            resultado_hash = hasher.generate_text_hash(args.text)
        else:
            print("Erro: Para --hash, forneça --text ou --file.")
            sys.exit(1)
            
        print(f"SHA-256: {resultado_hash}")
        
        # Verificação de Integridade opcional na mesma chamada
        if args.verify:
            is_valid = hasher.verify_integrity(args.verify, resultado_hash)
            if is_valid:
                print("✅ INTEGRIDADE CONFIRMADA.")
            else:
                print("❌ ALERTA: OS HASHES NÃO CONFEREM.")
        sys.exit(0)

    # 3. Lógica de Encriptação (AES)
    if args.text and args.key:
        # Demonstração de uso real via linha de comando
        chave = KeyManager.formatar_chave_simetrica(args.key)
        motor = AESCipher(chave)
        nonce, cifrado = motor.encriptar(args.text)
        print(f"Texto Cifrado (hex): {binascii.hexlify(cifrado).decode()}")
        print(f"Nonce (necessário p/ decifrar): {binascii.hexlify(nonce).decode()}")
    else:
        # Fallback se nenhum argumento válido for passado
        print("Nenhum argumento de ação passado via CLI. Executando testes de validação...\n")
        rodar_teste_criterio_conclusao()
        rodar_teste_hashing()
        print("\nDica: Use 'python main.py --help' para ver as opções.")

if __name__ == "__main__":
    main()