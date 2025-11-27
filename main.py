# main.py
import argparse
import sys
import os
import binascii

# --- Importações dos Módulos ---
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher
from src.ciphers.rsa_cipher import RSACipher
from src.hashes.sha_hasher import SHA256Hasher  # Nova importação

def main():
    # Configuração do Parser de Argumentos (CLI)
    parser = argparse.ArgumentParser(
        description="O ENCRIPTADOR - Sistema Completo (AES, RSA, SHA-256)",
        epilog="Exemplo Hash: python main.py --action hash --text 'Mensagem Importante'"
    )

    grupo_acao = parser.add_argument_group('Ações')
    grupo_config = parser.add_argument_group('Configurações')
    grupo_io = parser.add_argument_group('Entrada/Saída')

    # 1. Definição das Ações
    grupo_acao.add_argument(
        '--action', 
        choices=['encrypt', 'decrypt', 'generate-keys', 'hash', 'check-hash', 'test'], 
        default='test',
        help="Escolha a operação. 'hash' gera um resumo; 'check-hash' verifica integridade."
    )

    # 2. Configuração do Algoritmo
    grupo_config.add_argument(
        '--cipher',
        choices=['aes', 'rsa'],
        default='aes',
        help="Algoritmo de criptografia (Ignorado para ações de hash)."
    )

    # 3. Chave (Opcional para hash, obrigatória para criptografia)
    grupo_config.add_argument('--key', help="Chave (AES), Arquivo .pem (RSA) ou Hash para verificação (check-hash).")
    
    # 4. Entradas e Saídas
    grupo_io.add_argument('--text', help="Texto de entrada")
    grupo_io.add_argument('--file', help="Arquivo de entrada")
    grupo_io.add_argument('--output', help="Arquivo de saída")

    args = parser.parse_args()

    # ==========================================
    # BLOCO 1: GERAÇÃO DE CHAVES (RSA)
    # ==========================================
    if args.action == 'generate-keys':
        if args.cipher != 'rsa':
            sys.exit("Erro: A ação 'generate-keys' requer --cipher rsa")
        
        print("Gerando par de chaves RSA (2048 bits)...")
        priv, pub = KeyManager.gerar_par_chaves_rsa()
        nome = args.output if args.output else "id_rsa"
        
        KeyManager.salvar_chave(f"{nome}_priv.pem", priv)
        KeyManager.salvar_chave(f"{nome}_pub.pem", pub)
        print(f"Sucesso! Chaves salvas: {nome}_priv.pem e {nome}_pub.pem")
        sys.exit(0)

    # ==========================================
    # BLOCO 2: HASHING (SHA-256) - ÉPICO 5
    # ==========================================
    if args.action in ['hash', 'check-hash']:
        # Leitura dos dados (Comum para hash e criptografia)
        dados_bytes = b""
        if args.text:
            dados_bytes = args.text.encode('utf-8')
        elif args.file:
            try:
                with open(args.file, 'rb') as f: dados_bytes = f.read()
            except FileNotFoundError:
                sys.exit(f"Erro: Arquivo '{args.file}' não encontrado.")
        else:
            parser.error("Informe --text ou --file para processar o hash.")

        # Ação: Gerar Hash
        if args.action == 'hash':
            resultado = SHA256Hasher.gerar_hash(dados_bytes)
            print(f"\n[SHA-256] Hash Gerado:")
            print(f"{resultado}")
            
            if args.output:
                with open(args.output, 'w') as f: f.write(resultado)
                print(f"Hash salvo em: {args.output}")

        # Ação: Verificar Integridade (Bônus HU-16)
        elif args.action == 'check-hash':
            if not args.key:
                sys.exit("Erro: Para 'check-hash', informe o hash original no argumento --key")
            
            integro = SHA256Hasher.verificar_integridade(dados_bytes, args.key)
            status = "VÁLIDO (Íntegro)" if integro else "INVÁLIDO (Corrompido)"
            print(f"\n[Verificação de Integridade]")
            print(f"Resultado: {status}")
        
        sys.exit(0) # Encerra aqui se for hash

    # ==========================================
    # BLOCO 3: CRIPTOGRAFIA (AES / RSA)
    # ==========================================
    
    # Validação de argumentos para Encriptação
    if args.action == 'test':
        print("Modo de teste rápido não implementado neste bloco. Use --action encrypt/decrypt.")
        sys.exit(0)
        
    if not args.key:
        parser.error("Para encriptar ou decriptar, o argumento --key é obrigatório.")

    motor = None
    try:
        # Inicializa o motor correto
        if args.cipher == 'aes':
            k = KeyManager.formatar_chave_simetrica(args.key)
            motor = AESCipher(k)
        elif args.cipher == 'rsa':
            if not os.path.exists(args.key):
                sys.exit(f"Erro: Arquivo de chave '{args.key}' não encontrado.")
            k = KeyManager.carregar_chave_arquivo(args.key)
            motor = RSACipher(k)
    except Exception as e:
        sys.exit(f"Erro na inicialização da cifra: {e}")

    # Leitura dos dados
    dados_input = b""
    if args.text:
        # Se for decriptar texto, espera-se Hexadecimal
        if args.action == 'decrypt':
            try: dados_input = binascii.unhexlify(args.text)
            except: sys.exit("Erro: Texto para decriptar deve ser Hexadecimal válido.")
        else:
            dados_input = args.text.encode('utf-8')
    elif args.file:
        try:
            with open(args.file, 'rb') as f: dados_input = f.read()
        except FileNotFoundError:
            sys.exit(f"Erro: Arquivo '{args.file}' não encontrado.")
    else:
        parser.error("Informe --text ou --file")

    # Execução Encrypt/Decrypt
    try:
        if args.action == 'encrypt':
            # RSA requer string no encrypt (para ser compatível com encode interno da lib)
            # AES requer string também pela nossa interface
            texto_claro = dados_input.decode('utf-8', errors='ignore') if args.cipher == 'rsa' else dados_input.decode('utf-8')
            
            nonce, cifrado = motor.encriptar(texto_claro)
            
            # Pacote final
            pacote = (nonce if nonce else b"") + cifrado
            
            if args.output:
                with open(args.output, 'wb') as f: f.write(pacote)
                print(f"Sucesso. Salvo em: {args.output}")
            else:
                print(f"Resultado (Hex): {binascii.hexlify(pacote).decode()}")

        elif args.action == 'decrypt':
            if args.cipher == 'aes':
                if len(dados_input) < 16: sys.exit("Dados insuficientes para AES.")
                nonce, cifrado = dados_input[:16], dados_input[16:]
                resultado = motor.decriptar(nonce, cifrado)
            else:
                # RSA (sem nonce externo)
                resultado = motor.decriptar(None, dados_input)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f: f.write(resultado)
                print(f"Sucesso. Salvo em: {args.output}")
            else:
                print(f"Decriptado: {resultado}")

    except Exception as e:
        sys.exit(f"Erro na operação: {e}")

if __name__ == "__main__":
    main()