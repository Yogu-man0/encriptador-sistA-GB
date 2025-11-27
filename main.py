# main.py
import argparse
import sys
import os
import binascii

# Importações dos módulos da pasta src
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher
from src.ciphers.rsa_cipher import RSACipher

def rodar_teste_criterio_conclusao():
    """
    Mantém a validação da HU-08 (AES com chaves aleatórias).
    """
    import random
    import string
    
    print("\n>>> MODO DE TESTE AUTOMÁTICO (AES - Critérios HU-08 e HU-09) <<<")
    try:
        frase_original = input("Digite a frase para o teste: ").strip()
    except EOFError:
        frase_original = ""

    if not frase_original:
        frase_original = "Engenharia de Sistemas A - Teste RSA Sprint 3"
        print(f" Nenhum texto digitado. Usando frase padrão: '{frase_original}'")
    
    print(f"\nFrase Base: '{frase_original}'\n")

    for i in range(1, 6):
        tamanho_random = random.randint(5, 25)
        chave_raw = ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho_random))
        
        # Usa o método antigo (HU-09) que está dentro do KeyManager atualizado
        chave_ajustada = KeyManager.formatar_chave_simetrica(chave_raw)
        
        motor_aes = AESCipher(chave_ajustada)
        nonce, cifrado = motor_aes.encriptar(frase_original)
        texto_recuperado = motor_aes.decriptar(nonce, cifrado)
        
        cifrado_hex = binascii.hexlify(cifrado).decode('utf-8')
        status = "SUCESSO" if texto_recuperado == frase_original else "FALHA"
        
        print(f"[Teste #{i}]")
        print(f"  Entrada Chave: '{chave_raw}'")
        print(f"  Chave Ajustada: {chave_ajustada}")
        print(f"  Ciphertext:     {cifrado_hex[:30]}...")
        print(f"  Decriptação:    {status}")
        print("-" * 60)

def main():
    parser = argparse.ArgumentParser(
        description="O ENCRIPTADOR - Suporte a AES (Simétrico) e RSA (Assimétrico)",
        epilog="Exemplo RSA: python main.py --action encrypt --cipher rsa --key publica.pem --text 'Segredo'"
    )

    grupo_acao = parser.add_argument_group('Ações')
    grupo_config = parser.add_argument_group('Configurações')
    grupo_io = parser.add_argument_group('Entrada/Saída')

    # Ações possíveis
    grupo_acao.add_argument(
        '--action', 
        choices=['encrypt', 'decrypt', 'test', 'generate-keys'], 
        default='test',
        help="Ação a realizar. 'generate-keys' cria chaves RSA (HU-14)."
    )

    # Configuração da Cifra
    grupo_config.add_argument(
        '--cipher',
        choices=['aes', 'rsa'],
        default='aes',
        help="Algoritmo: 'aes' (padrão) ou 'rsa'."
    )

    grupo_config.add_argument('--key', help="Chave (AES: string, RSA: arquivo .pem)")

    # Entrada e Saída
    grupo_io.add_argument('--text', help="Texto de entrada")
    grupo_io.add_argument('--file', help="Arquivo de entrada")
    grupo_io.add_argument('--output', help="Arquivo de saída")

    args = parser.parse_args()

    # --- 1. GERAÇÃO DE CHAVES (HU-14) ---
    if args.action == 'generate-keys':
        if args.cipher != 'rsa':
            print("Erro: A ação 'generate-keys' só funciona com --cipher rsa")
            sys.exit(1)
        
        print("Gerando par de chaves RSA (2048 bits)...")
        priv, pub = KeyManager.gerar_par_chaves_rsa()
        
        nome_base = args.output if args.output else "id_rsa"
        
        # Salva usando os novos métodos do KeyManager
        KeyManager.salvar_chave(f"{nome_base}_priv.pem", priv)
        KeyManager.salvar_chave(f"{nome_base}_pub.pem", pub)
        
        print(f"Sucesso! Chaves salvas:\n - {nome_base}_priv.pem (Privada)\n - {nome_base}_pub.pem (Pública)")
        sys.exit(0)

    # --- 2. MODO DE TESTE ---
    if args.action == 'test':
        rodar_teste_criterio_conclusao()
        sys.exit(0)

    # --- 3. VALIDAÇÃO E PREPARAÇÃO DO MOTOR ---
    if not args.key:
        parser.error("O argumento --key é obrigatório para encriptar ou decriptar.")

    motor = None
    try:
        if args.cipher == 'aes':
            # HU-09: Formata string para bytes
            chave_fmt = KeyManager.formatar_chave_simetrica(args.key)
            motor = AESCipher(chave_fmt)
        
        elif args.cipher == 'rsa':
            # HU-13: Carrega arquivo PEM
            if not os.path.exists(args.key):
                print(f"Erro: Arquivo de chave '{args.key}' não encontrado.")
                sys.exit(1)
            
            print(f"Carregando chave RSA de: {args.key}")
            chave_conteudo = KeyManager.carregar_chave_arquivo(args.key)
            motor = RSACipher(chave_conteudo)

    except Exception as e:
        print(f"Erro ao inicializar criptografia: {e}")
        sys.exit(1)

    # --- 4. LEITURA DOS DADOS ---
    dados_input = b"" # Trabalharemos com bytes para ser universal
    
    if args.action == 'encrypt':
        if args.text:
            dados_input = args.text.encode('utf-8')
        elif args.file:
            try:
                with open(args.file, 'rb') as f: dados_input = f.read()
            except FileNotFoundError:
                print(f"Erro: Arquivo '{args.file}' não encontrado.")
                sys.exit(1)
        else:
            parser.error("Informe --text ou --file")

        # Cifragem
        try:
            # RSA retorna nonce=None; AES retorna nonce bytes.
            nonce, cifrado = motor.encriptar(dados_input.decode('utf-8', errors='ignore')) 
            # Nota: RSA OAEP geralmente lida com bytes, mas nossa interface pede string no 'encriptar'.
            # O .decode acima é um ajuste para manter compatibilidade com a assinatura da interface.
        except Exception as e:
            print(f"Erro na encriptação: {e}")
            sys.exit(1)

        # Empacotamento
        if args.cipher == 'aes':
            pacote = nonce + cifrado
        else:
            pacote = cifrado # RSA não tem nonce externo

        # Saída
        if args.output:
            with open(args.output, 'wb') as f: f.write(pacote)
            print(f"Arquivo encriptado salvo em: {args.output}")
        else:
            print(f"Resultado (Hex): {binascii.hexlify(pacote).decode()}")

    elif args.action == 'decrypt':
        # Leitura
        dados_encriptados = b""
        if args.text:
            try:
                dados_encriptados = binascii.unhexlify(args.text)
            except binascii.Error:
                print("Erro: O texto fornecido não é Hexadecimal válido.")
                sys.exit(1)
        elif args.file:
            try:
                with open(args.file, 'rb') as f: dados_encriptados = f.read()
            except FileNotFoundError:
                print(f"Erro: Arquivo '{args.file}' não encontrado.")
                sys.exit(1)
        else:
            parser.error("Informe --text ou --file")

        # Decifragem
        try:
            if args.cipher == 'aes':
                if len(dados_encriptados) < 16: raise ValueError("Dados insuficientes para AES.")
                nonce = dados_encriptados[:16]
                cifrado = dados_encriptados[16:]
                resultado = motor.decriptar(nonce, cifrado)
            else:
                # RSA
                resultado = motor.decriptar(None, dados_encriptados)
            
            # Saída
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f: f.write(resultado)
                print(f"Arquivo decriptado salvo em: {args.output}")
            else:
                print(f"Texto Decriptado: {resultado}")
        except Exception as e:
            print(f"Erro na decriptação: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()