# main.py
import argparse
import sys
import os
import binascii

# --- Importações dos Módulos ---
from src.key_manager import KeyManager
from src.ciphers.aes_cipher import AESCipher
from src.ciphers.rsa_cipher import RSACipher
from src.hashes.sha_hasher import SHA256Hasher
from src.key_exchange.dh_manager import DHManager

def limpar_tela():
    """Limpa o terminal para manter o menu organizado."""
    os.system('cls' if os.name == 'nt' else 'clear')

def rodar_teste_criterio_conclusao():
    import random
    import string
    
    print("\n>>> MODO DE TESTE AUTOMÁTICO (AES) <<<")
    try:
        frase_original = input("Digite a frase para o teste: ").strip()
    except EOFError:
        frase_original = ""

    if not frase_original:
        frase_original = "Engenharia de Sistemas A - Teste Automatizado"
    
    print(f"\nFrase Base: '{frase_original}'\n")

    for i in range(1, 6):
        tamanho = random.randint(5, 25)
        chave_raw = ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho))
        chave_fmt = KeyManager.formatar_chave_simetrica(chave_raw)
        motor = AESCipher(chave_fmt)
        nonce, cifrado = motor.encriptar(frase_original)
        recuperado = motor.decriptar(nonce, cifrado)
        
        status = "SUCESSO" if recuperado == frase_original else "FALHA"
        print(f"[Teste #{i}] Chave: {chave_raw:<20} | Decriptação: {status}")

def modo_interativo(parser):
    """
    Exibe o menu e retorna os argumentos escolhidos.
    """
    limpar_tela()
    print("="*50)
    print("      O ENCRIPTADOR - MODO INTERATIVO")
    print("="*50)
    print("1. Encriptar (AES/RSA)")
    print("2. Decriptar (AES/RSA)")
    print("3. Gerar Chaves (RSA)")
    print("4. Gerar Hash (SHA-256)")
    print("5. Verificar Hash")
    print("6. Diffie-Hellman (Gerar/Derivar)")
    print("7. Rodar Teste Automático")
    print("0. Sair")
    print("-" * 50)
    
    escolha = input("Escolha uma opção: ").strip()
    
    args_list = []

    if escolha == '0':
        print("Saindo...")
        sys.exit(0)

    elif escolha == '1': # Encrypt
        args_list.append('--action'); args_list.append('encrypt')
        tipo = input("Qual cifra? (aes/rsa) [padrao: aes]: ").strip().lower() or 'aes'
        args_list.append('--cipher'); args_list.append(tipo)
        
        texto = input("Digite o texto (ou ENTER para arquivo): ")
        if texto:
            args_list.append('--text'); args_list.append(texto)
        else:
            path = input("Caminho do arquivo de entrada: ").strip()
            args_list.append('--file'); args_list.append(path)
            
        key = input(f"Chave {'(Arquivo .pem)' if tipo == 'rsa' else '(Senha)'}: ").strip()
        args_list.append('--key'); args_list.append(key)
        
        out = input("Salvar em arquivo? (Nome ou ENTER para tela): ").strip()
        if out:
            args_list.append('--output'); args_list.append(out)

    elif escolha == '2': # Decrypt
        args_list.append('--action'); args_list.append('decrypt')
        tipo = input("Qual cifra? (aes/rsa) [padrao: aes]: ").strip().lower() or 'aes'
        args_list.append('--cipher'); args_list.append(tipo)
        
        texto = input("Cole o HEX (ou ENTER para arquivo): ")
        if texto:
            args_list.append('--text'); args_list.append(texto)
        else:
            path = input("Caminho do arquivo cifrado: ").strip()
            args_list.append('--file'); args_list.append(path)

        key = input(f"Chave {'(Arquivo .pem)' if tipo == 'rsa' else '(Senha)'}: ").strip()
        args_list.append('--key'); args_list.append(key)
        
        out = input("Salvar em arquivo? (Nome ou ENTER para tela): ").strip()
        if out:
            args_list.append('--output'); args_list.append(out)

    elif escolha == '3': # RSA Keys
        args_list.append('--action'); args_list.append('generate-keys')
        args_list.append('--cipher'); args_list.append('rsa')
        nome = input("Nome base (ex: minhas_chaves): ").strip()
        if nome:
            args_list.append('--output'); args_list.append(nome)

    elif escolha == '4': # Hash
        args_list.append('--action'); args_list.append('hash')
        texto = input("Texto para hash (ou ENTER para arquivo): ")
        if texto:
            args_list.append('--text'); args_list.append(texto)
        else:
            path = input("Caminho do arquivo: ").strip()
            args_list.append('--file'); args_list.append(path)
        
        out = input("Salvar hash em arquivo? (Nome ou ENTER): ").strip()
        if out:
            args_list.append('--output'); args_list.append(out)

    elif escolha == '5': # Check Hash
        args_list.append('--action'); args_list.append('check-hash')
        texto = input("Texto/Arquivo original: ")
        if os.path.exists(texto):
            args_list.append('--file'); args_list.append(texto)
        else:
            args_list.append('--text'); args_list.append(texto)
        orig = input("Cole o Hash Original: ").strip()
        args_list.append('--key'); args_list.append(orig)

    elif escolha == '6': # DFH
        sub = input("1. Gerar Chaves\n2. Derivar Segredo\nOpção: ").strip()
        if sub == '1':
            args_list.append('--action'); args_list.append('dh-generate')
            nome = input("Nome (ex: alice): ").strip()
            if nome: args_list.append('--output'); args_list.append(nome)
        else:
            args_list.append('--action'); args_list.append('dh-derive')
            priv = input("Sua chave privada (.dh): ").strip()
            pub = input("Chave pública do outro (.dh): ").strip()
            args_list.append('--key'); args_list.append(priv)
            args_list.append('--public-key'); args_list.append(pub)
            out = input("Salvar chave derivada? (Nome ou ENTER): ").strip()
            if out: args_list.append('--output'); args_list.append(out)

    elif escolha == '7': # Teste
        args_list.append('--action'); args_list.append('test')

    return parser.parse_args(args_list)

def processar_acao(args):
    """
    Executa a lógica principal baseada nos argumentos.
    Não usa sys.exit() em caso de erro, apenas retorna.
    """
    try:
        # 1. DFH
        if args.action == 'dh-generate':
            dh = DHManager()
            priv, pub = dh.gerar_chaves()
            nome = args.output if args.output else "dh"
            DHManager.salvar_param(f"{nome}_priv.dh", priv)
            DHManager.salvar_param(f"{nome}_pub.dh", pub)
            print(f"\n[SUCESSO] Gerado: {nome}_priv.dh e {nome}_pub.dh")
            return

        elif args.action == 'dh-derive':
            if not args.key or not args.public_key:
                print("Erro: Precisa de --key e --public-key")
                return
            
            p1 = DHManager.carregar_param(args.key)
            p2 = DHManager.carregar_param(args.public_key)
            dh = DHManager()
            segredo = dh.calcular_segredo_compartilhado(p1, p2)
            aes_key = SHA256Hasher.gerar_hash(segredo.encode())
            print(f"\n[SUCESSO] Chave AES Derivada: {aes_key}")
            if args.output:
                with open(args.output, 'w') as f: f.write(aes_key)
                print(f"Salvo em: {args.output}")
            return

        # 2. RSA KEYS
        elif args.action == 'generate-keys':
            print("Gerando RSA 2048 bits...")
            priv, pub = KeyManager.gerar_par_chaves_rsa()
            nome = args.output if args.output else "id_rsa"
            KeyManager.salvar_chave(f"{nome}_priv.pem", priv)
            KeyManager.salvar_chave(f"{nome}_pub.pem", pub)
            print(f"\n[SUCESSO] Gerado: {nome}_priv.pem e {nome}_pub.pem")
            return

        # 3. HASH
        elif args.action in ['hash', 'check-hash']:
            dados = b""
            if args.text: dados = args.text.encode('utf-8')
            elif args.file:
                if not os.path.exists(args.file):
                    print(f"Erro: Arquivo '{args.file}' não encontrado.")
                    return
                with open(args.file, 'rb') as f: dados = f.read()
            else:
                print("Erro: Precisa de texto ou arquivo.")
                return

            if args.action == 'hash':
                res = SHA256Hasher.gerar_hash(dados)
                print(f"\nHash SHA-256: {res}")
                if args.output:
                    with open(args.output, 'w') as f: f.write(res)
                    print(f"Salvo em: {args.output}")
            else:
                if not args.key: 
                    print("Erro: Cole o hash original em Key")
                    return
                valido = SHA256Hasher.verificar_integridade(dados, args.key)
                print(f"\nIntegridade: {'VÁLIDO' if valido else 'INVÁLIDO'}")
            return

        # 4. CRIPTOGRAFIA (AES/RSA)
        elif args.action in ['encrypt', 'decrypt']:
            if not args.key:
                print("Erro: Chave obrigatória.")
                return
            
            motor = None
            if args.cipher == 'aes':
                motor = AESCipher(KeyManager.formatar_chave_simetrica(args.key))
            elif args.cipher == 'rsa':
                if not os.path.exists(args.key):
                    print(f"Erro: Arquivo '{args.key}' não encontrado.")
                    return
                motor = RSACipher(KeyManager.carregar_chave_arquivo(args.key))

            dados_in = b""
            if args.text:
                dados_in = binascii.unhexlify(args.text) if args.action == 'decrypt' else args.text.encode('utf-8')
            elif args.file:
                if not os.path.exists(args.file):
                    print(f"Erro: Arquivo '{args.file}' não encontrado.")
                    return
                with open(args.file, 'rb') as f: dados_in = f.read()
            else:
                print("Erro: Informe --text ou --file")
                return
            
            if args.action == 'encrypt':
                txt = dados_in.decode('utf-8', 'ignore') if args.cipher == 'rsa' else dados_in.decode('utf-8')
                nonce, cifrado = motor.encriptar(txt)
                final = (nonce if nonce else b"") + cifrado
                if args.output:
                    with open(args.output, 'wb') as f: f.write(final)
                    print(f"\n[SUCESSO] Salvo em: {args.output}")
                else:
                    print(f"\nResultado (Hex): {binascii.hexlify(final).decode()}")
            else:
                if args.cipher == 'aes':
                    nonce, cifrado = dados_in[:16], dados_in[16:]
                    res = motor.decriptar(nonce, cifrado)
                else:
                    res = motor.decriptar(None, dados_in)
                
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f: f.write(res)
                    print(f"\n[SUCESSO] Salvo em: {args.output}")
                else:
                    print(f"\nDecriptado: {res}")
            return

        elif args.action == 'test':
            rodar_teste_criterio_conclusao()
            return

    except Exception as e:
        print(f"\n[ERRO]: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="O ENCRIPTADOR - Sistema Completo",
        epilog="Use --help para ver opções de linha de comando."
    )

    grupo_acao = parser.add_argument_group('Ações')
    grupo_config = parser.add_argument_group('Configurações')
    grupo_io = parser.add_argument_group('Entrada/Saída')

    grupo_acao.add_argument('--action', choices=['encrypt', 'decrypt', 'generate-keys', 'hash', 'check-hash', 'test', 'dh-generate', 'dh-derive'], help="Ação a realizar.")
    grupo_config.add_argument('--cipher', choices=['aes', 'rsa'], default='aes', help="Algoritmo.")
    grupo_config.add_argument('--key', help="Chave.")
    grupo_config.add_argument('--public-key', help="Chave Pública (DFH).")
    grupo_io.add_argument('--text', help="Texto de entrada")
    grupo_io.add_argument('--file', help="Arquivo de entrada")
    grupo_io.add_argument('--output', help="Arquivo de saída.")

    # --- LÓGICA DE DETECÇÃO DO MODO ---
    
    # MODO CLI (Argumentos passados na linha de comando) -> Roda uma vez e sai.
    if len(sys.argv) > 1:
        args = parser.parse_args()
        processar_acao(args)
    
    # MODO INTERATIVO (Sem argumentos / Duplo clique) -> Roda em Loop.
    else:
        while True:
            # 1. Mostra menu e pega args
            args = modo_interativo(parser)
            
            # 2. Executa a ação
            print("\n" + "*"*40)
            processar_acao(args)
            print("*"*40 + "\n")
            
            # 3. Pausa antes de voltar ao menu
            input("Pressione ENTER para voltar ao menu...")

if __name__ == "__main__":
    main()