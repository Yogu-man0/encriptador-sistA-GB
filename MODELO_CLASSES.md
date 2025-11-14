main.py - script principal
  setup_parser(): Função que cria e configura o argparse.ArgumentParser com todas as suas regras.

  main():
 - Chama setup_parser().parse_args().
 - Valida os argumentos (ex: se a chave é necessária para a cifra pedida).
 - Lê os dados de entrada (usando FileHelper).
 - Chama CipherFactory.get_operation(args.cipher).
 - Chama o método do objeto retornado (ex: operation.execute(data, args.key, args.mode)).
 - Gerencia a saída (console ou arquivo, usando FileHelper).

factory.py (Módulo da Fábrica)
  Classe CipherFactory:
  
  - Método estático get_operation(cipher_name: str):
  - Se cipher_name == "AES", retorna return AESCipher().
  - Se cipher_name == "RSA", retorna return RSACipher().
  - Se cipher_name == "SHA-256", retorna return SHA256Hasher().
  - Senão, levanta um erro ValueError("Cifra desconhecida").

ciphers/ (Pacote com as implementações)

  Classe AESCipher:
  
  - encrypt(data: bytes, key: str, mode: str) -> bytes: Implementa a lógica de criptografia AES.
  - decrypt(data: bytes, key: str, mode: str) -> bytes: Implementa a descriptografia.

  Classe RSACipher:
  
  - encrypt(data: bytes, public_key_path: str) -> bytes: Lê a chave pública do arquivo e criptografa.
  - decrypt(data: bytes, private_key_path: str) -> bytes: Lê a chave privada e descriptografa.
  - generate_keys(output_path: str): Gera o par de chaves e salva nos arquivos.

  Classe SHA256Hasher:
  
  - hash(data: bytes) -> str: Calcula o hash SHA-256 e retorna como uma string hexadecimal.

helpers.py (Módulo de Utilitários)
  Classe FileHelper:
  
  - Método estático read_file_bytes(path: str) -> bytes: Lê um arquivo em modo binário ('rb').
  - Método estático write_file_bytes(path: str, data: bytes): Escreve dados binários em um arquivo ('wb').

Classe KeyHelper:

  Método estático load_key_from(key_arg: str) -> str | bytes:
  
  - Tenta verificar se key_arg é um caminho de arquivo.
  - Se for, lê o arquivo (como texto ou bytes, dependendo da necessidade).
  - Se não for, assume que o próprio key_arg é a chave/senha.
