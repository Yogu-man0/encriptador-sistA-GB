Representa o primeiro esboço do sistema do projeto.

[ Usuário ]
     |
     
     v
     
[ 1. Interface CLI (main.py + argparse) ]

     |
     
     +--> (Coleta: arquivo, texto, cifra, chave, modo...)
     
     |
     
     v
     
[ 2. Orquestrador Principal (main() function) ]

     |
     
     +--> (Lê os dados de entrada: helpers.read_file() ou args.texto)
     
     |
     
     +--> "Qual cifra foi pedida?"
     
     |
     
     v
     
[ 3. Fábrica de Operações (CipherFactory) ]

     |
     
     +--> (Se "AES") --> [ 4a. Módulo AESCipher ]
     
     |
     
     +--> (Se "RSA") --> [ 4b. Módulo RSACipher ]
     
     |
     
     +--> (Se "SHA") --> [ 4c. Módulo SHA256Hasher ]
     
     |
     
     v
     
[ 5. Execução da Operação ]
     |
     
     +--> (O módulo escolhido processa os dados)
     
     |
     
     v
     
[ 6. Saída (Orquestrador) ]
     |
     +--> (Se args.output) --> [ helpers.write_file() ]
     |
     +--> (Senão)         --> [ print() para o console ]
