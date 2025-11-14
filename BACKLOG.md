Backlog do projeto de Eng Sist A - 2025.2 - UERJ

Épico 1: Interface de Linha de Comando (CLI)
Este épico cobre a interação básica do usuário com o programa via argparse.

  - HU-01 (Ajuda): Como um usuário, Eu quero poder usar os argumentos -h ou --help Para que eu possa ver todas as opções de comando e entender como usar o programa.
  
  - HU-02 (Input por Texto): Como um usuário, Eu quero fornecer um texto direto na linha de comando Para que eu possa criptografar ou descriptografar pequenos trechos de informação rapidamente.
  
  - HU-03 (Input por Arquivo): Como um usuário, Eu quero fornecer um arquivo de entrada (ex: --arquivo meu_doc.txt) Para que eu possa processar arquivos inteiros.
  
  - HU-04 (Validação de Input): Como um usuário, Eu quero receber uma mensagem de erro clara se eu não fornecer nem um texto direto nem um arquivo de entrada Para que eu saiba que usei o comando incorretamente.
  
  - HU-05 (Output para Arquivo): Como um usuário, Eu quero poder especificar um arquivo de saída (ex: --output saida.enc) Para que o resultado da operação seja salvo em disco.
  
  - HU-06 (Output para Console): Como um usuário, Eu quero que o resultado seja impresso no console se eu não especificar um arquivo de saída Para que eu possa ver o resultado imediatamente ou usá-lo em conjunto com outros programas (pipe).

Épico 2: Criptografia Simétrica (Ex: AES)
Focado nas funcionalidades de cifras que usam a mesma chave para criptografar e descriptografar.

  - HU-07 (Seleção de Cifra): Como um usuário, Eu quero poder escolher a cifra que desejo usar (ex: --cipher AES) Para que eu tenha controle sobre o método de criptografia.
  
  - HU-08 (Operação AES): Como um usuário, Eu quero poder criptografar e descriptografar meus dados usando o algoritmo AES Para que eu possa usar um padrão de indústria robusto e seguro.
  
  - HU-09 (Fornecimento de Chave): Como um usuário, Eu quero poder fornecer uma chave secreta (ex: --key "minha_senha_secreta") Para que eu possa realizar a criptografia/descriptografia simétrica.
  
  - HU-10 (Modo de Cifragem): Como um usuário, Eu quero poder especificar um modo de operação (ex: --mode CBC) ao usar uma cifra de bloco como o AES Para que eu possa controlar as propriedades de segurança da cifragem.

Épico 3: Criptografia Assimétrica (Ex: RSA)
  Focado em operações que usam um par de chaves (pública/privada).

  - HU-11 (Operação RSA - Criptografar): Como um usuário, Eu quero poder criptografar dados usando uma chave pública RSA (fornecida via --key) Para que apenas o detentor da chave privada correspondente possa lê-los.
  
  - HU-12 (Operação RSA - Descriptografar): Como um usuário, Eu quero poder descriptografar dados usando uma chave privada RSA (fornecida via --key) Para que eu possa ler dados que foram criptografados com minha chave pública.
  
  - HU-13 (Carregar Chave de Arquivo): Como um usuário, Eu quero que o argumento --key aceite um caminho de arquivo (ex: --key ./id_rsa.pub) Para que eu possa usar chaves (públicas ou privadas) salvas em disco de forma segura.

Épico 4: Geração de Chaves
  Funcionalidade separada para criar os artefatos necessários para a criptografia assimétrica.

  - HU-14 (Geração de Par de Chaves): Como um usuário, Eu quero ter um comando (ex: python crypto.py generate-rsa) Para que eu possa criar um novo par de chaves pública e privada para usar com RSA.
  
  - HU-15 (Salvar Chaves Geradas): Como um usuário, Eu quero que as chaves geradas sejam salvas em arquivos (ex: id_rsa e id_rsa.pub) Para que eu possa gerenciá-las e distribuí-las facilmente.

Épico 5: Hashing (Ex: SHA-256)
  Focado na geração de hashes (resumos) de dados.

  - HU-16 (Operação de Hash): Como um usuário, Eu quero poder gerar um hash SHA-256 do meu input (texto ou arquivo) Para que eu possa verificar a integridade dos dados ou criar uma assinatura.

Épico 6: Empacotamento e Distribuição (Build)
  Estas são "Histórias Técnicas", focadas na equipe de desenvolvimento, não no usuário final, mas cruciais para o projeto.

  - HU-17 (Build Windows): Como um desenvolvedor, Eu quero empacotar o programa em um executável .exe para Windows Para que usuários de Windows possam rodar a ferramenta sem instalar o Python.
  
  - HU-18 (Build Linux): Como um desenvolvedor, Eu quero empacotar o programa em um executável binário para Linux Para que usuários de Linux possam rodar a ferramenta facilmente em seus sistemas.

Backlog gerado com o auxilio do Gemini (para formatação de texto).
