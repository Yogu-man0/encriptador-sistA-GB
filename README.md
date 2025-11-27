# O Encriptador

Projeto de software desenvolvido para a disciplina de **Engenharia de Sistemas A**.
Uma ferramenta de linha de comando (CLI) para criptografia simétrica, assimétrica e verificação de integridade via hash.

**Alunos:**
 Gabriel Passos
 Barbara Alves

---

## Funcionalidades Implementadas

O projeto encontra-se na fase de conclusão do **Sprint 3**. As seguintes funcionalidades já estão operacionais:

### Criptografia Simétrica (AES)
* **Algoritmo:** AES (Advanced Encryption Standard).
* **Funcionalidades:** Encriptação e Decriptação.
* **Chaves:** Aceita senhas de texto (formatadas automaticamente para 128 bits).
* **Segurança:** Utiliza modo autenticado (EAX) com geração de Nonce aleatório.

### Criptografia Assimétrica (RSA)
* **Algoritmo:** RSA (Rivest–Shamir–Adleman).
* **Geração de Chaves:** Cria par de chaves (Pública/Privada) de 2048 bits em arquivos `.pem`.
* **Cifragem:** Encripta dados usando a **Chave Pública**.
* **Decifragem:** Decripta dados usando a **Chave Privada**.

### Hashing e Integridade (SHA-256)
* **Algoritmo:** SHA-256.
* **Geração:** Cria resumos (hashes) de textos ou arquivos.
* **Verificação:** Compara um hash original com o conteúdo atual para validar integridade (`check-hash`).

### Interface de Linha de Comando (CLI)
* Suporte a entrada direta de texto via `--text`.
* Suporte a leitura de arquivos via `--file`.
* Suporte a salvamento de resultado em arquivo via `--output`.
* Menu de ajuda automático (`--help`).

---

## 🛠️ Instalação e Dependências

O projeto foi desenvolvido em **Python 3**. A criptografia depende da biblioteca `pycryptodome`.

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/Yogu-man0/encriptador-sistA-GB.git](https://github.com/Yogu-man0/encriptador-sistA-GB.git)
   cd encriptador-sistA-GB
