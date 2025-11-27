# O Encriptador

Projeto de criptografia para a disciplina de Engenharia de Sistemas A.

## Funcionalidades Implementadas (Sprint Atual)
- [x] Estrutura base do projeto e Interfaces (`src/interfaces.py`).
- [x] Gerenciador de Chaves com formatação 128-bits - HU-09 (`src/key_manager.py`).
- [x] Algoritmo AES (Simétrico) - HU-08 (`src/ciphers/aes_cipher.py`).

## Planejamento do Próximo Sprint (Sprint 3)

**Objetivo:** Implementar criptografia assimétrica e hashing para garantir integridade e confidencialidade avançada.

### Backlog do Sprint 3:
1.  **Criptografia RSA (Épico 3)**
    * Implementar geração de chaves Pública/Privada (HU-14).
    * Implementar cifragem com chave pública (HU-11).
    * Implementar decifragem com chave privada (HU-12).
    * Adicionar classe `RSACipher` em `src/ciphers/`.

2.  **Hashing SHA-256 (Épico 5)**
    * Implementar geração de hash de textos e arquivos (HU-16).
    * Adicionar verificação de integridade na CLI.

3.  **Melhorias na CLI (Épico 1)**
    * Adicionar suporte a leitura de arquivos (`--file`) (HU-03).
    * Adicionar suporte a salvamento em arquivo (`--output`) (HU-05).

Feito com o auxilio do Gemini.
