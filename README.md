# O Encriptador

Projeto de software desenvolvido para a disciplina de **Engenharia de Sistemas A**.
Ferramenta completa de segurança que implementa algoritmos simétricos, assimétricos, hashing e protocolos de troca de chaves.

**Alunos:**
* Gabriel Passos
* Barbara Alves

---

## 🚀 Funcionalidades (Sprint 3 Finalizada)

* **AES (Simétrico):** Encriptação autenticada (EAX) de mensagens e arquivos.
* **RSA (Assimétrico):** Geração de chaves (2048 bits) e criptografia segura.
* **Diffie-Hellman (DFH):** Protocolo para troca segura de chaves em canais públicos.
* **SHA-256 (Hashing):** Verificação de integridade de arquivos e assinaturas.
* **Interface Dual:** Menu interativo (para iniciantes) e CLI robusta (para automação).

---

## 🛠️ Instalação e Execução

### Opção 1: Executável (Windows)
Não requer Python instalado. Baixe o arquivo na aba **Releases**.
* **Modo Menu:** Dê duplo clique no `O Encriptador.exe`.
* **Modo Comando:** Abra o terminal na pasta e rode `O Encriptador.exe --help`.

### Opção 2: Código Fonte (Linux/Mac/Windows)
Requer Python 3.

```bash
# 1. Clone e entre na pasta
git clone [https://github.com/Yogu-man0/encriptador-sistA-GB.git](https://github.com/Yogu-man0/encriptador-sistA-GB.git)
cd encriptador-sistA-GB

# 2. Instale dependências
pip install -r requirements.txt

# 3. Execute
python main.py
