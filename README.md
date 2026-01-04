cat <<EOF > README.md
# 💀 NEMESIS V2.1 (God Mode)

**NEMESIS** é um orquestrador de ataque para Bug Bounty. Ele automatiza todo o processo de Reconhecimento, Detecção de WAF e Escaneamento de Vulnerabilidades em múltiplos subdomínios simultaneamente.

## ⚡ Funcionalidades
* **Multi-Source Recon:** Coleta subdomínios via crt.sh, HackerTarget e AlienVault.
* **WAF Detector:** Identifica Cloudflare, AWS e Akamai.
* **Ghost Mode:** Tenta bypass automático de erro 403 usando Headers Spoofing.
* **Interactive Mode:** Interface simples, basta rodar e digitar o alvo.

## 📦 Instalação
\`\`\`bash
git clone https://github.com/brunopark852/nemesis-scanner.git
cd nemesis-scanner
pip install requests
\`\`\`

## 🚀 Uso
\`\`\`bash
# Modo Interativo (Recomendado)
python3 nemesis.py

# Modo CLI
python3 nemesis.py tesla.com -t 30
\`\`\`

---
**Autor:** Bruno Rodrigo
