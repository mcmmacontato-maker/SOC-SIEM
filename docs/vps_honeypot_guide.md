# 🛡️ Guia Completo — VPS Honeypot para SOC-SIEM

> Configure um servidor Linux na nuvem para capturar **ataques SSH reais** e alimentar seu SIEM com dados verdadeiros de brute-force, credential stuffing e reconhecimento.

---

## 1. Criando o VPS (Gratuito)

### Opção A — Oracle Cloud Free Tier (recomendado, grátis para sempre)
1. Acesse [cloud.oracle.com](https://cloud.oracle.com) → **Start for free**
2. Criar conta (precisa de cartão, mas não cobra)
3. **Compute → Instances → Create Instance**
   - Image: **Ubuntu 22.04**
   - Shape: VM.Standard.E2.1.Micro (Always Free)
   - Adicione sua chave pública SSH
4. Em **Networking → Security Lists → Ingress Rules**, libere a porta **22/TCP** (já vem aberta)
5. Anote o **IP público** da instância

### Opção B — DigitalOcean Droplet (~R$14/mês)
```bash
# Via CLI (doctl):
doctl compute droplet create honeypot \
  --image ubuntu-22-04-x64 \
  --size s-1vcpu-1gb \
  --region nyc1 \
  --ssh-keys SEU_KEY_ID
```

### Opção C — Google Cloud Free Tier
- Compute Engine → e2-micro (us-central1/us-east1/us-west1) → FREE forever
- Disco 30GB HDD grátis

---

## 2. Configurando o Honeypot

Copie e execute no VPS como root:

```bash
# Copiar script de setup via scp
scp vps_setup.sh root@SEU_IP:/tmp/

# Executar no VPS
ssh root@SEU_IP "bash /tmp/vps_setup.sh"
```

O script irá:
- ✅ Habilitar autenticação SSH por **senha** (atrai atacantes)
- ✅ Ativar logging **VERBOSE** no sshd
- ✅ **Desativar fail2ban** (queremos ver TODOS os ataques)
- ✅ Configurar UFW com portas estratégicas abertas
- ✅ Criar comando `honeypot-status` para monitoramento local

> ⚠️ **IMPORTANTE**: Este servidor é um honeypot — NÃO guarde dados pessoais ou sensíveis nele.

---

## 3. Iniciando a Coleta no SIEM Local

### Instalar dependência SSH

```bash
pip install paramiko
```

### Conectar e coletar (escolha um método):

```bash
# Com chave SSH (recomendado)
python vps_collector.py --host SEU_IP --user root --key C:\Users\SeuUsuario\.ssh\id_rsa

# Com senha
python vps_collector.py --host SEU_IP --user ubuntu --password SuaSenha

# Com histórico maior (últimas 2000 linhas)
python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa --history 2000

# Somente eventos novos (sem histórico)
python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa --no-history
```

### Em paralelo, rodar o SIEM

```bash
# Terminal 1 — SIEM Dashboard
python app.py

# Terminal 2 — Coletor VPS
python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa
```

Acesse: **http://localhost:5000**

---

## 4. O Que Esperar

| Tempo após expo à internet | O que acontece |
|---|---|
| **< 5 min** | Primeiros port scans (Shodan, Censys) |
| **5–30 min** | Primeiras tentativas SSH (bots automáticos) |
| **1–2 hora** | Dezenas de IPs diferentes tentando brute-force |
| **24 horas** | Centenas de IPs, usernames comuns: `root`, `admin`, `pi`, `ubuntu` |
| **1 semana** | Milhares de eventos, patterns claros de ataque |

### Usernames mais comuns que bots tentam
```
root, admin, ubuntu, pi, oracle, postgres, user, test,
guest, support, ftpuser, mysql, deploy, git, jenkins
```

---

## 5. Regras de Detecção Que Vão Disparar

Com dados reais, as seguintes regras do SIEM vão acionar:

| Regra | Quando dispara |
|-------|---------------|
| **SSH-001** | Múltiplas falhas do mesmo IP (brute-force) |
| **SSH-002** | Login bem-sucedido após falhas (credential stuffing) |

> Se SSH-002 disparar: **alerta crítico** — uma credencial foi comprometida.

---

## 6. Para o Portifólio

Screenshots que valem ouro:
1. **Dashboard com IPs reais** de múltiplos países atacando
2. **Relatório IR-0001** gerado automaticamente após um brute-force real
3. **Terminal do vps_collector** mostrando ataques chegando em tempo real
4. **Gráfico de timeline** com pico de ataques em horários específicos

### Frase para o README do portifólio
> "Mini-SIEM com coleta de logs em tempo real de um servidor honeypot exposto à internet. Detecta brute-force SSH com regras SIGMA-like mapeadas ao MITRE ATT&CK T1110.001, gera alertas automáticos e relatórios de Incident Response."

---

## 7. Segurança do Honeypot

- **Nunca use senhas reais** no VPS (deixe bots tentarem senhas genéricas)
- **Não acesse** serviços internos a partir do VPS honeypot
- **Monitore** o uso de CPU/banda — bots podem tentar mineração de cripto
- **Desligue** o honeypot quando não precisar para o demo
- O VPS **não tem acesso** ao seu PC local — a coleta é unidirecional (VPS → seu SIEM)

---

## 8. Alternativa Push: Agente no VPS

Em vez de o seu PC se conectar ao VPS, o VPS pode enviar logs para o SIEM:

```bash
# No VPS — instalar e rodar o agente de push
pip3 install requests

# Configurar SIEM_URL com o IP do seu PC local (na mesma rede ou VPN)
export SIEM_URL="http://SEU_IP_LOCAL:5000/api/ingest"

# Tail e push automático
tail -F /var/log/auth.log | while read line; do
  echo "$line" | grep -q "sshd" && \
  curl -s -X POST "$SIEM_URL" \
       -H "Content-Type: application/json" \
       -d "{\"raw\": \"$(echo $line | sed 's/"/\\"/g')\"}" > /dev/null
done
```

---

*SOC-SIEM Caseiro v1.0 — Guia de Honeypot VPS*
