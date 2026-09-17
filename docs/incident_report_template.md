# Relatório de Incidente — IR-XXXX

**Data de Geração:** YYYY-MM-DD HH:MM UTC  
**Classificação:** [CRITICAL / HIGH / MEDIUM]  
**Status:** ABERTO / FECHADO  
**Analista Responsável:** [Nome / SOC-Bot]  

---

## 1. Sumário Executivo

> Descreva em 2-3 linhas o que aconteceu, quando e o impacto potencial.

---

## 2. Detalhes do Incidente

| Campo              | Valor                        |
|--------------------|------------------------------|
| ID do Incidente    | IR-XXXX                      |
| Severidade         | [CRITICAL/HIGH/MEDIUM/LOW]   |
| IP de Origem       | x.x.x.x                      |
| IP de Destino      | x.x.x.x                      |
| Regra Disparada    | Nome da regra SIEM           |
| Tática MITRE       | Ex: Initial Access           |
| Técnica MITRE      | Ex: T1110.001                |
| Timestamp Inicial  | YYYY-MM-DDTHH:MM:SSZ         |
| Timestamp Final    | YYYY-MM-DDTHH:MM:SSZ         |

---

## 3. Timeline do Incidente

| Timestamp | Evento | Analista |
|-----------|--------|----------|
| HH:MM     | Alerta disparado pelo SIEM | SOC-Bot |
| HH:MM     | Incidente criado e triado | [Analista] |
| HH:MM     | IP bloqueado no firewall | [Analista] |
| HH:MM     | Investigação iniciada | [Analista] |
| HH:MM     | Contenção confirmada | [Analista] |

---

## 4. Evidências Coletadas

- [ ] Logs de autenticação (`/var/log/auth.log`)
- [ ] Logs do servidor web (`/var/log/nginx/access.log`)
- [ ] Dump de processos em execução
- [ ] Lista de conexões ativas (netstat)
- [ ] Hashes de arquivos modificados

---

## 5. Análise de Causa Raiz

> O que permitiu que o ataque ocorresse?
> Que vulnerabilidade ou fraqueza foi explorada?

---

## 6. Contenção e Erradicação

### Ações Tomadas
- [ ] IP bloqueado no firewall: `iptables -A INPUT -s X.X.X.X -j DROP`
- [ ] Sessões SSH encerradas
- [ ] Credenciais comprometidas rotacionadas
- [ ] Serviço afetado reiniciado em modo seguro

---

## 7. Indicadores de Comprometimento (IoCs)

| Tipo | Valor | Confiança |
|------|-------|-----------|
| IP   | x.x.x.x | Alta |
| User-Agent | sqlmap/1.7 | Alta |
| Hash MD5 | abc123... | Média |

---

## 8. Lições Aprendidas

- [ ] O que pode ser melhorado no processo de detecção?
- [ ] Alguma regra precisa ser ajustada (falso positivo/negativo)?
- [ ] Qual controle preventivo teria evitado o incidente?

---

## 9. Ações de Melhoria

| Ação | Responsável | Prazo |
|------|-------------|-------|
| Implementar Fail2Ban | Ops | 3 dias |
| Adicionar MFA para SSH | SecEng | 1 semana |
| Atualizar regra de detecção | SOC | 2 dias |

---

*Template de Incident Response — SOC-SIEM Caseiro v1.0*
