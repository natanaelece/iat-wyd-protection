# Testes

A validação deve separar P1 (IAT) de P2 (inline) e provar que o gate permanece fail-closed.

## 1. Baseline real

No mesmo build do cliente:

```text
P1 GetAdaptersInfo=CLEAN
P1 connect=CLEAN
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
ALLOWED=true
```

O cliente deve continuar normalmente.

## 2. Diferenciais P1

Cada IAT protegida deve conseguir bloquear sozinha:

| P1 GetAdaptersInfo | P1 connect | Esperado |
|---|---|---|
| `ANOMALY` | `CLEAN` | `BLOCK` |
| `CLEAN` | `ANOMALY` | `BLOCK` |
| `ANOMALY` | `ANOMALY` | `BLOCK` |

O bloqueio deve acontecer antes de `ConnectServer`.

## 3. Harness P2 mínimo

Valide pelo menos:

| Caso | Esperado |
|---|---|
| baseline do sistema | `CLEAN` |
| bytes sintéticos idênticos | `CLEAN` |
| diferença inline estilo `E9` | `ANOMALY` |
| diferença não coberta por relocation | `ANOMALY` |
| diferença coberta por máscara de relocation | `CLEAN` |
| falha de resolução | `RESOLUTION_ERROR` |

A máscara sintética comprova a semântica de `EvaluateWindow`; ela não substitui uma fixture PE diferencial específica do parser de relocations.

## 4. Reauditoria por tentativa

```text
PER_LOGIN_REAUDIT_STATICALLY_REQUIRED=true
```

A integração deve provar estaticamente que:

```text
P1 e P2 estão dentro de B_LOGIN_OK
clientIntegrityAllowed é decisão local da tentativa
clientIntegrityCheckCompleted não existe
P1/P2 executam antes de ConnectServer e GetAdaptersInfo do login
```

Um novo processo não é prova dinâmica de segundo clique no mesmo processo.

## 5. Resultado visual para BLOCK

![Resultado visual esperado após bloqueio](images/integrity-blocked-login.png)

```text
Falha na verificacao de integridade do cliente.
```

## 6. Evidência de laboratório preservada

No build de laboratório validado contra Medusa WP 1.097:

```text
DIRECT:
P1 GetAdaptersInfo=CLEAN
P1 connect=CLEAN
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
ALLOWED=true

MEDUSA:
P1 GetAdaptersInfo=ANOMALY
P1 connect=ANOMALY
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
ALLOWED=false
```

Esse resultado demonstra que o caminho runtime exercitado foi bloqueado pelo P1. Como P2 permaneceu `CLEAN`, o fallback inline não foi exercitado nessa passagem.

## 7. Interpretação correta

- `P2=CLEAN` com P1 `ANOMALY` não é falha de P2 quando não houve patch inline.
- `RESOLUTION_ERROR` bloqueia por indisponibilidade da verificação, mas não deve ser rotulado automaticamente como ataque.
- resultados valem apenas para o cliente/build/teste exatos.
- não generalize para o binário oficial do Exordion sem comparação explícita.

## 8. Cleanup

Remova qualquer instrumentação temporária usada para provocar anomalias e repita o baseline limpo antes de considerar o build final aprovado.
