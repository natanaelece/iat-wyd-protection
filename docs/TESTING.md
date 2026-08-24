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

## 6. Diferenciais combinados

Valide separadamente os mecanismos cobertos:

```text
IAT alterada, implementação final intacta:
P1=ANOMALY
P2=CLEAN
ALLOWED=false

IAT legítima, bytes inline alterados:
P1=CLEAN
P2=ANOMALY
ALLOWED=false
```

`P2=CLEAN` junto com `P1=ANOMALY` não é falha de P2 quando a alteração ocorreu somente na IAT.

## 7. Interpretação correta

- `RESOLUTION_ERROR` bloqueia por indisponibilidade da verificação, mas não deve ser rotulado automaticamente como ataque.
- os resultados valem apenas para o cliente/build/teste exatos.
- cada novo cliente ou build deve executar novamente baseline, diferenciais e regressão.

## 8. Cleanup

Remova qualquer instrumentação temporária usada para provocar anomalias e repita o baseline limpo antes de considerar o build final aprovado.
