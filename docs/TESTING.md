# Testes

A validação deve provar que cada API protegida consegue bloquear de forma independente.

## Matriz mínima

| Cenário | GetAdaptersInfo | connect | Resultado |
|---|---|---|---|
| Baseline | CLEAN | CLEAN | ALLOW |
| Adaptador/MAC isolado | ANOMALY | CLEAN | BLOCK |
| Proxy/conexão isolado | CLEAN | ANOMALY | BLOCK |
| Ambos alterados | ANOMALY | ANOMALY | BLOCK |
| Regressão final | CLEAN | CLEAN | ALLOW |

## Resultado visual esperado para BLOCK

Em qualquer cenário `BLOCK`, ao clicar em `Login`, a execução deve parar antes de `ConnectServer` e a interface deve exibir:

![Resultado visual esperado após bloqueio](images/integrity-blocked-login.png)

```text
Falha na verificacao de integridade do cliente.
```

## 1. Baseline

Compile o cliente sem instrumentação de teste e faça login normalmente.

Esperado:

```text
GetAdaptersInfo=CLEAN
connect=CLEAN
ALLOWED=true
```

## 2. GetAdaptersInfo isolado

Em ambiente de teste autorizado, altere somente a entrada protegida de `GetAdaptersInfo`, mantendo `connect` intacto.

Esperado:

```text
GetAdaptersInfo=ANOMALY
connect=CLEAN
ALLOWED=false
```

O login deve parar antes de `ConnectServer`.

## 3. connect isolado

Restaure `GetAdaptersInfo` e altere somente `connect`.

Esperado:

```text
GetAdaptersInfo=CLEAN
connect=ANOMALY
ALLOWED=false
```

O login deve parar antes de `ConnectServer`.

## 4. Cleanup e regressão

Remova toda instrumentação temporária, recompile e repita o baseline.

Esperado:

```text
GetAdaptersInfo=CLEAN
connect=CLEAN
ALLOWED=true
```

Esse último teste confirma que a instrumentação usada para validar o bloqueio não permaneceu no cliente final.
