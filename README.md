# WYD Client Integrity Protection

Proteção client-side em C++ para clientes **WYD Win32/x86** contra adulteração de `GetAdaptersInfo` e `connect` antes do login.

A versão atual usa duas camadas complementares:

- **P1 — IAT integrity:** detecta quando a entrada da Import Address Table deixa de apontar para a implementação autorizada.
- **P2 — inline integrity:** valida a integridade do código inicial da implementação final autorizada usando a própria imagem PE correspondente como referência.

P1 e P2 são reavaliados **em toda tentativa de login**. O login só continua quando todos os registros das duas camadas retornam `CLEAN`.

## Modelo de proteção

```text
P1: IAT aponta para a implementação autorizada?
        |
        +-- não -> BLOCK
        |
        +-- sim
             |
             v
P2: código inicial da implementação autorizada continua íntegro?
        |
        +-- não -> BLOCK
        |
        +-- sim -> ALLOW
```

Estados possíveis por API:

```text
CLEAN
ANOMALY
RESOLUTION_ERROR
```

A política é fail-closed: `ANOMALY` e `RESOLUTION_ERROR` bloqueiam o login; `RESOLUTION_ERROR` não deve ser classificado automaticamente como ataque.

O bloqueio deve ocorrer antes de `ConnectServer` e antes da consulta de `GetAdaptersInfo` usada pelo fluxo de login.

## APIs protegidas

- `IPHLPAPI.DLL!GetAdaptersInfo`
- `WSOCK32.dll!connect`
- `WS2_32.dll!connect`

## Resultado visual esperado

![Bloqueio de integridade no login](docs/images/integrity-blocked-login.png)

```text
Falha na verificacao de integridade do cliente.
```

## Estrutura

```text
iat-wyd-protection/
├─ src/
│  ├─ P1IatAudit.h
│  ├─ P1IatAudit.cpp
│  ├─ P2InlineAudit.h
│  └─ P2InlineAudit.cpp
├─ examples/
│  ├─ TMSelectServerScene_GATE_SNIPPET.cpp
│  ├─ TMProject.vcxproj_SNIPPETS.xml
│  └─ TMProject.vcxproj.filters_SNIPPETS.xml
├─ docs/
│  ├─ IMPLEMENTATION.md
│  ├─ TESTING.md
│  ├─ PROVENANCE.md
│  └─ images/
│     └─ integrity-blocked-login.png
├─ .github/workflows/
│  ├─ validate.yml
│  └─ release.yml
└─ LICENSE
```

## Implementação rápida

1. copie os quatro arquivos de `src/` para o projeto do cliente;
2. adicione P1 e P2 ao `.vcxproj`;
3. inclua `P1IatAudit.h` e `P2InlineAudit.h` no handler de login;
4. execute P1 e P2 em cada `B_LOGIN_OK`;
5. permita o login somente quando todos os resultados forem `CLEAN`;
6. bloqueie antes de `ConnectServer` em qualquer outro estado;
7. compile como Win32/x86 e execute a matriz de testes.

Guia: **[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)**  
Testes: **[docs/TESTING.md](docs/TESTING.md)**  
Proveniência e validação: **[docs/PROVENANCE.md](docs/PROVENANCE.md)**

## Evidência de validação

Em validação controlada do mesmo build Win32/x86:

```text
BASELINE:
P1 GetAdaptersInfo=CLEAN
P1 connect=CLEAN
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
ALLOW=true

IAT ALTERADA:
P1=ANOMALY
BLOCK=true

INLINE SINTÉTICO:
P2=ANOMALY
BLOCK=true
```

O P1 e o P2 são controles complementares: uma alteração exclusivamente na IAT pode ser detectada pelo P1 enquanto o P2 permanece `CLEAN`; uma alteração inline na implementação final pode ser detectada pelo P2 mesmo quando a IAT permanece legítima.

## Compatibilidade

A integração deve ser compilada e validada no build exato do cliente em que será utilizada.

## Release atual

A release **v2.0.0 — P1 + P2** publica um ZIP com os arquivos atuais de proteção, exemplos e documentação, acompanhado por um arquivo de checksums SHA-256.

## Licença

Consulte [LICENSE](LICENSE).
