# WYD Client Integrity Protection

Proteção client-side em C++ para clientes **WYD Win32/x86** contra adulteração de `GetAdaptersInfo` e `connect` antes do login.

A versão atual usa duas camadas complementares:

- **P1 — IAT integrity:** detecta quando a entrada da Import Address Table deixa de apontar para a implementação autorizada.
- **P2 — inline integrity:** resolve a implementação final autorizada e compara os primeiros 32 bytes carregados em memória com a mesma imagem PE em disco, mascarando relocations aplicáveis.

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
├─ SHA256SUMS
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
Proveniência e limites de evidência: **[docs/PROVENANCE.md](docs/PROVENANCE.md)**

## Evidência atual

A implementação P1 pública permanece byte-idêntica ao P1 validado no laboratório. O P2 publicado nesta atualização é byte-idêntico ao P2 promovido para `main` em `natanaelece/medusa-wyd-server`.

No build de laboratório validado:

```text
DIRECT:
P1 GetAdaptersInfo=CLEAN
P1 connect=CLEAN
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
ALLOW=true

MEDUSA WP 1.097:
P1 GetAdaptersInfo=ANOMALY
P1 connect=ANOMALY
P2 GetAdaptersInfo=CLEAN
P2 connect=CLEAN
BLOCK=true
```

O caminho inline não foi exercitado pela passagem runtime citada; a cobertura P2 para esse caso permanece baseada em baseline real limpo + análise estática + harness sintético reversível.

## Limitações

- target atual: Win32/x86;
- P2 compara uma janela inicial de 32 bytes e exige pelo menos 16 bytes não mascarados;
- alteração fora dessa janela pode não ser detectada;
- há uma janela TOCTOU entre a auditoria e o uso posterior da API;
- mecanismos out-of-process, como redirecionamento por driver/túnel, não são cobertos por P1/P2;
- verificações executadas dentro do próprio processo não são uma raiz autônoma de confiança.

## Fronteira de evidência

Este repositório distribui uma implementação genérica para clientes com código-fonte disponível. Resultados de laboratório se aplicam somente ao build/teste exatos correspondentes e **não estabelecem equivalência com o binário oficial do WYD do Exordion**.

## SHA256SUMS

`SHA256SUMS` preserva o hash do pacote de integração P1 publicado anteriormente. Ele é um artefato histórico e não representa automaticamente o conteúdo P1+P2 atual de `main`.

## Licença

Consulte [LICENSE](LICENSE).
