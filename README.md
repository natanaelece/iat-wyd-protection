# WYD Client IAT Protection

Proteção client-side em C++ para clientes **WYD** contra adulteração de APIs sensíveis antes do login.

A implementação verifica a **Import Address Table (IAT)** e bloqueia o fluxo de login quando `GetAdaptersInfo` ou `connect` deixam de apontar para implementações autorizadas.

## O que ela protege

Uma DLL injetada pode redirecionar funções que o cliente já usa normalmente:

```text
WYD.exe
  ├─ GetAdaptersInfo -> IPHLPAPI.DLL
  └─ connect         -> WSOCK32.dll / WS2_32.dll
```

Depois de um IAT hook, o cliente continua chamando as mesmas APIs, mas passa primeiro por código injetado.

### Manipulação de adaptador / MAC

```text
Windows
  ↓
GetAdaptersInfo
  ↓
hook injetado
  ↓
dados de adaptador modificados
  ↓
WYD
```

### Proxy injetado

```text
WYD
  ↓
connect
  ↓
hook injetado
  ↓
proxy
  ↓
servidor
```

## Como funciona

Antes de continuar o login, o auditor:

1. localiza os imports protegidos;
2. resolve a implementação legítima esperada;
3. verifica o endereço atual da IAT;
4. identifica o módulo responsável pelo endereço;
5. aceita forwarders legítimos;
6. classifica cada API como `CLEAN`, `ANOMALY` ou `RESOLUTION_ERROR`.

A política do gate é fail-closed:

```text
GetAdaptersInfo=CLEAN   + connect=CLEAN   -> ALLOW
GetAdaptersInfo=ANOMALY + connect=CLEAN   -> BLOCK
GetAdaptersInfo=CLEAN   + connect=ANOMALY -> BLOCK
```

O bloqueio ocorre antes de `ConnectServer`.

## Resultado visual esperado

Quando uma verificação detectar alteração e o usuário tentar fazer login, o fluxo é interrompido e o cliente exibe:

![Bloqueio de integridade no login](docs/images/integrity-blocked-login.png)

```text
Falha na verificacao de integridade do cliente.
```

Nesse estado o login não prossegue para `ConnectServer`.

## APIs protegidas

- `IPHLPAPI.DLL!GetAdaptersInfo`
- `WSOCK32.dll!connect`
- `WS2_32.dll!connect`

## Estrutura

```text
iat-wyd-protection/
├─ README.md
├─ LICENSE
├─ SHA256SUMS
├─ src/
│  ├─ P1IatAudit.h
│  └─ P1IatAudit.cpp
├─ docs/
│  ├─ IMPLEMENTATION.md
│  ├─ TESTING.md
│  └─ images/
│     └─ integrity-blocked-login.png
└─ examples/
   ├─ TMSelectServerScene_GATE_SNIPPET.cpp
   ├─ TMProject.vcxproj_SNIPPETS.xml
   └─ TMProject.vcxproj.filters_SNIPPETS.xml
```

## Implementação rápida

1. copie `src/P1IatAudit.h` e `src/P1IatAudit.cpp` para o projeto do cliente;
2. adicione os dois arquivos ao `.vcxproj`;
3. inclua `P1IatAudit.h` no arquivo que trata o login;
4. execute `AuditCurrentProcess()` no início de `B_LOGIN_OK`;
5. permita o login somente se todos os registros estiverem `CLEAN`;
6. retorne antes de `ConnectServer` quando houver falha de integridade;
7. compile e execute a matriz de testes.

Passo a passo completo: **[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)**  
Validação: **[docs/TESTING.md](docs/TESTING.md)**

## Requisitos atuais

- Windows
- C++
- cliente WYD com código-fonte
- target Win32 / x86

## Objetivo

Adicionar uma camada simples e reutilizável de hardening ao cliente WYD, dificultando abuso por alteração de IAT, spoofing baseado em APIs de rede e redirecionamento de conexão por proxy injetado.
