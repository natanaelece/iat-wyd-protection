# Implementação

Este guia mostra como integrar P1 + P2 no fluxo de login de um cliente WYD Win32/x86.

## 1. Copie os arquivos

```text
src/P1IatAudit.h
src/P1IatAudit.cpp
src/P2InlineAudit.h
src/P2InlineAudit.cpp
```

Coloque-os junto do projeto C++ do cliente. Os dois `.cpp` usam `pch.h`; preserve o precompiled header do projeto ou ajuste esse include conforme a estrutura local.

## 2. Adicione ao `.vcxproj`

Headers:

```xml
<ClInclude Include="P1IatAudit.h" />
<ClInclude Include="P2InlineAudit.h" />
```

Fontes:

```xml
<ClCompile Include="P1IatAudit.cpp" />
<ClCompile Include="P2InlineAudit.cpp" />
```

Snippets completos:

```text
examples/TMProject.vcxproj_SNIPPETS.xml
examples/TMProject.vcxproj.filters_SNIPPETS.xml
```

## 3. Inclua os auditores no login

Em `TMSelectServerScene.cpp`:

```cpp
#include "P1IatAudit.h"
#include "P2InlineAudit.h"
```

Localize `case B_LOGIN_OK` e coloque o gate depois do debounce e antes do fluxo normal de login.

Use:

```text
examples/TMSelectServerScene_GATE_SNIPPET.cpp
```

## 4. Regra do gate

Em **cada tentativa de login**:

1. P1 audita as IATs de `GetAdaptersInfo` e `connect`;
2. P2 audita o código inicial da implementação final autorizada dessas APIs;
3. a decisão começa negada;
4. P1 precisa devolver todos os registros esperados como `CLEAN`;
5. P2 precisa devolver todos os registros esperados como `CLEAN`;
6. qualquer `ANOMALY`, `RESOLUTION_ERROR` ou quantidade incompleta bloqueia.

Não mantenha cache one-shot como:

```cpp
static bool clientIntegrityCheckCompleted;
static bool clientIntegrityAllowed;
```

A decisão deve ser recalculada em todo `B_LOGIN_OK`.

## 5. O que P1 verifica

P1 confere o destino efetivo da IAT e aceita apenas a implementação autorizada, incluindo forwarders legítimos.

```text
IAT connect -> WS2_32!connect         = CLEAN
IAT connect -> destino não autorizado = ANOMALY
```

## 6. O que P2 verifica

P2 resolve a implementação final autorizada, valida a região executável correspondente e compara o código inicial carregado com a mesma imagem PE usada como referência.

A comparação considera relocations aplicáveis e retorna:

```text
código equivalente -> CLEAN
divergência relevante -> ANOMALY
falha de resolução/inspeção -> RESOLUTION_ERROR
```

P2 não depende de RVA fixo, endereço fixo, hash fixo de DLL do Windows ou nome de ferramenta externa.

## 7. Ordem obrigatória

```text
B_LOGIN_OK
  ↓
debounce
  ↓
P1
  ↓
P2
  ↓
todos os registros CLEAN?
  ├─ não -> mensagem + return 1
  └─ sim -> fluxo normal
              ↓
         ConnectServer / GetAdaptersInfo
```

O retorno de bloqueio precisa ocorrer antes das operações protegidas.

## 8. Build

Target atual:

```text
Windows
Win32 / x86
C++17
```

Compile com a toolchain do cliente e execute a matriz de [TESTING.md](TESTING.md).

## 9. Logs

Sugestão de formato:

```text
CLIENT_INTEGRITY LAYER=P1 API=... RESULT=CLEAN|ANOMALY|RESOLUTION_ERROR
CLIENT_INTEGRITY LAYER=P2 API=... RESULT=CLEAN|ANOMALY|RESOLUTION_ERROR
CLIENT_INTEGRITY_ALLOWED=true|false
```

Não registre IP, proxy, credenciais, MAC ou endereços de memória.

## 10. Validação final

Antes de distribuir o cliente, compile a integração no build exato e execute a matriz de testes documentada em [TESTING.md](TESTING.md).
