# Implementação

Este guia mostra onde colocar os arquivos e onde inserir o gate no fluxo de login de um cliente WYD Win32.

## 1. Copie os arquivos do auditor

Copie:

```text
src/P1IatAudit.h
src/P1IatAudit.cpp
```

para o diretório do projeto C++ do cliente, normalmente junto de `TMSelectServerScene.cpp` e do `.vcxproj`.

Exemplo:

```text
Projects/TMProject/
├─ P1IatAudit.h
├─ P1IatAudit.cpp
├─ TMSelectServerScene.cpp
└─ TMProject.vcxproj
```

`P1IatAudit.cpp` usa `pch.h`; mantenha o precompiled header do projeto ou ajuste esse include conforme a estrutura do seu source.

## 2. Adicione os arquivos ao `.vcxproj`

No grupo de headers:

```xml
<ClInclude Include="P1IatAudit.h" />
```

No grupo de fontes:

```xml
<ClCompile Include="P1IatAudit.cpp" />
```

Os snippets prontos estão em:

```text
examples/TMProject.vcxproj_SNIPPETS.xml
examples/TMProject.vcxproj.filters_SNIPPETS.xml
```

O `.filters` é opcional e serve apenas para organização no Visual Studio.

## 3. Inclua o auditor na cena de login

Abra `TMSelectServerScene.cpp` e adicione junto aos includes do projeto:

```cpp
#include "P1IatAudit.h"
```

## 4. Localize o clique de login

Procure o bloco:

```cpp
switch (idwControlID)
{
    case B_LOGIN_OK:
    {
```

Normalmente existe um debounce semelhante a:

```cpp
unsigned int LiveTime = g_pTimerManager->GetServerTime();
if (LastSendMsgTime + 1500 > LiveTime)
    return 1;
```

O gate deve entrar **logo depois desse trecho e antes do restante do login**.

## 5. Insira o gate

Use o arquivo:

```text
examples/TMSelectServerScene_GATE_SNIPPET.cpp
```

O bloco executa `P1IatAudit::AuditCurrentProcess()`, exige todos os registros `CLEAN` e interrompe o login em qualquer outro estado.

Trecho principal:

```cpp
static bool clientIntegrityCheckCompleted = false;
static bool clientIntegrityAllowed = false;

if (!clientIntegrityCheckCompleted)
{
    P1IatAudit::AuditRecord auditRecords[
        P1IatAudit::AuditRecordCount]{};

    const std::size_t auditCount =
        P1IatAudit::AuditCurrentProcess(
            auditRecords,
            P1IatAudit::AuditRecordCount);

    bool allRecordsClean =
        auditCount == P1IatAudit::AuditRecordCount;

    for (std::size_t i = 0;
         i < P1IatAudit::AuditRecordCount;
         ++i)
    {
        if (i >= auditCount ||
            auditRecords[i].result != P1IatAudit::Result::Clean)
        {
            allRecordsClean = false;
        }
    }

    clientIntegrityAllowed = allRecordsClean;
    clientIntegrityCheckCompleted = true;
}

if (!clientIntegrityAllowed)
{
    m_pMessagePanel->SetMessage(
        "Falha na verificacao de integridade do cliente.",
        4000);
    m_pMessagePanel->SetVisible(1, 1);
    return 1;
}
```

O exemplo completo inclui também logs por API.

## 6. Confirme a ordem do fluxo

O resultado final deve ficar conceitualmente assim:

```text
B_LOGIN_OK
  ↓
debounce
  ↓
P1IatAudit::AuditCurrentProcess
  ↓
todos CLEAN?
  ├─ não -> mensagem + return 1
  └─ sim -> fluxo normal de login
              ↓
         ConnectServer
```

O `ConnectServer` precisa permanecer **depois** do gate.

## 7. Build

A implementação atual é Win32/PE32. Compile o cliente como **Win32/x86**.

Se o projeto usa o nome canônico `WYD.exe`, um exemplo de configuração é:

```xml
<TargetName>WYD</TargetName>
```

## 8. Resultado esperado

Cliente normal:

```text
CLIENT_INTEGRITY API=GetAdaptersInfo ... RESULT=CLEAN
CLIENT_INTEGRITY API=connect ... RESULT=CLEAN
CLIENT_INTEGRITY ALLOWED=true
```

Alteração detectada:

```text
CLIENT_INTEGRITY ... RESULT=ANOMALY
CLIENT_INTEGRITY ALLOWED=false
```

Depois de integrar, execute a matriz de **[TESTING.md](TESTING.md)**.
