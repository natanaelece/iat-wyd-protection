# Proveniência e validação

## Identidade da implementação

A distribuição pública fixa a identidade Git dos quatro fontes reutilizáveis:

```text
src/P1IatAudit.h    = a2b9958ccebdc14fc7a6500bdf39a820c8def29a
src/P1IatAudit.cpp  = bdd71dcf0578498d623afcb42ed73175c6a814fd
src/P2InlineAudit.h = 7164919f44b79d19767e7511a54c9c77c1503dea
src/P2InlineAudit.cpp = 91611a59bba7e14effea47dd2bccd9cd2404e085
```

Esses valores são **Git blob IDs**, não SHA-256 de runtime.

```text
SOURCE_PROVENANCE=PINNED_GIT_BLOBS
```

## Evidência funcional

A implementação foi validada em ambiente controlado com cliente Win32/x86, cobrindo:

```text
BASELINE_P1_GETADAPTERSINFO=CLEAN
BASELINE_P1_CONNECT=CLEAN
BASELINE_P2_GETADAPTERSINFO=CLEAN
BASELINE_P2_CONNECT=CLEAN
BASELINE_ALLOWED=true
P1_IAT_DIFFERENTIAL=ANOMALY_BLOCKED
P2_INLINE_SYNTHETIC_DIFFERENTIAL=ANOMALY_BLOCKED
P2_REAL_BASELINE_RESOLUTION=PASS
P2_SYNTHETIC_RELOCATION_MASK_APPLICATION=PASS
PER_LOGIN_REAUDIT_STATICALLY_CONFIRMED=true
```

O P1 e o P2 são independentes e complementares. Um cenário que altera somente a IAT pode produzir `P1=ANOMALY` e `P2=CLEAN`; um cenário que mantém a IAT legítima e altera o código inicial da implementação final pode produzir `P1=CLEAN` e `P2=ANOMALY`.

## Compatibilidade

Esta implementação é genérica para clientes com código-fonte disponível, mas cada integração deve ser validada no cliente e build exatos em que será usada.

```text
RUNTIME_COMPATIBILITY_REQUIRES_EXACT_BUILD_TEST=true
CROSS_BUILD_EQUIVALENCE_NOT_ASSUMED=true
```
