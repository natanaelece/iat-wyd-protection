# Proveniência e limites de evidência

## Origem da implementação

Esta distribuição pública preserva os controles client-side validados no repositório de laboratório `natanaelece/medusa-wyd-server`.

Estado de referência promovido para `main`:

```text
SERVER_REPOSITORY=natanaelece/medusa-wyd-server
SERVER_MAIN_COMMIT=c0814b2f85d2c9cce2cc7a0ff685eebf3857615c
P2_MAIN_PROMOTION_PR=21
P2_MAIN_PROMOTION_PR_CI_RUN=32665767946
P2_MAIN_PROMOTION_PR_CI_CONCLUSION=success
```

Identidade Git dos fontes reutilizáveis:

```text
src/P1IatAudit.h   = a2b9958ccebdc14fc7a6500bdf39a820c8def29a
src/P1IatAudit.cpp = bdd71dcf0578498d623afcb42ed73175c6a814fd
src/P2InlineAudit.h = 7164919f44b79d19767e7511a54c9c77c1503dea
src/P2InlineAudit.cpp = 91611a59bba7e14effea47dd2bccd9cd2404e085
```

Esses valores são **Git blob IDs**, não SHA-256 de runtime.

## Evidência funcional

No cliente de laboratório `ClientSeiTbNao769`, build Win32/x86 validado:

```text
CLIENT_SHA256=6E3048D0984CC09755E8E060ABBF0E7D4DBB4559F31A64C55040EC646CB20E35
DIRECT_P1_GETADAPTERSINFO=CLEAN
DIRECT_P1_CONNECT=CLEAN
DIRECT_P2_GETADAPTERSINFO=CLEAN
DIRECT_P2_CONNECT=CLEAN
DIRECT_ALLOWED=true
MEDUSA_V1097_P1_GETADAPTERSINFO=ANOMALY
MEDUSA_V1097_P1_CONNECT=ANOMALY
MEDUSA_V1097_P2_GETADAPTERSINFO=CLEAN
MEDUSA_V1097_P2_CONNECT=CLEAN
MEDUSA_V1097_LOGIN_BLOCKED=true
```

O caminho Medusa 1.097 exercitado nessa passagem alterou as IATs e foi bloqueado pelo P1. O fallback inline não foi exercitado dinamicamente.

```text
INLINE_FALLBACK_RUNTIME_EXERCISED=false
INLINE_FALLBACK_CONTROL_EVIDENCE=STATIC_PLUS_SYNTHETIC_HARNESS
```

## Fronteira obrigatória

O repositório `medusa-wyd-server` contém clientes com fonte usados em laboratório controlado. Nenhum deles é modelo autoritativo do binário oficial do WYD do Exordion.

```text
LABORATORY_RESULTS_APPLY_TO_EXACT_CLIENT_BUILD_AND_TEST=true
OFFICIAL_EXORDION_EQUIVALENCE=NOT_CLAIMED
EXPLICIT_CROSS_COMPARISON_REQUIRED_BEFORE_GENERALIZATION=true
```

A implementação pode ser reutilizada em outros clientes com fonte, mas cada integração precisa de build e testes próprios. Sucesso em um cliente de laboratório não prova comportamento idêntico em outro binário.

## Limitações atuais

- target validado: Win32/x86;
- P1 cobre adulteração da IAT das APIs configuradas;
- P2 compara uma janela inicial de 32 bytes da implementação final autorizada;
- o parser de relocations está implementado, mas não possui fixture PE diferencial independente para `BuildRelocationMask`;
- existe TOCTOU entre auditoria e uso posterior da API;
- mecanismos out-of-process não são cobertos por P1/P2;
- controles executados dentro do próprio cliente não constituem raiz autônoma de confiança.
