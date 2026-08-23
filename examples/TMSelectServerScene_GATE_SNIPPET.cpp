// Adicione no topo de TMSelectServerScene.cpp:
// #include "P1IatAudit.h"
// #include "P2InlineAudit.h"

// Insira no início de case B_LOGIN_OK, depois do debounce e antes do fluxo normal de login.
// P1 e P2 são reavaliados em toda tentativa de login.

bool clientIntegrityAllowed = false;

P1IatAudit::AuditRecord p1AuditRecords[
    P1IatAudit::AuditRecordCount]{};

const std::size_t p1AuditCount =
    P1IatAudit::AuditCurrentProcess(
        p1AuditRecords,
        P1IatAudit::AuditRecordCount);

bool p1AllRecordsClean =
    p1AuditCount == P1IatAudit::AuditRecordCount;

for (std::size_t auditIndex = 0;
     auditIndex < P1IatAudit::AuditRecordCount;
     ++auditIndex)
{
    const bool recordAvailable = auditIndex < p1AuditCount;
    const P1IatAudit::AuditRecord& record = p1AuditRecords[auditIndex];

    LOG_WRITELOG(
        "CLIENT_INTEGRITY LAYER=P1 API=%s EXPECTED_MODULE=%s "
        "OBSERVED_MODULE=%s RESULT=%s\r\n",
        recordAvailable && record.api ? record.api : "<UNAVAILABLE>",
        recordAvailable ? record.expectedModule : "<UNRESOLVED>",
        recordAvailable ? record.observedModule : "<UNRESOLVED>",
        recordAvailable
            ? P1IatAudit::ResultToString(record.result)
            : "RESOLUTION_ERROR");

    if (!recordAvailable ||
        record.result != P1IatAudit::Result::Clean)
    {
        p1AllRecordsClean = false;
    }
}

P2InlineAudit::AuditRecord p2AuditRecords[
    P2InlineAudit::AuditRecordCount]{};

const std::size_t p2AuditCount =
    P2InlineAudit::AuditCurrentProcess(
        p2AuditRecords,
        P2InlineAudit::AuditRecordCount);

bool p2AllRecordsClean =
    p2AuditCount == P2InlineAudit::AuditRecordCount;

for (std::size_t auditIndex = 0;
     auditIndex < P2InlineAudit::AuditRecordCount;
     ++auditIndex)
{
    const bool recordAvailable = auditIndex < p2AuditCount;
    const P2InlineAudit::AuditRecord& record = p2AuditRecords[auditIndex];

    LOG_WRITELOG(
        "CLIENT_INTEGRITY LAYER=P2 API=%s FINAL_MODULE=%s RESULT=%s\r\n",
        recordAvailable && record.api ? record.api : "<UNAVAILABLE>",
        recordAvailable ? record.finalModule : "<UNRESOLVED>",
        recordAvailable
            ? P2InlineAudit::ResultToString(record.result)
            : "RESOLUTION_ERROR");

    if (!recordAvailable ||
        record.result != P2InlineAudit::Result::Clean)
    {
        p2AllRecordsClean = false;
    }
}

clientIntegrityAllowed = p1AllRecordsClean && p2AllRecordsClean;

LOG_WRITELOG(
    "CLIENT_INTEGRITY_ALLOWED=%s\r\n",
    clientIntegrityAllowed ? "true" : "false");

if (!clientIntegrityAllowed)
{
    m_pMessagePanel->SetMessage(
        "Falha na verificacao de integridade do cliente.",
        4000);
    m_pMessagePanel->SetVisible(1, 1);
    return 1;
}
