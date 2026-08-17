// Adicione no topo de TMSelectServerScene.cpp:
// #include "P1IatAudit.h"

// Insira no início de case B_LOGIN_OK, depois do debounce e antes do fluxo normal de login.

static bool clientIntegrityCheckCompleted = false;
static bool clientIntegrityAllowed = false;

if (!clientIntegrityCheckCompleted)
{
    clientIntegrityAllowed = false;

    P1IatAudit::AuditRecord auditRecords[
        P1IatAudit::AuditRecordCount]{};

    const std::size_t auditCount =
        P1IatAudit::AuditCurrentProcess(
            auditRecords,
            P1IatAudit::AuditRecordCount);

    bool allRecordsClean =
        auditCount == P1IatAudit::AuditRecordCount;

    for (std::size_t auditIndex = 0;
         auditIndex < P1IatAudit::AuditRecordCount;
         ++auditIndex)
    {
        const P1IatAudit::AuditRecord& record =
            auditRecords[auditIndex];

        const bool recordAvailable = auditIndex < auditCount;

        LOG_WRITELOG(
            "CLIENT_INTEGRITY API=%s EXPECTED_MODULE=%s "
            "OBSERVED_MODULE=%s RESULT=%s\r\n",
            recordAvailable && record.api
                ? record.api
                : "<UNAVAILABLE>",
            recordAvailable
                ? record.expectedModule
                : "<UNRESOLVED>",
            recordAvailable
                ? record.observedModule
                : "<UNRESOLVED>",
            recordAvailable
                ? P1IatAudit::ResultToString(record.result)
                : "RESOLUTION_ERROR");

        if (!recordAvailable ||
            record.result != P1IatAudit::Result::Clean)
        {
            allRecordsClean = false;
        }
    }

    clientIntegrityAllowed = allRecordsClean;
    clientIntegrityCheckCompleted = true;

    LOG_WRITELOG(
        "CLIENT_INTEGRITY ALLOWED=%s\r\n",
        clientIntegrityAllowed ? "true" : "false");
}

if (!clientIntegrityAllowed)
{
    m_pMessagePanel->SetMessage(
        "Falha na verificacao de integridade do cliente.",
        4000);
    m_pMessagePanel->SetVisible(1, 1);
    return 1;
}
