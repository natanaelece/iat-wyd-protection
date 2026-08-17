#pragma once

#include <Windows.h>
#include <cstddef>

namespace P1IatAudit
{
    enum class Decision
    {
        AuthorizedImplementation,
        LegitimateForwarder,
        UnauthorizedIatTarget,
        ResolutionError
    };

    enum class Result
    {
        Clean,
        Anomaly,
        ResolutionError
    };

    struct TargetFacts
    {
        bool resolutionSucceeded;
        bool observedInspectionSucceeded;
        bool expectedExportIsForwarder;
        const void* expectedAddress;
        const void* observedAddress;
        HMODULE declaredModule;
        HMODULE expectedModule;
        HMODULE observedModule;
        DWORD expectedState;
        DWORD expectedType;
        DWORD observedState;
        DWORD observedType;
        bool expectedExecutable;
        bool observedExecutable;
    };

    struct AuditRecord
    {
        const char* api;
        char expectedModule[64];
        char observedModule[64];
        Decision decision;
        Result result;
    };

    constexpr std::size_t AuditRecordCount = 2;

    Decision EvaluateTarget(const TargetFacts& facts);
    Result ResultForDecision(Decision decision);
    const char* DecisionToString(Decision decision);
    const char* ResultToString(Result result);

    std::size_t AuditCurrentProcess(
        AuditRecord* records,
        std::size_t capacity);
}
