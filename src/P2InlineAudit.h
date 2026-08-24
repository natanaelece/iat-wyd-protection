#pragma once

#include <cstddef>

namespace P2InlineAudit
{
    enum class Result
    {
        Clean,
        Anomaly,
        ResolutionError
    };

    struct WindowFacts
    {
        bool resolutionSucceeded;
        const unsigned char* liveBytes;
        const unsigned char* cleanBytes;
        const bool* relocationMask;
        std::size_t windowSize;
    };

    struct AuditRecord
    {
        const char* api;
        char finalModule[64];
        Result result;
    };

    constexpr std::size_t AuditRecordCount = 2;
    constexpr std::size_t ComparisonWindowSize = 32;
    constexpr std::size_t MinimumComparedBytes = 16;

    Result EvaluateWindow(const WindowFacts& facts);
    const char* ResultToString(Result result);

    std::size_t AuditCurrentProcess(
        AuditRecord* records,
        std::size_t capacity);
}
