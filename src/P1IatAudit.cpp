#include "pch.h"

#include "P1IatAudit.h"

#include <cstdint>
#include <cstring>
#include <limits>

namespace
{
    static_assert(sizeof(void*) == sizeof(DWORD),
        "P1-IAT-01 is implemented for the Win32 client target.");

    constexpr const char* UnresolvedModule = "<UNRESOLVED>";
    constexpr const char* NonImageModule = "<NON_IMAGE>";

    struct ImageLayout
    {
        const BYTE* base;
        DWORD size;
        const IMAGE_NT_HEADERS32* ntHeaders;
    };

    struct ImportCandidate
    {
        const char* moduleName;
        const char* importName;
        WORD importOrdinal;
        bool allowName;
        bool allowOrdinal;
    };

    struct ApiSpec
    {
        const char* api;
        const ImportCandidate* candidates;
        std::size_t candidateCount;
    };

    struct ImportTarget
    {
        const ImportCandidate* candidate;
        bool importedByOrdinal;
        const void* observedAddress;
    };

    struct AddressInfo
    {
        bool inspected;
        HMODULE module;
        DWORD state;
        DWORD type;
        bool executable;
        char moduleName[64];
    };

    enum class FindSlotResult
    {
        Found,
        NotFound,
        Error
    };

    const ImportCandidate ConnectCandidates[] = {
        { "WSOCK32.dll", "connect", 4, true, true },
        { "WS2_32.dll", "connect", 4, true, true }
    };

    const ImportCandidate GetAdaptersInfoCandidates[] = {
        { "IPHLPAPI.DLL", "GetAdaptersInfo", 0, true, false }
    };

    const ApiSpec ApiSpecs[] = {
        {
            "GetAdaptersInfo",
            GetAdaptersInfoCandidates,
            sizeof(GetAdaptersInfoCandidates) /
                sizeof(GetAdaptersInfoCandidates[0])
        },
        {
            "connect",
            ConnectCandidates,
            sizeof(ConnectCandidates) / sizeof(ConnectCandidates[0])
        }
    };

    bool IsRvaRangeValid(const ImageLayout& image, DWORD rva, std::size_t size)
    {
        const std::uint64_t end = static_cast<std::uint64_t>(rva) + size;
        return rva != 0 && end <= image.size;
    }

    bool TryMultiplySize(
        DWORD count,
        std::size_t elementSize,
        std::size_t* total)
    {
        if (!total || elementSize == 0 ||
            count > (std::numeric_limits<std::size_t>::max)() / elementSize)
        {
            return false;
        }

        *total = static_cast<std::size_t>(count) * elementSize;
        return true;
    }

    const void* RvaToPointer(
        const ImageLayout& image,
        DWORD rva,
        std::size_t size)
    {
        if (!IsRvaRangeValid(image, rva, size))
            return nullptr;

        return image.base + rva;
    }

    bool TryGetImageLayout(HMODULE module, ImageLayout* image)
    {
        if (!module || !image)
            return false;

        __try
        {
            const BYTE* base = reinterpret_cast<const BYTE*>(module);
            const IMAGE_DOS_HEADER* dos =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;

            const IMAGE_NT_HEADERS32* nt =
                reinterpret_cast<const IMAGE_NT_HEADERS32*>(
                    base + dos->e_lfanew);

            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
                nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
                nt->OptionalHeader.SizeOfImage <
                    sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))
            {
                return false;
            }

            image->base = base;
            image->size = nt->OptionalHeader.SizeOfImage;
            image->ntHeaders = nt;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool EqualsAsciiInsensitive(
        const ImageLayout& image,
        const char* imageText,
        const char* expected)
    {
        if (!imageText || !expected)
            return false;

        const BYTE* text = reinterpret_cast<const BYTE*>(imageText);
        if (text < image.base || text >= image.base + image.size)
            return false;

        const std::size_t maximum =
            static_cast<std::size_t>((image.base + image.size) - text);

        for (std::size_t index = 0; index < maximum; ++index)
        {
            const unsigned char left =
                static_cast<unsigned char>(imageText[index]);
            const unsigned char right =
                static_cast<unsigned char>(expected[index]);

            if (left >= 'A' && left <= 'Z')
            {
                if (static_cast<unsigned char>(left + ('a' - 'A')) != right &&
                    left != right)
                {
                    return false;
                }
            }
            else if (right >= 'A' && right <= 'Z')
            {
                if (left != static_cast<unsigned char>(right + ('a' - 'A')) &&
                    left != right)
                {
                    return false;
                }
            }
            else if (left != right)
            {
                return false;
            }

            if (left == 0)
                return true;
        }

        return false;
    }

    bool EqualsAsciiExact(
        const ImageLayout& image,
        const char* imageText,
        const char* expected)
    {
        if (!imageText || !expected)
            return false;

        const BYTE* text = reinterpret_cast<const BYTE*>(imageText);
        if (text < image.base || text >= image.base + image.size)
            return false;

        const std::size_t maximum =
            static_cast<std::size_t>((image.base + image.size) - text);

        for (std::size_t index = 0; index < maximum; ++index)
        {
            if (imageText[index] != expected[index])
                return false;
            if (imageText[index] == 0)
                return true;
        }

        return false;
    }

    bool IsExecutableProtection(DWORD protection)
    {
        switch (protection & 0xFFu)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    void CopyText(char* destination, std::size_t capacity, const char* source)
    {
        if (!destination || capacity == 0)
            return;

        if (!source)
            source = UnresolvedModule;

        strncpy_s(destination, capacity, source, _TRUNCATE);
    }

    bool InspectAddress(const void* address, AddressInfo* info)
    {
        if (!address || !info)
            return false;

        std::memset(info, 0, sizeof(*info));
        CopyText(info->moduleName, sizeof(info->moduleName), UnresolvedModule);

        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory))
            return false;

        info->state = memory.State;
        info->type = memory.Type;
        info->executable = IsExecutableProtection(memory.Protect);

        if (memory.Type != MEM_IMAGE)
        {
            CopyText(info->moduleName, sizeof(info->moduleName), NonImageModule);
            info->inspected = true;
            return true;
        }

        info->module = reinterpret_cast<HMODULE>(memory.AllocationBase);
        char path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameA(
            info->module,
            path,
            static_cast<DWORD>(sizeof(path)));

        if (length == 0 || length >= sizeof(path))
            return false;

        const char* name = path;
        for (const char* cursor = path; *cursor; ++cursor)
        {
            if (*cursor == '\\' || *cursor == '/')
                name = cursor + 1;
        }

        CopyText(info->moduleName, sizeof(info->moduleName), name);
        info->inspected = true;
        return true;
    }

    FindSlotResult FindIatSlot(
        HMODULE processModule,
        const ImportCandidate& candidate,
        ImportTarget* target)
    {
        ImageLayout image{};
        if (!TryGetImageLayout(processModule, &image))
            return FindSlotResult::Error;

        const IMAGE_DATA_DIRECTORY& imports =
            image.ntHeaders->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (!IsRvaRangeValid(
                image,
                imports.VirtualAddress,
                imports.Size) ||
            imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            return FindSlotResult::Error;
        }

        const IMAGE_IMPORT_DESCRIPTOR* descriptors =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                image.base + imports.VirtualAddress);
        const std::size_t descriptorCount =
            imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

        for (std::size_t descriptorIndex = 0;
             descriptorIndex < descriptorCount;
             ++descriptorIndex)
        {
            const IMAGE_IMPORT_DESCRIPTOR& descriptor =
                descriptors[descriptorIndex];

            if (descriptor.Name == 0 && descriptor.FirstThunk == 0)
                break;

            const char* moduleName = reinterpret_cast<const char*>(
                RvaToPointer(image, descriptor.Name, 1));
            if (!moduleName)
                return FindSlotResult::Error;

            if (!EqualsAsciiInsensitive(image, moduleName, candidate.moduleName))
                continue;

            if (descriptor.OriginalFirstThunk == 0 ||
                descriptor.FirstThunk == 0)
            {
                return FindSlotResult::Error;
            }

            if (descriptor.OriginalFirstThunk >= image.size ||
                descriptor.FirstThunk >= image.size)
            {
                return FindSlotResult::Error;
            }

            const std::size_t originalCapacity =
                (image.size - descriptor.OriginalFirstThunk) /
                sizeof(IMAGE_THUNK_DATA32);
            const std::size_t iatCapacity =
                (image.size - descriptor.FirstThunk) /
                sizeof(IMAGE_THUNK_DATA32);
            const std::size_t thunkCount =
                originalCapacity < iatCapacity ? originalCapacity : iatCapacity;

            const IMAGE_THUNK_DATA32* original =
                reinterpret_cast<const IMAGE_THUNK_DATA32*>(
                    RvaToPointer(
                        image,
                        descriptor.OriginalFirstThunk,
                        sizeof(IMAGE_THUNK_DATA32)));
            const IMAGE_THUNK_DATA32* iat =
                reinterpret_cast<const IMAGE_THUNK_DATA32*>(
                    RvaToPointer(
                        image,
                        descriptor.FirstThunk,
                        sizeof(IMAGE_THUNK_DATA32)));

            if (!original || !iat || thunkCount == 0)
                return FindSlotResult::Error;

            for (std::size_t thunkIndex = 0;
                 thunkIndex < thunkCount;
                 ++thunkIndex)
            {
                const DWORD originalValue = original[thunkIndex].u1.AddressOfData;
                if (originalValue == 0)
                    break;

                bool matches = false;
                bool importedByOrdinal = false;

                if (IMAGE_SNAP_BY_ORDINAL32(originalValue))
                {
                    importedByOrdinal = true;
                    matches = candidate.allowOrdinal &&
                        IMAGE_ORDINAL32(originalValue) == candidate.importOrdinal;
                }
                else if (candidate.allowName)
                {
                    const IMAGE_IMPORT_BY_NAME* importByName =
                        reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            RvaToPointer(
                                image,
                                originalValue,
                                sizeof(IMAGE_IMPORT_BY_NAME)));
                    if (!importByName)
                        return FindSlotResult::Error;

                    matches = EqualsAsciiExact(
                        image,
                        reinterpret_cast<const char*>(importByName->Name),
                        candidate.importName);
                }

                if (!matches)
                    continue;

                const DWORD functionValue = iat[thunkIndex].u1.Function;
                if (functionValue == 0)
                    return FindSlotResult::Error;

                target->candidate = &candidate;
                target->importedByOrdinal = importedByOrdinal;
                target->observedAddress = reinterpret_cast<const void*>(
                    static_cast<std::uintptr_t>(functionValue));
                return FindSlotResult::Found;
            }

            return FindSlotResult::NotFound;
        }

        return FindSlotResult::NotFound;
    }

    bool TryGetExportForwarderState(
        HMODULE module,
        const ImportTarget& target,
        bool* isForwarder)
    {
        if (!isForwarder)
            return false;

        *isForwarder = false;
        ImageLayout image{};
        if (!TryGetImageLayout(module, &image))
            return false;

        const IMAGE_DATA_DIRECTORY& exports =
            image.ntHeaders->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (exports.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            !IsRvaRangeValid(
                image,
                exports.VirtualAddress,
                exports.Size))
        {
            return false;
        }

        const IMAGE_EXPORT_DIRECTORY* directory =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                RvaToPointer(
                    image,
                    exports.VirtualAddress,
                    sizeof(IMAGE_EXPORT_DIRECTORY)));
        if (!directory)
            return false;

        std::size_t functionBytes = 0;
        if (!TryMultiplySize(
                directory->NumberOfFunctions,
                sizeof(DWORD),
                &functionBytes))
        {
            return false;
        }

        const DWORD* functions = reinterpret_cast<const DWORD*>(
            RvaToPointer(
                image,
                directory->AddressOfFunctions,
                functionBytes));
        if (!functions || directory->NumberOfFunctions == 0)
            return false;

        DWORD functionIndex = 0;
        if (target.importedByOrdinal)
        {
            const WORD ordinal = target.candidate->importOrdinal;
            if (ordinal < directory->Base)
                return false;

            functionIndex = ordinal - directory->Base;
            if (functionIndex >= directory->NumberOfFunctions)
                return false;
        }
        else
        {
            std::size_t nameBytes = 0;
            std::size_t ordinalBytes = 0;
            if (!TryMultiplySize(
                    directory->NumberOfNames,
                    sizeof(DWORD),
                    &nameBytes) ||
                !TryMultiplySize(
                    directory->NumberOfNames,
                    sizeof(WORD),
                    &ordinalBytes))
            {
                return false;
            }

            const DWORD* names = reinterpret_cast<const DWORD*>(
                RvaToPointer(
                    image,
                    directory->AddressOfNames,
                    nameBytes));
            const WORD* ordinals = reinterpret_cast<const WORD*>(
                RvaToPointer(
                    image,
                    directory->AddressOfNameOrdinals,
                    ordinalBytes));
            if (!names || !ordinals)
                return false;

            bool found = false;
            for (DWORD nameIndex = 0;
                 nameIndex < directory->NumberOfNames;
                 ++nameIndex)
            {
                const char* exportName = reinterpret_cast<const char*>(
                    RvaToPointer(image, names[nameIndex], 1));
                if (!exportName)
                    return false;

                if (EqualsAsciiExact(
                        image,
                        exportName,
                        target.candidate->importName))
                {
                    functionIndex = ordinals[nameIndex];
                    found = true;
                    break;
                }
            }

            if (!found || functionIndex >= directory->NumberOfFunctions)
                return false;
        }

        const DWORD functionRva = functions[functionIndex];
        if (!IsRvaRangeValid(image, functionRva, 1))
            return false;

        const std::uint64_t exportStart = exports.VirtualAddress;
        const std::uint64_t exportEnd = exportStart + exports.Size;
        *isForwarder = functionRva >= exportStart && functionRva < exportEnd;

        if (*isForwarder)
        {
            const char* forwarder = reinterpret_cast<const char*>(
                RvaToPointer(image, functionRva, 1));
            if (!forwarder)
                return false;

            bool terminated = false;
            const DWORD maximum =
                static_cast<DWORD>(exportEnd - functionRva);
            for (DWORD index = 0; index < maximum; ++index)
            {
                if (forwarder[index] == 0)
                {
                    terminated = true;
                    break;
                }
            }
            if (!terminated)
                return false;
        }

        return true;
    }

    void InitializeRecord(P1IatAudit::AuditRecord* record, const char* api)
    {
        std::memset(record, 0, sizeof(*record));
        record->api = api;
        CopyText(
            record->expectedModule,
            sizeof(record->expectedModule),
            UnresolvedModule);
        CopyText(
            record->observedModule,
            sizeof(record->observedModule),
            UnresolvedModule);
        record->decision = P1IatAudit::Decision::ResolutionError;
        record->result = P1IatAudit::Result::ResolutionError;
    }

    void AuditApi(const ApiSpec& spec, P1IatAudit::AuditRecord* record)
    {
        InitializeRecord(record, spec.api);

        HMODULE processModule = GetModuleHandleW(nullptr);
        if (!processModule)
            return;

        ImportTarget target{};
        FindSlotResult findResult = FindSlotResult::NotFound;
        for (std::size_t index = 0; index < spec.candidateCount; ++index)
        {
            findResult = FindIatSlot(
                processModule,
                spec.candidates[index],
                &target);
            if (findResult == FindSlotResult::Found ||
                findResult == FindSlotResult::Error)
            {
                break;
            }
        }

        if (findResult != FindSlotResult::Found || !target.candidate)
            return;

        HMODULE declaredModule = GetModuleHandleA(target.candidate->moduleName);
        if (!declaredModule)
            return;

        FARPROC expectedAddress = target.importedByOrdinal
            ? GetProcAddress(
                declaredModule,
                MAKEINTRESOURCEA(target.candidate->importOrdinal))
            : GetProcAddress(declaredModule, target.candidate->importName);
        if (!expectedAddress)
            return;

        bool isForwarder = false;
        if (!TryGetExportForwarderState(
                declaredModule,
                target,
                &isForwarder))
        {
            return;
        }

        AddressInfo expectedInfo{};
        AddressInfo observedInfo{};
        const bool expectedInspected = InspectAddress(
            reinterpret_cast<const void*>(expectedAddress),
            &expectedInfo);
        const bool observedInspected = InspectAddress(
            target.observedAddress,
            &observedInfo);

        if (expectedInspected)
        {
            CopyText(
                record->expectedModule,
                sizeof(record->expectedModule),
                expectedInfo.moduleName);
        }
        if (observedInspected)
        {
            CopyText(
                record->observedModule,
                sizeof(record->observedModule),
                observedInfo.moduleName);
        }

        P1IatAudit::TargetFacts facts{};
        facts.resolutionSucceeded = expectedInspected;
        facts.observedInspectionSucceeded = observedInspected;
        facts.expectedExportIsForwarder = isForwarder;
        facts.expectedAddress = reinterpret_cast<const void*>(expectedAddress);
        facts.observedAddress = target.observedAddress;
        facts.declaredModule = declaredModule;
        facts.expectedModule = expectedInfo.module;
        facts.observedModule = observedInfo.module;
        facts.expectedState = expectedInfo.state;
        facts.expectedType = expectedInfo.type;
        facts.observedState = observedInfo.state;
        facts.observedType = observedInfo.type;
        facts.expectedExecutable = expectedInfo.executable;
        facts.observedExecutable = observedInfo.executable;

        record->decision = P1IatAudit::EvaluateTarget(facts);
        record->result = P1IatAudit::ResultForDecision(record->decision);
    }
}

namespace P1IatAudit
{
    Decision EvaluateTarget(const TargetFacts& facts)
    {
        if (!facts.resolutionSucceeded ||
            !facts.observedInspectionSucceeded ||
            !facts.expectedAddress ||
            !facts.observedAddress ||
            !facts.declaredModule ||
            !facts.expectedModule ||
            facts.expectedState != MEM_COMMIT ||
            facts.expectedType != MEM_IMAGE ||
            !facts.expectedExecutable)
        {
            return Decision::ResolutionError;
        }

        if (facts.observedAddress != facts.expectedAddress)
            return Decision::UnauthorizedIatTarget;

        if (facts.observedState != MEM_COMMIT ||
            facts.observedType != MEM_IMAGE ||
            !facts.observedExecutable ||
            !facts.observedModule ||
            facts.observedModule != facts.expectedModule)
        {
            return Decision::ResolutionError;
        }

        if (facts.expectedExportIsForwarder)
            return Decision::LegitimateForwarder;

        if (facts.expectedModule != facts.declaredModule)
            return Decision::ResolutionError;

        return Decision::AuthorizedImplementation;
    }

    Result ResultForDecision(Decision decision)
    {
        switch (decision)
        {
        case Decision::AuthorizedImplementation:
        case Decision::LegitimateForwarder:
            return Result::Clean;
        case Decision::UnauthorizedIatTarget:
            return Result::Anomaly;
        default:
            return Result::ResolutionError;
        }
    }

    const char* DecisionToString(Decision decision)
    {
        switch (decision)
        {
        case Decision::AuthorizedImplementation:
            return "AUTHORIZED_IMPLEMENTATION";
        case Decision::LegitimateForwarder:
            return "LEGITIMATE_FORWARDER";
        case Decision::UnauthorizedIatTarget:
            return "UNAUTHORIZED_IAT_TARGET";
        default:
            return "RESOLUTION_ERROR";
        }
    }

    const char* ResultToString(Result result)
    {
        switch (result)
        {
        case Result::Clean:
            return "CLEAN";
        case Result::Anomaly:
            return "ANOMALY";
        default:
            return "RESOLUTION_ERROR";
        }
    }

    std::size_t AuditCurrentProcess(AuditRecord* records, std::size_t capacity)
    {
        if (!records || capacity < AuditRecordCount)
            return 0;

        for (std::size_t index = 0; index < AuditRecordCount; ++index)
        {
            __try
            {
                AuditApi(ApiSpecs[index], &records[index]);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                InitializeRecord(&records[index], ApiSpecs[index].api);
            }
        }

        return AuditRecordCount;
    }
}
