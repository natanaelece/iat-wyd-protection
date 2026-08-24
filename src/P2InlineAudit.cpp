#include "pch.h"

#include "P2InlineAudit.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
    static_assert(sizeof(void*) == sizeof(DWORD),
        "P2 inline integrity is implemented for the Win32 client target.");
    static_assert(P2InlineAudit::ComparisonWindowSize >= 16,
        "The inline comparison window must cover at least 16 bytes.");

    constexpr const char* UnresolvedModule = "<UNRESOLVED>";

    struct ApiSpec
    {
        const char* api;
        const char* declaredModule;
        const char* exportName;
        WORD exportOrdinal;
        bool resolveByOrdinal;
    };

    const ApiSpec ApiSpecs[] = {
        { "GetAdaptersInfo", "IPHLPAPI.DLL", "GetAdaptersInfo", 0, false },
        { "connect", "WSOCK32.dll", "connect", 4, true }
    };

    struct LoadedImageLayout
    {
        const BYTE* base;
        DWORD size;
        const IMAGE_NT_HEADERS32* ntHeaders;
    };

    struct RawImageLayout
    {
        const BYTE* base;
        std::size_t fileSize;
        const IMAGE_NT_HEADERS32* ntHeaders;
        const IMAGE_SECTION_HEADER* sections;
        WORD sectionCount;
    };

    class ReadOnlyImageFile
    {
    public:
        ReadOnlyImageFile()
            : m_file(INVALID_HANDLE_VALUE),
              m_mapping(nullptr),
              m_view(nullptr),
              m_size(0)
        {
        }

        ~ReadOnlyImageFile()
        {
            if (m_view)
                UnmapViewOfFile(m_view);
            if (m_mapping)
                CloseHandle(m_mapping);
            if (m_file != INVALID_HANDLE_VALUE)
                CloseHandle(m_file);
        }

        bool Open(const wchar_t* path)
        {
            if (!path || m_file != INVALID_HANDLE_VALUE)
                return false;

            m_file = CreateFileW(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (m_file == INVALID_HANDLE_VALUE)
                return false;

            LARGE_INTEGER size{};
            if (!GetFileSizeEx(m_file, &size) || size.QuadPart <= 0 ||
                static_cast<unsigned long long>(size.QuadPart) >
                    (std::numeric_limits<std::size_t>::max)())
            {
                return false;
            }

            m_size = static_cast<std::size_t>(size.QuadPart);
            m_mapping = CreateFileMappingW(
                m_file,
                nullptr,
                PAGE_READONLY,
                0,
                0,
                nullptr);
            if (!m_mapping)
                return false;

            m_view = static_cast<const BYTE*>(MapViewOfFile(
                m_mapping,
                FILE_MAP_READ,
                0,
                0,
                0));
            return m_view != nullptr;
        }

        const BYTE* Data() const
        {
            return m_view;
        }

        std::size_t Size() const
        {
            return m_size;
        }

    private:
        HANDLE m_file;
        HANDLE m_mapping;
        const BYTE* m_view;
        std::size_t m_size;
    };

    bool IsExecutableProtection(DWORD protection)
    {
        if ((protection & PAGE_GUARD) != 0 ||
            (protection & PAGE_NOACCESS) != 0)
        {
            return false;
        }

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

    void CopySanitizedBaseName(
        char* destination,
        std::size_t capacity,
        const wchar_t* path)
    {
        if (!destination || capacity == 0)
            return;

        CopyText(destination, capacity, UnresolvedModule);
        if (!path)
            return;

        const wchar_t* name = path;
        for (const wchar_t* cursor = path; *cursor; ++cursor)
        {
            if (*cursor == L'\\' || *cursor == L'/')
                name = cursor + 1;
        }

        std::size_t output = 0;
        for (const wchar_t* cursor = name;
             *cursor && output + 1 < capacity;
             ++cursor)
        {
            const wchar_t value = *cursor;
            const bool allowed =
                (value >= L'a' && value <= L'z') ||
                (value >= L'A' && value <= L'Z') ||
                (value >= L'0' && value <= L'9') ||
                value == L'.' || value == L'_' || value == L'-';
            destination[output++] = allowed
                ? static_cast<char>(value)
                : '?';
        }

        if (output == 0)
        {
            CopyText(destination, capacity, UnresolvedModule);
            return;
        }

        destination[output] = 0;
    }

    bool TryGetLoadedImageLayout(
        HMODULE module,
        LoadedImageLayout* image)
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
                nt->OptionalHeader.SizeOfImage < sizeof(IMAGE_DOS_HEADER))
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

    bool IsFileRangeValid(
        std::size_t fileSize,
        std::size_t offset,
        std::size_t size)
    {
        return offset <= fileSize && size <= fileSize - offset;
    }

    bool TryGetRawImageLayout(
        const BYTE* base,
        std::size_t fileSize,
        RawImageLayout* image)
    {
        if (!base || !image || fileSize < sizeof(IMAGE_DOS_HEADER))
            return false;

        const IMAGE_DOS_HEADER* dos =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            return false;

        const std::size_t ntOffset = static_cast<std::size_t>(dos->e_lfanew);
        if (!IsFileRangeValid(fileSize, ntOffset, sizeof(IMAGE_NT_HEADERS32)))
            return false;

        const IMAGE_NT_HEADERS32* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
            nt->FileHeader.SizeOfOptionalHeader <
                sizeof(IMAGE_OPTIONAL_HEADER32) ||
            nt->FileHeader.NumberOfSections == 0 ||
            nt->OptionalHeader.SizeOfHeaders == 0 ||
            nt->OptionalHeader.SizeOfImage < nt->OptionalHeader.SizeOfHeaders)
        {
            return false;
        }

        const std::size_t sectionOffset = ntOffset +
            offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
            nt->FileHeader.SizeOfOptionalHeader;
        const std::size_t sectionBytes =
            static_cast<std::size_t>(nt->FileHeader.NumberOfSections) *
            sizeof(IMAGE_SECTION_HEADER);
        if (!IsFileRangeValid(fileSize, sectionOffset, sectionBytes))
            return false;

        image->base = base;
        image->fileSize = fileSize;
        image->ntHeaders = nt;
        image->sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            base + sectionOffset);
        image->sectionCount = nt->FileHeader.NumberOfSections;
        return true;
    }

    const BYTE* RawRvaToPointer(
        const RawImageLayout& image,
        DWORD rva,
        std::size_t size)
    {
        const std::uint64_t rvaEnd =
            static_cast<std::uint64_t>(rva) + size;
        if (rvaEnd > image.ntHeaders->OptionalHeader.SizeOfImage)
            return nullptr;

        if (rva < image.ntHeaders->OptionalHeader.SizeOfHeaders)
        {
            if (rvaEnd > image.ntHeaders->OptionalHeader.SizeOfHeaders ||
                !IsFileRangeValid(image.fileSize, rva, size))
            {
                return nullptr;
            }
            return image.base + rva;
        }

        const IMAGE_SECTION_HEADER* match = nullptr;
        for (WORD index = 0; index < image.sectionCount; ++index)
        {
            const IMAGE_SECTION_HEADER& section = image.sections[index];
            const std::uint64_t sectionStart = section.VirtualAddress;
            const std::uint64_t sectionEnd = sectionStart +
                section.SizeOfRawData;
            if (rva >= sectionStart && rvaEnd <= sectionEnd)
            {
                if (match)
                    return nullptr;
                match = &section;
            }
        }

        if (!match)
            return nullptr;

        const std::size_t fileOffset =
            static_cast<std::size_t>(match->PointerToRawData) +
            static_cast<std::size_t>(rva - match->VirtualAddress);
        if (!IsFileRangeValid(image.fileSize, fileOffset, size))
            return nullptr;

        return image.base + fileOffset;
    }

    bool CopyRawRva(
        const RawImageLayout& image,
        DWORD rva,
        void* destination,
        std::size_t size)
    {
        const BYTE* source = RawRvaToPointer(image, rva, size);
        if (!source || !destination)
            return false;

        std::memcpy(destination, source, size);
        return true;
    }

    bool IsRawRangeZero(
        const RawImageLayout& image,
        DWORD rva,
        DWORD size)
    {
        for (DWORD index = 0; index < size; ++index)
        {
            const BYTE* value = RawRvaToPointer(image, rva + index, 1);
            if (!value || *value != 0)
                return false;
        }
        return true;
    }

    bool RangesIntersect(
        DWORD firstRva,
        std::size_t firstSize,
        DWORD secondRva,
        std::size_t secondSize)
    {
        const std::uint64_t firstEnd =
            static_cast<std::uint64_t>(firstRva) + firstSize;
        const std::uint64_t secondEnd =
            static_cast<std::uint64_t>(secondRva) + secondSize;
        return firstRva < secondEnd && secondRva < firstEnd;
    }

    bool MarkRelocation(
        DWORD targetRva,
        std::size_t relocationSize,
        DWORD windowRva,
        bool* mask,
        std::size_t windowSize)
    {
        if (!mask || relocationSize == 0)
            return false;

        if (!RangesIntersect(
                targetRva,
                relocationSize,
                windowRva,
                windowSize))
        {
            return true;
        }

        for (std::size_t index = 0; index < windowSize; ++index)
        {
            const DWORD byteRva = windowRva + static_cast<DWORD>(index);
            if (RangesIntersect(byteRva, 1, targetRva, relocationSize))
                mask[index] = true;
        }
        return true;
    }

    bool BuildRelocationMask(
        const RawImageLayout& image,
        DWORD windowRva,
        bool* mask,
        std::size_t windowSize)
    {
        if (!mask || windowSize == 0)
            return false;

        std::memset(mask, 0, sizeof(bool) * windowSize);
        if (image.ntHeaders->OptionalHeader.NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            return true;
        }

        const IMAGE_DATA_DIRECTORY& relocations =
            image.ntHeaders->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocations.VirtualAddress == 0 && relocations.Size == 0)
            return true;
        if (relocations.VirtualAddress == 0 ||
            relocations.Size < sizeof(IMAGE_BASE_RELOCATION) ||
            static_cast<std::uint64_t>(relocations.VirtualAddress) +
                relocations.Size >
                image.ntHeaders->OptionalHeader.SizeOfImage)
        {
            return false;
        }

        DWORD consumed = 0;
        while (consumed < relocations.Size)
        {
            const DWORD remaining = relocations.Size - consumed;
            if (remaining < sizeof(IMAGE_BASE_RELOCATION))
            {
                return IsRawRangeZero(
                    image,
                    relocations.VirtualAddress + consumed,
                    remaining);
            }

            IMAGE_BASE_RELOCATION block{};
            if (!CopyRawRva(
                    image,
                    relocations.VirtualAddress + consumed,
                    &block,
                    sizeof(block)))
            {
                return false;
            }

            if (block.VirtualAddress == 0 && block.SizeOfBlock == 0)
            {
                return IsRawRangeZero(
                    image,
                    relocations.VirtualAddress + consumed,
                    remaining);
            }
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > remaining ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) %
                    sizeof(WORD)) != 0)
            {
                return false;
            }

            const DWORD entryCount =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                sizeof(WORD);
            const DWORD entriesRva = relocations.VirtualAddress + consumed +
                sizeof(IMAGE_BASE_RELOCATION);

            for (DWORD entryIndex = 0;
                 entryIndex < entryCount;
                 ++entryIndex)
            {
                WORD entry = 0;
                if (!CopyRawRva(
                        image,
                        entriesRva + entryIndex * sizeof(WORD),
                        &entry,
                        sizeof(entry)))
                {
                    return false;
                }

                const WORD type = entry >> 12;
                const WORD offset = entry & 0x0FFFu;
                const std::uint64_t targetValue =
                    static_cast<std::uint64_t>(block.VirtualAddress) + offset;
                if (targetValue > (std::numeric_limits<DWORD>::max)())
                    return false;
                const DWORD targetRva = static_cast<DWORD>(targetValue);

                std::size_t relocationSize = 0;
                switch (type)
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    continue;
                case IMAGE_REL_BASED_HIGH:
                case IMAGE_REL_BASED_LOW:
                    relocationSize = sizeof(WORD);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    relocationSize = sizeof(DWORD);
                    break;
                case IMAGE_REL_BASED_HIGHADJ:
                    relocationSize = sizeof(WORD);
                    if (entryIndex + 1 >= entryCount)
                        return false;
                    ++entryIndex;
                    break;
                default:
                    if (RangesIntersect(
                            targetRva,
                            sizeof(DWORD),
                            windowRva,
                            windowSize))
                    {
                        return false;
                    }
                    continue;
                }

                if (!MarkRelocation(
                        targetRva,
                        relocationSize,
                        windowRva,
                        mask,
                        windowSize))
                {
                    return false;
                }
            }

            consumed += block.SizeOfBlock;
        }

        return consumed == relocations.Size;
    }

    bool SameImageIdentity(
        const LoadedImageLayout& live,
        const RawImageLayout& clean)
    {
        return
            live.ntHeaders->FileHeader.Machine ==
                clean.ntHeaders->FileHeader.Machine &&
            live.ntHeaders->FileHeader.TimeDateStamp ==
                clean.ntHeaders->FileHeader.TimeDateStamp &&
            live.ntHeaders->FileHeader.NumberOfSections ==
                clean.ntHeaders->FileHeader.NumberOfSections &&
            live.ntHeaders->OptionalHeader.SizeOfImage ==
                clean.ntHeaders->OptionalHeader.SizeOfImage &&
            live.ntHeaders->OptionalHeader.CheckSum ==
                clean.ntHeaders->OptionalHeader.CheckSum;
    }

    bool TryCopyLiveBytes(
        const void* source,
        void* destination,
        std::size_t size)
    {
        if (!source || !destination || size == 0)
            return false;

        __try
        {
            std::memcpy(destination, source, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void InitializeRecord(
        P2InlineAudit::AuditRecord* record,
        const char* api)
    {
        std::memset(record, 0, sizeof(*record));
        record->api = api;
        CopyText(
            record->finalModule,
            sizeof(record->finalModule),
            UnresolvedModule);
        record->result = P2InlineAudit::Result::ResolutionError;
    }

    void AuditApi(
        const ApiSpec& spec,
        P2InlineAudit::AuditRecord* record)
    {
        InitializeRecord(record, spec.api);

        HMODULE declaredModule = GetModuleHandleA(spec.declaredModule);
        if (!declaredModule)
            return;

        FARPROC finalAddress = spec.resolveByOrdinal
            ? GetProcAddress(
                declaredModule,
                MAKEINTRESOURCEA(spec.exportOrdinal))
            : GetProcAddress(declaredModule, spec.exportName);
        if (!finalAddress)
            return;

        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(
                reinterpret_cast<const void*>(finalAddress),
                &memory,
                sizeof(memory)) != sizeof(memory) ||
            memory.State != MEM_COMMIT ||
            memory.Type != MEM_IMAGE ||
            !IsExecutableProtection(memory.Protect) ||
            !memory.AllocationBase)
        {
            return;
        }

        const std::uintptr_t addressValue =
            reinterpret_cast<std::uintptr_t>(finalAddress);
        const std::uintptr_t regionStart =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const std::uintptr_t regionEnd = regionStart + memory.RegionSize;
        if (regionEnd < regionStart || addressValue < regionStart ||
            P2InlineAudit::ComparisonWindowSize > regionEnd - addressValue)
        {
            return;
        }

        HMODULE finalModule = reinterpret_cast<HMODULE>(memory.AllocationBase);
        LoadedImageLayout liveImage{};
        if (!TryGetLoadedImageLayout(finalModule, &liveImage))
            return;

        const std::uintptr_t moduleBase =
            reinterpret_cast<std::uintptr_t>(liveImage.base);
        if (addressValue < moduleBase)
            return;
        const std::uintptr_t rvaValue = addressValue - moduleBase;
        if (rvaValue > (std::numeric_limits<DWORD>::max)() ||
            rvaValue > liveImage.size ||
            P2InlineAudit::ComparisonWindowSize > liveImage.size - rvaValue)
        {
            return;
        }
        const DWORD functionRva = static_cast<DWORD>(rvaValue);

        std::vector<wchar_t> modulePath(32768, L'\0');
        const DWORD pathLength = GetModuleFileNameW(
            finalModule,
            modulePath.data(),
            static_cast<DWORD>(modulePath.size()));
        if (pathLength == 0 || pathLength >= modulePath.size())
            return;

        CopySanitizedBaseName(
            record->finalModule,
            sizeof(record->finalModule),
            modulePath.data());

        ReadOnlyImageFile cleanFile;
        if (!cleanFile.Open(modulePath.data()))
            return;

        RawImageLayout cleanImage{};
        if (!TryGetRawImageLayout(
                cleanFile.Data(),
                cleanFile.Size(),
                &cleanImage) ||
            !SameImageIdentity(liveImage, cleanImage))
        {
            return;
        }

        std::array<unsigned char,
            P2InlineAudit::ComparisonWindowSize> cleanBytes{};
        for (std::size_t index = 0;
             index < cleanBytes.size();
             ++index)
        {
            if (!CopyRawRva(
                    cleanImage,
                    functionRva + static_cast<DWORD>(index),
                    &cleanBytes[index],
                    1))
            {
                return;
            }
        }

        std::array<bool, P2InlineAudit::ComparisonWindowSize>
            relocationMask{};
        if (!BuildRelocationMask(
                cleanImage,
                functionRva,
                relocationMask.data(),
                relocationMask.size()))
        {
            return;
        }

        std::array<unsigned char,
            P2InlineAudit::ComparisonWindowSize> liveBytes{};
        if (!TryCopyLiveBytes(
                reinterpret_cast<const void*>(finalAddress),
                liveBytes.data(),
                liveBytes.size()))
        {
            return;
        }

        P2InlineAudit::WindowFacts facts{};
        facts.resolutionSucceeded = true;
        facts.liveBytes = liveBytes.data();
        facts.cleanBytes = cleanBytes.data();
        facts.relocationMask = relocationMask.data();
        facts.windowSize = liveBytes.size();
        record->result = P2InlineAudit::EvaluateWindow(facts);
    }
}

namespace P2InlineAudit
{
    Result EvaluateWindow(const WindowFacts& facts)
    {
        if (!facts.resolutionSucceeded ||
            !facts.liveBytes ||
            !facts.cleanBytes ||
            !facts.relocationMask ||
            facts.windowSize < MinimumComparedBytes)
        {
            return Result::ResolutionError;
        }

        std::size_t comparedBytes = 0;
        for (std::size_t index = 0; index < facts.windowSize; ++index)
        {
            if (facts.relocationMask[index])
                continue;

            ++comparedBytes;
            if (facts.liveBytes[index] != facts.cleanBytes[index])
                return Result::Anomaly;
        }

        return comparedBytes >= MinimumComparedBytes
            ? Result::Clean
            : Result::ResolutionError;
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

    std::size_t AuditCurrentProcess(
        AuditRecord* records,
        std::size_t capacity)
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
