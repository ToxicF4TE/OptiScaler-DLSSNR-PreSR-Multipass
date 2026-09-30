// Adapted from y4my4my4m/OptiScaler_DLSSNR_Multipass_MFG, tag v4 (7b7220bb), GPL-3.0.
#include "pch.h"

#include "MfgUnlock.h"

#include <Config.h>
#include <State.h>
#include <Util.h>
#include <scanner/scanner.h>
#include <misc/IdentifyGpu.h>

#include <mutex>
#include <utility>

namespace
{
// mov ebx,1 / mov r8d,3 / cmp edi,0x1b0 / cmovl r8d,ebx. The two counts and the architecture
// constant together are unique in the module; the wildcards cover nothing, they are here only to
// keep the shape readable.
constexpr std::string_view kAdvertisePattern = "BB 01 00 00 00 41 B8 03 00 00 00 81 FF B0 01 00 00 44 0F 4C C3";

// cmp eax,0x1b0 / jl / cmp ebx,3 / jbe. The only comparison against the architecture constant that
// is followed by a signed branch and a count test.
constexpr std::string_view kValidatePattern = "3D B0 01 00 00 7C ? 83 FB 03 76";

// Five generated frames, the count both patched sites carry.
constexpr uint8_t kMaxGeneratedFrames = 5;

// 310.9 restructured both gates. The count is no longer an immediate next to the comparison: the
// Blackwell branch starts at five and reads a configured value, and anything below Blackwell is sent
// to a branch that publishes one.
//     cmp ebp, 0x1b0
//     jl  ada          <- neutralised, so every card takes the Blackwell branch
//     mov edi, 0x5
constexpr std::string_view kAdvertisePattern309 = "81 FD B0 01 00 00 0F 8C ? ? ? ? BF 05 00 00 00";

// The capability flag in the same build is a setae rather than a branch.
//     cmp   eax, 0x1b0
//     setae al
constexpr std::string_view kValidatePattern309 = "3D B0 01 00 00 0F 93 C0";

// scanner::GetAddress only walks sections marked executable. Fatbins are data, so they need their own
// search. Returns 0 unless exactly one non-executable section holds the sequence, once.
uintptr_t FindDataBytes(HMODULE module, const uint8_t* needle, size_t length)
{
    auto base = reinterpret_cast<uint8_t*>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    uintptr_t found = 0;
    size_t hits = 0;

    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = section[i];

        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            continue;

        uint8_t* start = base + s.VirtualAddress;
        uint8_t* end = start + s.Misc.VirtualSize;

        for (uint8_t* p = std::search(start, end, needle, needle + length); p != end;
             p = std::search(p + 1, end, needle, needle + length))
        {
            found = reinterpret_cast<uintptr_t>(p);

            if (++hits > 1)
                return 0;
        }
    }

    return hits == 1 ? found : 0;
}

MfgUnlock::Status g_status {};
std::mutex g_mutex;

// A synchronous NGX logging callback can re-enter the loader or query our status.
// Capture diagnostics while patching and deliver them only after releasing g_mutex.
struct PatchLogs
{
    std::vector<std::pair<spdlog::level::level_enum, std::string>> messages;

    template <typename... Args>
    void Add(spdlog::level::level_enum level, const char* function, std::format_string<Args...> format, Args&&... args)
    {
        messages.emplace_back(level, std::format("{} {}", function, std::format(format, std::forward<Args>(args)...)));
    }

    void Flush() const
    {
        for (const auto& [level, message] : messages)
            spdlog::log(level, "{}", message);
    }
};

// Polling must retain the image while waiting for an apply transaction. Loader
// notifications already own their load reference. Release outside g_mutex.
struct ModuleReference
{
    HMODULE module = nullptr;
    ~ModuleReference()
    {
        if (module)
            FreeLibrary(module);
    }
};

uintptr_t UniqueAddress(HMODULE module, std::string_view pattern)
{
    const auto first = scanner::GetAddress(module, pattern);
    return first && !scanner::GetAddress(module, pattern, 0, first + 1) ? first : 0;
}

// The module's own file version, for the report. A signature that does not match is expected on a
// version nobody has looked at, and the version is the one thing that makes such a report actionable.
std::string ModuleVersion(HMODULE module)
{
    wchar_t path[MAX_PATH] {};

    if (GetModuleFileNameW(module, path, MAX_PATH) == 0)
        return {};

    version_t file {};
    version_t product {};

    if (!Util::GetFileVersion(path, &file, &product))
        return {};

    return std::format("{}.{}.{}", file.major, file.minor, file.patch);
}

bool WriteBytes(uintptr_t address, const uint8_t* bytes, size_t count, PatchLogs& logs)
{
    DWORD oldProtect = 0;

    if (!VirtualProtect((LPVOID) address, count, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        logs.Add(spdlog::level::warn, __FUNCTION__, "VirtualProtect failed at {:X}", address);
        return false;
    }

    std::memcpy((void*) address, bytes, count);

    DWORD ignored = 0;
    VirtualProtect((LPVOID) address, count, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID) address, count);

    return true;
}

std::string Hex(const uint8_t* bytes, size_t count)
{
    std::string out;

    for (size_t i = 0; i < count; ++i)
        out += std::format("{}{:02X}", i == 0 ? "" : " ", bytes[i]);

    return out;
}

// Rewrites count and neutralises the architecture clamp, so MultiFrameCountMax is published as five.
bool PatchAdvertise(HMODULE module, PatchLogs& logs)
{
    if (const auto at309 = UniqueAddress(module, kAdvertisePattern309); at309 != 0)
    {
        // The jl is a rel32, six bytes.
        const auto branchAt = at309 + 6;
        const uint8_t nop[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x90 };

        logs.Add(spdlog::level::info, __FUNCTION__, "MFG unlock: advertise (310.9) at {:X}, jl {} -> {}", at309,
                 Hex((const uint8_t*) branchAt, sizeof(nop)), Hex(nop, sizeof(nop)));

        return WriteBytes(branchAt, nop, sizeof(nop), logs);
    }

    const auto address = UniqueAddress(module, kAdvertisePattern);

    if (address == 0)
    {
        logs.Add(spdlog::level::warn, __FUNCTION__,
                 "MFG unlock: the advertise signature did not match, nvngx_dlssg.dll left alone");
        return false;
    }

    // Offsets within the matched sequence: the r8d immediate, and the cmovl.
    const auto countAt = address + 7;
    const auto cmovAt = address + 17;

    const uint8_t count[] = { kMaxGeneratedFrames };
    const uint8_t nop[] = { 0x0F, 0x1F, 0x40, 0x00 };

    logs.Add(spdlog::level::info, __FUNCTION__, "MFG unlock: advertise at {:X}, count {} -> {}, cmovl {} -> {}",
             address, *(const uint8_t*) countAt, kMaxGeneratedFrames, Hex((const uint8_t*) cmovAt, sizeof(nop)),
             Hex(nop, sizeof(nop)));

    return WriteBytes(countAt, count, sizeof(count), logs) && WriteBytes(cmovAt, nop, sizeof(nop), logs);
}

// Drops the Ada branch and raises the accepted count, so a request for five is not rejected.
bool PatchValidate(HMODULE module, PatchLogs& logs)
{
    if (const auto at309 = UniqueAddress(module, kValidatePattern309); at309 != 0)
    {
        // setae al -> mov al, 1, so the flag is set whatever the architecture reports.
        const auto setAt = at309 + 5;
        const uint8_t always[] = { 0xB0, 0x01, 0x90 };

        logs.Add(spdlog::level::info, __FUNCTION__, "MFG unlock: validate (310.9) at {:X}, setae {} -> {}", at309,
                 Hex((const uint8_t*) setAt, sizeof(always)), Hex(always, sizeof(always)));

        return WriteBytes(setAt, always, sizeof(always), logs);
    }

    const auto address = UniqueAddress(module, kValidatePattern);

    if (address == 0)
    {
        logs.Add(spdlog::level::warn, __FUNCTION__,
                 "MFG unlock: the validate signature did not match, nvngx_dlssg.dll left alone");
        return false;
    }

    // Offsets within the matched sequence: the jl, and the immediate of the count test behind it.
    const auto branchAt = address + 5;
    const auto countAt = address + 9;

    const uint8_t nop[] = { 0x90, 0x90 };
    const uint8_t count[] = { kMaxGeneratedFrames };

    logs.Add(spdlog::level::info, __FUNCTION__, "MFG unlock: validate at {:X}, jl {} -> {}, count {} -> {}", address,
             Hex((const uint8_t*) branchAt, sizeof(nop)), Hex(nop, sizeof(nop)), *(const uint8_t*) countAt,
             kMaxGeneratedFrames);

    return WriteBytes(branchAt, nop, sizeof(nop), logs) && WriteBytes(countAt, count, sizeof(count), logs);
}

// Gives Ada the Blackwell kernels the module already carries.
//
// nvngx_dlssg.dll ships two builds of the interpolation kernels. Kernel_EstimateIntermMvecsScatter
// reads three f32 fields of its parameter block on sm_120 and one on sm_89, so on Ada every generated
// frame is placed at the same point between the two real ones: the world does not advance between
// them while the interface, composited once per present, does. At 2X there is one frame and nothing
// to distinguish; above it that is the whole symptom.
//
// The sm_120 module uses no instruction Ada lacks. So per container: the Blackwell PTX image is
// relabelled sm_89, its .target directive is rewritten in place (".target sm_120" and
// ".target sm_89 " are both fourteen bytes, and the directive sits in the literal run at the head of
// the LZ4 stream), and the images that were sm_89 -- the Ada PTX and its SASS -- are relabelled to an
// architecture that does not exist so the driver cannot select them. The driver then JITs Blackwell's
// kernel when it asks for Ada's.
//
// Nothing is copied in and no payload changes length. A container without both images is left alone.
constexpr uint32_t kArchAda = 89;
constexpr uint32_t kArchBlackwell = 120;

// No such shader model. Parks an image where nothing will ask for it.
constexpr uint32_t kArchParked = 122;

// Offsets inside a fatbin image header: payload length, and the architecture the image answers for.
constexpr size_t kImagePayloadSize = 8;
constexpr size_t kImageArch = 28;

unsigned int RewriteBlackwellKernels(HMODULE module, PatchLogs& logs)
{
    auto base = reinterpret_cast<uint8_t*>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    const uint8_t magic[] = { 0x50, 0xED, 0x55, 0xBA };
    unsigned int rewritten = 0;

    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = section[i];

        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            continue;

        uint8_t* start = base + s.VirtualAddress;
        uint8_t* end = start + s.Misc.VirtualSize;

        for (uint8_t* c = std::search(start, end, magic, magic + sizeof(magic)); c < end;
             c = std::search(c + 1, end, magic, magic + sizeof(magic)))
        {
            if (end - c < 16)
                break;

            const auto headerSize = *reinterpret_cast<const uint16_t*>(c + 6);
            const auto fatSize = *reinterpret_cast<const uint64_t*>(c + 8);

            if (headerSize != 0x10 || fatSize == 0 || fatSize > (uint64_t) (end - c - 16))
                continue;

            uint8_t* blackwell = nullptr;
            size_t blackwellHeader = 0;
            size_t blackwellPayload = 0;
            std::vector<uint8_t*> ada;
            bool valid = true;

            for (uint8_t* image = c + 16; image < c + 16 + fatSize;)
            {
                const auto remaining = (uint64_t) (c + 16 + fatSize - image);
                if (remaining < kImageArch + sizeof(uint32_t))
                {
                    valid = false;
                    break;
                }
                const auto kind = *reinterpret_cast<const uint16_t*>(image);
                const auto imageHeader = *reinterpret_cast<const uint32_t*>(image + 4);
                const auto payload = *reinterpret_cast<const uint64_t*>(image + kImagePayloadSize);
                const auto arch = *reinterpret_cast<const uint32_t*>(image + kImageArch);

                if (imageHeader < kImageArch + sizeof(uint32_t) || imageHeader > remaining || payload == 0 ||
                    payload > remaining - imageHeader)
                {
                    valid = false;
                    break;
                }

                // kind 1 is PTX, 2 is a cubin. Only the PTX can be retargeted; the cubin is parked.
                if (kind == 1 && arch == kArchBlackwell)
                {
                    blackwell = image;
                    blackwellHeader = imageHeader;
                    blackwellPayload = payload;
                }
                else if (arch == kArchAda)
                {
                    ada.push_back(image);
                }

                image += imageHeader + payload;
            }

            if (!valid || blackwell == nullptr || ada.empty())
                continue;

            const char from[] = ".target sm_120";
            const char to[] = ".target sm_89 ";
            static_assert(sizeof(from) == sizeof(to), "the directive rewrite must not change length");

            uint8_t* body = blackwell + blackwellHeader;
            uint8_t* bodyEnd = body + blackwellPayload;
            auto at = std::search(body, bodyEnd, from, from + sizeof(from) - 1);

            if (at == bodyEnd)
                continue;

            const uint32_t ada89 = kArchAda;
            const uint32_t parked = kArchParked;
            // Prepare one complete container first. A failed protection change must not leave
            // its PTX target and architecture headers disagreeing, or count a partial rewrite.
            std::vector<uint8_t> patched(c, c + 16 + fatSize);
            std::memcpy(patched.data() + (at - c), to, sizeof(to) - 1);
            std::memcpy(patched.data() + (blackwell + kImageArch - c), &ada89, sizeof(ada89));
            for (uint8_t* image : ada)
                std::memcpy(patched.data() + (image + kImageArch - c), &parked, sizeof(parked));
            if (WriteBytes(reinterpret_cast<uintptr_t>(c), patched.data(), patched.size(), logs))
                ++rewritten;
        }
    }

    logs.Add(spdlog::level::info, __FUNCTION__, "MFG unlock: {} kernel containers answer Ada with the Blackwell image",
             rewritten);

    return rewritten;
}
} // namespace

bool MfgUnlock::Enabled()
{
    if (!Config::Instance()->FGDLSSGAdaMfgUnlock.value_or_default() ||
        Config::Instance()->FGDLSSGAmpereMfgUnlock.value_or_default() || State::Instance().externalFrameGeneration)
        return false;
    const auto& gpu = IdentifyGpu::getPrimaryGpu();
    // The kernel retarget is Ada-specific. Do not patch Ampere/Turing or change Blackwell's working path.
    return gpu.vendorId == VendorId::Nvidia && gpu.nvidiaArchInfo.architecture_id == NV_GPU_ARCHITECTURE_AD100;
}

void MfgUnlock::TryApply(HMODULE requestedModule)
{
    if (!Enabled())
        return;

    ModuleReference reference;
    auto module = requestedModule;
    if (!module)
    {
        if (!GetModuleHandleExW(0, L"nvngx_dlssg.dll", &reference.module))
            return;
        module = reference.module;
    }

    // NGX can probe a local DLL before selecting a different cached provider. Track each image,
    // while allowing an explicit load notification to recognise a reload at a previously used base.
    static std::vector<HMODULE> triedModules;
    {
        std::lock_guard lock(g_mutex);
        if (!requestedModule && std::find(triedModules.begin(), triedModules.end(), module) != triedModules.end())
            return;
    }

    // These can take the loader/GPU locks. Never hold our transaction mutex around them.
    const auto version = ModuleVersion(module);
    const auto& gpu = IdentifyGpu::getPrimaryGpu();
    const bool preBlackwell = gpu.vendorId == VendorId::Nvidia &&
                              gpu.nvidiaArchInfo.architecture_id >= NV_GPU_ARCHITECTURE_TU100 &&
                              gpu.nvidiaArchInfo.architecture_id <= NV_GPU_ARCHITECTURE_AD100;
    const bool rewriteKernels = Config::Instance()->FGDLSSGAdaBlackwellKernels.value_or(preBlackwell);

    PatchLogs logs;
    std::unique_lock lock(g_mutex);
    // Recheck after metadata retrieval: another thread may have completed this image.
    const bool seen = std::find(triedModules.begin(), triedModules.end(), module) != triedModules.end();
    if (seen && requestedModule == nullptr)
        return;

    // Patched gates no longer match. Unknown probes must not erase a supported provider's status.
    const bool knownGates =
        (UniqueAddress(module, kAdvertisePattern309) && UniqueAddress(module, kValidatePattern309)) ||
        (UniqueAddress(module, kAdvertisePattern) && UniqueAddress(module, kValidatePattern));
    if (seen && !knownGates)
        return;
    if (!seen)
        triedModules.push_back(module);
    if (!knownGates)
    {
        logs.Add(spdlog::level::warn, __FUNCTION__,
                 "MFG unlock: unsupported or ambiguous DLSSG {} signatures; left unchanged", version);
    }
    else
    {
        Status status {};
        status.ModuleFound = true;
        status.SnippetVersion = version;

        // On Ada the unlock and compatible interpolation kernels belong together.
        if (rewriteKernels)
            status.KernelsRewritten = RewriteBlackwellKernels(module, logs);

        if (status.KernelsRewritten == 0)
        {
            logs.Add(spdlog::level::warn, __FUNCTION__,
                     "MFG unlock: no compatible interpolation kernels; frame-count gates left unchanged");
        }
        else
        {
            status.AdvertiseMatched = PatchAdvertise(module, logs);
            status.ValidateMatched = PatchValidate(module, logs);

            if (status.AdvertiseMatched && status.ValidateMatched)
                logs.Add(spdlog::level::info, __FUNCTION__,
                         "MFG unlock: nvngx_dlssg.dll patched for {} generated frames", kMaxGeneratedFrames);
            else
                logs.Add(spdlog::level::warn, __FUNCTION__,
                         "MFG unlock: nvngx_dlssg.dll incomplete, advertise {}, validate {}", status.AdvertiseMatched,
                         status.ValidateMatched);
        }
        g_status = std::move(status);
    }
    lock.unlock();
    logs.Flush();
}

unsigned int MfgUnlock::UnlockedMax()
{
    std::lock_guard lock(g_mutex);
    return g_status.AdvertiseMatched && g_status.ValidateMatched && g_status.KernelsRewritten > 0 ? kMaxGeneratedFrames
                                                                                                  : 0;
}

bool MfgUnlock::Pending()
{
    if (!Enabled())
        return false;
    std::lock_guard lock(g_mutex);
    return !g_status.ModuleFound;
}

MfgUnlock::Status MfgUnlock::LastStatus()
{
    std::lock_guard lock(g_mutex);
    return g_status;
}
