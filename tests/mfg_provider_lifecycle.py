#!/usr/bin/env python3
"""Test the production Ada provider lifecycle and loader branches with fake modules.

Run on Windows from an x64 Native Tools prompt:
    python tests/mfg_provider_lifecycle.py

The production functions and relevant loader blocks are extracted from this tree,
not reimplemented. Only OS loading, signature scanning, and GPU/patch boundaries
are faked. Each case runs in a fresh process to reset function-local state.
No game, NVIDIA runtime, GPU, or third-party Python package is needed.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start + len(signature))
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


STUBS = r'''
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <compare>
#include <concepts>
#include <cstdio>
#include <cwctype>
#include <filesystem>
#include <format>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

thread_local bool applyLockHeld = false;
std::atomic<bool> boundaryViolation{false}, checkBoundaries{false}, pauseKernels{false};
std::promise<void> kernelsPaused, resumeKernels;
auto resumeSignal = resumeKernels.get_future().share();
struct CheckedMutex {
    std::mutex mutex;
    std::atomic<unsigned> attempts{0};
    void lock() { ++attempts; mutex.lock(); applyLockHeld = true; }
    void unlock() { applyLockHeld = false; mutex.unlock(); }
} g_mutex;
void outsideApplyLock() {
    if (checkBoundaries && applyLockHeld) boundaryViolation = true;
}
void insideApplyLock() {
    if (checkBoundaries && !applyLockHeld) boundaryViolation = true;
}
// Pause exactly after the production kernel-count assignment, before its gate test.
struct KernelCount {
    unsigned value = 0;
    operator unsigned() const { return value; }
    KernelCount& operator=(unsigned count) {
        value = count;
        if (count == 31 && pauseKernels.exchange(false)) {
            kernelsPaused.set_value();
            resumeSignal.wait();
        }
        return *this;
    }
};
std::function<void()> loggingCallback;
namespace spdlog {
namespace level { enum level_enum { info, warn }; }
template<class... Args> void log(level::level_enum, Args&&...) {
    outsideApplyLock();
    // Record unsafe dispatch without hanging the negative-control process.
    if (!applyLockHeld && loggingCallback) loggingCallback();
}
}

struct FakeModule {
    bool supported = true, loaded = true, kernelCompatible = true;
    bool advertise = false, validate = false, advertiseWritable = true;
    bool kernelsRetargeted = false;
    unsigned rewrites = 0, references = 0;
    std::string version = "310.9.1";
};
using HMODULE = FakeModule*;
constexpr unsigned kMaxGeneratedFrames = 5;
constexpr int NV_GPU_ARCHITECTURE_TU100 = 0x160;
constexpr int NV_GPU_ARCHITECTURE_AD100 = 0x190;
enum class VendorId { Nvidia, Other };
struct Option {
    std::optional<bool> value;
    bool value_or_default() const { return value.value_or(false); }
    bool value_or(bool fallback) const { return value.value_or(fallback); }
};

// The real CustomOptional implementation is inserted here.
/* CONFIG_OPTION */
struct feature_version {
    int major, minor, patch;
    auto operator<=>(const feature_version&) const = default;
};
namespace sl {
enum class Result { eOk };
enum class DLSSGMode { eOff, eOn };
struct DLSSGOptions { unsigned numFramesToGenerate = 3; DLSSGMode mode = DLSSGMode::eOn; };
struct DLSSGState { unsigned numFramesToGenerateMax = 1; };
}
unsigned nativeCeiling = 1;
sl::DLSSGMode emittedMode = sl::DLSSGMode::eOn;
sl::Result o_slDLSSGGetState(int, sl::DLSSGState& state, const sl::DLSSGOptions*) {
    state.numFramesToGenerateMax = nativeCeiling;
    return sl::Result::eOk;
}

struct Config {
    CustomOptional<int, NoDefault> FGDLSSGOverrideInterpolationCount;
    Option FGDLSSGAdaMfgUnlock{true}, FGDLSSGAmpereMfgUnlock{false};
    Option FGDLSSGAdaBlackwellKernels{};
    static Config* Instance() { static Config config; return &config; }
};
struct State {
    feature_version streamlineVersion{2,14,1};
    std::optional<int> dlssgMfgMax;
    bool externalFrameGeneration = false;
    std::string NGX_OTA_Dlss, NGX_OTA_Dlssd;
    static State& Instance() { static State state; return state; }
};
namespace IdentifyGpu {
struct GPU {
    VendorId vendorId = VendorId::Nvidia;
    struct { int architecture_id = NV_GPU_ARCHITECTURE_AD100; } nvidiaArchInfo;
};
GPU gpu;
const GPU& getPrimaryGpu() { outsideApplyLock(); return gpu; }
}
namespace MfgUnlock {
struct Status {
    bool ModuleFound = false, AdvertiseMatched = false, ValidateMatched = false;
    KernelCount KernelsRewritten;
    std::string SnippetVersion;
};
void TryApply(HMODULE = nullptr);
bool Enabled();
bool Pending();
unsigned int UnlockedMax();
const Status& LastStatus();
}
MfgUnlock::Status g_status;
HMODULE current = nullptr, nextLoaded = nullptr;
unsigned loaderCalls = 0;
unsigned referenceAcquires = 0, referenceReleases = 0, versionReads = 0;
HMODULE GetModuleHandleW(const wchar_t*) {
    outsideApplyLock(); return current && current->loaded ? current : nullptr;
}
bool GetModuleHandleExW(unsigned, const wchar_t*, HMODULE* module) {
    outsideApplyLock();
    *module = GetModuleHandleW(nullptr);
    if (!*module) return false;
    ++(*module)->references; ++referenceAcquires;
    return true;
}
bool FreeLibrary(HMODULE module) {
    outsideApplyLock(); --module->references; ++referenceReleases;
    return true;
}
namespace NtdllProxy {
HMODULE LoadLibraryExW_Ldr(const wchar_t*, void*, int) {
    ++loaderCalls;
    current = nextLoaded;
    return nextLoaded;
}
}
constexpr std::string_view kAdvertisePattern309 = "advertise";
constexpr std::string_view kValidatePattern309 = "validate";
constexpr std::string_view kAdvertisePattern = "legacyAdvertise";
constexpr std::string_view kValidatePattern = "legacyValidate";
uintptr_t UniqueAddress(HMODULE module, std::string_view pattern) {
    insideApplyLock();
    if (!module->supported || !module->loaded) return 0;
    if (pattern == kAdvertisePattern309) return !module->advertise;
    if (pattern == kValidatePattern309) return !module->validate;
    return 0;
}
std::string ModuleVersion(HMODULE module) {
    outsideApplyLock(); ++versionReads; return module->version;
}
// The production diagnostic/reference helpers are inserted here.
/* PATCH_HELPERS */
template<class... Logs> unsigned RewriteBlackwellKernels(HMODULE module, Logs&... logs) {
    insideApplyLock();
    ++module->rewrites;
    const bool canRewrite = module->kernelCompatible && !module->kernelsRetargeted;
    module->kernelsRetargeted |= canRewrite;
    (logs.Add(spdlog::level::info, "RewriteBlackwellKernels", "kernels {}", canRewrite), ...);
    return canRewrite ? 31 : 0;
}
template<class... Logs> bool PatchAdvertise(HMODULE module, Logs&... logs) {
    insideApplyLock();
    (logs.Add(spdlog::level::info, "PatchAdvertise", "advertise"), ...);
    return module->advertise = module->advertiseWritable;
}
template<class... Logs> bool PatchValidate(HMODULE module, Logs&... logs) {
    insideApplyLock();
    (logs.Add(spdlog::level::info, "PatchValidate", "validate"), ...);
    return module->validate = true;
}
std::string wstring_to_string(const wchar_t* path) {
    std::wstring wide(path);
    std::string narrow;
    for (wchar_t character : wide) narrow.push_back(static_cast<char>(character));
    return narrow;
}
#define LOG_INFO(...) spdlog::log(spdlog::level::info, __VA_ARGS__)
#define LOG_WARN(...) spdlog::log(spdlog::level::warn, __VA_ARGS__)
'''

CASES = r'''
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)
bool unlocked(const FakeModule& module) {
    return module.advertise && module.validate && module.rewrites == 1;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string name = argv[1];
    FakeModule local, cached, unknown;
    cached.version = "310.9.0";
    unknown.supported = false;
    const std::wstring dll = L"C:\\game\\nvngx_dlssg.dll";
    const std::wstring bin = L"C:\\ProgramData\\NVIDIA\\NGX\\models\\dlssg\\versions\\20318464\\files\\160_e658700.bin";
    if (name.starts_with("concurrent_")) {
        checkBoundaries = true;
        pauseKernels = true;
        auto paused = kernelsPaused.get_future();
        std::thread writer([&] { MfgUnlock::TryApply(&local); });
        const bool writerPaused = paused.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        const unsigned before = g_mutex.attempts;
        std::promise<void> readerDone;
        auto done = readerDone.get_future();
        bool readerGood = false;
        std::thread reader([&] {
            if (name == "concurrent_provider_notifications") {
                MfgUnlock::TryApply(&local); readerGood = true;
            } else if (name == "concurrent_status_snapshot") {
                const auto status = MfgUnlock::LastStatus();
                readerGood = status.AdvertiseMatched && status.ValidateMatched && status.KernelsRewritten == 31;
            } else if (name == "concurrent_unlocked_max") {
                readerGood = MfgUnlock::UnlockedMax() == 5;
            } else if (name == "concurrent_pending") {
                readerGood = !MfgUnlock::Pending();
            }
            readerDone.set_value();
        });
        // Observe either the contender's actual mutex acquisition attempt or an
        // unprotected return. No scheduling assumption or stress-only oracle.
        for (unsigned i = 0; i < 2000 && g_mutex.attempts == before &&
                done.wait_for(std::chrono::seconds(0)) != std::future_status::ready; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        const bool readerBlocked = g_mutex.attempts > before;
        resumeKernels.set_value();
        writer.join(); reader.join();
        CHECK(writerPaused && readerBlocked && readerGood && !boundaryViolation);
        CHECK(unlocked(local) && MfgUnlock::UnlockedMax() == 5);
    } else if (name == "stable_status_snapshot") {
        local.version = std::string(96, 'L'); cached.version = std::string(96, 'C');
        Load(dll, &local);
        const auto& previous = MfgUnlock::LastStatus();
        Load(bin, &cached);
        CHECK(previous.SnippetVersion == local.version && previous.AdvertiseMatched);
        CHECK(MfgUnlock::LastStatus().SnippetVersion == cached.version);
    } else if (name == "metadata_outside_lock") {
        checkBoundaries = true;
        Load(dll, &local);
        CHECK(unlocked(local) && !boundaryViolation);
    } else if (name == "logging_reentry") {
        checkBoundaries = true;
        unsigned callbacks = 0;
        bool complete = true;
        loggingCallback = [&] {
            ++callbacks;
            const auto status = MfgUnlock::LastStatus();
            complete &= status.AdvertiseMatched && status.ValidateMatched && status.KernelsRewritten == 31;
            MfgUnlock::TryApply(&local);
        };
        Load(dll, &local);
        CHECK(callbacks > 0 && complete && !boundaryViolation && unlocked(local));
    } else if (name == "polled_module_reference") {
        checkBoundaries = true;
        current = &local;
        MfgUnlock::TryApply();
        const unsigned reads = versionReads;
        MfgUnlock::TryApply();
        CHECK(unlocked(local) && !boundaryViolation && local.references == 0);
        CHECK(referenceAcquires == 2 && referenceReleases == 2 && versionReads == reads);
    } else if (name == "local_then_cached") {
        Load(dll, &local); CHECK(unlocked(local)); CHECK(!MfgUnlock::Pending());
        local.loaded = false;
        Load(bin, &cached); CHECK(unlocked(cached));
        CHECK(g_status.SnippetVersion == "310.9.0" && MfgUnlock::UnlockedMax() == 5);
    } else if (name == "cached_then_local") {
        Load(bin, &cached); Load(dll, &local);
        CHECK(unlocked(local) && unlocked(cached));
    } else if (name == "duplicate_notifications") {
        Load(dll, &local); Load(dll, &local); MfgUnlock::TryApply();
        CHECK(unlocked(local));
    } else if (name == "same_address_reload") {
        Load(dll, &local); local = FakeModule{}; Load(dll, &local);
        CHECK(unlocked(local));
    } else if (name == "unsupported_after_success") {
        Load(bin, &cached); Load(dll, &unknown);
        CHECK(unknown.rewrites == 0 && !unknown.advertise && !unknown.validate);
        CHECK(MfgUnlock::UnlockedMax() == 5 && g_status.SnippetVersion == "310.9.0");
    } else if (name == "unsupported_before_supported") {
        Load(dll, &unknown); CHECK(MfgUnlock::Pending());
        Load(bin, &cached); CHECK(unlocked(cached));
    } else if (name == "unsupported_address_reused") {
        Load(dll, &unknown); unknown = FakeModule{}; Load(dll, &unknown);
        CHECK(unlocked(unknown));
    } else if (name == "incompatible_kernels") {
        Load(dll, &local); cached.kernelCompatible = false; Load(bin, &cached);
        CHECK(!cached.advertise && !cached.validate && cached.rewrites == 1);
        CHECK(MfgUnlock::UnlockedMax() == 0);
    } else if (name == "kernels_disabled_after_success") {
        Load(dll, &local); Config::Instance()->FGDLSSGAdaBlackwellKernels.value = false;
        Load(bin, &cached);
        CHECK(cached.rewrites == 0 && !cached.advertise && !cached.validate);
        CHECK(MfgUnlock::UnlockedMax() == 0);
    } else if (name == "partial_gate_failure") {
        Load(dll, &local); cached.advertiseWritable = false; Load(bin, &cached);
        CHECK(!cached.advertise && cached.validate && MfgUnlock::UnlockedMax() == 0);
    } else if (name == "unlock_disabled") {
        Config::Instance()->FGDLSSGAdaMfgUnlock.value = false;
        Load(dll, &local); Load(bin, &cached); MfgUnlock::TryApply(&local);
        CHECK(local.rewrites == 0 && cached.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "ampere_unlock_selected") {
        Config::Instance()->FGDLSSGAmpereMfgUnlock.value = true;
        Load(dll, &local); Load(bin, &cached); MfgUnlock::TryApply(&local);
        CHECK(local.rewrites == 0 && cached.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "external_fg") {
        State::Instance().externalFrameGeneration = true;
        CHECK(Load(dll, &local) == nullptr && Load(bin, &cached) == nullptr);
        MfgUnlock::TryApply(&local);
        CHECK(loaderCalls == 0 && local.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "non_ada" || name == "non_nvidia") {
        if (name == "non_ada") IdentifyGpu::gpu.nvidiaArchInfo.architecture_id = 0x170;
        else IdentifyGpu::gpu.vendorId = VendorId::Other;
        Load(dll, &local); Load(bin, &cached); MfgUnlock::TryApply(&local);
        CHECK(local.rewrites == 0 && cached.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "absent_provider") {
        MfgUnlock::TryApply(); CHECK(MfgUnlock::Pending());
        CHECK(Load(bin, nullptr) == nullptr && MfgUnlock::Pending());
        Load(bin, &cached); CHECK(unlocked(cached));
    } else if (name == "normalized_cache_path") {
        Load(L"C:/ProgramData/NVIDIA/NGX/models//DLSSG/versions/20318464/files/160_e658700.bin", &cached);
        CHECK(unlocked(cached));
    } else if (name == "other_ota_features") {
        Load(L"C:\\NGX\\models\\dlss\\versions\\1\\files\\runtime.bin", &local);
        Load(L"C:\\NGX\\models\\dlssd\\versions\\1\\files\\runtime.bin", &cached);
        Load(L"C:\\unrelated\\runtime.bin", &unknown);
        CHECK(local.rewrites == 0 && cached.rewrites == 0 && unknown.rewrites == 0);
        CHECK(!State::Instance().NGX_OTA_Dlss.empty() && !State::Instance().NGX_OTA_Dlssd.empty());



    } else if (name == "initial_override_above_max" || name == "initial_state_override_above_max" ||
               name == "initial_zero_override" || name == "initial_unset_override") {
        auto& requested = Config::Instance()->FGDLSSGOverrideInterpolationCount;
        if (name != "initial_unset_override") requested = name == "initial_zero_override" ? 0 : 6;
        Load(dll, &local);
        if (name == "initial_state_override_above_max") QuerySettings();
        const auto sent = ApplySettings();
        CHECK(State::Instance().dlssgMfgMax == 5);
        if (name == "initial_unset_override")
            CHECK(!requested.has_value() && sent == 3 && emittedMode == sl::DLSSGMode::eOn);
        else if (name == "initial_zero_override")
            CHECK(requested.value() == 0 && requested.value_for_config_or(-1) == 0 && emittedMode == sl::DLSSGMode::eOff);
        else CHECK(sent == 5 && requested.value_for_config_or(-1) == 6);
    } else if (name == "pending_limit_options" || name == "pending_limit_state" ||
               name == "pending_limit_recovery" || name == "unsupported_limit_recovery") {
        auto& requested = Config::Instance()->FGDLSSGOverrideInterpolationCount;
        requested = 3;
        if (name != "pending_limit_recovery") Load(dll, &unknown);
        CHECK(MfgUnlock::Pending());
        if (name == "pending_limit_state") QuerySettings();
        else CHECK(ApplySettings() == 1);
        CHECK(State::Instance().dlssgMfgMax == 1 && requested.value() == 1);
        CHECK(requested.value_for_config_or(-1) == 3 && MfgUnlock::Pending());
        if (name == "pending_limit_recovery" || name == "unsupported_limit_recovery") {
            Load(bin, &cached);
            nativeCeiling = 5;
            CHECK(ApplySettings() == 3 && State::Instance().dlssgMfgMax == 5);
            CHECK(requested.value_for_config_or(-1) == 3);
        }
    } else if (name == "provisional_limit_recovery" || name == "state_query_limit_recovery" ||
               name == "newer_user_override" || name == "newer_user_override_one") {
        auto& requested = Config::Instance()->FGDLSSGOverrideInterpolationCount;
        requested = 3;
        local.kernelCompatible = false;
        Load(dll, &local);
        if (name == "state_query_limit_recovery") QuerySettings();
        else CHECK(ApplySettings() == 1);
        CHECK(State::Instance().dlssgMfgMax == 1 && requested.value() == 1);
        CHECK(requested.value_for_config_or(-1) == 3);
        const int expected = name == "newer_user_override" ? 2 : name == "newer_user_override_one" ? 1 : 3;
        if (expected != 3) requested = expected;
        Load(bin, &cached);
        nativeCeiling = 5;
        if (name == "state_query_limit_recovery") QuerySettings();
        CHECK(ApplySettings() == expected && State::Instance().dlssgMfgMax == 5);
        CHECK(requested.value_for_config_or(-1) == expected);
    } else return 2;
    std::printf("PASS %s\n", argv[1]);
    return 0;
}
'''

SCENARIOS = (
    "initial_override_above_max", "initial_state_override_above_max", "initial_zero_override", "initial_unset_override",
    "pending_limit_options", "pending_limit_state", "pending_limit_recovery", "unsupported_limit_recovery",
    "local_then_cached", "cached_then_local", "duplicate_notifications",
    "same_address_reload", "unsupported_after_success", "unsupported_before_supported",
    "unsupported_address_reused", "incompatible_kernels", "kernels_disabled_after_success",
    "partial_gate_failure", "unlock_disabled", "ampere_unlock_selected", "external_fg",
    "non_ada", "non_nvidia", "absent_provider", "normalized_cache_path", "other_ota_features",
    "concurrent_provider_notifications", "concurrent_status_snapshot", "concurrent_unlocked_max",
    "concurrent_pending", "stable_status_snapshot", "metadata_outside_lock", "logging_reentry",
    "polled_module_reference",
    "provisional_limit_recovery", "state_query_limit_recovery", "newer_user_override", "newer_user_override_one",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--compiler", default="cl")
    parser.add_argument("--case", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    unlock = (args.source_root / "OptiScaler/framegen/dlssg/MfgUnlock.cpp").read_text(encoding="utf-8-sig")
    hook = (args.source_root / "OptiScaler/hooks/LibraryLoad_Hooks.cpp").read_text(encoding="utf-8-sig")
    helpers = ""
    for signature in ("struct PatchLogs", "struct ModuleReference"):
        if signature in unlock:
            helpers += body(unlock, signature) + ";\n"
    code = STUBS.replace("/* PATCH_HELPERS */", helpers) + "\n"
    if "MfgUnlock::Status MfgUnlock::LastStatus()" in unlock:
        code = code.replace("const Status& LastStatus();", "Status LastStatus();")
    for signature in ("bool MfgUnlock::Enabled()", "void MfgUnlock::TryApply(",
                      "bool MfgUnlock::Pending()", "unsigned int MfgUnlock::UnlockedMax()",
                      "const MfgUnlock::Status& MfgUnlock::LastStatus()",
                      "MfgUnlock::Status MfgUnlock::LastStatus()"):
        if signature in unlock:
            if signature == "MfgUnlock::Status MfgUnlock::LastStatus()" and \
                    "const MfgUnlock::Status& MfgUnlock::LastStatus()" in unlock:
                continue
            code += body(unlock, signature) + "\n"
    # These are the actual loader branches, including their eligibility checks.
    code += r'''
HMODULE Load(std::wstring libName, HMODULE module) {
    nextLoaded = module;
    const wchar_t* lpLibFullPath = libName.c_str();
    auto normalizedPath = std::filesystem::path(libName).lexically_normal().wstring();
    std::transform(normalizedPath.begin(), normalizedPath.end(), normalizedPath.begin(), std::towlower);
'''
    code += body(hook, "if (State::Instance().externalFrameGeneration)") + "\n"
    ada = hook[hook.index("// Optional Ada unlock"):]
    code += body(ada, "if (") + "\n"
    code += body(hook, 'if (libName.ends_with(L".bin"))') + "\n"
    code += "return NtdllProxy::LoadLibraryExW_Ldr(lpLibFullPath, nullptr, 0);\n}\n"

    config = (args.source_root / "OptiScaler/Config.h").read_text(encoding="utf-8-sig")
    optional = config[config.index("enum HasDefaultValue"):config.index("constexpr inline int UnboundKey")]
    code = code.replace("/* CONFIG_OPTION */", optional)
    streamline = (args.source_root / "OptiScaler/hooks/Streamline_Hooks.cpp").read_text(encoding="utf-8-sig")
    code += "\n#define OPTISCALER_RTX40_MFG 1\n#define LOG_TRACE(...) ((void)0)\n"
    code += body(streamline, "void RefreshAdaMfgLimit()") + "\n"
    code += "unsigned ApplySettings() { auto& state = State::Instance(); sl::DLSSGOptions newOptions;\n"
    code += "const bool dlssgPotentiallyActive = true, enableDynamicMode = false; const int viewport = 0;\n"
    code += body(streamline, "if (dlssgPotentiallyActive && state.streamlineVersion >= feature_version { 2, 7, 1 })")
    code += "\nemittedMode = newOptions.mode; return newOptions.numFramesToGenerate; }\n"
    # Include the actual GetState preamble and caching branch, not a duplicate of its policy.
    get_state = streamline[streamline.index("sl::Result StreamlineHooks::hkslDLSSGGetState("):]
    start = get_state.index("auto& optiState = State::Instance();")
    stop = get_state.index("if (optiState.streamlineVersion >= feature_version { 2, 7, 1 })", start)
    code += "void QuerySettings() { const int viewport = 0;\n" + get_state[start:stop]
    code += body(get_state[stop:], "if (optiState.streamlineVersion >= feature_version { 2, 7, 1 })") + "\n}\n"

    code += CASES
    compiler = shutil.which(args.compiler)
    if not compiler:
        parser.error("compiler unavailable; use an x64 Native Tools prompt")
    with tempfile.TemporaryDirectory(prefix="mfg-provider-lifecycle-") as directory:
        directory = Path(directory)
        cpp, exe = directory / "lifecycle.cpp", directory / "lifecycle.exe"
        cpp.write_text(code, encoding="utf-8")
        command = [compiler, "/nologo", "/std:c++latest", "/EHsc", "/Od", str(cpp),
                   f"/Fe:{exe}", f"/Fo:{directory / 'lifecycle.obj'}"]
        subprocess.run(command, cwd=directory, check=True)
        failures = []
        for case in args.case or SCENARIOS:
            if subprocess.run([str(exe), case], cwd=directory, timeout=15).returncode:
                failures.append(case)
        if failures:
            raise SystemExit("Failed scenarios: " + ", ".join(failures))


if __name__ == "__main__":
    main()
