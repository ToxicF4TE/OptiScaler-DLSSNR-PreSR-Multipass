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
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


STUBS = r'''
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct FakeModule {
    bool supported = true, loaded = true, kernelCompatible = true;
    bool advertise = false, validate = false, advertiseWritable = true;
    unsigned rewrites = 0;
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
struct Config {
    Option FGDLSSGAdaMfgUnlock{true}, FGDLSSGAmpereMfgUnlock{false};
    Option FGDLSSGAdaBlackwellKernels{};
    static Config* Instance() { static Config config; return &config; }
};
struct State {
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
const GPU& getPrimaryGpu() { return gpu; }
}
namespace MfgUnlock {
struct Status {
    bool ModuleFound = false, AdvertiseMatched = false, ValidateMatched = false;
    unsigned KernelsRewritten = 0;
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
HMODULE GetModuleHandleW(const wchar_t*) { return current && current->loaded ? current : nullptr; }
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
    if (!module->supported || !module->loaded) return 0;
    if (pattern == kAdvertisePattern309) return !module->advertise;
    if (pattern == kValidatePattern309) return !module->validate;
    return 0;
}
std::string ModuleVersion(HMODULE module) { return module->version; }
unsigned RewriteBlackwellKernels(HMODULE module) {
    ++module->rewrites;
    return module->kernelCompatible ? 31 : 0;
}
bool PatchAdvertise(HMODULE module) { return module->advertise = module->advertiseWritable; }
bool PatchValidate(HMODULE module) { return module->validate = true; }
std::string wstring_to_string(const wchar_t* path) {
    std::wstring wide(path);
    std::string narrow;
    for (wchar_t character : wide) narrow.push_back(static_cast<char>(character));
    return narrow;
}
#define LOG_INFO(...) ((void)0)
#define LOG_WARN(...) ((void)0)
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
    if (name == "local_then_cached") {
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
    } else return 2;
    std::printf("PASS %s\n", argv[1]);
    return 0;
}
'''

SCENARIOS = (
    "local_then_cached", "cached_then_local", "duplicate_notifications",
    "same_address_reload", "unsupported_after_success", "unsupported_before_supported",
    "unsupported_address_reused", "incompatible_kernels", "kernels_disabled_after_success",
    "partial_gate_failure", "unlock_disabled", "ampere_unlock_selected", "external_fg",
    "non_ada", "non_nvidia", "absent_provider", "normalized_cache_path", "other_ota_features",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--compiler", default="cl")
    parser.add_argument("--case", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    unlock = (args.source_root / "OptiScaler/framegen/dlssg/MfgUnlock.cpp").read_text(encoding="utf-8-sig")
    hook = (args.source_root / "OptiScaler/hooks/LibraryLoad_Hooks.cpp").read_text(encoding="utf-8-sig")
    code = STUBS + "\n"
    for signature in ("bool MfgUnlock::Enabled()", "void MfgUnlock::TryApply(",
                      "bool MfgUnlock::Pending()", "unsigned int MfgUnlock::UnlockedMax()",
                      "const MfgUnlock::Status& MfgUnlock::LastStatus()"):
        if signature in unlock:
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
    code += "return NtdllProxy::LoadLibraryExW_Ldr(lpLibFullPath, nullptr, 0);\n}\n" + CASES
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
            if subprocess.run([str(exe), case], cwd=directory).returncode:
                failures.append(case)
        if failures:
            raise SystemExit("Failed scenarios: " + ", ".join(failures))


if __name__ == "__main__":
    main()
