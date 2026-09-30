#!/usr/bin/env python3
"""Exercise the production provider lifecycle with fake loader/scanner boundaries.

Run from an x64 Native Tools prompt: python tests/mfg_provider_lifecycle.py
No GPU, game, NVIDIA DLL, third-party Python package, or installation is needed.
The bodies under test and the loader eligibility expression come from the source
tree, rather than a second implementation of its state machine. Each scenario
runs in a fresh process to reset the production function-local static state.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def function(source, signature):
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
#include <cwchar>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

struct FakeModule {
    bool supported = true, loaded = true;
    bool advertise = false, validate = false, kernelCompatible = true;
    unsigned rewrites = 0;
    std::string version = "310.9.1";
};
using HMODULE = FakeModule*;
enum class TemporalMethod { None, Retarget, Ptx };
struct Status {
    bool ModuleFound = false, AdvertiseMatched = false, ValidateMatched = false;
    unsigned KernelsRewritten = 0;
    TemporalMethod TemporalAttempted = TemporalMethod::None;
    std::string TemporalDetail, SnippetVersion, PluginCeiling;
};
Status g_status;
std::recursive_mutex g_mutex;
std::vector<HMODULE> g_plugins, g_pluginsTried;
HMODULE current = nullptr;
bool session = true;
unsigned pluginScans = 0;
constexpr int MAX_PATH = 260;
constexpr unsigned kMaxGeneratedFrames = 5;
constexpr int NV_GPU_ARCHITECTURE_AD100 = 1;
enum class VendorId { Nvidia, Other };
namespace IdentifyGpu {
struct GPU {
    VendorId vendorId = VendorId::Nvidia;
    struct { int architecture_id = NV_GPU_ARCHITECTURE_AD100; } nvidiaArchInfo;
};
GPU gpu;
const GPU& getPrimaryGpu() { return gpu; }
}
bool AdaUnlockWanted() {
    return session && IdentifyGpu::gpu.vendorId == VendorId::Nvidia &&
           IdentifyGpu::gpu.nvidiaArchInfo.architecture_id == NV_GPU_ARCHITECTURE_AD100;
}
HMODULE FindProvider() { return current; }
constexpr std::string_view kAdvertisePattern309 = "advertise";
constexpr std::string_view kValidatePattern309 = "validate";
constexpr std::string_view kAdvertisePattern = "legacyAdvertise";
constexpr std::string_view kValidatePattern = "legacyValidate";
uintptr_t UniqueAddress(HMODULE m, std::string_view pattern) {
    if (!m->loaded || !m->supported) return 0;
    if (pattern == kAdvertisePattern309) return !m->advertise;
    if (pattern == kValidatePattern309) return !m->validate;
    return 0;
}
unsigned GetModuleFileNameW(HMODULE m, wchar_t* path, int) {
    if (!m->loaded) return 0;
    std::wcscpy(path, L"fake.dll");
    return 8;
}
std::string wstring_to_string(const wchar_t*) { return "fake.dll"; }
std::string ModuleVersion(HMODULE m) { return m->version; }
unsigned RewriteBlackwellKernels(HMODULE m) {
    ++m->rewrites;
    return m->kernelCompatible ? 31 : 0;
}
bool PatchAdvertise(HMODULE m) { m->advertise = true; return true; }
bool PatchValidate(HMODULE m) { m->validate = true; return true; }
#define LOG_INFO(...) ((void)0)
#define LOG_WARN(...) ((void)0)
namespace Ptx {
struct Result { unsigned redirected = 0; std::string detail; };
void Apply(HMODULE, Result&) {}
}
namespace MfgUnlock {
void TryApply(HMODULE);
bool Pending();
bool EnabledForSession() { return session; }
Status LastStatus() { return g_status; }
TemporalMethod ConfiguredTemporalMethod() { return TemporalMethod::Retarget; }
unsigned UnlockedMax() {
    return g_status.AdvertiseMatched && g_status.ValidateMatched &&
           g_status.KernelsRewritten > 0 ? kMaxGeneratedFrames : 0;
}
namespace Plugin {
struct CeilingSite { unsigned compiled = 5; };
enum class FindResult { Found, Ambiguous, None, BadImage };
enum class ApplyResult { Patched, ProtectFailed, Mismatch };
FindResult FindCeilingSite(HMODULE m, CeilingSite&) {
    ++pluginScans;
    return m->loaded ? FindResult::Found : FindResult::BadImage;
}
ApplyResult ApplyCeilingPatch(CeilingSite&) { return ApplyResult::Patched; }
}
}
void PatchPluginCeilings();
'''


CASES = r'''
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)
bool unlocked(const FakeModule& m) { return m.advertise && m.validate && m.rewrites == 1; }
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string name = argv[1];
    FakeModule local, cached, unknown, plugin;
    cached.version = "310.9.0";
    unknown.supported = false;
    unknown.version = "310.2.1";
    auto load = [&](HMODULE module) {
        current = module;
        if (LOAD_ELIGIBILITY) MfgUnlock::TryApply(module);
    };
    if (name == "local_then_cached") {
        load(&local); CHECK(unlocked(local));
        CHECK(!MfgUnlock::Pending()); // first discovery is complete
        local.loaded = false;
        load(&cached); CHECK(unlocked(cached));
        CHECK(g_status.SnippetVersion == "310.9.0");
    } else if (name == "cached_then_local") {
        load(&cached); load(&local);
        CHECK(unlocked(local)); CHECK(unlocked(cached));
    } else if (name == "duplicate_notifications") {
        load(&local); load(&local); MfgUnlock::TryApply(nullptr);
        CHECK(unlocked(local));
    } else if (name == "same_address_reload") {
        load(&local); local = FakeModule{}; load(&local);
        CHECK(unlocked(local));
    } else if (name == "unsupported_after_success") {
        load(&cached); load(&unknown);
        CHECK(unknown.rewrites == 0 && !unknown.advertise && !unknown.validate);
        CHECK(MfgUnlock::UnlockedMax() == 5 && g_status.SnippetVersion == "310.9.0");
    } else if (name == "unsupported_before_supported") {
        load(&unknown); CHECK(MfgUnlock::Pending());
        load(&cached); CHECK(unlocked(cached));
    } else if (name == "unsupported_address_reused") {
        load(&unknown); unknown = FakeModule{}; load(&unknown);
        CHECK(unlocked(unknown));
    } else if (name == "incompatible_kernels") {
        load(&local); cached.kernelCompatible = false; load(&cached);
        CHECK(!cached.advertise && !cached.validate);
        CHECK(MfgUnlock::UnlockedMax() == 0);
        CHECK(!g_status.AdvertiseMatched && !g_status.ValidateMatched);
    } else if (name == "session_disabled") {
        session = false; load(&local); MfgUnlock::TryApply(&local);
        CHECK(local.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "non_ada") {
        IdentifyGpu::gpu.nvidiaArchInfo.architecture_id = 2;
        load(&local); CHECK(local.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "non_nvidia") {
        IdentifyGpu::gpu.vendorId = VendorId::Other;
        load(&local); CHECK(local.rewrites == 0 && !MfgUnlock::Pending());
    } else if (name == "absent_provider") {
        MfgUnlock::TryApply(nullptr); CHECK(MfgUnlock::Pending());
        load(&cached); CHECK(unlocked(cached));
    } else if (name == "stale_plugin") {
        plugin.loaded = false; g_plugins.push_back(&plugin);
        load(&cached);
        CHECK(pluginScans == 0 && g_pluginsTried.empty());
    } else if (name == "plugin_loaded_later") {
        plugin.loaded = false; g_plugins.push_back(&plugin);
        load(&local); plugin.loaded = true; load(&cached);
        CHECK(pluginScans == 1 && g_status.PluginCeiling == "patched");
    } else return 2;
    std::printf("PASS %s\n", argv[1]);
    return 0;
}
'''

SCENARIOS = (
    "local_then_cached", "cached_then_local", "duplicate_notifications",
    "same_address_reload", "unsupported_after_success", "unsupported_before_supported",
    "unsupported_address_reused", "incompatible_kernels", "session_disabled",
    "non_ada", "non_nvidia", "absent_provider", "stale_plugin", "plugin_loaded_later",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--compiler", default="cl", help="cl or a C++20 compiler such as clang++")
    parser.add_argument("--case", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    root = args.source_root
    unlock = (root / "OptiScaler/framegen/dlssg/MfgUnlock.cpp").read_text(encoding="utf-8-sig")
    hook = (root / "OptiScaler/hooks/LibraryLoad_Hooks.cpp").read_text(encoding="utf-8-sig")
    # Keep the actual loader condition: changing TryApply alone cannot fix this bug.
    line = next(line for line in hook.splitlines()
                if "MfgUnlock::Provider::IsProviderPath(normalizedPath) &&" in line)
    eligibility = line.split("&&", 1)[1].strip().rsplit(")", 1)[0]
    code = STUBS + "\n" + function(unlock, "void PatchPluginCeilings()") + "\n"
    code += function(unlock, "void MfgUnlock::TryApply(") + "\n"
    code += function(unlock, "bool MfgUnlock::Pending()") + "\n"
    code += CASES.replace("LOAD_ELIGIBILITY", eligibility)
    compiler = shutil.which(args.compiler)
    if not compiler:
        parser.error("compiler unavailable; use an x64 Native Tools prompt or --compiler")
    with tempfile.TemporaryDirectory(prefix="mfg-provider-lifecycle-") as directory:
        directory = Path(directory)
        cpp, exe = directory / "lifecycle.cpp", directory / "lifecycle.exe"
        cpp.write_text(code, encoding="utf-8")
        if Path(compiler).stem.lower() in ("cl", "clang-cl"):
            command = [compiler, "/nologo", "/std:c++20", "/EHsc", "/Od", str(cpp),
                       f"/Fe:{exe}", f"/Fo:{directory / 'lifecycle.obj'}"]
        else:
            command = [compiler, "-std=c++20", "-pthread", "-O0", str(cpp), "-o", str(exe)]
        subprocess.run(command, cwd=directory, check=True)
        failures = []
        for case in args.case or SCENARIOS:
            if subprocess.run([str(exe), case], cwd=directory).returncode:
                failures.append(case)
        if failures:
            raise SystemExit("Failed scenarios: " + ", ".join(failures))


if __name__ == "__main__":
    main()
