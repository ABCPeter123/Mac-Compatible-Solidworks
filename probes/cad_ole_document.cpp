/*
 * Original x64 Win32 COM compound-document persistence experiment.
 *
 * Three distinct EXE processes create, edit and verify a tiny synthetic 3D
 * part in an OLE Structured Storage (Compound File Binary) document.
 * The payload is NOT a SOLIDWORKS part or a representation of its format.
 * No activation, vendor binary, network or installed runtime is required.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cstdint>

#pragma pack(push, 1)
struct Part {
    uint32_t magic;
    uint32_t schema;
    uint32_t revision;
    int32_t width_mm;
    int32_t height_mm;
    int32_t depth_mm;
    uint32_t feature_count;
    uint32_t feature_flags;
};
#pragma pack(pop)

static const uint32_t kMagic = 0x43414453; /* "SDAC" in little-endian */
static const DWORD kReadWrite = STGM_READWRITE | STGM_SHARE_EXCLUSIVE;
static const DWORD kCreate = STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE;
static const DWORD kRootWrite = STGM_READWRITE | STGM_SHARE_EXCLUSIVE | STGM_TRANSACTED;
static const wchar_t *kStorageName = L"PartDocument";
static const wchar_t *kStreamName = L"ModelGeometry";

static Part initial_model() {
    Part model = { kMagic, 1u, 1u, 10, 20, 30, 1u, 0x01u };
    return model;
}
static Part edited_model() {
    Part model = { kMagic, 1u, 2u, 12, 20, 30, 2u, 0x03u };
    return model;
}
static bool equal_models(const Part& a, const Part& b) {
    return std::memcmp(&a, &b, sizeof(Part)) == 0;
}
static int report(const char *phase, const char *reason) {
    const bool pass = std::strcmp(reason, "OK") == 0;
    std::printf("SWCOMPAT_CAD_DOC_SCHEMA=1\n");
    std::printf("SWCOMPAT_CAD_DOC_PHASE=%s\n", phase);
    std::printf("SWCOMPAT_CAD_DOC_RESULT=%s\n", pass ? "PASS" : "FAIL");
    std::printf("SWCOMPAT_CAD_DOC_REASON=%s\n", reason);
    std::fflush(stdout);
    return pass ? 0 : 1;
}

/* Root transaction is committed only after nested stream data is complete. */
static const char *create_doc(const wchar_t *filename) {
    IStorage *root = nullptr;
    IStorage *part = nullptr;
    IStream *stream = nullptr;
    HRESULT hr = StgCreateDocfile(
        filename, kCreate | STGM_TRANSACTED, 0, &root);
    if (FAILED(hr) || !root) return "CREATE_ROOT";
    const char *reason = "OK";
    do {
        hr = root->CreateStorage(kStorageName, kCreate, 0, 0, &part);
        if (FAILED(hr) || !part) { reason = "CREATE_CHILD"; break; }
        hr = part->CreateStream(kStreamName, kCreate, 0, 0, &stream);
        if (FAILED(hr) || !stream) { reason = "CREATE_STREAM"; break; }
        Part model = initial_model();
        ULONG written = 0;
        hr = stream->Write(&model, sizeof(model), &written);
        if (FAILED(hr) || written != sizeof(model)) { reason = "WRITE"; break; }
        hr = stream->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "STREAM_COMMIT"; break; }
        stream->Release(); stream = nullptr;
        hr = part->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "CHILD_COMMIT"; break; }
        part->Release(); part = nullptr;
        hr = root->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "ROOT_COMMIT"; break; }
    } while (false);
    if (stream) stream->Release();
    if (part) part->Release();
    root->Release();
    return reason;
}

static const char *open_and_compare(const wchar_t *filename,
                                     const Part& expected, bool mutate) {
    IStorage *root = nullptr;
    IStorage *part = nullptr;
    IStream *stream = nullptr;
    HRESULT hr = StgOpenStorage(filename, nullptr, kRootWrite, nullptr, 0, &root);
    if (FAILED(hr) || !root) return "OPEN_ROOT";
    const char *reason = "OK";
    do {
        hr = root->OpenStorage(kStorageName, nullptr, kReadWrite,
                               nullptr, 0, &part);
        if (FAILED(hr) || !part) { reason = "OPEN_CHILD"; break; }
        hr = part->OpenStream(kStreamName, nullptr, kReadWrite, 0, &stream);
        if (FAILED(hr) || !stream) { reason = "OPEN_STREAM"; break; }
        Part found = {};
        ULONG read = 0;
        hr = stream->Read(&found, sizeof(found), &read);
        if (FAILED(hr) || read != sizeof(found)) { reason = "READ"; break; }
        if (!equal_models(found, expected)) { reason = "MODEL_MISMATCH"; break; }
        if (!mutate) break;
        LARGE_INTEGER zero = {};
        hr = stream->Seek(zero, STREAM_SEEK_SET, nullptr);
        if (FAILED(hr)) { reason = "SEEK"; break; }
        Part edited = edited_model();
        ULONG written = 0;
        hr = stream->Write(&edited, sizeof(edited), &written);
        if (FAILED(hr) || written != sizeof(edited)) { reason = "WRITE"; break; }
        hr = stream->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "STREAM_COMMIT"; break; }
        stream->Release(); stream = nullptr;
        hr = part->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "CHILD_COMMIT"; break; }
        part->Release(); part = nullptr;
        hr = root->Commit(STGC_DEFAULT);
        if (FAILED(hr)) { reason = "ROOT_COMMIT"; break; }
    } while (false);
    if (stream) stream->Release();
    if (part) part->Release();
    root->Release();
    return reason;
}

int wmain(int argc, wchar_t **argv) {
    const char *phase = "UNKNOWN";
    if (argc != 3) return report(phase, "ARGUMENT");
    if (std::wcscmp(argv[1], L"create") == 0) phase = "CREATE";
    else if (std::wcscmp(argv[1], L"edit") == 0) phase = "EDIT";
    else if (std::wcscmp(argv[1], L"verify") == 0) phase = "VERIFY";
    else return report(phase, "ARGUMENT");

    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(init)) return report(phase, "COM_INIT");
    const char *reason;
    if (std::strcmp(phase, "CREATE") == 0)
        reason = create_doc(argv[2]);
    else
        reason = open_and_compare(argv[2],
            std::strcmp(phase, "EDIT") == 0 ? initial_model() : edited_model(),
            std::strcmp(phase, "EDIT") == 0);
    CoUninitialize();
    return report(phase, reason);
}
