/* PE frames self-test (build.sh): PeOpen, MappedImages and PeWalk against Wine's own x64 ntdll.dll; the maps poll's unloads.
 * The expected frames come from the function bytes and the file's headers, read here independently of
 * pe.cpp (the prolog sweep decodes push/sub instructions, not unwind codes). */
#include "../agent/linux/pe.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;
#define EXPECT(condition)                                                     \
    do {                                                                      \
        if (!(condition)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            failures++;                                                       \
        }                                                                     \
    } while (0)

namespace {
const char* kDll = "/opt/wine-stable/lib/wine/x86_64-windows/ntdll.dll";
const char* kUnix = "/opt/wine-stable/lib/wine/x86_64-unix/ntdll.so";
constexpr uint64_t kBase = 0x6fffffc00000ull;

std::vector<uint8_t> file;
uint32_t U32(size_t at) { uint32_t v; std::memcpy(&v, &file[at], 4); return v; }
uint16_t U16(size_t at) { uint16_t v; std::memcpy(&v, &file[at], 2); return v; }

struct Section { uint32_t rva, size, raw, rawSize, flags; };
std::vector<Section> sections;
size_t Offset(uint32_t rva)
{
    for (const Section& s : sections)
        if (rva >= s.rva && rva - s.rva < s.rawSize) return s.raw + (rva - s.rva);
    return 0;
}

/* push reg / push r8-r15 then sub rsp,imm: bytes of the prolog and the frame size. */
std::pair<size_t, uint32_t> Decode(const uint8_t* code)
{
    size_t at = 0;
    uint32_t pushes = 0, sub = 0;
    for (;;) {
        if (code[at] >= 0x50 && code[at] <= 0x57) { pushes++; at++; continue; }
        if (code[at] == 0x41 && code[at + 1] >= 0x50 && code[at + 1] <= 0x57) { pushes++; at += 2; continue; }
        if (!std::memcmp(code + at, "\x48\x83\xec", 3)) { sub = code[at + 3]; at += 4; }
        else if (!std::memcmp(code + at, "\x48\x81\xec", 3)) { std::memcpy(&sub, code + at + 3, 4); at += 7; }
        break;
    }
    return {at, pushes * 8 + sub};
}

void Put(std::vector<uint8_t>& stack, size_t at, uint64_t value)
{
    if (stack.size() < at + 8) stack.resize(at + 8);
    std::memcpy(&stack[at], &value, 8);
}
}  // namespace

int main()
{
    /* the maps poll's unloads: an image a poll listed executable that a later poll no longer lists at all; a data
     * mapping never was a load, and code made not executable is still mapped. */
    {
        ImageList listed;
        std::vector<MappedImage> poll = {{"/x/a.dll", 0x10000, 0x5000, true, nullptr},
                                         {"/x/data.dll", 0x20000, 0x1000, false, nullptr},
                                         {"/x/b.so", 0x30000, 0x2000, true, nullptr}};
        EXPECT(ImageUnloads(listed, poll).empty() && listed.size() == 2);
        poll[0].executable = false;
        poll.erase(poll.begin() + 1, poll.end());
        const auto gone = ImageUnloads(listed, poll);
        EXPECT(gone.size() == 1 && gone[0].first.first == 0x30000 && gone[0].first.second == "/x/b.so" && gone[0].second == 0x2000);
        EXPECT(listed.size() == 1 && ImageUnloads(listed, {}).size() == 1 && listed.empty());
    }

    std::ifstream in(kDll, std::ios::binary);
    if (!in) {
        std::printf("linux_pe_test: SKIP (%s not found)\n", kDll);
        return 0;
    }
    file.assign(std::istreambuf_iterator<char>(in), {});
    const uint32_t nt = U32(0x3c), optional = nt + 24, optionalSize = U16(nt + 20);
    const uint32_t sizeOfImage = U32(optional + 56);
    for (uint32_t i = 0; i < U16(nt + 6); i++) {
        const size_t h = optional + optionalSize + i * 40;
        sections.push_back({U32(h + 12), U32(h + 8), U32(h + 20), U32(h + 16), U32(h + 36)});
    }
    uint32_t text = 0, rdata = 0;
    for (const Section& s : sections) {
        if (s.flags & 0x20000000u && !text) text = s.rva;
        if (!(s.flags & 0x20000020u) && !rdata) rdata = s.rva;
    }
    const uint32_t pdata = U32(optional + 112 + 24), pdataCount = U32(optional + 112 + 28) / 12;

    /* a: the x64 ntdll.dll parses, once. */
    auto image = PeOpen(kDll);
    EXPECT(image && image->machine == 0x8664 && image->sizeOfImage == sizeOfImage);
    if (!image) return 1;
    EXPECT(image->functions.size() > 1000 && image->functions.size() <= pdataCount);
    EXPECT(!image->code.empty() && image->Code(text) && !image->Code(rdata));
    EXPECT(PeOpen(kDll) == image);

    /* b: not PE, missing, a directory, or not the mapped inode. */
    struct stat info {};
    stat(kDll, &info);
    EXPECT(PeOpen(kUnix) == nullptr);
    EXPECT(PeOpen("/nonexistent/ntdll.dll") == nullptr);
    EXPECT(PeOpen("/opt/wine-stable/lib/wine") == nullptr);
    EXPECT(PeOpen(kDll, info.st_ino + 1) == nullptr && PeOpen(kDll, info.st_ino) == image);

    /* c: maps grouping: a PE load per header mapping spanning SizeOfImage (code may be anonymous), a data-file
     * mapping is not executable, and an ELF file is one image from its lowest to highest mapping. */
    std::ostringstream maps;
    char line[512];
    auto add = [&](uint64_t low, uint64_t high, const char* perms, uint64_t offset, uint64_t inode, const char* path) {
        std::snprintf(line, sizeof(line), "%llx-%llx %s %08llx 103:02 %llu %s\n", (unsigned long long)low,
                      (unsigned long long)high, perms, (unsigned long long)offset, (unsigned long long)inode, path);
        maps << line;
    };
    add(0x140000000, 0x140001000, "r--p", 0, info.st_ino, kDll);                 /* second load: code anonymous */
    add(0x140001000, 0x140070000, "rwxp", 0, 0, "");
    add(0x200000000, 0x200100000, "r--p", 0, info.st_ino, kDll);                 /* mapped as data */
    add(0x7f0000000000, 0x7f0000010000, "r--p", 0, 77, kUnix);
    add(0x7f0000010000, 0x7f0000020000, "r-xp", 0x10000, 77, kUnix);
    add(kBase, kBase + 0x1000, "r--p", 0, info.st_ino, kDll);
    add(kBase + 0x1000, kBase + 0x73000, "r-xp", 0x1000, info.st_ino, kDll);
    add(kBase + 0x73000, kBase + 0x74000, "rw-p", 0x73000, info.st_ino, kDll);
    std::istringstream mapsIn(maps.str());
    const std::vector<MappedImage> mapped = MappedImages(mapsIn);
    EXPECT(mapped.size() == 4);
    if (mapped.size() == 4) {
        EXPECT(mapped[0].base == 0x140000000 && mapped[0].size == sizeOfImage && mapped[0].pe == image && mapped[0].executable);
        EXPECT(mapped[1].base == 0x200000000 && mapped[1].pe && !mapped[1].executable);
        EXPECT(mapped[2].base == kBase && mapped[2].size == sizeOfImage && mapped[2].executable);
        EXPECT(mapped[3].path == kUnix && !mapped[3].pe && mapped[3].base == 0x7f0000000000 && mapped[3].size == 0x20000 &&
               mapped[3].executable);
    }
    PeRanges ranges;
    ranges.ranges.push_back({kBase, kBase + sizeOfImage, image});
    EXPECT(ranges.Find(kBase + 0x1000) && !ranges.Find(kBase + sizeOfImage) && !ranges.Find(kBase - 1));

    /* The functions in .pdata with their own bytes. */
    struct Function { uint32_t begin, end, unwind; };
    std::vector<Function> functions;
    for (uint32_t i = 0; i < pdataCount; i++) {
        const size_t at = Offset(pdata) + i * 12;
        functions.push_back({U32(at), U32(at + 4), U32(at + 8)});
    }
    const uint64_t target = kBase + functions[functions.size() / 2].begin + 5;   /* a return address to plant */
    std::vector<uint64_t> out;

    /* d: a syscall stub (mov r10,rcx; mov eax,N) is a leaf: frame 0 is rip, frame 1 the qword at rsp. */
    bool stub = false;
    for (const Function& f : functions) {
        if (f.end - f.begin != 0x20 || std::memcmp(&file[Offset(f.begin)], "\x4c\x8b\xd1\xb8", 4)) continue;
        std::vector<uint8_t> stack;
        Put(stack, 0, target);
        out.clear();
        const PeWalkResult walk = PeWalk(ranges, kBase + f.begin + 0x12, 0x10000, 0, stack.data(), 8, out, 16);
        EXPECT(walk.frames == 2 && walk.scanned == 0 && out.size() == 2 && out[0] == kBase + f.begin + 0x12 && out[1] == target);
        stub = true;
        break;
    }
    EXPECT(stub);

    /* e: the sweep. Every function whose bytes are push.../sub rsp of exactly its prolog size (UNWIND_INFO
     * version 1, no frame register, no chain): from just after the prolog the caller is past the frame. */
    unsigned swept = 0, wrong = 0;
    for (const Function& f : functions) {
        const size_t info = Offset(f.unwind);
        if (!info || (file[info] & 7) != 1 || (file[info] >> 3) & 4 || (file[info + 3] & 15)) continue;
        const auto decoded = Decode(&file[Offset(f.begin)]);
        if (decoded.first != file[info + 1] || decoded.first >= f.end - f.begin || decoded.second + 16 > 512) continue;
        std::vector<uint8_t> stack(decoded.second, 0);
        Put(stack, decoded.second, target);
        out.clear();
        const PeWalkResult walk =
            PeWalk(ranges, kBase + f.begin + decoded.first, 0x20000, 0, stack.data(), stack.size(), out, 16);
        if (walk.frames == 2 && out[1] == target) swept++;
        else wrong++;
    }
    std::printf("linux_pe_test: sweep unwound %u functions, %u wrong\n", swept, wrong);
    EXPECT(swept >= 100 && wrong == 0);

    /* f: rip outside every image: the stack words inside PE code are scanned, data and garbage are not. */
    {
        std::vector<uint8_t> stack;
        Put(stack, 0, 0x1234);
        Put(stack, 8, kBase + text + 0x10);
        Put(stack, 16, kBase + rdata);
        Put(stack, 24, 0);
        Put(stack, 32, target);
        out.clear();
        const PeWalkResult walk = PeWalk(ranges, 0x1000, 0x30000, 0, stack.data(), stack.size(), out, 16);
        EXPECT(walk.frames == 3 && walk.scanned == 2 && out[0] == 0x1000 && out[1] == kBase + text + 0x10 && out[2] == target);
    }

    /* g: rbp frames (push rbp; mov rbp,rsp with frame register rbp): unwound from rbp, not rsp. */
    unsigned framed = 0;
    for (const Function& f : functions) {
        const size_t info = Offset(f.unwind);
        if (!info || (file[info + 3] & 15) != 5 || std::memcmp(&file[Offset(f.begin)], "\x55\x48\x89\xe5", 4)) continue;
        std::vector<uint8_t> stack;
        Put(stack, 0x40, 0x7777);    /* saved rbp at rbp */
        Put(stack, 0x48, target);    /* return address above it */
        out.clear();
        const PeWalkResult walk = PeWalk(ranges, kBase + f.begin + 4, 0x40000, 0x40040, stack.data(), stack.size(), out, 2);
        EXPECT(walk.frames == 2 && out[1] == target);
        framed++;
    }
    EXPECT(framed >= 1);

    /* h: bounds. */
    out.clear();
    EXPECT(PeWalk(ranges, 0, 0, 0, nullptr, 0, out, 16).frames == 0 && out.empty());
    EXPECT(PeWalk(ranges, kBase + text, 0, 0, nullptr, 0, out, 0).frames == 0 && out.empty());
    EXPECT(PeWalk(PeRanges{}, kBase + text, 0x50000, 0, nullptr, 0, out, 16).frames == 1 && out.size() == 1);
    {
        std::vector<uint8_t> stack;
        for (size_t at = 0; at < 512; at += 8) Put(stack, at, target);   /* a stack full of code addresses */
        out.clear();
        const PeWalkResult walk = PeWalk(PeRanges{ranges}, 0x1000, 0x60000, 0, stack.data(), 512, out, 16);
        EXPECT(walk.frames == 16 && out.size() == 16);
        out.clear();
        EXPECT(PeWalk(ranges, 0x1000, 0x60000, 0, stack.data(), 5, out, 16).frames == 1);   /* a partial word */
    }

    /* i: packed code (no .pdata): only frame 0 is a leaf; past it the stack is scanned, so a local
     * (0xdeadbeef) is never reported as an unwound frame. */
    {
        auto packed = std::make_shared<PeImage>();
        packed->machine = 0x8664;
        packed->sizeOfImage = 0x10000;
        packed->code.emplace_back(0x1000, 0x8000);
        const uint64_t game = 0x140000000;
        PeRanges gameRanges;
        gameRanges.ranges.push_back({game, game + 0x10000, packed});
        std::vector<uint8_t> stack;
        Put(stack, 0, game + 0x3000);
        Put(stack, 8, 0xdeadbeef);
        Put(stack, 16, game + 0x4000);
        out.clear();
        const PeWalkResult walk = PeWalk(gameRanges, game + 0x2000, 0x70000, 0, stack.data(), stack.size(), out, 16);
        EXPECT(walk.frames == 3 && walk.scanned == 1 && out[1] == game + 0x3000 && out[2] == game + 0x4000);
    }

    /* j: a section header claiming ~4 GiB is clamped to the file: the unwind data is still read. */
    {
        std::vector<uint8_t> bad = file;
        for (uint32_t i = 0; i < sections.size(); i++) {
            const Section& s = sections[i];
            if (functions[0].unwind < s.rva || functions[0].unwind - s.rva >= s.rawSize) continue;
            const size_t h = optional + optionalSize + i * 40;
            const uint32_t huge = 0xf0000000;
            std::memcpy(&bad[h + 8], &huge, 4);
            std::memcpy(&bad[h + 16], &huge, 4);
        }
        char path[] = "/tmp/linux_pe_test.XXXXXX";
        const int fd = mkstemp(path);
        EXPECT(fd >= 0 && write(fd, bad.data(), bad.size()) == static_cast<ssize_t>(bad.size()));
        if (fd >= 0) close(fd);
        const auto clamped = PeOpen(path);
        unlink(path);
        EXPECT(clamped && !clamped->functions.empty() && clamped->At(clamped->functions[0].unwind, 4));
        if (clamped)
            for (const auto& section : clamped->data) EXPECT(section.second.size() <= bad.size());
    }

    /* k: WMI provider modules by file name (images.cpp writes etw_wmi for their loads). */
    EXPECT(WmiModule("/opt/wine-stable/lib/wine/x86_64-windows/wbemprox.dll") == "wbemprox.dll");
    EXPECT(WmiModule("/opt/wine-stable/lib/wine/i386-windows/WbemDisp.dll") == "wbemdisp.dll");
    EXPECT(WmiModule("/p/drive_c/windows/system32/wbem/fastprox.dll") == "fastprox.dll");
    EXPECT(WmiModule(kDll).empty() && WmiModule("wbemprox.dll.so").empty() && WmiModule("").empty());

    /* l: the four IWbemServices methods msmon probes, found in Wine's x64 and i386 wbemprox.dll (checked by hand against
     * llvm-dwarfdump --lookup: wbem_services_ExecQuery, _ExecQueryAsync, _GetObject, _CreateInstanceEnum). */
    for (const auto& build : {std::make_pair("x86_64", 0x8664), std::make_pair("i386", 0x14c)}) {
        uint16_t machine = 0;
        const auto methods = PeWmiMethods(std::string("/opt/wine-stable/lib/wine/") + build.first + "-windows/wbemprox.dll", machine);
        EXPECT(methods.size() == 4 && machine == build.second);
        for (size_t a = 0; a < methods.size(); a++) {
            EXPECT(methods[a] != 0);
            for (size_t b = a + 1; b < methods.size(); b++) EXPECT(methods[a] != methods[b]);
        }
    }
    uint16_t none = 1;
    EXPECT(PeWmiMethods(kDll, none) == std::vector<uint64_t>(4, 0) && none == 0);

    if (failures) {
        std::printf("linux_pe_test: %d failures\n", failures);
        return 1;
    }
    std::printf("linux_pe_test: PASS\n");
    return 0;
}
