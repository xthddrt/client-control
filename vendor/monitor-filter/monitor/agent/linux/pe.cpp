#include "pe.h"
#include "bpf/monitor_bpf.h"   /* MM_UP_WMI_* */
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <sstream>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

/* PE parsing, maps grouping and the x64 unwinder behind PE frames (pe.h, docs/LINUX.md "PE frames"). */

namespace {

constexpr uint16_t kAmd64 = 0x8664;

template <typename T>
T Get(const uint8_t* bytes)
{
    T value;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

bool ReadAt(int fd, uint64_t offset, void* buffer, size_t size)
{
    return pread(fd, buffer, size, static_cast<off_t>(offset)) == static_cast<ssize_t>(size);
}

/* A PE file (base 0), or a loaded image at base in a process's memory (fd = /proc/<pid>/mem): its sections are at
 * their RVA there, and SizeOfImage bounds every read. */
std::shared_ptr<const PeImage> Parse(int fd, uint64_t fileSize, uint64_t base = 0)
{
    const bool loaded = base != 0;
    auto read = [&](uint64_t offset, void* buffer, size_t size) { return ReadAt(fd, base + offset, buffer, size); };
    uint8_t dos[64];
    if (!read(0, dos, sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z') return nullptr;
    const uint32_t nt = Get<uint32_t>(dos + 0x3c);
    uint8_t file[24];   /* "PE\0\0" + IMAGE_FILE_HEADER */
    if (nt >= fileSize || !read(nt, file, sizeof(file)) || std::memcmp(file, "PE\0\0", 4) != 0) return nullptr;
    auto image = std::make_shared<PeImage>();
    image->machine = Get<uint16_t>(file + 4);
    image->timeDateStamp = Get<uint32_t>(file + 8);
    const uint16_t sectionCount = std::min<uint16_t>(Get<uint16_t>(file + 6), 96);
    const uint16_t optionalSize = Get<uint16_t>(file + 20);
    std::vector<uint8_t> optional(optionalSize);
    if (optionalSize < 64 || !read(nt + 24, optional.data(), optionalSize)) return nullptr;
    const uint16_t magic = Get<uint16_t>(optional.data());
    if (magic != 0x10b && magic != 0x20b) return nullptr;
    image->sizeOfImage = Get<uint32_t>(optional.data() + 56);
    if (loaded) fileSize = std::min<uint64_t>(image->sizeOfImage, 64u << 20);   /* the client writes these headers */
    /* IMAGE_DIRECTORY_ENTRY_EXPORT (0): the module's own name */
    const uint32_t directories = magic == 0x20b ? 112 : 96;
    uint32_t exportRva = 0;
    if (optionalSize >= directories + 8 && Get<uint32_t>(optional.data() + directories - 4) > 0)
        exportRva = Get<uint32_t>(optional.data() + directories);
    /* IMAGE_DIRECTORY_ENTRY_EXCEPTION (3) of a PE32+ image: .pdata */
    uint32_t pdataRva = 0, pdataSize = 0;
    if (magic == 0x20b && optionalSize >= 112 + 4 * 8 && Get<uint32_t>(optional.data() + 108) > 3) {
        pdataRva = Get<uint32_t>(optional.data() + 112 + 3 * 8);
        pdataSize = Get<uint32_t>(optional.data() + 112 + 3 * 8 + 4);
    }

    struct Section {
        uint32_t rva, size, raw, rawSize;
    };
    std::vector<Section> sections;
    std::vector<uint8_t> table(sectionCount * 40u);
    if (!read(nt + 24 + optionalSize, table.data(), table.size())) return nullptr;
    for (uint16_t index = 0; index < sectionCount; index++) {
        const uint8_t* header = table.data() + index * 40;
        const uint32_t virtualSize = Get<uint32_t>(header + 8), rva = Get<uint32_t>(header + 12);
        const uint32_t rawSize = loaded ? virtualSize : Get<uint32_t>(header + 16), raw = loaded ? rva : Get<uint32_t>(header + 20);
        const uint32_t characteristics = Get<uint32_t>(header + 36);
        const uint32_t size = virtualSize ? virtualSize : rawSize;
        /* Header sizes are untrusted: keep only bytes the file has, so a bogus size cannot allocate GiBs. */
        const uint32_t inFile = raw < fileSize ? static_cast<uint32_t>(std::min<uint64_t>(rawSize, fileSize - raw)) : 0;
        sections.push_back({rva, size, raw, std::min<uint32_t>(inFile, size)});
        /* IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE */
        if (characteristics & 0x20000020u) image->code.emplace_back(rva, rva + size);
    }
    auto section = [&](uint32_t rva) -> const Section* {
        for (const Section& item : sections)
            if (rva >= item.rva && rva - item.rva < item.rawSize) return &item;
        return nullptr;
    };

    if (image->machine == kAmd64 && pdataSize >= 12) {
        const Section* holder = section(pdataRva);
        const uint32_t count = std::min<uint32_t>(pdataSize / 12, 1u << 20);
        std::vector<uint8_t> pdata(count * 12u);
        if (holder && holder->rawSize - (pdataRva - holder->rva) >= pdata.size() &&
            read(holder->raw + (pdataRva - holder->rva), pdata.data(), pdata.size())) {
            for (uint32_t index = 0; index < count; index++) {
                const uint8_t* entry = pdata.data() + index * 12;
                PeImage::Function function{Get<uint32_t>(entry), Get<uint32_t>(entry + 4), Get<uint32_t>(entry + 8)};
                if (function.begin < function.end && function.unwind) image->functions.push_back(function);
            }
            std::sort(image->functions.begin(), image->functions.end(),
                      [](const PeImage::Function& left, const PeImage::Function& right) { return left.begin < right.begin; });
            /* Keep the bytes of every section that holds unwind info (.xdata or .rdata), read once. */
            for (const Section& item : sections) {
                const bool holds = std::any_of(image->functions.begin(), image->functions.end(), [&](const auto& function) {
                    return function.unwind >= item.rva && function.unwind - item.rva < item.rawSize;
                });
                if (!holds) continue;
                std::vector<uint8_t> bytes(item.rawSize);
                if (read(item.raw, bytes.data(), bytes.size())) image->data.emplace_back(item.rva, std::move(bytes));
            }
        }
    }
    /* IMAGE_EXPORT_DIRECTORY.Name (+12) */
    const Section* exports = section(exportRva);
    uint8_t directory[16];
    if (exportRva && exports && read(exports->raw + (exportRva - exports->rva), directory, sizeof(directory))) {
        const uint32_t nameRva = Get<uint32_t>(directory + 12);
        const Section* holder = section(nameRva);
        char name[64] = {};
        if (holder && read(holder->raw + (nameRva - holder->rva), name, std::min<uint32_t>(sizeof(name) - 1, holder->rawSize - (nameRva - holder->rva))))
            image->name.assign(name, strnlen(name, sizeof(name)));
    }
    return image;
}

/* The captured PE stack: bytes copied at rsp. */
struct Stack {
    uint64_t rsp;
    const uint8_t* bytes;
    uint32_t size;
    bool Read(uint64_t address, uint64_t& value) const
    {
        if (address < rsp || address - rsp > size || size - (address - rsp) < 8) return false;
        std::memcpy(&value, bytes + (address - rsp), 8);
        return true;
    }
};

/* One x64 frame by the image's UNWIND_INFO (RtlVirtualUnwind's rules): the caller's rsp and rbp and the
 * return address. Only rbp is tracked, so a frame register other than rbp fails the frame.
 * shortcut: no epilog detection (a return address that starts an epilog unwinds the same either way; only
 * a frame-0 rip inside an epilog is wrong, and frame 0 is the leaf NtXxx stub), add it if rip can be. */
bool Unwind(const PeImage& image, uint32_t rva, bool returnAddress, const Stack& stack, uint64_t& sp, uint64_t& bp,
            uint64_t& ret)
{
    const PeImage::Function* found = image.Find(returnAddress ? rva - 1 : rva);
    /* Only frame 0 can be a leaf: a return address's function made a call, so without an entry its frame
     * is unknown (packed code without .pdata) and the stack scan takes over. */
    if (!found && returnAddress) return false;
    uint64_t rsp = sp, rbp = bp;
    bool machineFrame = false;
    if (found) {   /* no entry at frame 0: a leaf function, the return address is at rsp */
        PeImage::Function function = *found;
        for (int chain = 0;; chain++) {
            /* An odd unwind RVA points at another RUNTIME_FUNCTION (not seen in MSVC/mingw x64 output). */
            if (chain == 32 || (function.unwind & 1)) return false;
            const uint8_t* info = image.At(function.unwind, 4);
            if (!info) return false;
            const unsigned version = info[0] & 7, flags = info[0] >> 3, prolog = info[1], count = info[2];
            const unsigned frameRegister = info[3] & 15, frameOffset = info[3] >> 4;
            const uint32_t slots = (count + 1) & ~1u;
            const uint8_t* codes = image.At(function.unwind + 4, slots * 2 + ((flags & 4) ? 12 : 0));
            if ((version != 1 && version != 2) || !codes || (frameRegister && frameRegister != 5)) return false;
            /* Codes past the prolog offset have not run yet; outside the prolog they all have. */
            const uint32_t prologOffset = rva >= function.begin && rva - function.begin < prolog ? rva - function.begin : ~0u;
            const uint64_t frame = frameRegister ? rbp - frameOffset * 16ull : rsp;
            for (unsigned index = 0; index < count;) {
                const unsigned at = codes[index * 2], op = codes[index * 2 + 1] & 15, opInfo = codes[index * 2 + 1] >> 4;
                const unsigned size = op == 1 ? (opInfo ? 3 : 2) : (op == 4 || op == 6 || op == 8) ? 2 : (op == 5 || op == 7 || op == 9) ? 3 : 1;
                if (index + size > count) return false;
                /* A 1-slot code can be the last one with CountOfCodes even: its next slot is past the checked bytes. */
                const uint32_t slot1 = size >= 2 ? Get<uint16_t>(codes + index * 2 + 2) : 0;
                const uint32_t wide = size == 3 ? slot1 | static_cast<uint32_t>(Get<uint16_t>(codes + index * 2 + 4)) << 16 : 0;
                if (prologOffset >= at) {
                    uint64_t value = 0;
                    switch (op) {
                    case 0:   /* UWOP_PUSH_NONVOL */
                        if (opInfo == 5 && !stack.Read(rsp, rbp)) return false;
                        rsp += 8;
                        break;
                    case 1: rsp += opInfo ? wide : slot1 * 8; break;   /* UWOP_ALLOC_LARGE */
                    case 2: rsp += opInfo * 8 + 8; break;              /* UWOP_ALLOC_SMALL */
                    case 3:                                            /* UWOP_SET_FPREG */
                        if (!frameRegister) return false;
                        rsp = frame;
                        break;
                    case 4:   /* UWOP_SAVE_NONVOL */
                    case 5:   /* UWOP_SAVE_NONVOL_FAR */
                        if (opInfo == 5 && !stack.Read(frame + (op == 4 ? slot1 * 8 : wide), rbp)) return false;
                        break;
                    case 10:  /* UWOP_PUSH_MACHFRAME: rip, cs, eflags, rsp, ss (after an error code if opInfo) */
                        if (opInfo) rsp += 8;
                        if (!stack.Read(rsp, ret) || !stack.Read(rsp + 24, value)) return false;
                        rsp = value;
                        machineFrame = true;
                        break;
                    case 6: case 7: case 8: case 9: break;   /* xmm saves; version 2 epilog descriptors */
                    default: return false;
                    }
                }
                index += size;
            }
            if (!(flags & 4)) break;   /* UNW_FLAG_CHAININFO: continue with the parent's RUNTIME_FUNCTION */
            const uint8_t* parent = codes + slots * 2;
            function = {Get<uint32_t>(parent), Get<uint32_t>(parent + 4), Get<uint32_t>(parent + 8)};
        }
    }
    if (!machineFrame) {
        if (!stack.Read(rsp, ret)) return false;
        rsp += 8;
    }
    sp = rsp;
    bp = rbp;
    return true;
}

}  // namespace

const PeImage::Function* PeImage::Find(uint32_t rva) const
{
    auto next = std::upper_bound(functions.begin(), functions.end(), rva,
                                 [](uint32_t value, const Function& function) { return value < function.begin; });
    if (next == functions.begin()) return nullptr;
    --next;
    return rva < next->end ? &*next : nullptr;
}

bool PeImage::Code(uint32_t rva) const
{
    return std::any_of(code.begin(), code.end(), [&](const auto& range) { return rva >= range.first && rva < range.second; });
}

const uint8_t* PeImage::At(uint32_t rva, uint32_t size) const
{
    for (const auto& section : data) {
        if (rva >= section.first && rva - section.first <= section.second.size() &&
            section.second.size() - (rva - section.first) >= size)
            return section.second.data() + (rva - section.first);
    }
    return nullptr;
}

std::shared_ptr<const PeImage> PeLoaded(int memory, uint64_t base)
{
    return base ? Parse(memory, 1u << 20, base) : nullptr;
}

std::shared_ptr<const PeImage> PeOpen(const std::string& path, uint64_t inode)
{
    static std::mutex mutex;
    static std::map<std::tuple<std::string, uint64_t, uint64_t, int64_t>, std::shared_ptr<const PeImage>> cache;
    /* Mapped files known not to be PE, so a scan does not stat every data file again.
     * shortcut: a non-PE file rewritten in place into a PE keeps its inode and stays non-PE; key by mtime
     * too if that happens. */
    static std::set<std::pair<std::string, uint64_t>> notPe;
    if (inode) {
        std::lock_guard<std::mutex> lock(mutex);
        if (notPe.count({path, inode})) return nullptr;
    }
    struct stat info {};
    /* Regular files only (never open a mapped device), and only the file that is mapped. */
    if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode) || (inode && info.st_ino != inode)) return nullptr;
    const auto key = std::make_tuple(path, static_cast<uint64_t>(info.st_ino), static_cast<uint64_t>(info.st_size),
                                     static_cast<int64_t>(info.st_mtim.tv_sec) * 1000000000 + info.st_mtim.tv_nsec);
    std::lock_guard<std::mutex> lock(mutex);
    auto found = cache.find(key);
    if (found != cache.end()) return found->second;
    std::shared_ptr<const PeImage> image;
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd >= 0) {
        image = Parse(fd, static_cast<uint64_t>(info.st_size));
        close(fd);
    }
    /* shortcut: the cache keeps every file version it saw (negative entries too); bounded by the files a
     * session maps, evict if long sessions map many updated files. */
    cache.emplace(key, image);
    if (!image && inode) notPe.emplace(path, inode);
    return image;
}

std::vector<MappedImage> MappedImages(std::istream& maps)
{
    struct Line {
        uint64_t low, high, offset, inode;
        bool executable;
        std::string path;
    };
    std::vector<Line> lines;
    std::string text;
    while (std::getline(maps, text)) {
        std::istringstream fields(text);
        std::string range, perms, offset, device, inode, path;
        if (!(fields >> range >> perms >> offset >> device >> inode)) continue;
        std::getline(fields >> std::ws, path);
        const size_t dash = range.find('-');
        if (dash == std::string::npos) continue;
        try {
            lines.push_back({std::stoull(range.substr(0, dash), nullptr, 16), std::stoull(range.substr(dash + 1), nullptr, 16),
                             std::stoull(offset, nullptr, 16), std::stoull(inode), perms.size() > 2 && perms[2] == 'x', path});
        } catch (const std::exception&) {
        }
    }
    std::vector<MappedImage> images;
    std::map<std::string, MappedImage> files;
    std::map<std::pair<std::string, uint64_t>, std::shared_ptr<const PeImage>> opened;
    for (const Line& line : lines) {
        if (line.path.empty() || line.path[0] != '/') continue;
        auto key = std::make_pair(line.path, line.inode);
        auto found = opened.find(key);
        if (found == opened.end()) found = opened.emplace(key, PeOpen(line.path, line.inode)).first;
        if (const auto& pe = found->second) {
            /* shortcut: a PE file mapped as data (LoadLibraryEx AS_DATAFILE) at offset 0 also counts as a load
             * if something executable lies within SizeOfImage of it; tell them apart by Wine's view type if it
             * matters. */
            if (line.offset == 0) images.push_back({line.path, line.low, pe->sizeOfImage, false, pe});
            continue;
        }
        MappedImage& file = files[line.path];
        if (file.path.empty()) {
            file.path = line.path;
            file.base = line.low;
        }
        file.size = std::max(file.base + file.size, line.high) - std::min(file.base, line.low);
        file.base = std::min(file.base, line.low);
        file.executable = file.executable || line.executable;
    }
    /* Wine maps PE sections writable and mprotects code executable later; often the code is anonymous memory
     * (sections not page-aligned in the file), so look at every mapping inside the image. */
    for (MappedImage& image : images) {
        for (const Line& line : lines)
            if (line.executable && line.low < image.base + image.size && line.high > image.base) image.executable = true;
    }
    for (auto& item : files) images.push_back(std::move(item.second));
    std::sort(images.begin(), images.end(), [](const MappedImage& left, const MappedImage& right) { return left.base < right.base; });
    return images;
}

std::vector<std::pair<std::pair<uint64_t, std::string>, uint64_t>> ImageUnloads(ImageList& listed, const std::vector<MappedImage>& images)
{
    ImageList now;
    for (const MappedImage& image : images) {
        const auto key = std::make_pair(image.base, image.path);
        if (image.executable || listed.count(key)) now[key] = image.size;
    }
    std::vector<std::pair<std::pair<uint64_t, std::string>, uint64_t>> gone;
    for (const auto& item : listed)
        if (!now.count(item.first)) gone.push_back(item);
    listed = std::move(now);
    return gone;
}

void PeForgetGone(const PeRanges& previous, const PeRanges& now, std::vector<PeRanges::Range>& anon)
{
    for (const PeRanges::Range& gone : previous.ranges) {
        if (gone.path.empty() || std::any_of(now.ranges.begin(), now.ranges.end(), [&](const PeRanges::Range& range) {
                return range.base == gone.base && range.path == gone.path;
            }))
            continue;
        anon.erase(std::remove_if(anon.begin(), anon.end(), [&](const PeRanges::Range& range) { return range.base == gone.base; }),
                   anon.end());
    }
}

const PeRanges::Range* PeRanges::Find(uint64_t address) const
{
    auto next = std::upper_bound(ranges.begin(), ranges.end(), address,
                                 [](uint64_t value, const Range& range) { return value < range.base; });
    if (next == ranges.begin()) return nullptr;
    --next;
    return address < next->end ? &*next : nullptr;
}

PeWalkResult PeWalk(const PeRanges& images, uint64_t rip, uint64_t rsp, uint64_t rbp, const uint8_t* stack,
                    uint32_t bytes, std::vector<uint64_t>& out, size_t max)
{
    PeWalkResult result;
    if (rip == 0 || max == 0) return result;
    const Stack copy{rsp, stack, stack ? bytes : 0};
    out.push_back(rip);
    result.frames = 1;
    uint64_t pc = rip, sp = rsp, bp = rbp;
    for (bool first = true; result.frames < max; first = false) {
        const PeRanges::Range* range = images.Find(pc);
        if (!range || range->image->machine != kAmd64) break;
        uint64_t nextSp = sp, nextBp = bp, ret = 0;
        if (!Unwind(*range->image, static_cast<uint32_t>(pc - range->base), !first, copy, nextSp, nextBp, ret) || nextSp <= sp)
            break;
        sp = nextSp;
        bp = nextBp;
        if (ret == 0) return result;   /* the thread's outermost frame */
        out.push_back(ret);
        result.frames++;
        pc = ret;
    }
    /* Where unwinding stops (code without an image or unwind info, e.g. a packed game), the rest of the copied
     * stack is scanned for words inside PE code sections.
     * shortcut: a scanned word may be a stale or non-return address (no call-site check); check that the bytes
     * before it are a call if false frames mislead. */
    for (uint64_t offset = (sp - rsp + 7) & ~7ull; offset + 8 <= copy.size && result.frames < max; offset += 8) {
        uint64_t word = 0;
        std::memcpy(&word, copy.bytes + offset, 8);
        const PeRanges::Range* range = images.Find(word);
        if (!range || !range->image->Code(static_cast<uint32_t>(word - range->base))) continue;
        out.push_back(word);
        result.frames++;
        result.scanned++;
    }
    return result;
}

std::string WmiModule(const std::string& path)
{
    std::string name = path.substr(path.find_last_of('/') + 1);
    for (char& c : name) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    for (const char* module : {"wbemprox.dll", "wbemdisp.dll", "wmiutils.dll", "fastprox.dll"}) {
        if (name == module) return name;
    }
    return {};
}

std::vector<uint64_t> PeWmiMethods(const std::string& path, uint16_t& machine)
{
    static const unsigned kEntries[MM_UP_WMI_METHODS] = {20, 21, 6, 18};   /* by MM_UP_WMI_* */
    static std::mutex mutex;
    static std::map<std::string, std::pair<std::vector<uint64_t>, uint16_t>> cache;
    std::lock_guard<std::mutex> lock(mutex);
    auto found = cache.find(path);
    if (found != cache.end()) {
        machine = found->second.second;
        return found->second.first;
    }
    std::pair<std::vector<uint64_t>, uint16_t>& result = cache[path];
    result.first.assign(MM_UP_WMI_METHODS, 0);
    machine = 0;
    std::vector<uint8_t> file;
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat info {};
    if (fd >= 0 && fstat(fd, &info) == 0 && info.st_size > 0x400 && info.st_size < (64 << 20)) {
        file.resize(static_cast<size_t>(info.st_size));
        if (!ReadAt(fd, 0, file.data(), file.size())) file.clear();
    }
    if (fd >= 0) close(fd);
    const uint8_t* bytes = file.data();
    auto inFile = [&](uint64_t offset, uint64_t size) { return offset <= file.size() && size <= file.size() - offset; };
    if (!inFile(0, 0x40)) return result.first;
    const uint32_t nt = Get<uint32_t>(bytes + 0x3c);
    if (!inFile(nt, 24 + 0x60) || std::memcmp(bytes + nt, "PE\0\0", 4) != 0) return result.first;
    const uint16_t magic = Get<uint16_t>(bytes + nt + 24);
    const unsigned width = magic == 0x20b ? 8 : 4;
    const uint64_t imageBase = width == 8 ? Get<uint64_t>(bytes + nt + 24 + 24) : Get<uint32_t>(bytes + nt + 24 + 28);
    const uint32_t table = nt + 24 + Get<uint16_t>(bytes + nt + 20);
    const uint16_t count = Get<uint16_t>(bytes + nt + 6);
    if (!inFile(table, count * 40ull)) return result.first;
    /* RVA -> file offset; Code: only inside an executable section. */
    auto offsetOf = [&](uint64_t rva, bool code) -> uint64_t {
        for (uint16_t index = 0; index < count; index++) {
            const uint8_t* header = bytes + table + index * 40;
            const uint32_t va = Get<uint32_t>(header + 12), rawSize = Get<uint32_t>(header + 16), raw = Get<uint32_t>(header + 20);
            if (rva >= va && rva - va < rawSize && (!code || (Get<uint32_t>(header + 36) & 0x20000020u) != 0)) return raw + (rva - va);
        }
        return 0;
    };
    auto pointer = [&](uint64_t offset) { return width == 8 ? Get<uint64_t>(bytes + offset) : Get<uint32_t>(bytes + offset); };
    /* The DIE of wbem_services_vtbl: its name inline (DW_FORM_string), then within a few attributes its location, an
     * exprloc of width + 1 bytes: DW_OP_addr (0x03) and the address. shortcut: a build that names it through
     * .debug_str or keeps no DWARF gives 0 (no query text); parse .debug_info properly if such a build is used. */
    static const char kName[] = "wbem_services_vtbl";
    for (auto at = file.begin(); (at = std::search(at, file.end(), kName, kName + sizeof(kName))) != file.end(); ++at) {
        const size_t name = static_cast<size_t>(at - file.begin()) + sizeof(kName);
        for (size_t scan = name; scan < name + 32 && inFile(scan, 2 + width); scan++) {
            if (bytes[scan] != width + 1 || bytes[scan + 1] != 0x03) continue;
            std::vector<uint64_t> code(MM_UP_WMI_METHODS, 0);
            for (unsigned method = 0; method < MM_UP_WMI_METHODS; method++) {
                const uint64_t entry = offsetOf(pointer(scan + 2) - imageBase + kEntries[method] * width, false);
                if (entry != 0 && inFile(entry, width)) code[method] = offsetOf(pointer(entry) - imageBase, true);
            }
            if (code[MM_UP_WMI_EXEC_QUERY] == 0) continue;
            machine = Get<uint16_t>(bytes + nt + 4);
            result = {code, machine};
            return code;
        }
    }
    return result.first;
}
