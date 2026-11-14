#pragma once
/*
 * PE (Windows-side) frames of Wine threads (docs/LINUX.md "PE frames"): PE files parsed from disk, the
 * images mapped in a process, and an x64 unwinder over the PE stack copied by pe.bpf.h. No session.h
 * types, so tests/linux_pe_test.cpp links pe.cpp alone.
 */
#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/* One PE file: its size in memory, executable sections and (x64) .pdata/.xdata. */
struct PeImage {
    struct Function {
        uint32_t begin, end, unwind;   /* RUNTIME_FUNCTION RVAs */
    };
    uint16_t machine = 0;              /* 0x8664 x64, 0x14c i386 */
    uint32_t sizeOfImage = 0;
    uint32_t timeDateStamp = 0;        /* IMAGE_FILE_HEADER: link time */
    std::string name;                  /* the export directory's module name, "" without one */
    std::vector<Function> functions;   /* sorted by begin; x64 only */
    std::vector<std::pair<uint32_t, uint32_t>> code;          /* executable sections [begin, end) */
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> data;   /* sections holding UNWIND_INFO: rva, bytes */

    const Function* Find(uint32_t rva) const;
    bool Code(uint32_t rva) const;
    const uint8_t* At(uint32_t rva, uint32_t size) const;   /* size bytes of data at rva, or nullptr */
};

/* The parsed PE file at path, or nullptr (not a regular PE file, or not the file with that inode any more).
 * Parsed once per path, inode, size and mtime and cached. */
std::shared_ptr<const PeImage> PeOpen(const std::string& path, uint64_t inode = 0);

/* The PE image loaded at base in a process's memory (memory: an fd of /proc/<pid>/mem), or nullptr. Not cached. */
std::shared_ptr<const PeImage> PeLoaded(int memory, uint64_t base);

/* One image in /proc/<pid>/maps. A PE image is one per load: base = the mapping of its header (file offset
 * 0), size = SizeOfImage. Any other file is one per path: lowest address and span to the highest. */
struct MappedImage {
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
    bool executable = false;   /* a mapping inside it is executable (Wine mprotects PE code later) */
    std::shared_ptr<const PeImage> pe;
};
std::vector<MappedImage> MappedImages(std::istream& maps);   /* sorted by base */

/* The maps poll's unloads (images.cpp): Listed holds (base, path) -> size of the images the last poll listed that were
 * executable then or before; returns those Images (this poll's) no longer lists, and Listed becomes this poll's. */
using ImageList = std::map<std::pair<uint64_t, std::string>, uint64_t>;
std::vector<std::pair<std::pair<uint64_t, std::string>, uint64_t>> ImageUnloads(ImageList& listed, const std::vector<MappedImage>& images);

/* A process's executable PE images, sorted by base. */
struct PeRanges {
    struct Range {
        uint64_t base, end;
        std::shared_ptr<const PeImage> image;
        std::string path = {};   /* the mapped file ("" for an image found in anonymous memory) */
    };
    std::vector<Range> ranges;
    const Range* Find(uint64_t address) const;
};

/* images.cpp's scan: Wine reads a native image's sections into anonymous memory, so AnonImage also finds the image as
 * a PE in anonymous memory (ImagesAddPe). Such a range of Anon at the base of a file image that Previous held and Now
 * does not was that image: it is dropped with it (else a watch on the module would stay on the freed base). */
void PeForgetGone(const PeRanges& previous, const PeRanges& now, std::vector<PeRanges::Range>& anon);

/* Appends to out (at most max entries) the PE frames of one Wine syscall: rip, then the return addresses
 * unwound from the stack bytes copied at rsp, then the words of the rest of the stack that lie in PE code. */
struct PeWalkResult {
    uint32_t frames = 0;    /* entries appended */
    uint32_t scanned = 0;   /* of them, found by the stack scan */
};
PeWalkResult PeWalk(const PeRanges& images, uint64_t rip, uint64_t rsp, uint64_t rbp, const uint8_t* stack,
                    uint32_t bytes, std::vector<uint64_t>& out, size_t max);

/* The lower-case file name of a WMI module (wbemprox, wbemdisp, wmiutils, fastprox: Wine runs WMI inside the
 * calling process, so their load is its WMI use), or "" for any other path. */
std::string WmiModule(const std::string& path);

/* The file offsets of the IWbemServices methods msmon probes, by MM_UP_WMI_* (ExecQuery, ExecQueryAsync, GetObject,
 * CreateInstanceEnum: vtable entries 20, 21, 6, 18) in a wbemprox.dll, each 0 if not found (all 0 without ExecQuery);
 * Machine: the PE's machine. Found through the DWARF Wine's builds keep (the vtable variable's DW_OP_addr location).
 * Cached per path. */
std::vector<uint64_t> PeWmiMethods(const std::string& path, uint16_t& machine);

/* images.cpp: the PE images of a tracked process as of its last maps scan, or nullptr. */
std::shared_ptr<const PeRanges> ImagesPe(uint32_t pid, uint64_t start);
/* images.cpp: a PE image found in anonymous memory (bpf.cpp AnonImage); every later scan keeps it in ImagesPe, unless
 * it was a file image's own (PeForgetGone). */
void ImagesAddPe(uint32_t pid, uint64_t start, uint64_t base, std::shared_ptr<const PeImage> image);
