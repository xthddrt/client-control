#include "session.h"
#include "pe.h"
#include <sys/stat.h>
#include <algorithm>
#include <cwchar>
#include <fstream>
#include <map>
#include <set>
#include <tuple>

/*
 * image_load from /proc/<pid>/maps (pe.cpp MappedImages): one record per load of a PE image (value0 = the
 * mapping of its header, value1 = SizeOfImage) and per other executable file (value0 = lowest address of its
 * mappings, value1 = span to the highest). Polled on track, on an executable mmap/mprotect and every two
 * seconds, so a library loaded and unloaded between polls is missed. An image a poll listed executable that a later
 * poll no longer lists at all is unloaded: a file_section record image_unload;source=maps_poll (value0 its base, value1
 * its size), and its next load is logged again. A WMI module's load is also an etw_wmi
 * record (pe.cpp WmiModule). The scan also keeps each process's PE
 * images for the PE frames of its syscall records (ImagesPe). A scan on the eBPF thread holds its loads
 * (ImagesRelease logs them later): it reads the maps ahead of the mmap/mprotect records still queued, whose
 * loads those records name themselves (thread, stack, source=). shortcut: the 2 s poll and Track (other threads)
 * still log at once, so behind a backlog they can name such a load first; hold them too while eBPF runs if that shows.
 */

static std::mutex gMutex;
static std::set<std::tuple<DWORD, uint64_t, uint64_t, std::string>> gSeen;
static std::map<std::pair<DWORD, uint64_t>, std::pair<uint64_t, std::shared_ptr<const PeRanges>>> gPe;   /* scan, ranges */
static std::map<std::pair<DWORD, uint64_t>, std::vector<PeRanges::Range>> gAnon;   /* PE images in anonymous memory */
static uint64_t gScan;
static std::map<std::pair<DWORD, uint64_t>, std::map<std::pair<uint64_t, std::string>, MappedImage>> gHeld;   /* hold */
/* Each process's images (base, path) -> size the last poll listed that were executable then or before: an unload is
 * one the next poll lists no more. With the inode of the executable they belong to: an exec starts the list over. */
static std::map<std::pair<DWORD, uint64_t>, std::pair<uint64_t, ImageList>> gMapped;

/* Ranges plus the process's anonymous PE images, sorted by base (PeRanges::Find). Caller holds gMutex. */
static std::shared_ptr<PeRanges> WithAnon(DWORD pid, uint64_t start, PeRanges ranges)
{
    auto found = gAnon.find({pid, start});
    if (found != gAnon.end()) ranges.ranges.insert(ranges.ranges.end(), found->second.begin(), found->second.end());
    std::sort(ranges.ranges.begin(), ranges.ranges.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
    return std::make_shared<PeRanges>(std::move(ranges));
}

void ImagesReset()
{
    std::lock_guard<std::mutex> lock(gMutex);
    gSeen.clear();
    gPe.clear();
    gAnon.clear();
    gHeld.clear();
    gMapped.clear();
}

void ImagesForget(DWORD pid)
{
    std::lock_guard<std::mutex> lock(gMutex);
    for (auto it = gSeen.begin(); it != gSeen.end();) {
        it = std::get<0>(*it) == pid ? gSeen.erase(it) : std::next(it);
    }
    for (auto it = gPe.begin(); it != gPe.end();) {
        it = it->first.first == pid ? gPe.erase(it) : std::next(it);
    }
    for (auto it = gAnon.begin(); it != gAnon.end();) {
        it = it->first.first == pid ? gAnon.erase(it) : std::next(it);
    }
    for (auto it = gHeld.begin(); it != gHeld.end();) {
        it = it->first.first == pid ? gHeld.erase(it) : std::next(it);
    }
    for (auto it = gMapped.begin(); it != gMapped.end();) {
        it = it->first.first == pid ? gMapped.erase(it) : std::next(it);
    }
}

void ImagesAddPe(uint32_t pid, uint64_t start, uint64_t base, std::shared_ptr<const PeImage> image)
{
    std::lock_guard<std::mutex> lock(gMutex);
    auto& anon = gAnon[{pid, start}];
    for (const auto& range : anon)
        if (range.base == base) return;
    anon.push_back({base, base + image->sizeOfImage, std::move(image)});
    auto& slot = gPe[{pid, start}];
    PeRanges ranges = slot.second ? *slot.second : PeRanges{};
    ranges.ranges.push_back(anon.back());
    std::sort(ranges.ranges.begin(), ranges.ranges.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
    slot.second = std::make_shared<PeRanges>(std::move(ranges));
}

/* A load the kernel sensors logged themselves (bpf.cpp ImageLoaded): the scan below then skips it. */
bool ImagesClaim(DWORD pid, uint64_t start, uint64_t base, const std::string& path)
{
    std::lock_guard<std::mutex> lock(gMutex);
    return gSeen.emplace(pid, start, base, path).second;
}

std::shared_ptr<const PeRanges> ImagesPe(uint32_t pid, uint64_t start)
{
    std::lock_guard<std::mutex> lock(gMutex);
    auto found = gPe.find({pid, start});
    return found == gPe.end() ? nullptr : found->second.second;
}

/* The image's load (and a WMI module's etw_wmi record) unless already logged. */
static void LogImage(LinuxSession& session, DWORD pid, uint64_t start, const MappedImage& image)
{
    /* ETW WMI-Activity has no Linux source (Wine's WMI is in-process): the provider's load is the record.
     * Its own work (SMBIOS, disk, adapter reads) carries it as a PE frame module. Keyed apart from the
     * image_load, which the kernel sensors may have claimed (ImagesClaim). */
    const std::string wmi = WmiModule(image.path);
    bool wmiNew = false, imageNew;
    {
        std::lock_guard<std::mutex> lock(gMutex);
        if (!wmi.empty()) wmiNew = gSeen.emplace(pid, start, image.base, "wmi:" + image.path).second;
        imageNew = gSeen.emplace(pid, start, image.base, image.path).second;
    }
    if (wmiNew)
        session.Log(MSMON_SENSOR_LINUX_MAPS_POLL, MsMonEtwWmi, pid, start, 0, image.base, image.size,
                    L"module:" + LinuxWide(wmi),
                    L"operation=provider_loaded;module=" + LinuxWide(image.path) + L";query=unavailable");
    if (imageNew)
        session.Log(MSMON_SENSOR_LINUX_MAPS_POLL, MsMonImageLoad, pid, start, 0, image.base, image.size,
                    LinuxWide(image.path));
}

void ImagesRelease(LinuxSession& session, DWORD pid)
{
    decltype(gHeld) held;
    {
        std::lock_guard<std::mutex> lock(gMutex);
        for (auto it = gHeld.begin(); it != gHeld.end();) {
            if (pid != 0 && it->first.first != pid) {
                ++it;
                continue;
            }
            held.insert(gHeld.extract(it++));
        }
    }
    for (const auto& [process, images] : held)
        for (const auto& image : images) LogImage(session, process.first, process.second, image.second);
}

void ImagesScan(LinuxSession& session, DWORD pid, uint64_t start, bool hold, bool inherited, bool unloads)
{
    session.Enter(MSMON_SENSOR_LINUX_MAPS_POLL);
    uint64_t scan;
    {
        std::lock_guard<std::mutex> lock(gMutex);
        scan = ++gScan;
    }
    struct stat exe {};
    const uint64_t exeInode = unloads && stat(("/proc/" + std::to_string(pid) + "/exe").c_str(), &exe) == 0 ? exe.st_ino : 0;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    const std::vector<MappedImage> images = MappedImages(maps);
    /* A reused PID's maps belong to another process. */
    if (images.empty() || LinuxProcessStart(pid) != start) return;
    /* Unloads (the 2 s poll alone, so two scans never diff at once): what the last poll listed executable and this one
     * lists no more; its next load is logged again. An exec (another executable) is a new address space, not unloads,
     * even before the agent has read its record. shortcut: a process that execs its own executable again lists its
     * libraries as unloaded; compare the maps' start times too if that is seen. */
    std::vector<std::pair<std::pair<uint64_t, std::string>, uint64_t>> unloaded;
    if (unloads) {
        std::lock_guard<std::mutex> lock(gMutex);
        auto& listed = gMapped[{pid, start}];
        if (listed.first != exeInode) listed = {exeInode, {}};
        unloaded = ImageUnloads(listed.second, images);
        for (const auto& [key, size] : unloaded) {
            gSeen.erase({pid, start, key.first, key.second});
            gSeen.erase({pid, start, key.first, "wmi:" + key.second});
        }
    }
    for (const auto& [key, size] : unloaded) {
        wchar_t base[24];
        swprintf(base, 24, L"0x%llx", static_cast<unsigned long long>(key.first));
        session.Log(MSMON_SENSOR_LINUX_MAPS_POLL, MsMonFileSection, pid, start, 0, key.first, size, LinuxWide(key.second),
                    L"image_unload;source=maps_poll;base=" + std::wstring(base));
    }
    PeRanges pe;
    for (const MappedImage& image : images) {
        if (!image.executable) continue;
        if (image.pe) pe.ranges.push_back({image.base, image.base + image.size, image.pe, image.path});
        if (inherited) {
            std::lock_guard<std::mutex> lock(gMutex);
            gSeen.emplace(pid, start, image.base, image.path);
            const std::string wmi = WmiModule(image.path);
            if (!wmi.empty()) gSeen.emplace(pid, start, image.base, "wmi:" + image.path);
            continue;
        }
        if (!hold) {
            LogImage(session, pid, start, image);
            continue;
        }
        std::lock_guard<std::mutex> lock(gMutex);
        gHeld[{pid, start}].emplace(std::make_pair(image.base, image.path), image);
    }
    std::lock_guard<std::mutex> lock(gMutex);
    /* The poll and ring threads scan concurrently: a scan that read maps earlier never replaces a later one. */
    auto& slot = gPe[{pid, start}];
    if (scan <= slot.first) return;
    const auto anon = gAnon.find({pid, start});
    if (slot.second && anon != gAnon.end()) PeForgetGone(*slot.second, pe, anon->second);
    slot = {scan, WithAnon(pid, start, std::move(pe))};
}
