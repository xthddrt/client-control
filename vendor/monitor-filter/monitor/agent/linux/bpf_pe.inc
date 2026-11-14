/* pecaller: the PE (Windows-side) frames of a Wine thread's syscall (pe.bpf.h copies them, pe.cpp unwinds
 * them; docs/LINUX.md "PE frames"). Included by bpf.cpp at global scope after Record/Repeated/FlushRepeats. */
#include "pe.h"

namespace {
constexpr size_t kPeFrames = MSMON_MAX_STACK_FRAMES - MM_FRAMES;

/* The PE frames of an ia32 Wine thread (MM_PE_I386): eip (inside the NtXxx stub), then the 4-byte words of the
 * copied 32-bit stack that lie in PE code, the first being the return into NtXxx's caller. i386 PE images have no
 * .pdata, so there is no unwinding. shortcut: a scanned word may be stale (no call-site check), as PeWalk's scan;
 * follow the EBP chain if false frames mislead. */
PeWalkResult PeWalk32(const PeRanges& images, const mm_pe& pe, std::vector<uint64_t>& out, size_t max)
{
    PeWalkResult walk;
    if (max == 0) return walk;
    out.push_back(pe.rip);
    walk.frames = 1;
    const uint32_t bytes = std::min<uint32_t>(pe.bytes, MM_PE_BYTES);
    for (uint32_t offset = 0; offset + 4 <= bytes && walk.frames < max; offset += 4) {
        uint32_t word = 0;
        std::memcpy(&word, pe.stack + offset, 4);
        const PeRanges::Range* range = images.Find(word);
        if (!range || !range->image->Code(static_cast<uint32_t>(word - range->base))) continue;
        out.push_back(word);
        walk.frames++;
        walk.scanned++;
    }
    return walk;
}

/* record.stack = the PE frames (when pe.rip != 0), then the unix frames. Also used for wineserver-request
 * records, so it relies on pe and the frames only. */
void PeFrames(const mm_pe& pe, DWORD tgid, uint64_t start, const __u64* frames, uint32_t count, LinuxRecord& record)
{
    record.stack.clear();
    if (pe.rip != 0) {
        static const PeRanges kNone;
        const std::shared_ptr<const PeRanges> images = ImagesPe(tgid, start);
        const PeWalkResult walk =
            (pe.flags & MM_PE_I386) != 0
                ? PeWalk32(images ? *images : kNone, pe, record.stack, kPeFrames)
                : PeWalk(images ? *images : kNone, pe.rip, pe.rsp, pe.rbp, pe.stack,
                         std::min<uint32_t>(pe.bytes, MM_PE_BYTES), record.stack, kPeFrames);
        if (walk.frames) {
            if ((pe.flags & MM_PE_I386) != 0) record.detail += L";pe_i386=1";
            record.detail += L";pe_frames=" + std::to_wstring(walk.frames);
            if (walk.scanned) record.detail += L";pe_scanned=" + std::to_wstring(walk.scanned);
        }
    }
    record.stack.insert(record.stack.end(), frames, frames + count);
}

int PeOpened(std::wstring& detail, unsigned&)
{
    detail += L";pe_frames=" + std::to_wstring(kPeFrames) + L";pe_stack_bytes=" + std::to_wstring(MM_PE_BYTES);
    return 0;
}

void PeNotes(Notes& notes)
{
    notes.push_back({L"pe_frames",
                     L"syscall records of x64 Wine threads put up to " + std::to_wstring(kPeFrames) +
                         L" PE (Windows-side) frames before the unix frames: the NtXxx stub in ntdll.dll, the return"
                         L" addresses unwound with the images' .pdata/.xdata from " + std::to_wstring(MM_PE_BYTES) +
                         L" bytes of the PE stack (detail pe_frames=N), then words of that stack inside PE code"
                         L" (pe_scanned=M, may be stale); ia32 Wine threads (32-bit PE programs under old WoW64) give eip"
                         L" and the stack words in PE code (pe_i386=1); frames are resolved"
                         L" against image_load of the last maps scan; modules lists the first 8 images"});
}
}  // namespace
