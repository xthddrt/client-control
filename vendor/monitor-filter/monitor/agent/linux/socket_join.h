#pragma once

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * The wineserver socket join (docs/LINUX.md).  Under Wine, wineserver creates, connects, binds
 * and accepts sockets and closes them; the game only reads and writes them (same inode).  A
 * socket one tracked process made (its creator) is remembered by inode; the first I/O of any
 * other tracked process on it attaches that process (its network_flow_established),
 * and its bytes are counted until the socket ends for it (its network_flow_close).  Pure
 * bookkeeping, not thread-safe: bpf.cpp feeds it, locks it and writes the records it returns.
 *
 * A use ends when the creator closes the inode (socket_closed: wineserver holds one fd per socket
 * until the last Windows handle closes), the creator exits (socket_closed) or leaves scope
 * (untracked: its later close is not seen, so the entry is dropped), the user exits or leaves scope, the inode number comes back from socket()/accept() (inode_reused) or the session
 * ends.  A user's own close() ends nothing: Wine clients close per-call fds (a real session shows
 * the game closing an fd of a socket before wineserver even connected it).
 * shortcut: a helper that hands its socket to another process and closes its own fd ends the
 * join early; count fds per process if such a helper appears.
 * shortcut: a socket the creator never bound or connected (a UDP socket the game sendto()s on)
 * has no endpoint and is not joined; join it on the user's own sendto address if game UDP matters.
 * shortcut: only the fd the Syscall table resolves is joined: sendfile/splice/copy_file_range name
 * their input fd, so bytes they move out of a socket count as received and bytes they move into
 * one are not counted; resolve the output fd too if a client sends that way (Wine does not).
 * shortcut: sockets made before the session are unknown (not joined); seed from /proc/net/tcp*
 * and /proc/<wineserver>/fd if attaching to an already connected game matters.
 */
class SocketJoin {
public:
    struct Who {
        uint32_t pid = 0;
        uint64_t start = 0;   /* process start (FILETIME): pid + start is the identity */
        bool operator==(const Who& other) const { return pid == other.pid && start == other.start; }
    };
    enum Via : uint8_t { kSocket, kConnect, kBind, kListen, kAccept };
    struct Socket {
        Who creator;             /* the process that made it: wineserver under Wine */
        Via via = kSocket;       /* its last creator call: the via word that starts the records' detail */
        unsigned family = 0;     /* AF_*, 0 unknown */
        unsigned type = 0;       /* SOCK_* (from socket(), or stream for accept), 0 unknown */
        uint16_t port = 0;       /* the endpoint's port: remote for connect/accept, local for bind/listen */
        std::wstring endpoint;   /* as the creator's record names it; empty: nothing to attribute yet */
        long status = 0;         /* the creator call's result (negative errno) */
        uint64_t time = 0;       /* when the creator made that call */
    };
    struct Use {
        Who who;
        uint64_t sent = 0;
        uint64_t received = 0;
    };
    /* One record to write: Use was attached now (opened), or its use ended (reason, at time). */
    struct Change {
        bool opened = false;
        uint64_t inode = 0;
        Socket socket;
        Use use;
        const wchar_t* reason = L"";
        uint64_t time = 0;
    };
    using Changes = std::vector<Change>;

    /* A creator call on Inode.  socket()/accept() return a new socket, so an entry already holding
     * the number belonged to a dead one; connect/bind/listen update the entry (family, type and an
     * empty endpoint keep what is known). */
    Changes Made(uint64_t inode, const Who& creator, Via via, unsigned family, unsigned type, uint16_t port,
                 const std::wstring& endpoint, long status, uint64_t time)
    {
        Changes changes;
        Entry& entry = entries_[inode];
        if (via == kSocket || via == kAccept) {
            End(inode, entry, L"inode_reused", time, changes);
            entry = Entry{};
        }
        Socket& socket = entry.socket;
        socket.creator = creator;
        socket.via = via;
        if (family != 0) socket.family = family;
        if (type != 0) socket.type = type;
        if (!endpoint.empty()) {
            socket.endpoint = endpoint;
            socket.port = port;
        }
        socket.status = status;
        socket.time = time;
        return changes;
    }

    /* Who read or wrote Inode: the first I/O on a socket another process made attaches it. */
    Changes Io(uint64_t inode, const Who& who, uint64_t sent, uint64_t received, uint64_t time)
    {
        Changes changes;
        auto found = entries_.find(inode);
        if (found == entries_.end() || found->second.socket.creator == who || found->second.socket.endpoint.empty())
            return changes;
        std::vector<Use>& uses = found->second.uses;
        auto use = std::find_if(uses.begin(), uses.end(), [&](const Use& item) { return item.who == who; });
        if (use == uses.end()) {
            uses.push_back(Use{who, 0, 0});
            use = uses.end() - 1;
            changes.push_back(Change{true, inode, found->second.socket, *use, L"", time});
        }
        use->sent += sent;
        use->received += received;
        return changes;
    }

    /* Who closed an fd of Inode: only the creator's close ends the socket. */
    Changes Closed(uint64_t inode, const Who& who, uint64_t time)
    {
        Changes changes;
        auto found = entries_.find(inode);
        if (found == entries_.end() || !(found->second.socket.creator == who)) return changes;
        End(inode, found->second, L"socket_closed", time, changes);
        entries_.erase(found);
        return changes;
    }

    /* Who exited (process_exit) or left scope: its uses end with Reason, and the sockets it made end
     * with it (socket_closed on exit, the socket may live on when it only left scope). */
    Changes Gone(const Who& who, const wchar_t* reason, uint64_t time)
    {
        Changes changes;
        const wchar_t* made = std::wcscmp(reason, L"process_exit") == 0 ? L"socket_closed" : reason;
        for (auto it = entries_.begin(); it != entries_.end();) {
            Entry& entry = it->second;
            if (entry.socket.creator == who) {
                End(it->first, entry, made, time, changes);
                it = entries_.erase(it);
                continue;
            }
            auto use = std::find_if(entry.uses.begin(), entry.uses.end(), [&](const Use& item) { return item.who == who; });
            if (use != entry.uses.end()) {
                changes.push_back(Change{false, it->first, entry.socket, *use, reason, time});
                entry.uses.erase(use);
            }
            ++it;
        }
        return changes;
    }

    /* Session end: every use ends (session_end) and nothing is kept. */
    Changes Flush(uint64_t time)
    {
        Changes changes;
        for (auto& item : entries_) End(item.first, item.second, L"session_end", time, changes);
        entries_.clear();
        return changes;
    }

    /* The socket Inode names and its first user (user.pid 0 while none); false when unknown. */
    bool Lookup(uint64_t inode, Socket& socket, Who& user) const
    {
        auto found = entries_.find(inode);
        if (found == entries_.end()) return false;
        socket = found->second.socket;
        user = found->second.uses.empty() ? Who{} : found->second.uses.front().who;
        return true;
    }

private:
    struct Entry {
        Socket socket;
        std::vector<Use> uses;
    };

    static void End(uint64_t inode, Entry& entry, const wchar_t* reason, uint64_t time, Changes& changes)
    {
        for (const Use& use : entry.uses) changes.push_back(Change{false, inode, entry.socket, use, reason, time});
        entry.uses.clear();
    }

    /* shortcut: an entry whose creator close was lost (ring full) stays until the creator exits, the
     * inode returns or the session ends; cap it if sessions run for days. */
    std::unordered_map<uint64_t, Entry> entries_;
};
