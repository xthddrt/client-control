#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

/*
 * DNS wire format (RFC 1035) for the etw_dns records the eBPF sensor writes from the client's own
 * port-53 traffic (bpf.cpp). Pure functions over untrusted bytes: every read is bounds-checked,
 * compression pointers must point backwards (so a name always ends), and counts are capped.
 */

namespace {

uint16_t Be16(const uint8_t* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

/* A label byte as presentation text: letters, digits, '-' and '_' as they are, anything else
 * (including '.', ';', '|', '=' and spaces) as \DDD, so a name cannot break the detail fields. */
void AppendLabel(std::wstring& out, const uint8_t* label, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        const uint8_t c = label[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            out += static_cast<wchar_t>(c);
        } else {
            wchar_t escaped[8];
            swprintf(escaped, 8, L"\\%03u", static_cast<unsigned>(c));
            out += escaped;
        }
    }
}

/* The (possibly compressed) name at Offset; Next is the offset after it in the message. */
bool ReadName(const uint8_t* data, size_t size, size_t offset, std::wstring& name, size_t& next)
{
    name.clear();
    next = 0;
    size_t position = offset;
    size_t wire = 0;
    for (unsigned labels = 0; labels < 128; labels++) {
        if (position >= size) return false;
        const uint8_t length = data[position];
        if ((length & 0xC0) == 0xC0) {
            if (position + 1 >= size) return false;
            const size_t target = static_cast<size_t>(((length & 0x3F) << 8) | data[position + 1]);
            if (target >= position) return false;   /* only backwards: no loops */
            if (next == 0) next = position + 2;
            position = target;
            continue;
        }
        if ((length & 0xC0) != 0) return false;     /* extended label types are not used */
        if (length == 0) {
            if (next == 0) next = position + 1;
            if (name.empty()) name = L".";
            return true;
        }
        if (position + 1 + length > size || (wire += length + 1) > 255) return false;
        if (!name.empty()) name += L'.';
        AppendLabel(name, data + position + 1, length);
        position += 1 + length;
    }
    return false;
}

const wchar_t* TypeName(uint16_t type)
{
    switch (type) {
    case 1: return L"A";
    case 2: return L"NS";
    case 5: return L"CNAME";
    case 12: return L"PTR";
    case 28: return L"AAAA";
    default: return nullptr;
    }
}

}  // namespace

/* One DNS message as the etw_dns record carries it: Name is the first question's name;
 * Detail is "query_type=N;dns_id=N", and for a response also ";rcode=N" and, when it has
 * answers, ";answers=TYPE value|..." (A/AAAA addresses, NS/CNAME/PTR names, TYPEnn for other
 * types). False when Data is not a well-formed message with a question. */
bool DnsDescribe(const uint8_t* data, size_t size, std::wstring& name, std::wstring& detail, bool& response)
{
    name.clear();
    detail.clear();
    response = false;
    if (data == nullptr || size < 12) return false;
    const uint16_t id = Be16(data);
    const uint16_t flags = Be16(data + 2);
    const unsigned questions = Be16(data + 4);
    const unsigned answers = Be16(data + 6);
    if (questions == 0 || questions > 16) return false;
    size_t position = 12;
    uint16_t queryType = 0;
    for (unsigned index = 0; index < questions; index++) {
        std::wstring questionName;
        size_t next = 0;
        if (!ReadName(data, size, position, questionName, next) || next + 4 > size) return false;
        if (index == 0) {
            name = questionName;
            queryType = Be16(data + next);
        }
        position = next + 4;
    }
    response = (flags & 0x8000) != 0;
    detail = L"query_type=" + std::to_wstring(queryType) + L";dns_id=" + std::to_wstring(id);
    if (!response) return true;
    detail += L";rcode=" + std::to_wstring(flags & 0xF);
    std::wstring list;
    for (unsigned index = 0; index < answers && index < 32; index++) {
        std::wstring owner;
        size_t next = 0;
        if (!ReadName(data, size, position, owner, next) || next + 10 > size) break;
        const uint16_t type = Be16(data + next);
        const size_t length = Be16(data + next + 8);
        const size_t rdata = next + 10;
        if (rdata + length > size) break;
        position = rdata + length;
        const wchar_t* typeName = TypeName(type);
        std::wstring value;
        if ((type == 1 && length == 4) || (type == 28 && length == 16)) {
            char text[INET6_ADDRSTRLEN] = {};
            inet_ntop(type == 1 ? AF_INET : AF_INET6, data + rdata, text, sizeof(text));
            value.assign(text, text + strnlen(text, sizeof(text)));
        } else if (type == 2 || type == 5 || type == 12) {
            size_t ignored = 0;
            if (!ReadName(data, size, rdata, value, ignored)) continue;
        } else {
            typeName = nullptr;
        }
        if (!list.empty()) list += L'|';
        list += typeName != nullptr ? std::wstring(typeName) + L" " + value : L"TYPE" + std::to_wstring(type);
    }
    if (!list.empty()) detail += L";answers=" + list;
    return true;
}

/* DNS over TCP: appends Bytes to Stream (one direction of one socket) and returns the complete
 * messages it now holds; each is framed by a 2-byte big-endian length (RFC 1035 4.2.2). */
std::vector<std::string> DnsTcpTake(std::string& stream, const uint8_t* bytes, size_t size)
{
    std::vector<std::string> messages;
    stream.append(reinterpret_cast<const char*>(bytes), size);
    while (stream.size() >= 2) {
        const size_t length = Be16(reinterpret_cast<const uint8_t*>(stream.data()));
        if (stream.size() < 2 + length) break;
        messages.push_back(stream.substr(2, length));
        stream.erase(0, 2 + length);
    }
    return messages;
}
