#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include "linux/win32.h"
#endif
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

const std::vector<std::wstring>& RpcOpnumProperties();
std::wstring RpcGuidText(const GUID& guid);
bool RpcOperationName(const std::wstring& interfaceUuid, uint64_t opnum,
                      std::wstring& service, std::wstring& method);
/* The service name of a known interface UUID (any opnum), e.g. for a bind. */
bool RpcInterfaceName(const std::wstring& interfaceUuid, std::wstring& service);

/* Desktop services reached over AF_UNIX (Linux): the service a socket endpoint ("unix:/run/user/1000/bus",
 * "unix:@/tmp/.X11-unix/X0") belongs to: x11, dbus_session, dbus_system, atspi, pulse, pipewire, wayland, or "". */
std::wstring UnixService(const std::wstring& endpoint);

/* An X11 server's extension as its QueryExtension reply gives it: the major opcode of its requests, its first event
 * and first error codes (0: none). A display's table is the same for every client. */
struct X11Extension {
    std::string name;
    uint8_t major = 0, firstEvent = 0, firstError = 0;
};
using X11Extensions = std::vector<X11Extension>;
/* The extensions a display's table asks for (the agent's QueryExtension per name). */
const std::vector<std::string>& X11ExtensionNames();
/* An X11 request's name from its op (unix_bpf.h: major << 8, | minor for an extension): the core request, or
 * <EXTENSION>.<request> through Extensions (<EXTENSION>.<minor> past the tables, ext<major>.<minor> unknown). */
std::wstring X11RequestName(uint32_t op, const X11Extensions& extensions);
/* One X11 request (Size bytes from its header on; Big: a big-endian client) as (name, extra detail): what it touches
 * (QueryExtension's and InternAtom's name, a window, property, selection, drawable and area, a grab's window, a
 * SendEvent's event, XTEST's input type...). RealInput: XTEST's and SendEvent's key or button too (else withheld). */
std::pair<std::wstring, std::wstring> X11Request(const uint8_t* bytes, size_t size, bool big, const X11Extensions& extensions,
                                                 bool realInput);
/* What an X11 server sent (unix_bpf.h op): reply, error:<name>:<request>, event:<name> (sent_event:<name> for a
 * SendEvent's), an extension's event or error as <EXTENSION>.event<n> / .error<n>. */
std::wstring X11ReceivedName(uint32_t op, const X11Extensions& extensions);
/* A PulseAudio native protocol command (pulsecore/native-common.h), memblock (audio) or other (unix_bpf.h). */
std::wstring PulseCommandName(uint32_t command);
/* One D-Bus message from its header on (Size bytes there) as (operation, extra detail): a method call or signal as
 * interface.member with destination and path (message=signal), a reply as method_return, an error as error:<name>,
 * each with its serial or reply_serial and sender; a call or signal whose member the bytes do not reach by its type
 * (DbusTypeName), fields_cut=1 when the bytes end inside its header fields. ("", "") for no message. */
std::pair<std::wstring, std::wstring> DbusMessage(const uint8_t* bytes, size_t size);
/* The D-Bus messages in one call's bytes (its SASL handshake skipped), each as DbusMessage names it, as far as the bytes
 * hold them. */
std::vector<std::pair<std::wstring, std::wstring>> DbusMessages(const uint8_t* bytes, size_t size);
/* A D-Bus message type (unix_bpf.h op): sasl (0, the handshake's lines), method_call, method_return, error, signal. */
std::wstring DbusTypeName(uint32_t type);

