#include "rpc_names.h"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <sstream>

const std::vector<std::wstring>& RpcOpnumProperties()
{
    static const std::vector<std::wstring> names = { L"ProcNum", L"OpNum", L"OperationNum" };
    return names;
}

std::wstring RpcGuidText(const GUID& guid)
{
    wchar_t text[40];
    swprintf_s(text, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               guid.Data1, guid.Data2, guid.Data3,
               guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
               guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return text;
}

namespace {
struct Entry { const wchar_t* uuid; uint64_t opnum; const wchar_t* service; const wchar_t* method; };
const Entry entries[] = {
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 0, L"WTS/TermSrvSession", L"RpcOpenSession" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 1, L"WTS/TermSrvSession", L"RpcCloseSession" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 4, L"WTS/TermSrvSession", L"RpcLogoff" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 5, L"WTS/TermSrvSession", L"RpcGetUserName" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 6, L"WTS/TermSrvSession", L"RpcGetTerminalName" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 7, L"WTS/TermSrvSession", L"RpcGetState" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 12, L"WTS/TermSrvSession", L"RpcGetSessionInformation" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 17, L"WTS/TermSrvSession", L"RpcGetSessionInformationEx" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 0, L"WTS/TermSrvEnumeration", L"RpcOpenEnum" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 1, L"WTS/TermSrvEnumeration", L"RpcCloseEnum" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 5, L"WTS/TermSrvEnumeration", L"RpcGetEnumResult" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 8, L"WTS/TermSrvEnumeration", L"RpcGetSessionIds" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 9, L"WTS/TermSrvEnumeration", L"RpcGetEnumResultEx" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 10, L"WTS/TermSrvEnumeration", L"RpcGetAllSessions" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 11, L"WTS/TermSrvEnumeration", L"RpcGetAllSessionsEx" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 0, L"WTS/RCMPublic", L"RpcGetClientData" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 1, L"WTS/RCMPublic", L"RpcGetConfigData" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 2, L"WTS/RCMPublic", L"RpcGetProtocolStatus" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 3, L"WTS/RCMPublic", L"RpcGetLastInputTime" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 4, L"WTS/RCMPublic", L"RpcGetRemoteAddress" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 8, L"WTS/RCMPublic", L"RpcGetAllListeners" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 9, L"WTS/RCMPublic", L"RpcGetSessionProtocolLastInputTime" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 10, L"WTS/RCMPublic", L"RpcGetUserCertificates" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 11, L"WTS/RCMPublic", L"RpcQuerySessionData" },
        { L"6bffd098-a112-3610-9833-46c3f87e345a", 0, L"Wkssvc", L"NetrWkstaGetInfo" },
        { L"6bffd098-a112-3610-9833-46c3f87e345a", 2, L"Wkssvc", L"NetrWkstaUserEnum" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 0, L"LSA/lsarpc", L"LsarClose" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 6, L"LSA/lsarpc", L"LsarOpenPolicy" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 7, L"LSA/lsarpc", L"LsarQueryInformationPolicy" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 14, L"LSA/lsarpc", L"LsarLookupNames" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 15, L"LSA/lsarpc", L"LsarLookupSids" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 0, L"SAMR", L"SamrConnect" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 1, L"SAMR", L"SamrCloseHandle" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 5, L"SAMR", L"SamrLookupDomainInSamServer" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 6, L"SAMR", L"SamrEnumerateDomainsInSamServer" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 7, L"SAMR", L"SamrOpenDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 13, L"SAMR", L"SamrEnumerateUsersInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 17, L"SAMR", L"SamrLookupNamesInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 18, L"SAMR", L"SamrLookupIdsInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 57, L"SAMR", L"SamrConnect2" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 61, L"SAMR", L"SamrConnect3" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 62, L"SAMR", L"SamrConnect4" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 64, L"SAMR", L"SamrConnect5" },
        /* MS-SCMR: the service control manager (services.exe; Wine's svcctl pipe). */
        { L"367abb81-9844-35f1-ad32-98f038001003", 0, L"SCM/svcctl", L"RCloseServiceHandle" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 1, L"SCM/svcctl", L"RControlService" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 2, L"SCM/svcctl", L"RDeleteService" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 6, L"SCM/svcctl", L"RQueryServiceStatus" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 12, L"SCM/svcctl", L"RCreateServiceW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 14, L"SCM/svcctl", L"REnumServicesStatusW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 15, L"SCM/svcctl", L"ROpenSCManagerW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 16, L"SCM/svcctl", L"ROpenServiceW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 17, L"SCM/svcctl", L"RQueryServiceConfigW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 19, L"SCM/svcctl", L"RStartServiceW" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 40, L"SCM/svcctl", L"RQueryServiceStatusEx" },
        { L"367abb81-9844-35f1-ad32-98f038001003", 42, L"SCM/svcctl", L"REnumServicesStatusExW" },
};
/* Interfaces named on bind only (no opnum table). */
const Entry interfaces[] = {
        { L"e1af8308-5d1f-11c9-91a4-08002b14a0fa", 0, L"EPM/epmapper", nullptr },
        { L"338cd001-2244-31f1-aaaa-900038001003", 0, L"WINREG", nullptr },
        { L"4b324fc8-1670-01d3-1278-5a47bf6ee188", 0, L"SRVSVC", nullptr },
        { L"8d9f4e40-a03d-11ce-8f69-08003e30051b", 0, L"PNP/ntsvcs", nullptr },
        { L"000001a0-0000-0000-c000-000000000046", 0, L"DCOM/IRemoteSCMActivator", nullptr },
        { L"99fcfec4-5260-101b-bbcb-00aa0021347a", 0, L"DCOM/IObjectExporter", nullptr },
};

std::wstring NormalizeUuid(const std::wstring& interfaceUuid)
{
    std::wstring normalized = interfaceUuid;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), L'{'), normalized.end());
    normalized.erase(std::remove(normalized.begin(), normalized.end(), L'}'), normalized.end());
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return normalized;
}
}  // namespace

bool RpcInterfaceName(const std::wstring& interfaceUuid, std::wstring& service)
{
    const std::wstring normalized = NormalizeUuid(interfaceUuid);
    for (const auto& entry : entries) {
        if (normalized == entry.uuid) {
            service = entry.service;
            return true;
        }
    }
    for (const auto& entry : interfaces) {
        if (normalized == entry.uuid) {
            service = entry.service;
            return true;
        }
    }
    return false;
}

bool RpcOperationName(const std::wstring& interfaceUuid, uint64_t opnum,
                      std::wstring& service, std::wstring& method)
{
    const std::wstring normalized = NormalizeUuid(interfaceUuid);
    for (const auto& entry : entries) {
        if (normalized == entry.uuid && opnum == entry.opnum) {
            service = entry.service;
            method = entry.method;
            return true;
        }
    }
    return false;
}

std::wstring UnixService(const std::wstring& endpoint)
{
    auto has = [&](const wchar_t* part) { return endpoint.find(part) != std::wstring::npos; };
    auto ends = [&](const std::wstring& tail) {
        return endpoint.size() >= tail.size() && endpoint.compare(endpoint.size() - tail.size(), tail.size(), tail) == 0;
    };
    if (has(L"/.X11-unix/X")) return L"x11";
    if (has(L"/at-spi/")) return L"atspi";
    if (ends(L"/system_bus_socket") || ends(L"/system_bus")) return L"dbus_system";   /* the bus, or monfilter's proxy */
    if (ends(L"/bus") || has(L"/dbus-")) return L"dbus_session";
    if (ends(L"/pulse/native")) return L"pulse";
    if (has(L"/pipewire-")) return L"pipewire";
    if (has(L"/wayland-")) return L"wayland";
    return {};
}

namespace {

/* Word Index of a space-separated table, or "" past its end. */
std::wstring UnixWord(const char* table, uint32_t index)
{
    std::istringstream in(table);
    std::string word;
    for (uint32_t at = 0; in >> word; at++) {
        if (at == index) return std::wstring(word.begin(), word.end());
    }
    return {};
}

/* X11 core requests 1-119 and 127 (xproto). */
const char* const kX11Requests =
    "- CreateWindow ChangeWindowAttributes GetWindowAttributes DestroyWindow DestroySubwindows ChangeSaveSet ReparentWindow "
    "MapWindow MapSubwindows UnmapWindow UnmapSubwindows ConfigureWindow CirculateWindow GetGeometry QueryTree InternAtom "
    "GetAtomName ChangeProperty DeleteProperty GetProperty ListProperties SetSelectionOwner GetSelectionOwner "
    "ConvertSelection SendEvent GrabPointer UngrabPointer GrabButton UngrabButton ChangeActivePointerGrab GrabKeyboard "
    "UngrabKeyboard GrabKey UngrabKey AllowEvents GrabServer UngrabServer QueryPointer GetMotionEvents TranslateCoordinates "
    "WarpPointer SetInputFocus GetInputFocus QueryKeymap OpenFont CloseFont QueryFont QueryTextExtents ListFonts "
    "ListFontsWithInfo SetFontPath GetFontPath CreatePixmap FreePixmap CreateGC ChangeGC CopyGC SetDashes SetClipRectangles "
    "FreeGC ClearArea CopyArea CopyPlane PolyPoint PolyLine PolySegment PolyRectangle PolyArc FillPoly PolyFillRectangle "
    "PolyFillArc PutImage GetImage PolyText8 PolyText16 ImageText8 ImageText16 CreateColormap FreeColormap "
    "CopyColormapAndFree InstallColormap UninstallColormap ListInstalledColormaps AllocColor AllocNamedColor AllocColorCells "
    "AllocColorPlanes FreeColors StoreColors StoreNamedColor QueryColors LookupColor CreateCursor CreateGlyphCursor "
    "FreeCursor RecolorCursor QueryBestSize QueryExtension ListExtensions ChangeKeyboardMapping GetKeyboardMapping "
    "ChangeKeyboardControl GetKeyboardControl Bell ChangePointerControl GetPointerControl SetScreenSaver GetScreenSaver "
    "ChangeHosts ListHosts SetAccessControl SetCloseDownMode KillClient RotateProperties ForceScreenSaver SetPointerMapping "
    "GetPointerMapping SetModifierMapping GetModifierMapping - - - - - - - NoOperation";
/* X11 extensions a display's table asks for, and their requests by minor opcode ("" past what is named here: the
 * extension and the number). */
const struct {
    const char* name;
    const char* requests;
} kX11Extensions[] = {
    {"BIG-REQUESTS", "Enable"},
    {"XC-MISC", "GetVersion GetXIDRange GetXIDList"},
    {"XTEST", "GetVersion CompareCursor FakeInput GrabControl"},
    {"RECORD", "QueryVersion CreateContext RegisterClients UnregisterClients GetContext EnableContext DisableContext "
               "FreeContext"},
    {"X-Resource", "QueryVersion QueryClients QueryClientResources QueryClientPixmapBytes QueryClientIds QueryResourceBytes"},
    {"MIT-SHM", "QueryVersion Attach Detach PutImage GetImage CreatePixmap AttachFd CreateSegment"},
    {"Composite", "QueryVersion RedirectWindow RedirectSubwindows UnredirectWindow UnredirectSubwindows "
                  "CreateRegionFromBorderClip NameWindowPixmap GetOverlayWindow ReleaseOverlayWindow"},
    {"DRI3", "QueryVersion Open PixmapFromBuffer BufferFromPixmap FenceFromFD FDFromFence GetSupportedModifiers "
             "PixmapFromBuffers BuffersFromPixmap SetDRMDeviceInUse ImportSyncobj FreeSyncobj"},
    {"Present", "QueryVersion Pixmap NotifyMSC SelectInput QueryCapabilities PixmapSynced"},
    {"DAMAGE", "QueryVersion Create Destroy Subtract Add"},
    {"XFIXES", "QueryVersion ChangeSaveSet SelectSelectionInput SelectCursorInput GetCursorImage CreateRegion "
               "CreateRegionFromBitmap CreateRegionFromWindow CreateRegionFromGC CreateRegionFromPicture DestroyRegion "
               "SetRegion CopyRegion UnionRegion IntersectRegion SubtractRegion InvertRegion TranslateRegion RegionExtents "
               "FetchRegion SetGCClipRegion SetWindowShapeRegion SetPictureClipRegion SetCursorName GetCursorName "
               "GetCursorImageAndName ChangeCursor ChangeCursorByName ExpandRegion HideCursor ShowCursor "
               "CreatePointerBarrier DeletePointerBarrier SetClientDisconnectMode GetClientDisconnectMode"},
    {"XInputExtension", "- GetExtensionVersion ListInputDevices OpenDevice CloseDevice SetDeviceMode SelectExtensionEvent "
                        "GetSelectedExtensionEvents ChangeDeviceDontPropagateList GetDeviceDontPropagateList "
                        "GetDeviceMotionEvents ChangeKeyboardDevice ChangePointerDevice GrabDevice UngrabDevice "
                        "GrabDeviceKey UngrabDeviceKey GrabDeviceButton UngrabDeviceButton AllowDeviceEvents "
                        "GetDeviceFocus SetDeviceFocus GetFeedbackControl ChangeFeedbackControl GetDeviceKeyMapping "
                        "ChangeDeviceKeyMapping GetDeviceModifierMapping SetDeviceModifierMapping GetDeviceButtonMapping "
                        "SetDeviceButtonMapping QueryDeviceState SendExtensionEvent DeviceBell SetDeviceValuators "
                        "GetDeviceControl ChangeDeviceControl ListDeviceProperties ChangeDeviceProperty "
                        "DeleteDeviceProperty GetDeviceProperty XIQueryPointer XIWarpPointer XIChangeCursor "
                        "XIChangeHierarchy XISetClientPointer XIGetClientPointer XISelectEvents XIQueryVersion "
                        "XIQueryDevice XISetFocus XIGetFocus XIGrabDevice XIUngrabDevice XIAllowEvents "
                        "XIPassiveGrabDevice XIPassiveUngrabDevice XIListProperties XIChangeProperty XIDeleteProperty "
                        "XIGetProperty XIGetSelectedEvents XIBarrierReleasePointer"},
    {"SYNC", ""}, {"RANDR", ""}, {"RENDER", ""}, {"SHAPE", ""}, {"XKEYBOARD", ""}, {"GLX", ""}, {"DRI2", ""},
    {"XVideo", ""}, {"XINERAMA", ""}, {"SECURITY", ""}, {"MIT-SCREEN-SAVER", ""}, {"DPMS", ""},
    {"Generic Event Extension", ""}, {"DOUBLE-BUFFER", ""}, {"XFree86-VidModeExtension", ""}, {"XFree86-DGA", ""},
};
/* Core events 2-35 and errors 1-17 (xproto); XInputExtension's and Present's GenericEvent types. */
const char* const kX11Events =
    "- - KeyPress KeyRelease ButtonPress ButtonRelease MotionNotify EnterNotify LeaveNotify FocusIn FocusOut KeymapNotify "
    "Expose GraphicsExpose NoExpose VisibilityNotify CreateNotify DestroyNotify UnmapNotify MapNotify MapRequest "
    "ReparentNotify ConfigureNotify ConfigureRequest GravityNotify ResizeRequest CirculateNotify CirculateRequest "
    "PropertyNotify SelectionClear SelectionRequest SelectionNotify ColormapNotify ClientMessage MappingNotify GenericEvent";
const char* const kX11Errors =
    "- Request Value Window Pixmap Atom Cursor Font Match Drawable Access Alloc Colormap GContext IDChoice Name Length "
    "Implementation";
const char* const kXiEvents =
    "- DeviceChanged KeyPress KeyRelease ButtonPress ButtonRelease Motion Enter Leave FocusIn FocusOut HierarchyChanged "
    "PropertyEvent RawKeyPress RawKeyRelease RawButtonPress RawButtonRelease RawMotion TouchBegin TouchUpdate TouchEnd "
    "TouchOwnership RawTouchBegin RawTouchUpdate RawTouchEnd BarrierHit BarrierLeave";
const char* const kPresentEvents = "ConfigureNotify CompleteNotify IdleNotify RedirectNotify";
constexpr uint32_t kX11SentEvent = 0x800000;   /* unix_bpf.h MM_UNIX_X11_SENT: a SendEvent's */

/* PulseAudio native protocol commands (pulsecore/native-common.h). */
const char* const kPulseCommands =
    "ERROR TIMEOUT REPLY CREATE_PLAYBACK_STREAM DELETE_PLAYBACK_STREAM CREATE_RECORD_STREAM DELETE_RECORD_STREAM EXIT AUTH "
    "SET_CLIENT_NAME LOOKUP_SINK LOOKUP_SOURCE DRAIN_PLAYBACK_STREAM STAT GET_PLAYBACK_LATENCY CREATE_UPLOAD_STREAM "
    "DELETE_UPLOAD_STREAM FINISH_UPLOAD_STREAM PLAY_SAMPLE REMOVE_SAMPLE GET_SERVER_INFO GET_SINK_INFO GET_SINK_INFO_LIST "
    "GET_SOURCE_INFO GET_SOURCE_INFO_LIST GET_MODULE_INFO GET_MODULE_INFO_LIST GET_CLIENT_INFO GET_CLIENT_INFO_LIST "
    "GET_SINK_INPUT_INFO GET_SINK_INPUT_INFO_LIST GET_SOURCE_OUTPUT_INFO GET_SOURCE_OUTPUT_INFO_LIST GET_SAMPLE_INFO "
    "GET_SAMPLE_INFO_LIST SUBSCRIBE SET_SINK_VOLUME SET_SINK_INPUT_VOLUME SET_SOURCE_VOLUME SET_SINK_MUTE SET_SOURCE_MUTE "
    "CORK_PLAYBACK_STREAM FLUSH_PLAYBACK_STREAM TRIGGER_PLAYBACK_STREAM SET_DEFAULT_SINK SET_DEFAULT_SOURCE "
    "SET_PLAYBACK_STREAM_NAME SET_RECORD_STREAM_NAME KILL_CLIENT KILL_SINK_INPUT KILL_SOURCE_OUTPUT LOAD_MODULE "
    "UNLOAD_MODULE ADD_AUTOLOAD REMOVE_AUTOLOAD GET_AUTOLOAD_INFO GET_AUTOLOAD_INFO_LIST GET_RECORD_LATENCY "
    "CORK_RECORD_STREAM FLUSH_RECORD_STREAM PREBUF_PLAYBACK_STREAM REQUEST OVERFLOW UNDERFLOW PLAYBACK_STREAM_KILLED "
    "RECORD_STREAM_KILLED SUBSCRIBE_EVENT MOVE_SINK_INPUT MOVE_SOURCE_OUTPUT SET_SINK_INPUT_MUTE SUSPEND_SINK "
    "SUSPEND_SOURCE SET_PLAYBACK_STREAM_BUFFER_ATTR SET_RECORD_STREAM_BUFFER_ATTR UPDATE_PLAYBACK_STREAM_SAMPLE_RATE "
    "UPDATE_RECORD_STREAM_SAMPLE_RATE PLAYBACK_STREAM_SUSPENDED RECORD_STREAM_SUSPENDED PLAYBACK_STREAM_MOVED "
    "RECORD_STREAM_MOVED UPDATE_RECORD_STREAM_PROPLIST UPDATE_PLAYBACK_STREAM_PROPLIST UPDATE_CLIENT_PROPLIST "
    "REMOVE_RECORD_STREAM_PROPLIST REMOVE_PLAYBACK_STREAM_PROPLIST REMOVE_CLIENT_PROPLIST STARTED EXTENSION GET_CARD_INFO "
    "GET_CARD_INFO_LIST SET_CARD_PROFILE CLIENT_EVENT PLAYBACK_STREAM_EVENT RECORD_STREAM_EVENT "
    "PLAYBACK_BUFFER_ATTR_CHANGED RECORD_BUFFER_ATTR_CHANGED SET_SINK_PORT SET_SOURCE_PORT SET_SOURCE_OUTPUT_VOLUME "
    "SET_SOURCE_OUTPUT_MUTE SET_PORT_LATENCY_OFFSET ENABLE_SRBCHANNEL DISABLE_SRBCHANNEL REGISTER_MEMFD_SHMID "
    "SEND_OBJECT_MESSAGE";

uint32_t Read32(const uint8_t* bytes, bool big)
{
    return big ? (uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 | bytes[3])
               : (uint32_t(bytes[3]) << 24 | uint32_t(bytes[2]) << 16 | uint32_t(bytes[1]) << 8 | bytes[0]);
}

std::wstring Narrow8(const uint8_t* bytes, size_t size)
{
    std::wstring text;
    for (size_t index = 0; index < size && bytes[index]; index++) text += static_cast<wchar_t>(bytes[index]);
    return text;
}

}  // namespace

namespace {

std::wstring Wide(const std::string& text)
{
    return std::wstring(text.begin(), text.end());
}

std::wstring HexText(uint64_t value)
{
    wchar_t text[24];
    swprintf(text, 24, L"0x%llx", static_cast<unsigned long long>(value));
    return text;
}

const X11Extension* X11Major(uint32_t major, const X11Extensions& extensions)
{
    for (const X11Extension& extension : extensions) {
        if (extension.major == major) return &extension;
    }
    return nullptr;
}

/* The extension whose event (or error) range holds Code: the greatest first code at or below it. */
const X11Extension* X11Range(uint32_t code, const X11Extensions& extensions, bool error)
{
    const X11Extension* found = nullptr;
    for (const X11Extension& extension : extensions) {
        const uint8_t first = error ? extension.firstError : extension.firstEvent;
        if (first != 0 && first <= code && (!found || first > (error ? found->firstError : found->firstEvent))) found = &extension;
    }
    return found;
}

std::wstring X11Minor(const std::string& extension, uint32_t minor)
{
    for (const auto& known : kX11Extensions) {
        if (extension == known.name) {
            const std::wstring name = UnixWord(known.requests, minor);
            return name.empty() || name == L"-" ? std::to_wstring(minor) : name;
        }
    }
    return std::to_wstring(minor);
}

const wchar_t* X11InputType(uint32_t type)
{
    switch (type) {
    case 2: return L"KeyPress";
    case 3: return L"KeyRelease";
    case 4: return L"ButtonPress";
    case 5: return L"ButtonRelease";
    case 6: return L"MotionNotify";
    default: return L"other";
    }
}

}  // namespace

const std::vector<std::string>& X11ExtensionNames()
{
    static const std::vector<std::string> names = [] {
        std::vector<std::string> list;
        for (const auto& known : kX11Extensions) list.emplace_back(known.name);
        return list;
    }();
    return names;
}

std::wstring X11RequestName(uint32_t op, const X11Extensions& extensions)
{
    const uint32_t major = (op >> 8) & 0xff, minor = op & 0xff;
    if (major < 128) {
        const std::wstring name = UnixWord(kX11Requests, major);
        return name.empty() || name == L"-" ? L"request" + std::to_wstring(major) : name;
    }
    const X11Extension* extension = X11Major(major, extensions);
    if (!extension) return L"ext" + std::to_wstring(major) + L"." + std::to_wstring(minor);
    return Wide(extension->name) + L"." + X11Minor(extension->name, minor);
}

std::pair<std::wstring, std::wstring> X11Request(const uint8_t* b, size_t size, bool big, const X11Extensions& extensions,
                                                 bool realInput)
{
    if (size < 4) return {};
    const uint32_t major = b[0], minor = b[1];
    const std::wstring name = X11RequestName(major << 8 | (major >= 128 ? minor : 0), extensions);
    auto u16 = [&](size_t at) { return at + 2 <= size ? (big ? b[at] << 8 | b[at + 1] : b[at + 1] << 8 | b[at]) : 0u; };
    auto u32 = [&](size_t at) { return at + 4 <= size ? Read32(b + at, big) : 0u; };
    auto i16 = [&](size_t at) { return std::to_wstring(static_cast<int16_t>(u16(at))); };
    auto id = [&](const wchar_t* field, size_t at) { return std::wstring(L";") + field + L"=" + HexText(u32(at)); };
    auto text = [&](size_t length, size_t at) { return Narrow8(b + std::min(at, size), std::min(length, size - std::min(at, size))); };
    auto area = [&](size_t at) { return L";x=" + i16(at) + L";y=" + i16(at + 2) + L";width=" + std::to_wstring(u16(at + 4)) +
                                        L";height=" + std::to_wstring(u16(at + 6)); };
    std::wstring extra;
    if (major < 128) {
        switch (major) {
        case 16: extra = L";name=" + text(u16(4), 8); break;                                    /* InternAtom */
        case 98: extra = L";extension=" + text(u16(4), 8); break;                               /* QueryExtension */
        case 18:                                                                                  /* ChangeProperty */
            extra = id(L"window", 4) + id(L"property", 8) + id(L"type", 12) + L";format=" + std::to_wstring(size > 16 ? b[16] : 0) +
                    L";length=" + std::to_wstring(u32(20));
            break;
        case 19: extra = id(L"window", 4) + id(L"property", 8); break;                          /* DeleteProperty */
        case 20:                                                                                  /* GetProperty */
            extra = id(L"window", 4) + id(L"property", 8) + id(L"type", 12) + L";offset=" + std::to_wstring(u32(16)) +
                    L";length=" + std::to_wstring(u32(20));
            break;
        case 22: extra = id(L"owner", 4) + id(L"selection", 8); break;                          /* SetSelectionOwner */
        case 23: extra = id(L"selection", 4); break;                                            /* GetSelectionOwner */
        case 24: extra = id(L"requestor", 4) + id(L"selection", 8) + id(L"target", 12) + id(L"property", 16); break;
        case 25: {                                                                                /* SendEvent */
            const uint32_t type = size > 12 ? b[12] & 0x7f : 0;
            const std::wstring event = UnixWord(kX11Events, type);
            extra = id(L"destination", 4) + L";event=" + (event.empty() || event == L"-" ? std::to_wstring(type) : event) +
                    ((type == 2 || type == 3) && !realInput ? L";input=withheld" : (type == 2 || type == 3) && size > 13
                                                                                        ? L";detail=" + std::to_wstring(b[13])
                                                                                        : L"");
            break;
        }
        case 40: extra = id(L"window", 4) + id(L"to", 8); break;                                /* TranslateCoordinates */
        case 41: extra = id(L"window", 8) + L";x=" + i16(20) + L";y=" + i16(22); break;        /* WarpPointer */
        case 42: extra = id(L"focus", 4); break;                                                /* SetInputFocus */
        case 33:                                                                                  /* GrabKey */
            extra = id(L"window", 4) + L";modifiers=" + HexText(u16(8)) + L";key=" + std::to_wstring(size > 10 ? b[10] : 0);
            break;
        case 73: extra = id(L"drawable", 4) + area(8); break;                                   /* GetImage */
        case 113: extra = id(L"resource", 4); break;                                            /* KillClient */
        case 1: extra = id(L"window", 4) + id(L"parent", 8); break;                             /* CreateWindow */
        case 2: case 3: case 4: case 5: case 8: case 10: case 12: case 14: case 15: case 21: case 26: case 28: case 31:
        case 38:
            extra = id(major == 14 ? L"drawable" : L"window", 4);   /* window requests, grabs, QueryTree, QueryPointer */
            break;
        default: break;
        }
        return {name, extra};
    }
    const X11Extension* extension = X11Major(major, extensions);
    const std::string ext = extension ? extension->name : std::string();
    if (ext == "XTEST" && minor == 2) {   /* FakeInput: type, detail, time, root, rootX, rootY */
        const uint32_t type = size > 4 ? b[4] : 0;
        extra = std::wstring(L";type=") + X11InputType(type) + id(L"root", 12) + L";x=" + i16(24) + L";y=" + i16(26) +
                (type >= 2 && type <= 5 && !realInput ? L";input=withheld" : L";detail=" + std::to_wstring(size > 5 ? b[5] : 0));
    } else if (ext == "MIT-SHM" && (minor == 3 || minor == 4)) {   /* PutImage, GetImage */
        extra = id(L"drawable", 4) + (minor == 4 ? area(8) : L"");
    } else if (ext == "Composite" && minor == 5) {   /* CreateRegionFromBorderClip: the region made, the window */
        extra = id(L"region", 4) + id(L"window", 8);
    } else if (ext == "Composite" && minor >= 1 && minor <= 7) {
        extra = id(L"window", 4) + (minor == 6 ? id(L"pixmap", 8) : L"");
    } else if (ext == "X-Resource" && minor == 4) {   /* QueryClientIds: specs (client, mask) */
        const uint32_t count = u32(4);
        extra = L";specs=" + std::to_wstring(count) + L";clients=";
        for (uint32_t index = 0; index < count && index < 16 && 8 + index * 8 + 4 <= size; index++)
            extra += (index ? L"," : L"") + HexText(u32(8 + index * 8));
    } else if (ext == "X-Resource" && (minor == 2 || minor == 3)) {
        extra = id(L"client", 4);
    } else if (ext == "RECORD" && (minor == 1 || minor == 2)) {   /* CreateContext, RegisterClients */
        extra = id(L"context", 4) + L";clients=" + std::to_wstring(u32(12)) + L";ranges=" + std::to_wstring(u32(16));
    } else if (ext == "RECORD" && minor >= 3) {
        extra = id(L"context", 4);
    } else if (ext == "DRI3" && minor >= 1 && minor <= 3) {
        extra = id(minor == 1 ? L"drawable" : L"pixmap", 4);
    } else if (ext == "Present" && minor == 1) {
        extra = id(L"window", 4) + id(L"pixmap", 8);
    } else if (ext == "XInputExtension" && (minor == 40 || minor == 46 || minor == 49 || minor == 51)) {
        extra = id(L"window", 4);   /* XIQueryPointer, XISelectEvents, XISetFocus, XIGrabDevice */
    } else if (ext == "XInputExtension" && minor == 54) {   /* XIPassiveGrabDevice: time, then its window */
        extra = id(L"window", 8);
    } else if (ext == "XInputExtension" && minor == 41) {   /* XIWarpPointer: dst_win, then src x/y/w/h, FP16.16 destination */
        extra = id(L"window", 8) + L";x=" + std::to_wstring(static_cast<int32_t>(u32(24)) >> 16) + L";y=" +
                std::to_wstring(static_cast<int32_t>(u32(28)) >> 16);
    } else if (ext == "XFIXES" && minor == 2) {   /* SelectSelectionInput */
        extra = id(L"window", 4) + id(L"selection", 8);
    }
    return {name, extra};
}

std::wstring X11ReceivedName(uint32_t op, const X11Extensions& extensions)
{
    const uint32_t type = op >> 24;
    if (type == 1) return L"reply";
    if (type == 0) {
        const uint32_t code = (op >> 16) & 0xff, major = (op >> 8) & 0xff;
        std::wstring error = code < 18 ? UnixWord(kX11Errors, code) : std::wstring();
        if (error.empty() || error == L"-") {
            const X11Extension* extension = X11Range(code, extensions, true);
            error = extension ? Wide(extension->name) + L".error" + std::to_wstring(code - extension->firstError)
                              : L"error" + std::to_wstring(code);
        }
        return L"error:" + error + L":" + X11RequestName(major << 8 | (major >= 128 ? (op & 0xff) : 0), extensions);
    }
    std::wstring event;
    if (type == 35) {   /* GenericEvent: its extension and type */
        const X11Extension* extension = X11Major((op >> 8) & 0xff, extensions);
        const uint32_t evtype = op & 0xff;
        const std::string ext = extension ? extension->name : std::string();
        std::wstring named = ext == "XInputExtension" ? UnixWord(kXiEvents, evtype) : ext == "Present" ? UnixWord(kPresentEvents, evtype)
                                                                                                        : std::wstring();
        event = (ext.empty() ? L"ext" + std::to_wstring((op >> 8) & 0xff) : Wide(ext)) + L"." +
                (named.empty() || named == L"-" ? std::to_wstring(evtype) : named);
    } else if (type < 35) {
        event = UnixWord(kX11Events, type);
    } else {
        const X11Extension* extension = X11Range(type, extensions, false);
        event = extension ? Wide(extension->name) + L".event" + std::to_wstring(type - extension->firstEvent)
                          : L"event" + std::to_wstring(type);
    }
    return ((op & kX11SentEvent) ? L"sent_event:" : L"event:") + event;
}

std::wstring PulseCommandName(uint32_t command)
{
    if (command == 0xffff) return L"memblock";
    if (command == 0xfffe) return L"other";
    const std::wstring name = UnixWord(kPulseCommands, command);
    return name.empty() ? L"COMMAND_" + std::to_wstring(command) : name;
}

std::wstring DbusTypeName(uint32_t type)
{
    static const wchar_t* const names[] = {L"sasl", L"method_call", L"method_return", L"error", L"signal"};
    return type < std::size(names) ? names[type] : L"type" + std::to_wstring(type);
}

namespace {
/* A D-Bus message's start: endianness, type (1 call, 2 return, 3 error, 4 signal), flags, version 1. */
bool DbusStart(const uint8_t* m, size_t size)
{
    return size >= 16 && (m[0] == 'l' || m[0] == 'B') && m[1] >= 1 && m[1] <= 4 && m[3] == 1;
}
}  // namespace

std::pair<std::wstring, std::wstring> DbusMessage(const uint8_t* m, size_t size)
{
    if (!DbusStart(m, size)) return {};
    /* After the 16-byte header (body length, serial, fields' length) an array of (code, variant) fields, each 8-aligned:
     * 1 path, 2 interface, 3 member, 4 error name, 5 reply serial, 6 destination, 7 sender. */
    const bool big = m[0] == 'B';
    const uint64_t fields = Read32(m + 12, big);
    const size_t end = static_cast<size_t>(std::min<uint64_t>(size, 16 + fields));
    std::wstring text[8];
    uint32_t replySerial = 0;
    for (size_t f = 16; f + 4 <= end;) {
        const uint8_t code = m[f], length = m[f + 1];
        if (f + 3 + length > end) break;
        const uint8_t type = m[f + 2];
        f += 3 + length;   /* code, signature length, signature, NUL */
        if (type == 's' || type == 'o') {
            f = (f + 3) & ~size_t(3);
            if (f + 4 > end) break;
            const size_t n = Read32(m + f, big);
            if (code < 8) text[code] = Narrow8(m + f + 4, std::min(n, end - f - 4));
            f += 4 + n + 1;
        } else if (type == 'g') {
            if (f >= end) break;
            f += 2 + m[f];
        } else if (type == 'u' || type == 'h') {
            f = (f + 3) & ~size_t(3);
            if (f + 4 > end) break;
            if (code == 5) replySerial = Read32(m + f, big);
            f += 4;
        } else {
            break;
        }
        f = (f + 7) & ~size_t(7);
    }
    const std::wstring sender = (text[7].empty() ? L"" : L";sender=" + text[7]) + (end < 16 + fields ? L";fields_cut=1" : L"");
    if (m[1] == 2) return {L"method_return", L";reply_serial=" + std::to_wstring(replySerial) + sender};
    if (m[1] == 3) return {L"error:" + text[4], L";reply_serial=" + std::to_wstring(replySerial) + sender};
    return {text[3].empty() ? DbusTypeName(m[1]) : (text[2].empty() ? L"" : text[2] + L".") + text[3],
            (m[1] == 4 ? L";message=signal" : L"") + (text[6].empty() ? L"" : L";destination=" + text[6]) +
                (text[1].empty() ? L"" : L";path=" + text[1]) + L";serial=" + std::to_wstring(Read32(m + 8, big)) + sender};
}

std::vector<std::pair<std::wstring, std::wstring>> DbusMessages(const uint8_t* b, size_t size)
{
    std::vector<std::pair<std::wstring, std::wstring>> out;
    /* The SASL handshake (text lines after a NUL credentials byte): skipped up to and with BEGIN. */
    size_t at = size != 0 && b[0] == 0 ? 1 : 0;
    while (at < size && b[at] >= 'A' && b[at] <= 'Z' && !DbusStart(b + at, size - at)) {
        const uint8_t* line = b + at;
        const uint8_t* end = static_cast<const uint8_t*>(memchr(line, '\n', size - at));
        if (!end) return out;
        at = end - b + 1;
        if (end - line >= 5 && std::memcmp(line, "BEGIN", 5) == 0) break;
    }
    while (DbusStart(b + at, size - at)) {
        const uint8_t* m = b + at;
        const bool big = m[0] == 'B';
        const uint64_t total = 16 + ((uint64_t(Read32(m + 12, big)) + 7) & ~7ull) + Read32(m + 4, big);
        out.push_back(DbusMessage(m, size - at));
        if (total > size - at) break;
        at += static_cast<size_t>(total);
    }
    return out;
}
