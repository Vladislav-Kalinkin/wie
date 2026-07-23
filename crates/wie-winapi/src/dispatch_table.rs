//! Auto-generated dense WinAPI id dispatch.
//! Regenerate: `python3 scripts/gen_winapi_dispatch.py`
//! Source of truth for handler bodies: historical match arms (kept here as id match).

use crate::{
    WinApiEnvironment, WinApiHandlerResult, WinApiState, advapi32, comctl32, comdlg32, d3d9, gdi32,
    kernel32, user32, uxtheme, winmm,
};
use anyhow::{Result, bail};

/// Dense handler identifier. Resolved once when building the fake-API table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum WinApiId {
    Kernel32Getversionexa = 0,
    Kernel32Getmodulehandlea = 1,
    Kernel32Getcommandlinea = 2,
    Kernel32Getcommandlinew = 3,
    Kernel32Getstartupinfoa = 4,
    Kernel32Getprocessheap = 5,
    Kernel32Getsystemtimeasfiletime = 6,
    Kernel32Getcurrentprocessid = 7,
    Kernel32Getcurrentthreadid = 8,
    Kernel32Gettickcount = 9,
    Kernel32Queryperformancecounter = 10,
    Kernel32Heapalloc = 11,
    Kernel32Heapfree = 12,
    Kernel32Heaprealloc = 13,
    Kernel32Heapcreate = 14,
    Kernel32Heapsetinformation = 15,
    Kernel32Initializecriticalsection = 16,
    Kernel32Entercriticalsection = 17,
    Kernel32Leavecriticalsection = 18,
    Kernel32Deletecriticalsection = 19,
    Kernel32Flsalloc = 20,
    Kernel32Flsfree = 21,
    Kernel32Flssetvalue = 22,
    Kernel32Flsgetvalue = 23,
    Kernel32Getstdhandle = 24,
    Kernel32Getfiletype = 25,
    Kernel32Sethandlecount = 26,
    Kernel32Getenvironmentstringsw = 27,
    Kernel32Freeenvironmentstringsw = 28,
    Kernel32Widechartomultibyte = 29,
    Kernel32Getlasterror = 30,
    Kernel32Setlasterror = 31,
    Kernel32Getacp = 32,
    Kernel32Getoemcp = 33,
    Kernel32Getcpinfo = 34,
    Kernel32Isvalidcodepage = 35,
    Kernel32Getstringtypew = 36,
    Kernel32Multibytetowidechar = 37,
    Kernel32Lcmapstringw = 38,
    Kernel32Getmodulefilenamea = 39,
    Kernel32Getmodulefilenamew = 40,
    Kernel32Setunhandledexceptionfilter = 41,
    Kernel32Heapsize = 42,
    Advapi32Regcreatekeyexa = 43,
    Advapi32Regopenkeyexa = 44,
    Advapi32Regqueryvalueexa = 45,
    Advapi32Regqueryvalueexw = 46,
    Advapi32Regsetvalueexa = 47,
    Advapi32Regsetvalueexw = 48,
    Advapi32Regdeletevaluea = 49,
    Advapi32Regclosekey = 50,
    Advapi32Initializesecuritydescriptor = 51,
    Advapi32Setsecuritydescriptordacl = 52,
    Kernel32Loadlibrarya = 53,
    Kernel32Loadlibraryw = 54,
    Kernel32Freelibrary = 55,
    Kernel32Getprocaddress = 56,
    Kernel32Getfileattributesa = 57,
    Kernel32Getfileattributesw = 58,
    Kernel32Findfirstfilew = 59,
    Kernel32Findfirstfilea = 60,
    Kernel32Findnextfilew = 61,
    Kernel32Findnextfilea = 62,
    Kernel32Findclose = 63,
    User32Getasynckeystate = 64,
    User32Peekmessagea = 65,
    Kernel32Loadlibraryexa = 66,
    Kernel32Loadlibraryexw = 67,
    Kernel32Findresourcea = 68,
    Kernel32Loadresource = 69,
    Kernel32Lockresource = 70,
    Kernel32Sizeofresource = 71,
    Kernel32Getsystemdefaultlangid = 72,
    Kernel32Getuserdefaultlangid = 73,
    Kernel32Globalmemorystatus = 74,
    Kernel32Getlocaltime = 75,
    User32Loadicona = 76,
    User32Loadcursora = 77,
    User32Registerclassexw = 78,
    User32Registerclassexa = 79,
    Kernel32Createfilew = 80,
    Kernel32Createfilea = 81,
    Kernel32Closehandle = 82,
    User32Messageboxw = 83,
    User32Messageboxa = 84,
    Kernel32Getfileinformationbyhandle = 85,
    Kernel32Filetimetolocalfiletime = 86,
    Kernel32Filetimetosystemtime = 87,
    Kernel32Gettimezoneinformation = 88,
    Kernel32Getfiletime = 89,
    Kernel32Setfilepointer = 90,
    Kernel32Getfilesize = 91,
    Kernel32Encodepointer = 92,
    Kernel32Decodepointer = 93,
    Kernel32Initializecriticalsectionandspincount = 94,
    User32Setprocessdpiaware = 95,
    User32Trackmouseevent = 96,
    Comctl32Dllgetversion = 97,
    Kernel32Readfile = 98,
    Kernel32Writefile = 99,
    User32Getcursorpos = 100,
    User32Getsystemmetrics = 101,
    User32Monitorfromwindow = 102,
    User32Getmonitorinfoa = 103,
    User32Getmonitorinfow = 104,
    User32Enumdisplaymonitors = 105,
    User32Enumdisplaydevicesa = 106,
    User32Enumdisplaydevicesw = 107,
    User32Monitorfrompoint = 108,
    Comctl32Ordinal17 = 111,
    User32Getwindowrect = 112,
    User32Getdpiforwindow = 113,
    User32Postmessagea = 114,
    User32Getsystemmetricsfordpi = 115,
    User32Adjustwindowrectexfordpi = 116,
    User32Setwindowpos = 117,
    User32Setscrollinfo = 118,
    User32Scrollwindowex = 119,
    User32Scrolldc = 120,
    User32Beginpaint = 121,
    User32Endpaint = 122,
    User32Clipcursor = 123,
    User32Getclipcursor = 124,
    User32Callmsgfiltera = 125,
    User32Callmsgfilterw = 126,
    User32Getdc = 127,
    User32Sendmessagea = 128,
    User32Sendmessagew = 129,
    Comdlg32Getopenfilenamea = 130,
    Comdlg32Getopenfilenamew = 131,
    Comdlg32Getsavefilenamea = 132,
    Comdlg32Getsavefilenamew = 133,
    Comdlg32Commdlgextendederror = 134,
    Comdlg32Choosecolora = 135,
    Gdi32Selectobject = 136,
    Gdi32Gettextextentpoint32a = 137,
    Gdi32Gettextextentpoint32w = 138,
    Gdi32Exttextoutw = 139,
    User32Releasedc = 140,
    Kernel32Getcurrentdirectoryw = 141,
    Kernel32Setcurrentdirectoryw = 142,
    User32Loadimagea = 143,
    User32Loadimagew = 144,
    Comctl32Initcommoncontrolsex = 145,
    UxthemeSetwindowtheme = 146,
    User32Setwindowlongptrw = 147,
    User32Getwindowlongptra = 148,
    User32Getwindowlongptrw = 149,
    Gdi32Getobjecta = 150,
    Comctl32ImagelistCreate = 151,
    Gdi32Createcompatibledc = 152,
    Gdi32Createdibsection = 153,
    Gdi32Createcompatiblebitmap = 154,
    Gdi32Getdevicecaps = 155,
    Gdi32Createfonta = 156,
    Gdi32Createfontw = 157,
    Gdi32Createfontindirecta = 158,
    Gdi32Gettextmetricsa = 159,
    Gdi32Settextcolor = 160,
    Gdi32Setbkcolor = 161,
    Gdi32Setbkmode = 162,
    Gdi32Textouta = 163,
    Gdi32Bitblt = 164,
    Gdi32Stretchblt = 165,
    Gdi32Patblt = 166,
    Gdi32Getpixel = 167,
    Gdi32Deletedc = 168,
    Comctl32ImagelistAddmasked = 169,
    Comctl32ImagelistSetbkcolor = 170,
    Comctl32ImagelistDestroy = 171,
    Gdi32Deleteobject = 172,
    User32Destroyicon = 173,
    User32Iswindow = 174,
    User32Iswindowvisible = 175,
    User32Iswindowenabled = 176,
    User32Getparent = 177,
    User32Getactivewindow = 178,
    User32Getforegroundwindow = 179,
    User32Showwindow = 180,
    User32Enablewindow = 181,
    User32Setforegroundwindow = 182,
    User32Setactivewindow = 183,
    User32Setfocus = 184,
    User32Getfocus = 185,
    User32Setcapture = 186,
    User32Getcapture = 187,
    User32Releasecapture = 188,
    User32Setcursor = 189,
    User32Updatewindow = 190,
    User32Invalidaterect = 191,
    User32Redrawwindow = 192,
    User32Setwindowtexta = 193,
    User32Setwindowtextw = 194,
    User32Getwindowtexta = 195,
    User32Getwindowtextw = 196,
    User32Getclientrect = 197,
    User32Movewindow = 198,
    User32Screentoclient = 199,
    User32Clienttoscreen = 200,
    User32Getdesktopwindow = 201,
    User32Getsyscolor = 202,
    User32Getsyscolorbrush = 203,
    User32Getdialogbaseunits = 204,
    User32Setrect = 205,
    User32Isiconic = 206,
    User32Iszoomed = 207,
    User32Getwindowthreadprocessid = 208,
    User32Getdlgctrlid = 209,
    Kernel32Getcurrentprocess = 210,
    Kernel32Sleep = 211,
    WinmmTimegettime = 212,
    Kernel32Localalloc = 213,
    Kernel32Localfree = 214,
    Kernel32Globalalloc = 215,
    Kernel32Globalfree = 216,
    Kernel32Globallock = 217,
    Kernel32Globalunlock = 218,
    Kernel32Globalsize = 219,
    Kernel32Muldiv = 220,
    User32Getcursor = 221,
    User32Ischild = 222,
    User32Getwindow = 223,
    User32Setkeyboardstate = 224,
    User32Getkeyboardstate = 225,
    User32Getkeystate = 226,
    User32Mapvirtualkeya = 227,
    User32Setwindowlongptra = 228,
    User32Settimer = 229,
    User32Killtimer = 230,
    User32Adjustwindowrectex = 231,
    Kernel32Globaladdatoma = 232,
    Kernel32Globaldeleteatom = 233,
    User32Setwindowshookexw = 234,
    User32Unhookwindowshookex = 235,
    User32Callnexthookex = 236,
    Kernel32Getfullpathnamew = 237,
    D3d9Direct3dcreate9 = 238,
    D3d9Idirect3d9Getadaptercount = 239,
    D3d9Idirect3d9Getadaptermonitor = 240,
    D3d9Idirect3d9Getdevicecaps = 241,
    D3d9Idirect3d9Getadapterdisplaymode = 242,
    D3d9Idirect3d9Createdevice = 243,
    D3d9Idirect3ddevice9Setvertexshader = 244,
    D3d9Idirect3ddevice9Setfvf = 245,
    D3d9Idirect3ddevice9Setrenderstate = 246,
    D3d9Idirect3ddevice9Settexturestagestate = 247,
    D3d9Idirect3ddevice9Setsamplerstate = 248,
    User32Enablemenuitem = 249,
    User32Checkmenuitem = 250,
    User32Getmessagea = 251,
    User32Translatemessage = 252,
    User32Defwindowproca = 253,
    User32Defwindowprocw = 254,
    User32Defframeproca = 255,
    User32Defframeprocw = 256,
    User32Defmdichildproca = 257,
    User32Defmdichildprocw = 258,
    User32Createmenu = 259,
    User32Createpopupmenu = 260,
    User32Appendmenua = 261,
    User32Appendmenuw = 262,
    User32Setmenu = 263,
    User32Destroymenu = 264,
    User32Removemenu = 265,
    User32Deletemenu = 266,
    User32Modifymenua = 267,
    User32Modifymenuw = 268,
    User32Getsystemmenu = 269,
    User32Trackpopupmenu = 270,
    User32Getmenuiteminfoa = 271,
    User32Getmenuiteminfow = 272,
    User32Setmenuiteminfoa = 273,
    User32Setmenuiteminfow = 274,
    User32Checkmenuradioitem = 275,
    User32Dispatchmessagea = 276,
    D3d9Idirect3ddevice9Release = 277,
    D3d9Idirect3d9Release = 278,
    Kernel32Getfullpathnamea = 279,
    Kernel32Getcurrentdirectorya = 280,
    Kernel32Setcurrentdirectorya = 281,
    Kernel32Createdirectoryw = 282,
    Kernel32Createdirectorya = 283,
    Kernel32Removefirectoryw = 284,
    Kernel32Removefirectorya = 285,
    Kernel32Deletefilew = 286,
    Kernel32Deletefilea = 287,
    Kernel32Movefilew = 288,
    Kernel32Movefilea = 289,
    Kernel32Gettemppathw = 290,
    Kernel32Gettemppatha = 291,
    Kernel32Gettempfilenamew = 292,
    Kernel32Gettempfilenamea = 293,
    Kernel32Getdrivetypew = 294,
    Kernel32Getdrivetypea = 295,
    Kernel32Getlogicaldrives = 296,
    Kernel32Getsystemdirectoryw = 297,
    Kernel32Getsystemdirectorya = 298,
    Kernel32Getwindowsdirectoryw = 299,
    Kernel32Getwindowsdirectorya = 300,
    Kernel32Getfilesizeex = 301,
    Kernel32Setfilepointerex = 302,
    Kernel32Setendoffile = 303,
    Kernel32Flushfilebuffers = 304,
}

pub const WINAPI_ID_COUNT: usize = 305;

impl WinApiId {
    /// Discriminant as `u16` (`#[repr(u16)]`).
    #[must_use]
    #[allow(clippy::as_conversions)]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Reconstruct from the dense discriminant (`0 .. WINAPI_ID_COUNT`).
    #[must_use]
    #[allow(clippy::as_conversions, unsafe_code)]
    pub const fn from_u16(raw: u16) -> Option<Self> {
        if (raw as usize) >= WINAPI_ID_COUNT {
            return None;
        }
        // SAFETY: `WinApiId` is `#[repr(u16)]` with contiguous discriminants 0..COUNT.
        Some(unsafe { core::mem::transmute::<u16, Self>(raw) })
    }
}

/// Static (library, name, id) rows for one-time resolution.
static WINAPI_NAME_ROWS: &[(&str, &str, WinApiId)] = &[
    (
        "kernel32.dll",
        "getversionexa",
        WinApiId::Kernel32Getversionexa,
    ),
    (
        "kernel32.dll",
        "getmodulehandlea",
        WinApiId::Kernel32Getmodulehandlea,
    ),
    (
        "kernel32.dll",
        "getcommandlinea",
        WinApiId::Kernel32Getcommandlinea,
    ),
    (
        "kernel32.dll",
        "getcommandlinew",
        WinApiId::Kernel32Getcommandlinew,
    ),
    (
        "kernel32.dll",
        "getstartupinfoa",
        WinApiId::Kernel32Getstartupinfoa,
    ),
    (
        "kernel32.dll",
        "getprocessheap",
        WinApiId::Kernel32Getprocessheap,
    ),
    (
        "kernel32.dll",
        "getsystemtimeasfiletime",
        WinApiId::Kernel32Getsystemtimeasfiletime,
    ),
    (
        "kernel32.dll",
        "getcurrentprocessid",
        WinApiId::Kernel32Getcurrentprocessid,
    ),
    (
        "kernel32.dll",
        "getcurrentthreadid",
        WinApiId::Kernel32Getcurrentthreadid,
    ),
    (
        "kernel32.dll",
        "gettickcount",
        WinApiId::Kernel32Gettickcount,
    ),
    (
        "kernel32.dll",
        "queryperformancecounter",
        WinApiId::Kernel32Queryperformancecounter,
    ),
    ("kernel32.dll", "heapalloc", WinApiId::Kernel32Heapalloc),
    ("kernel32.dll", "heapfree", WinApiId::Kernel32Heapfree),
    ("kernel32.dll", "heaprealloc", WinApiId::Kernel32Heaprealloc),
    ("kernel32.dll", "heapcreate", WinApiId::Kernel32Heapcreate),
    (
        "kernel32.dll",
        "heapsetinformation",
        WinApiId::Kernel32Heapsetinformation,
    ),
    (
        "kernel32.dll",
        "initializecriticalsection",
        WinApiId::Kernel32Initializecriticalsection,
    ),
    (
        "kernel32.dll",
        "entercriticalsection",
        WinApiId::Kernel32Entercriticalsection,
    ),
    (
        "kernel32.dll",
        "leavecriticalsection",
        WinApiId::Kernel32Leavecriticalsection,
    ),
    (
        "kernel32.dll",
        "deletecriticalsection",
        WinApiId::Kernel32Deletecriticalsection,
    ),
    ("kernel32.dll", "flsalloc", WinApiId::Kernel32Flsalloc),
    ("kernel32.dll", "flsfree", WinApiId::Kernel32Flsfree),
    ("kernel32.dll", "flssetvalue", WinApiId::Kernel32Flssetvalue),
    ("kernel32.dll", "flsgetvalue", WinApiId::Kernel32Flsgetvalue),
    (
        "kernel32.dll",
        "getstdhandle",
        WinApiId::Kernel32Getstdhandle,
    ),
    ("kernel32.dll", "getfiletype", WinApiId::Kernel32Getfiletype),
    (
        "kernel32.dll",
        "sethandlecount",
        WinApiId::Kernel32Sethandlecount,
    ),
    (
        "kernel32.dll",
        "getenvironmentstringsw",
        WinApiId::Kernel32Getenvironmentstringsw,
    ),
    (
        "kernel32.dll",
        "freeenvironmentstringsw",
        WinApiId::Kernel32Freeenvironmentstringsw,
    ),
    (
        "kernel32.dll",
        "widechartomultibyte",
        WinApiId::Kernel32Widechartomultibyte,
    ),
    (
        "kernel32.dll",
        "getlasterror",
        WinApiId::Kernel32Getlasterror,
    ),
    (
        "kernel32.dll",
        "setlasterror",
        WinApiId::Kernel32Setlasterror,
    ),
    ("kernel32.dll", "getacp", WinApiId::Kernel32Getacp),
    ("kernel32.dll", "getoemcp", WinApiId::Kernel32Getoemcp),
    ("kernel32.dll", "getcpinfo", WinApiId::Kernel32Getcpinfo),
    (
        "kernel32.dll",
        "isvalidcodepage",
        WinApiId::Kernel32Isvalidcodepage,
    ),
    (
        "kernel32.dll",
        "getstringtypew",
        WinApiId::Kernel32Getstringtypew,
    ),
    (
        "kernel32.dll",
        "multibytetowidechar",
        WinApiId::Kernel32Multibytetowidechar,
    ),
    (
        "kernel32.dll",
        "lcmapstringw",
        WinApiId::Kernel32Lcmapstringw,
    ),
    (
        "kernel32.dll",
        "getmodulefilenamea",
        WinApiId::Kernel32Getmodulefilenamea,
    ),
    (
        "kernel32.dll",
        "getmodulefilenamew",
        WinApiId::Kernel32Getmodulefilenamew,
    ),
    (
        "kernel32.dll",
        "setunhandledexceptionfilter",
        WinApiId::Kernel32Setunhandledexceptionfilter,
    ),
    ("kernel32.dll", "heapsize", WinApiId::Kernel32Heapsize),
    (
        "advapi32.dll",
        "regcreatekeyexa",
        WinApiId::Advapi32Regcreatekeyexa,
    ),
    (
        "advapi32.dll",
        "regopenkeyexa",
        WinApiId::Advapi32Regopenkeyexa,
    ),
    (
        "advapi32.dll",
        "regqueryvalueexa",
        WinApiId::Advapi32Regqueryvalueexa,
    ),
    (
        "advapi32.dll",
        "regqueryvalueexw",
        WinApiId::Advapi32Regqueryvalueexw,
    ),
    (
        "advapi32.dll",
        "regsetvalueexa",
        WinApiId::Advapi32Regsetvalueexa,
    ),
    (
        "advapi32.dll",
        "regsetvalueexw",
        WinApiId::Advapi32Regsetvalueexw,
    ),
    (
        "advapi32.dll",
        "regdeletevaluea",
        WinApiId::Advapi32Regdeletevaluea,
    ),
    ("advapi32.dll", "regclosekey", WinApiId::Advapi32Regclosekey),
    (
        "advapi32.dll",
        "initializesecuritydescriptor",
        WinApiId::Advapi32Initializesecuritydescriptor,
    ),
    (
        "advapi32.dll",
        "setsecuritydescriptordacl",
        WinApiId::Advapi32Setsecuritydescriptordacl,
    ),
    (
        "kernel32.dll",
        "loadlibrarya",
        WinApiId::Kernel32Loadlibrarya,
    ),
    (
        "kernel32.dll",
        "loadlibraryw",
        WinApiId::Kernel32Loadlibraryw,
    ),
    ("kernel32.dll", "freelibrary", WinApiId::Kernel32Freelibrary),
    (
        "kernel32.dll",
        "getprocaddress",
        WinApiId::Kernel32Getprocaddress,
    ),
    (
        "kernel32.dll",
        "getfileattributesa",
        WinApiId::Kernel32Getfileattributesa,
    ),
    (
        "kernel32.dll",
        "getfileattributesw",
        WinApiId::Kernel32Getfileattributesw,
    ),
    (
        "kernel32.dll",
        "findfirstfilew",
        WinApiId::Kernel32Findfirstfilew,
    ),
    (
        "kernel32.dll",
        "findfirstfilea",
        WinApiId::Kernel32Findfirstfilea,
    ),
    (
        "kernel32.dll",
        "findnextfilew",
        WinApiId::Kernel32Findnextfilew,
    ),
    (
        "kernel32.dll",
        "findnextfilea",
        WinApiId::Kernel32Findnextfilea,
    ),
    ("kernel32.dll", "findclose", WinApiId::Kernel32Findclose),
    (
        "user32.dll",
        "getasynckeystate",
        WinApiId::User32Getasynckeystate,
    ),
    ("user32.dll", "peekmessagea", WinApiId::User32Peekmessagea),
    (
        "kernel32.dll",
        "loadlibraryexa",
        WinApiId::Kernel32Loadlibraryexa,
    ),
    (
        "kernel32.dll",
        "loadlibraryexw",
        WinApiId::Kernel32Loadlibraryexw,
    ),
    (
        "kernel32.dll",
        "findresourcea",
        WinApiId::Kernel32Findresourcea,
    ),
    (
        "kernel32.dll",
        "loadresource",
        WinApiId::Kernel32Loadresource,
    ),
    (
        "kernel32.dll",
        "lockresource",
        WinApiId::Kernel32Lockresource,
    ),
    (
        "kernel32.dll",
        "sizeofresource",
        WinApiId::Kernel32Sizeofresource,
    ),
    (
        "kernel32.dll",
        "getsystemdefaultlangid",
        WinApiId::Kernel32Getsystemdefaultlangid,
    ),
    (
        "kernel32.dll",
        "getuserdefaultlangid",
        WinApiId::Kernel32Getuserdefaultlangid,
    ),
    (
        "kernel32.dll",
        "globalmemorystatus",
        WinApiId::Kernel32Globalmemorystatus,
    ),
    (
        "kernel32.dll",
        "getlocaltime",
        WinApiId::Kernel32Getlocaltime,
    ),
    ("user32.dll", "loadicona", WinApiId::User32Loadicona),
    ("user32.dll", "loadcursora", WinApiId::User32Loadcursora),
    (
        "user32.dll",
        "registerclassexw",
        WinApiId::User32Registerclassexw,
    ),
    (
        "user32.dll",
        "registerclassexa",
        WinApiId::User32Registerclassexa,
    ),
    ("kernel32.dll", "createfilew", WinApiId::Kernel32Createfilew),
    ("kernel32.dll", "createfilea", WinApiId::Kernel32Createfilea),
    ("kernel32.dll", "closehandle", WinApiId::Kernel32Closehandle),
    ("user32.dll", "messageboxw", WinApiId::User32Messageboxw),
    ("user32.dll", "messageboxa", WinApiId::User32Messageboxa),
    (
        "kernel32.dll",
        "getfileinformationbyhandle",
        WinApiId::Kernel32Getfileinformationbyhandle,
    ),
    (
        "kernel32.dll",
        "filetimetolocalfiletime",
        WinApiId::Kernel32Filetimetolocalfiletime,
    ),
    (
        "kernel32.dll",
        "filetimetosystemtime",
        WinApiId::Kernel32Filetimetosystemtime,
    ),
    (
        "kernel32.dll",
        "gettimezoneinformation",
        WinApiId::Kernel32Gettimezoneinformation,
    ),
    ("kernel32.dll", "getfiletime", WinApiId::Kernel32Getfiletime),
    (
        "kernel32.dll",
        "setfilepointer",
        WinApiId::Kernel32Setfilepointer,
    ),
    ("kernel32.dll", "getfilesize", WinApiId::Kernel32Getfilesize),
    (
        "kernel32.dll",
        "encodepointer",
        WinApiId::Kernel32Encodepointer,
    ),
    (
        "kernel32.dll",
        "decodepointer",
        WinApiId::Kernel32Decodepointer,
    ),
    (
        "kernel32.dll",
        "initializecriticalsectionandspincount",
        WinApiId::Kernel32Initializecriticalsectionandspincount,
    ),
    (
        "user32.dll",
        "setprocessdpiaware",
        WinApiId::User32Setprocessdpiaware,
    ),
    (
        "user32.dll",
        "trackmouseevent",
        WinApiId::User32Trackmouseevent,
    ),
    (
        "comctl32.dll",
        "dllgetversion",
        WinApiId::Comctl32Dllgetversion,
    ),
    ("kernel32.dll", "readfile", WinApiId::Kernel32Readfile),
    ("kernel32.dll", "writefile", WinApiId::Kernel32Writefile),
    ("user32.dll", "getcursorpos", WinApiId::User32Getcursorpos),
    (
        "user32.dll",
        "getsystemmetrics",
        WinApiId::User32Getsystemmetrics,
    ),
    (
        "user32.dll",
        "monitorfromwindow",
        WinApiId::User32Monitorfromwindow,
    ),
    (
        "user32.dll",
        "getmonitorinfoa",
        WinApiId::User32Getmonitorinfoa,
    ),
    (
        "user32.dll",
        "getmonitorinfow",
        WinApiId::User32Getmonitorinfow,
    ),
    (
        "user32.dll",
        "enumdisplaymonitors",
        WinApiId::User32Enumdisplaymonitors,
    ),
    (
        "user32.dll",
        "enumdisplaydevicesa",
        WinApiId::User32Enumdisplaydevicesa,
    ),
    (
        "user32.dll",
        "enumdisplaydevicesw",
        WinApiId::User32Enumdisplaydevicesw,
    ),
    (
        "user32.dll",
        "monitorfrompoint",
        WinApiId::User32Monitorfrompoint,
    ),
    ("comctl32.dll", "ordinal 17", WinApiId::Comctl32Ordinal17),
    ("user32.dll", "getwindowrect", WinApiId::User32Getwindowrect),
    (
        "user32.dll",
        "getdpiforwindow",
        WinApiId::User32Getdpiforwindow,
    ),
    ("user32.dll", "postmessagea", WinApiId::User32Postmessagea),
    (
        "user32.dll",
        "getsystemmetricsfordpi",
        WinApiId::User32Getsystemmetricsfordpi,
    ),
    (
        "user32.dll",
        "adjustwindowrectexfordpi",
        WinApiId::User32Adjustwindowrectexfordpi,
    ),
    ("user32.dll", "setwindowpos", WinApiId::User32Setwindowpos),
    ("user32.dll", "setscrollinfo", WinApiId::User32Setscrollinfo),
    (
        "user32.dll",
        "scrollwindowex",
        WinApiId::User32Scrollwindowex,
    ),
    ("user32.dll", "scrolldc", WinApiId::User32Scrolldc),
    ("user32.dll", "beginpaint", WinApiId::User32Beginpaint),
    ("user32.dll", "endpaint", WinApiId::User32Endpaint),
    ("user32.dll", "clipcursor", WinApiId::User32Clipcursor),
    ("user32.dll", "getclipcursor", WinApiId::User32Getclipcursor),
    (
        "user32.dll",
        "callmsgfiltera",
        WinApiId::User32Callmsgfiltera,
    ),
    (
        "user32.dll",
        "callmsgfilterw",
        WinApiId::User32Callmsgfilterw,
    ),
    ("user32.dll", "getdc", WinApiId::User32Getdc),
    ("user32.dll", "sendmessagea", WinApiId::User32Sendmessagea),
    ("user32.dll", "sendmessagew", WinApiId::User32Sendmessagew),
    (
        "comdlg32.dll",
        "getopenfilenamea",
        WinApiId::Comdlg32Getopenfilenamea,
    ),
    (
        "comdlg32.dll",
        "getopenfilenamew",
        WinApiId::Comdlg32Getopenfilenamew,
    ),
    (
        "comdlg32.dll",
        "getsavefilenamea",
        WinApiId::Comdlg32Getsavefilenamea,
    ),
    (
        "comdlg32.dll",
        "getsavefilenamew",
        WinApiId::Comdlg32Getsavefilenamew,
    ),
    (
        "comdlg32.dll",
        "commdlgextendederror",
        WinApiId::Comdlg32Commdlgextendederror,
    ),
    (
        "comdlg32.dll",
        "choosecolora",
        WinApiId::Comdlg32Choosecolora,
    ),
    ("gdi32.dll", "selectobject", WinApiId::Gdi32Selectobject),
    (
        "gdi32.dll",
        "gettextextentpoint32a",
        WinApiId::Gdi32Gettextextentpoint32a,
    ),
    (
        "gdi32.dll",
        "gettextextentpoint32w",
        WinApiId::Gdi32Gettextextentpoint32w,
    ),
    ("gdi32.dll", "exttextoutw", WinApiId::Gdi32Exttextoutw),
    ("user32.dll", "releasedc", WinApiId::User32Releasedc),
    (
        "kernel32.dll",
        "getcurrentdirectoryw",
        WinApiId::Kernel32Getcurrentdirectoryw,
    ),
    (
        "kernel32.dll",
        "setcurrentdirectoryw",
        WinApiId::Kernel32Setcurrentdirectoryw,
    ),
    ("user32.dll", "loadimagea", WinApiId::User32Loadimagea),
    ("user32.dll", "loadimagew", WinApiId::User32Loadimagew),
    (
        "comctl32.dll",
        "initcommoncontrolsex",
        WinApiId::Comctl32Initcommoncontrolsex,
    ),
    (
        "uxtheme.dll",
        "setwindowtheme",
        WinApiId::UxthemeSetwindowtheme,
    ),
    (
        "user32.dll",
        "setwindowlongptrw",
        WinApiId::User32Setwindowlongptrw,
    ),
    (
        "user32.dll",
        "getwindowlongptra",
        WinApiId::User32Getwindowlongptra,
    ),
    (
        "user32.dll",
        "getwindowlongptrw",
        WinApiId::User32Getwindowlongptrw,
    ),
    ("gdi32.dll", "getobjecta", WinApiId::Gdi32Getobjecta),
    (
        "comctl32.dll",
        "imagelist_create",
        WinApiId::Comctl32ImagelistCreate,
    ),
    (
        "gdi32.dll",
        "createcompatibledc",
        WinApiId::Gdi32Createcompatibledc,
    ),
    (
        "gdi32.dll",
        "createdibsection",
        WinApiId::Gdi32Createdibsection,
    ),
    (
        "gdi32.dll",
        "createcompatiblebitmap",
        WinApiId::Gdi32Createcompatiblebitmap,
    ),
    ("gdi32.dll", "getdevicecaps", WinApiId::Gdi32Getdevicecaps),
    ("gdi32.dll", "createfonta", WinApiId::Gdi32Createfonta),
    ("gdi32.dll", "createfontw", WinApiId::Gdi32Createfontw),
    (
        "gdi32.dll",
        "createfontindirecta",
        WinApiId::Gdi32Createfontindirecta,
    ),
    (
        "gdi32.dll",
        "gettextmetricsa",
        WinApiId::Gdi32Gettextmetricsa,
    ),
    ("gdi32.dll", "settextcolor", WinApiId::Gdi32Settextcolor),
    ("gdi32.dll", "setbkcolor", WinApiId::Gdi32Setbkcolor),
    ("gdi32.dll", "setbkmode", WinApiId::Gdi32Setbkmode),
    ("gdi32.dll", "textouta", WinApiId::Gdi32Textouta),
    ("gdi32.dll", "bitblt", WinApiId::Gdi32Bitblt),
    ("gdi32.dll", "stretchblt", WinApiId::Gdi32Stretchblt),
    ("gdi32.dll", "patblt", WinApiId::Gdi32Patblt),
    ("gdi32.dll", "getpixel", WinApiId::Gdi32Getpixel),
    ("gdi32.dll", "deletedc", WinApiId::Gdi32Deletedc),
    (
        "comctl32.dll",
        "imagelist_addmasked",
        WinApiId::Comctl32ImagelistAddmasked,
    ),
    (
        "comctl32.dll",
        "imagelist_setbkcolor",
        WinApiId::Comctl32ImagelistSetbkcolor,
    ),
    (
        "comctl32.dll",
        "imagelist_destroy",
        WinApiId::Comctl32ImagelistDestroy,
    ),
    ("gdi32.dll", "deleteobject", WinApiId::Gdi32Deleteobject),
    ("user32.dll", "destroyicon", WinApiId::User32Destroyicon),
    ("user32.dll", "iswindow", WinApiId::User32Iswindow),
    (
        "user32.dll",
        "iswindowvisible",
        WinApiId::User32Iswindowvisible,
    ),
    (
        "user32.dll",
        "iswindowenabled",
        WinApiId::User32Iswindowenabled,
    ),
    ("user32.dll", "getparent", WinApiId::User32Getparent),
    (
        "user32.dll",
        "getactivewindow",
        WinApiId::User32Getactivewindow,
    ),
    (
        "user32.dll",
        "getforegroundwindow",
        WinApiId::User32Getforegroundwindow,
    ),
    ("user32.dll", "showwindow", WinApiId::User32Showwindow),
    ("user32.dll", "enablewindow", WinApiId::User32Enablewindow),
    (
        "user32.dll",
        "setforegroundwindow",
        WinApiId::User32Setforegroundwindow,
    ),
    (
        "user32.dll",
        "setactivewindow",
        WinApiId::User32Setactivewindow,
    ),
    ("user32.dll", "setfocus", WinApiId::User32Setfocus),
    ("user32.dll", "getfocus", WinApiId::User32Getfocus),
    ("user32.dll", "setcapture", WinApiId::User32Setcapture),
    ("user32.dll", "getcapture", WinApiId::User32Getcapture),
    (
        "user32.dll",
        "releasecapture",
        WinApiId::User32Releasecapture,
    ),
    ("user32.dll", "setcursor", WinApiId::User32Setcursor),
    ("user32.dll", "updatewindow", WinApiId::User32Updatewindow),
    (
        "user32.dll",
        "invalidaterect",
        WinApiId::User32Invalidaterect,
    ),
    ("user32.dll", "redrawwindow", WinApiId::User32Redrawwindow),
    (
        "user32.dll",
        "setwindowtexta",
        WinApiId::User32Setwindowtexta,
    ),
    (
        "user32.dll",
        "setwindowtextw",
        WinApiId::User32Setwindowtextw,
    ),
    (
        "user32.dll",
        "getwindowtexta",
        WinApiId::User32Getwindowtexta,
    ),
    (
        "user32.dll",
        "getwindowtextw",
        WinApiId::User32Getwindowtextw,
    ),
    ("user32.dll", "getclientrect", WinApiId::User32Getclientrect),
    ("user32.dll", "movewindow", WinApiId::User32Movewindow),
    (
        "user32.dll",
        "screentoclient",
        WinApiId::User32Screentoclient,
    ),
    (
        "user32.dll",
        "clienttoscreen",
        WinApiId::User32Clienttoscreen,
    ),
    (
        "user32.dll",
        "getdesktopwindow",
        WinApiId::User32Getdesktopwindow,
    ),
    ("user32.dll", "getsyscolor", WinApiId::User32Getsyscolor),
    (
        "user32.dll",
        "getsyscolorbrush",
        WinApiId::User32Getsyscolorbrush,
    ),
    (
        "user32.dll",
        "getdialogbaseunits",
        WinApiId::User32Getdialogbaseunits,
    ),
    ("user32.dll", "setrect", WinApiId::User32Setrect),
    ("user32.dll", "isiconic", WinApiId::User32Isiconic),
    ("user32.dll", "iszoomed", WinApiId::User32Iszoomed),
    (
        "user32.dll",
        "getwindowthreadprocessid",
        WinApiId::User32Getwindowthreadprocessid,
    ),
    ("user32.dll", "getdlgctrlid", WinApiId::User32Getdlgctrlid),
    (
        "kernel32.dll",
        "getcurrentprocess",
        WinApiId::Kernel32Getcurrentprocess,
    ),
    ("kernel32.dll", "sleep", WinApiId::Kernel32Sleep),
    ("winmm.dll", "timegettime", WinApiId::WinmmTimegettime),
    ("kernel32.dll", "localalloc", WinApiId::Kernel32Localalloc),
    ("kernel32.dll", "localfree", WinApiId::Kernel32Localfree),
    ("kernel32.dll", "globalalloc", WinApiId::Kernel32Globalalloc),
    ("kernel32.dll", "globalfree", WinApiId::Kernel32Globalfree),
    ("kernel32.dll", "globallock", WinApiId::Kernel32Globallock),
    (
        "kernel32.dll",
        "globalunlock",
        WinApiId::Kernel32Globalunlock,
    ),
    ("kernel32.dll", "globalsize", WinApiId::Kernel32Globalsize),
    ("kernel32.dll", "muldiv", WinApiId::Kernel32Muldiv),
    ("user32.dll", "getcursor", WinApiId::User32Getcursor),
    ("user32.dll", "ischild", WinApiId::User32Ischild),
    ("user32.dll", "getwindow", WinApiId::User32Getwindow),
    (
        "user32.dll",
        "setkeyboardstate",
        WinApiId::User32Setkeyboardstate,
    ),
    (
        "user32.dll",
        "getkeyboardstate",
        WinApiId::User32Getkeyboardstate,
    ),
    ("user32.dll", "getkeystate", WinApiId::User32Getkeystate),
    (
        "user32.dll",
        "mapvirtualkeya",
        WinApiId::User32Mapvirtualkeya,
    ),
    (
        "user32.dll",
        "setwindowlongptra",
        WinApiId::User32Setwindowlongptra,
    ),
    ("user32.dll", "settimer", WinApiId::User32Settimer),
    ("user32.dll", "killtimer", WinApiId::User32Killtimer),
    (
        "user32.dll",
        "adjustwindowrectex",
        WinApiId::User32Adjustwindowrectex,
    ),
    (
        "kernel32.dll",
        "globaladdatoma",
        WinApiId::Kernel32Globaladdatoma,
    ),
    (
        "kernel32.dll",
        "globaldeleteatom",
        WinApiId::Kernel32Globaldeleteatom,
    ),
    (
        "user32.dll",
        "setwindowshookexw",
        WinApiId::User32Setwindowshookexw,
    ),
    (
        "user32.dll",
        "unhookwindowshookex",
        WinApiId::User32Unhookwindowshookex,
    ),
    (
        "user32.dll",
        "callnexthookex",
        WinApiId::User32Callnexthookex,
    ),
    (
        "kernel32.dll",
        "getfullpathnamew",
        WinApiId::Kernel32Getfullpathnamew,
    ),
    (
        "kernel32.dll",
        "getfullpathnamea",
        WinApiId::Kernel32Getfullpathnamea,
    ),
    (
        "kernel32.dll",
        "getcurrentdirectorya",
        WinApiId::Kernel32Getcurrentdirectorya,
    ),
    (
        "kernel32.dll",
        "setcurrentdirectorya",
        WinApiId::Kernel32Setcurrentdirectorya,
    ),
    (
        "kernel32.dll",
        "createdirectoryw",
        WinApiId::Kernel32Createdirectoryw,
    ),
    (
        "kernel32.dll",
        "createdirectorya",
        WinApiId::Kernel32Createdirectorya,
    ),
    (
        "kernel32.dll",
        "removedirectoryw",
        WinApiId::Kernel32Removefirectoryw,
    ),
    (
        "kernel32.dll",
        "removedirectorya",
        WinApiId::Kernel32Removefirectorya,
    ),
    ("kernel32.dll", "deletefilew", WinApiId::Kernel32Deletefilew),
    ("kernel32.dll", "deletefilea", WinApiId::Kernel32Deletefilea),
    ("kernel32.dll", "movefilew", WinApiId::Kernel32Movefilew),
    ("kernel32.dll", "movefilea", WinApiId::Kernel32Movefilea),
    (
        "kernel32.dll",
        "gettemppathw",
        WinApiId::Kernel32Gettemppathw,
    ),
    (
        "kernel32.dll",
        "gettemppatha",
        WinApiId::Kernel32Gettemppatha,
    ),
    (
        "kernel32.dll",
        "gettempfilenamew",
        WinApiId::Kernel32Gettempfilenamew,
    ),
    (
        "kernel32.dll",
        "gettempfilenamea",
        WinApiId::Kernel32Gettempfilenamea,
    ),
    (
        "kernel32.dll",
        "getdrivetypew",
        WinApiId::Kernel32Getdrivetypew,
    ),
    (
        "kernel32.dll",
        "getdrivetypea",
        WinApiId::Kernel32Getdrivetypea,
    ),
    (
        "kernel32.dll",
        "getlogicaldrives",
        WinApiId::Kernel32Getlogicaldrives,
    ),
    (
        "kernel32.dll",
        "getsystemdirectoryw",
        WinApiId::Kernel32Getsystemdirectoryw,
    ),
    (
        "kernel32.dll",
        "getsystemdirectorya",
        WinApiId::Kernel32Getsystemdirectorya,
    ),
    (
        "kernel32.dll",
        "getwindowsdirectoryw",
        WinApiId::Kernel32Getwindowsdirectoryw,
    ),
    (
        "kernel32.dll",
        "getwindowsdirectorya",
        WinApiId::Kernel32Getwindowsdirectorya,
    ),
    (
        "kernel32.dll",
        "getfilesizeex",
        WinApiId::Kernel32Getfilesizeex,
    ),
    (
        "kernel32.dll",
        "setfilepointerex",
        WinApiId::Kernel32Setfilepointerex,
    ),
    (
        "kernel32.dll",
        "setendoffile",
        WinApiId::Kernel32Setendoffile,
    ),
    (
        "kernel32.dll",
        "flushfilebuffers",
        WinApiId::Kernel32Flushfilebuffers,
    ),
    ("d3d9.dll", "direct3dcreate9", WinApiId::D3d9Direct3dcreate9),
    (
        "d3d9.dll",
        "idirect3d9::getadaptercount",
        WinApiId::D3d9Idirect3d9Getadaptercount,
    ),
    (
        "d3d9.dll",
        "idirect3d9::getadaptermonitor",
        WinApiId::D3d9Idirect3d9Getadaptermonitor,
    ),
    (
        "d3d9.dll",
        "idirect3d9::getdevicecaps",
        WinApiId::D3d9Idirect3d9Getdevicecaps,
    ),
    (
        "d3d9.dll",
        "idirect3d9::getadapterdisplaymode",
        WinApiId::D3d9Idirect3d9Getadapterdisplaymode,
    ),
    (
        "d3d9.dll",
        "idirect3d9::createdevice",
        WinApiId::D3d9Idirect3d9Createdevice,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::setvertexshader",
        WinApiId::D3d9Idirect3ddevice9Setvertexshader,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::setfvf",
        WinApiId::D3d9Idirect3ddevice9Setfvf,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::setrenderstate",
        WinApiId::D3d9Idirect3ddevice9Setrenderstate,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::settexturestagestate",
        WinApiId::D3d9Idirect3ddevice9Settexturestagestate,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::setsamplerstate",
        WinApiId::D3d9Idirect3ddevice9Setsamplerstate,
    ),
    (
        "user32.dll",
        "enablemenuitem",
        WinApiId::User32Enablemenuitem,
    ),
    ("user32.dll", "checkmenuitem", WinApiId::User32Checkmenuitem),
    ("user32.dll", "getmessagea", WinApiId::User32Getmessagea),
    (
        "user32.dll",
        "translatemessage",
        WinApiId::User32Translatemessage,
    ),
    (
        "user32.dll",
        "defwindowproca",
        WinApiId::User32Defwindowproca,
    ),
    (
        "user32.dll",
        "defwindowprocw",
        WinApiId::User32Defwindowprocw,
    ),
    ("user32.dll", "defframeproca", WinApiId::User32Defframeproca),
    ("user32.dll", "defframeprocw", WinApiId::User32Defframeprocw),
    (
        "user32.dll",
        "defmdichildproca",
        WinApiId::User32Defmdichildproca,
    ),
    (
        "user32.dll",
        "defmdichildprocw",
        WinApiId::User32Defmdichildprocw,
    ),
    ("user32.dll", "createmenu", WinApiId::User32Createmenu),
    (
        "user32.dll",
        "createpopupmenu",
        WinApiId::User32Createpopupmenu,
    ),
    ("user32.dll", "appendmenua", WinApiId::User32Appendmenua),
    ("user32.dll", "appendmenuw", WinApiId::User32Appendmenuw),
    ("user32.dll", "setmenu", WinApiId::User32Setmenu),
    ("user32.dll", "destroymenu", WinApiId::User32Destroymenu),
    ("user32.dll", "removemenu", WinApiId::User32Removemenu),
    ("user32.dll", "deletemenu", WinApiId::User32Deletemenu),
    ("user32.dll", "modifymenua", WinApiId::User32Modifymenua),
    ("user32.dll", "modifymenuw", WinApiId::User32Modifymenuw),
    ("user32.dll", "getsystemmenu", WinApiId::User32Getsystemmenu),
    (
        "user32.dll",
        "trackpopupmenu",
        WinApiId::User32Trackpopupmenu,
    ),
    (
        "user32.dll",
        "getmenuiteminfoa",
        WinApiId::User32Getmenuiteminfoa,
    ),
    (
        "user32.dll",
        "getmenuiteminfow",
        WinApiId::User32Getmenuiteminfow,
    ),
    (
        "user32.dll",
        "setmenuiteminfoa",
        WinApiId::User32Setmenuiteminfoa,
    ),
    (
        "user32.dll",
        "setmenuiteminfow",
        WinApiId::User32Setmenuiteminfow,
    ),
    (
        "user32.dll",
        "checkmenuradioitem",
        WinApiId::User32Checkmenuradioitem,
    ),
    (
        "user32.dll",
        "dispatchmessagea",
        WinApiId::User32Dispatchmessagea,
    ),
    (
        "d3d9.dll",
        "idirect3ddevice9::release",
        WinApiId::D3d9Idirect3ddevice9Release,
    ),
    (
        "d3d9.dll",
        "idirect3d9::release",
        WinApiId::D3d9Idirect3d9Release,
    ),
];

/// Resolve library/export to id. Case-insensitive, allocation-free.
/// Intended for session setup (once per import), not the hot emu loop.
#[must_use]
pub fn resolve_winapi_id(library: &str, name: &str) -> Option<WinApiId> {
    for &(lib, export, id) in WINAPI_NAME_ROWS {
        if lib.eq_ignore_ascii_case(library) && export.eq_ignore_ascii_case(name) {
            return Some(id);
        }
    }
    None
}

/// Reverse lookup: dense id → (`library`, `export`) as stored in the name table.
///
/// Names are lowercase (as in `WINAPI_NAME_ROWS`). Used for trace/profile only.
#[must_use]
pub fn winapi_id_export(id: WinApiId) -> Option<(&'static str, &'static str)> {
    for &(lib, export, row_id) in WINAPI_NAME_ROWS {
        if row_id == id {
            return Some((lib, export));
        }
    }
    None
}

#[must_use]
pub fn is_winapi_implemented(library: &str, name: &str) -> bool {
    if resolve_winapi_id(library, name).is_some() {
        return true;
    }
    // Soft UCRT / msvcrt path (string dispatch, not dense WinApiId).
    if crate::ucrt::is_ucrt_library(library) {
        if crate::ucrt::crt_data_import_va(name).is_some() {
            return true;
        }
        // Mirror dispatch_ucrt arms that are callable exports.
        let n = name.to_ascii_lowercase();
        return matches!(
            n.as_str(),
            "__acrt_iob_func"
                | "fwrite"
                | "fflush"
                | "setvbuf"
                | "__stdio_common_vfprintf"
                | "malloc"
                | "calloc"
                | "free"
                | "_set_new_mode"
                | "__p__environ"
                | "__p__acmdln"
                | "__p___argc"
                | "__p___argv"
                | "__p__commode"
                | "__p__fmode"
                | "_configthreadlocale"
                | "__setusermatherr"
                | "__c_specific_handler"
                | "memcpy"
                | "memmove"
                | "memcmp"
                | "memset"
                | "strlen"
                | "strncmp"
                | "_initterm"
                | "_initterm_e"
                | "_configure_narrow_argv"
                | "_initialize_narrow_environment"
                | "_crt_atexit"
                | "_set_app_type"
                | "__set_app_type"
                | "_set_invalid_parameter_handler"
                | "__getmainargs"
                | "_xcptfilter"
                | "_cexit"
                | "_c_exit"
                | "signal"
                | "exit"
                | "_exit"
                | "abort"
                | "realloc"
                | "_isatty"
                | "_get_osfhandle"
                | "fputc"
                | "fputs"
                | "fgetc"
                | "strcmp"
                | "wcscmp"
                | "wcsstr"
                | "_onexit"
                | "__dllonexit"
                | "_beginthreadex"
                | "_endthreadex"
                | "_purecall"
        );
    }
    if library.eq_ignore_ascii_case("ole32.dll") {
        let n = name.to_ascii_lowercase();
        return matches!(
            n.as_str(),
            "coinitialize" | "coinitializeex" | "couninitialize" | "cocreateinstance"
        );
    }
    if library.eq_ignore_ascii_case("shell32.dll") {
        let n = name.to_ascii_lowercase();
        return matches!(
            n.as_str(),
            "shgetfolderpathw" | "shgetpathfromidlistw" | "shbrowseforfolderw"
        );
    }
    if library.eq_ignore_ascii_case("oleaut32.dll") {
        let n = name.to_ascii_lowercase();
        return matches!(
            n.as_str(),
            "sysallocstring"
                | "sysallocstringlen"
                | "sysfreestring"
                | "sysstringlen"
                | "sysstringbyteslen"
                | "variantclear"
                | "variantcopy"
                | "ordinal 2"
                | "ordinal 4"
                | "ordinal 6"
                | "ordinal 7"
                | "ordinal 9"
                | "ordinal 10"
        );
    }
    if library.eq_ignore_ascii_case("KERNEL32.dll") {
        let n = name.to_ascii_lowercase();
        return matches!(
            n.as_str(),
            "getversion"
                | "getmodulehandlew"
                | "lstrlenw"
                | "lstrcpyw"
                | "lstrcatw"
                | "virtualalloc"
                | "virtualfree"
                | "virtualprotect"
                | "virtualquery"
                | "flushinstructioncache"
                | "tlsgetvalue"
                | "tlssetvalue"
                | "tlsalloc"
                | "tlsfree"
                | "createthread"
                | "exitthread"
                | "getexitcodethread"
                | "waitforsingleobject"
                | "createeventa"
                | "createeventw"
                | "setevent"
                | "resetevent"
                | "getcurrentthread"
                | "setconsolectrlhandler"
                | "getconsolemode"
                | "setconsolemode"
                | "getconsolescreenbufferinfo"
                | "setfileapistooem"
                | "queryperformancefrequency"
                | "getsysteminfo"
                | "isprocessorfeaturepresent"
                | "globalmemorystatusex"
                | "getprocesstimes"
                | "getlargepageminimum"
                | "getprocessaffinitymask"
                | "setprocessaffinitymask"
                | "setthreadaffinitymask"
                | "comparefiletime"
                | "localfiletimetofiletime"
                | "filetimetodosdatetime"
                | "dosdatetimetofiletime"
                | "getdiskfreespaceexw"
                | "getdiskfreespacew"
                | "getlogicaldrivestringsw"
                | "setfileattributesw"
                | "setfiletime"
                | "formatmessagew"
                | "resumethread"
                | "createsemaphorew"
                | "createsemaphorea"
                | "releasesemaphore"
                | "openeventw"
                | "openeventa"
                | "waitformultipleobjects"
                | "movefilewithprogressw"
                | "createhardlinkw"
                | "findfirststreamw"
                | "findnextstreamw"
                | "deviceiocontrol"
                | "mapviewoffile"
                | "unmapviewoffile"
                | "openfilemappingw"
                | "openfilemappinga"
        );
    }
    false
}

/// Hot-path dispatch: integer match (LLVM jump table), no string work.
pub fn dispatch_winapi_id(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: WinApiEnvironment,
    state: &mut WinApiState,
    id: WinApiId,
) -> Result<WinApiHandlerResult> {
    match id {
        WinApiId::Kernel32Getversionexa => kernel32::handle_get_version_ex_a(engine),
        WinApiId::Kernel32Getmodulehandlea => {
            kernel32::handle_get_module_handle_a(engine, environment, state)
        }
        WinApiId::Kernel32Getcommandlinea => {
            kernel32::handle_get_command_line_a(engine, environment.command_line_a_ptr)
        }
        WinApiId::Kernel32Getcommandlinew => {
            kernel32::handle_get_command_line_w(engine, environment.command_line_w_ptr)
        }
        WinApiId::Kernel32Getstartupinfoa => kernel32::handle_get_startup_info_a(engine),
        WinApiId::Kernel32Getprocessheap => {
            kernel32::handle_get_process_heap(engine, environment.process_heap_handle)
        }
        WinApiId::Kernel32Getsystemtimeasfiletime => {
            kernel32::handle_get_system_time_as_file_time(engine)
        }
        WinApiId::Kernel32Getcurrentprocessid => kernel32::handle_get_current_process_id(engine),
        WinApiId::Kernel32Getcurrentthreadid => {
            kernel32::handle_get_current_thread_id(engine, state)
        }
        WinApiId::Kernel32Gettickcount => kernel32::handle_get_tick_count(engine),
        WinApiId::Kernel32Queryperformancecounter => {
            kernel32::handle_query_performance_counter(engine)
        }
        WinApiId::Kernel32Heapalloc => kernel32::handle_heap_alloc(engine, state),
        WinApiId::Kernel32Heapfree => kernel32::handle_heap_free(engine, state),
        WinApiId::Kernel32Heaprealloc => kernel32::handle_heap_realloc(engine, state),
        WinApiId::Kernel32Heapcreate => {
            kernel32::handle_heap_create(engine, environment.process_heap_handle)
        }
        WinApiId::Kernel32Heapsetinformation => kernel32::handle_heap_set_information(engine),
        WinApiId::Kernel32Initializecriticalsection => {
            kernel32::handle_initialize_critical_section(engine)
        }
        WinApiId::Kernel32Entercriticalsection => {
            kernel32::handle_enter_critical_section(engine, state)
        }
        WinApiId::Kernel32Leavecriticalsection => {
            kernel32::handle_leave_critical_section(engine, state)
        }
        WinApiId::Kernel32Deletecriticalsection => kernel32::handle_delete_critical_section(engine),
        WinApiId::Kernel32Flsalloc => kernel32::handle_fls_alloc(engine, state),
        WinApiId::Kernel32Flsfree => kernel32::handle_fls_free(engine, state),
        WinApiId::Kernel32Flssetvalue => kernel32::handle_fls_set_value(engine, state),
        WinApiId::Kernel32Flsgetvalue => kernel32::handle_fls_get_value(engine, state),
        WinApiId::Kernel32Getstdhandle => kernel32::handle_get_std_handle(engine),
        WinApiId::Kernel32Getfiletype => kernel32::handle_get_file_type(engine, state),
        WinApiId::Kernel32Sethandlecount => kernel32::handle_set_handle_count(engine),
        WinApiId::Kernel32Getenvironmentstringsw => kernel32::handle_get_environment_strings_w(
            engine,
            environment.environment_strings_w_ptr,
        ),
        WinApiId::Kernel32Freeenvironmentstringsw => {
            kernel32::handle_free_environment_strings_w(engine)
        }
        WinApiId::Kernel32Widechartomultibyte => kernel32::handle_wide_char_to_multi_byte(engine),
        WinApiId::Kernel32Getlasterror => kernel32::handle_get_last_error(engine, state),
        WinApiId::Kernel32Setlasterror => kernel32::handle_set_last_error(engine, state),
        WinApiId::Kernel32Getacp => kernel32::handle_get_acp(engine),
        WinApiId::Kernel32Getoemcp => kernel32::handle_get_oem_cp(engine),
        WinApiId::Kernel32Getcpinfo => kernel32::handle_get_cp_info(engine),
        WinApiId::Kernel32Isvalidcodepage => kernel32::handle_is_valid_code_page(engine),
        WinApiId::Kernel32Getstringtypew => kernel32::handle_get_string_type_w(engine),
        WinApiId::Kernel32Multibytetowidechar => kernel32::handle_multi_byte_to_wide_char(engine),
        WinApiId::Kernel32Lcmapstringw => kernel32::handle_lc_map_string_w(engine),
        WinApiId::Kernel32Getmodulefilenamea => kernel32::handle_get_module_file_name_a(
            engine,
            state,
            environment.module_file_name_a_ptr,
        ),
        WinApiId::Kernel32Getmodulefilenamew => kernel32::handle_get_module_file_name_w(
            engine,
            state,
            environment.module_file_name_w_ptr,
        ),
        WinApiId::Kernel32Setunhandledexceptionfilter => {
            kernel32::handle_set_unhandled_exception_filter(engine)
        }
        WinApiId::Kernel32Heapsize => kernel32::handle_heap_size(engine, state),
        WinApiId::Advapi32Regcreatekeyexa => advapi32::handle_reg_create_key_ex_a(engine, state),
        WinApiId::Advapi32Regopenkeyexa => advapi32::handle_reg_open_key_ex_a(engine, state),
        WinApiId::Advapi32Regqueryvalueexa => advapi32::handle_reg_query_value_ex_a(engine),
        WinApiId::Advapi32Regqueryvalueexw => advapi32::handle_reg_query_value_ex_w(engine),
        WinApiId::Advapi32Regsetvalueexa => advapi32::handle_reg_set_value_ex_a(engine),
        WinApiId::Advapi32Regsetvalueexw => advapi32::handle_reg_set_value_ex_w(engine),
        WinApiId::Advapi32Regdeletevaluea => advapi32::handle_reg_delete_value_a(engine),
        WinApiId::Advapi32Regclosekey => advapi32::handle_reg_close_key(engine),
        WinApiId::Advapi32Initializesecuritydescriptor => {
            advapi32::handle_initialize_security_descriptor(engine)
        }
        WinApiId::Advapi32Setsecuritydescriptordacl => {
            advapi32::handle_set_security_descriptor_dacl(engine)
        }
        WinApiId::Kernel32Loadlibrarya => {
            kernel32::handle_load_library_a(engine, environment, state)
        }
        WinApiId::Kernel32Loadlibraryw => {
            kernel32::handle_load_library_w(engine, environment, state)
        }
        WinApiId::Kernel32Freelibrary => kernel32::handle_free_library(engine, state),
        WinApiId::Kernel32Getprocaddress => kernel32::handle_get_proc_address(engine, state),
        WinApiId::Kernel32Getfileattributesa => {
            kernel32::handle_get_file_attributes_a(engine, state)
        }
        WinApiId::Kernel32Getfileattributesw => {
            kernel32::handle_get_file_attributes_w(engine, state)
        }
        WinApiId::Kernel32Findfirstfilew => kernel32::handle_find_first_file_w(engine, state),
        WinApiId::Kernel32Findfirstfilea => kernel32::handle_find_first_file_a(engine, state),
        WinApiId::Kernel32Findnextfilew => kernel32::handle_find_next_file_w(engine, state),
        WinApiId::Kernel32Findnextfilea => kernel32::handle_find_next_file_a(engine, state),
        WinApiId::Kernel32Findclose => kernel32::handle_find_close(engine, state),
        WinApiId::User32Getasynckeystate => user32::handle_get_async_key_state(engine, state),
        WinApiId::User32Peekmessagea => user32::handle_peek_message_a(engine, state),
        WinApiId::Kernel32Loadlibraryexa => {
            kernel32::handle_load_library_ex_a(engine, environment, state)
        }
        WinApiId::Kernel32Loadlibraryexw => {
            kernel32::handle_load_library_ex_w(engine, environment, state)
        }
        WinApiId::Kernel32Findresourcea => kernel32::handle_find_resource_a(engine, state),
        WinApiId::Kernel32Loadresource => kernel32::handle_load_resource(engine, state),
        WinApiId::Kernel32Lockresource => kernel32::handle_lock_resource(engine, state),
        WinApiId::Kernel32Sizeofresource => kernel32::handle_sizeof_resource(engine, state),
        WinApiId::Kernel32Getsystemdefaultlangid => {
            kernel32::handle_get_system_default_lang_id(engine)
        }
        WinApiId::Kernel32Getuserdefaultlangid => kernel32::handle_get_user_default_lang_id(engine),
        WinApiId::Kernel32Globalmemorystatus => kernel32::handle_global_memory_status(engine),
        WinApiId::Kernel32Getlocaltime => kernel32::handle_get_local_time(engine),
        WinApiId::User32Loadicona => user32::handle_load_icon_a(engine),
        WinApiId::User32Loadcursora => user32::handle_load_cursor_a(engine),
        WinApiId::User32Registerclassexw => user32::handle_register_class_ex_w(engine, state),
        WinApiId::User32Registerclassexa => user32::handle_register_class_ex_a(engine, state),
        WinApiId::Kernel32Createfilew => kernel32::handle_create_file_w(engine, state),
        WinApiId::Kernel32Createfilea => kernel32::handle_create_file_a(engine, state),
        WinApiId::Kernel32Closehandle => kernel32::handle_close_handle(engine, state),
        WinApiId::User32Messageboxw => user32::handle_message_box_w(engine),
        WinApiId::User32Messageboxa => user32::handle_message_box_a(engine),
        WinApiId::Kernel32Getfileinformationbyhandle => {
            kernel32::handle_get_file_information_by_handle(engine, state)
        }
        WinApiId::Kernel32Filetimetolocalfiletime => {
            kernel32::handle_file_time_to_local_file_time(engine, state)
        }
        WinApiId::Kernel32Filetimetosystemtime => {
            kernel32::handle_file_time_to_system_time(engine, state)
        }
        WinApiId::Kernel32Gettimezoneinformation => {
            kernel32::handle_get_time_zone_information(engine, state)
        }
        WinApiId::Kernel32Getfiletime => kernel32::handle_get_file_time(engine, state),
        WinApiId::Kernel32Setfilepointer => kernel32::handle_set_file_pointer(engine, state),
        WinApiId::Kernel32Getfilesize => kernel32::handle_get_file_size(engine, state),
        WinApiId::Kernel32Encodepointer => kernel32::handle_encode_pointer(engine),
        WinApiId::Kernel32Decodepointer => kernel32::handle_decode_pointer(engine),
        WinApiId::Kernel32Initializecriticalsectionandspincount => {
            kernel32::handle_initialize_critical_section_and_spin_count(engine)
        }
        WinApiId::User32Setprocessdpiaware => user32::handle_set_process_dpi_aware(engine),
        WinApiId::User32Trackmouseevent => user32::handle_track_mouse_event(engine),
        WinApiId::Comctl32Dllgetversion => comctl32::handle_dll_get_version(engine),
        WinApiId::Kernel32Readfile => kernel32::handle_read_file(engine, state),
        WinApiId::Kernel32Writefile => kernel32::handle_write_file(engine, state),
        WinApiId::User32Getcursorpos => user32::handle_get_cursor_pos(engine),
        WinApiId::User32Getsystemmetrics => user32::handle_get_system_metrics(engine),
        WinApiId::User32Monitorfromwindow => user32::handle_monitor_from_window(engine),
        WinApiId::User32Getmonitorinfoa => user32::handle_get_monitor_info_a(engine),
        WinApiId::User32Getmonitorinfow => user32::handle_get_monitor_info_w(engine),
        WinApiId::User32Enumdisplaymonitors => user32::handle_enum_display_monitors(engine),
        WinApiId::User32Enumdisplaydevicesa => user32::handle_enum_display_devices_a(engine),
        WinApiId::User32Enumdisplaydevicesw => user32::handle_enum_display_devices_w(engine),
        WinApiId::User32Monitorfrompoint => user32::handle_monitor_from_point(engine),
        WinApiId::Comctl32Ordinal17 => comctl32::handle_init_common_controls(engine),
        WinApiId::User32Getwindowrect => user32::handle_get_window_rect(engine, state),
        WinApiId::User32Getdpiforwindow => user32::handle_get_dpi_for_window(engine),
        WinApiId::User32Postmessagea => user32::handle_post_message_a(engine, state),
        WinApiId::User32Getsystemmetricsfordpi => user32::handle_get_system_metrics_for_dpi(engine),
        WinApiId::User32Adjustwindowrectexfordpi => {
            user32::handle_adjust_window_rect_ex_for_dpi(engine)
        }
        WinApiId::User32Setwindowpos => user32::handle_set_window_pos(engine),
        WinApiId::User32Setscrollinfo => user32::handle_set_scroll_info(engine),
        WinApiId::User32Scrollwindowex => user32::handle_scroll_window_ex(engine),
        WinApiId::User32Scrolldc => user32::handle_scroll_dc(engine),
        WinApiId::User32Beginpaint => user32::handle_begin_paint(engine, state),
        WinApiId::User32Endpaint => user32::handle_end_paint(engine, state),
        WinApiId::User32Clipcursor => user32::handle_clip_cursor(engine),
        WinApiId::User32Getclipcursor => user32::handle_get_clip_cursor(engine),
        WinApiId::User32Callmsgfiltera => user32::handle_call_msg_filter(engine, "CallMsgFilterA"),
        WinApiId::User32Callmsgfilterw => user32::handle_call_msg_filter(engine, "CallMsgFilterW"),
        WinApiId::User32Getdc => user32::handle_get_dc(engine),
        WinApiId::User32Sendmessagea => user32::handle_send_message_a(engine, state),
        WinApiId::User32Sendmessagew => user32::handle_send_message_w(engine, state),
        WinApiId::Comdlg32Getopenfilenamea => comdlg32::handle_get_open_file_name_a(engine, state),
        WinApiId::Comdlg32Getopenfilenamew => comdlg32::handle_get_open_file_name_w(engine, state),
        WinApiId::Comdlg32Getsavefilenamea => comdlg32::handle_get_save_file_name_a(engine, state),
        WinApiId::Comdlg32Getsavefilenamew => comdlg32::handle_get_save_file_name_w(engine, state),
        WinApiId::Comdlg32Commdlgextendederror => {
            comdlg32::handle_comm_dlg_extended_error(engine, state)
        }
        WinApiId::Comdlg32Choosecolora => comdlg32::handle_choose_color_a(engine, state),
        WinApiId::Gdi32Selectobject => gdi32::handle_select_object(engine),
        WinApiId::Gdi32Gettextextentpoint32a => gdi32::handle_get_text_extent_point_32_a(engine),
        WinApiId::Gdi32Gettextextentpoint32w => gdi32::handle_get_text_extent_point_32_w(engine),
        WinApiId::Gdi32Exttextoutw => gdi32::handle_ext_text_out_w(engine),
        WinApiId::User32Releasedc => user32::handle_release_dc(engine),
        WinApiId::Kernel32Getcurrentdirectoryw => {
            kernel32::handle_get_current_directory_w(engine, state)
        }
        WinApiId::Kernel32Setcurrentdirectoryw => {
            kernel32::handle_set_current_directory_w(engine, state)
        }
        WinApiId::User32Loadimagea => user32::handle_load_image_a(engine),
        WinApiId::User32Loadimagew => user32::handle_load_image_w(engine),
        WinApiId::Comctl32Initcommoncontrolsex => comctl32::handle_init_common_controls_ex(engine),
        WinApiId::UxthemeSetwindowtheme => uxtheme::handle_set_window_theme(engine),
        WinApiId::User32Setwindowlongptrw => user32::handle_set_window_long_ptr_w(engine, state),
        WinApiId::User32Getwindowlongptra => user32::handle_get_window_long_ptr_a(engine, state),
        WinApiId::User32Getwindowlongptrw => user32::handle_get_window_long_ptr_w(engine, state),
        WinApiId::Gdi32Getobjecta => gdi32::handle_get_object_a(engine),
        WinApiId::Comctl32ImagelistCreate => comctl32::handle_image_list_create(engine, state),
        WinApiId::Gdi32Createcompatibledc => gdi32::handle_create_compatible_dc(engine),
        WinApiId::Gdi32Createdibsection => gdi32::handle_create_dib_section(engine, state),
        WinApiId::Gdi32Createcompatiblebitmap => {
            gdi32::handle_create_compatible_bitmap(engine, state)
        }
        WinApiId::Gdi32Getdevicecaps => gdi32::handle_get_device_caps(engine),
        WinApiId::Gdi32Createfonta => gdi32::handle_create_font_a(engine, state),
        WinApiId::Gdi32Createfontw => gdi32::handle_create_font_w(engine, state),
        WinApiId::Gdi32Createfontindirecta => gdi32::handle_create_font_indirect_a(engine, state),
        WinApiId::Gdi32Gettextmetricsa => gdi32::handle_get_text_metrics_a(engine),
        WinApiId::Gdi32Settextcolor => gdi32::handle_set_text_color(engine),
        WinApiId::Gdi32Setbkcolor => gdi32::handle_set_bk_color(engine),
        WinApiId::Gdi32Setbkmode => gdi32::handle_set_bk_mode(engine),
        WinApiId::Gdi32Textouta => gdi32::handle_text_out_a(engine),
        WinApiId::Gdi32Bitblt => gdi32::handle_bit_blt(engine),
        WinApiId::Gdi32Stretchblt => gdi32::handle_stretch_blt(engine),
        WinApiId::Gdi32Patblt => gdi32::handle_pat_blt(engine),
        WinApiId::Gdi32Getpixel => gdi32::handle_get_pixel(engine),
        WinApiId::Gdi32Deletedc => gdi32::handle_delete_dc(engine),
        WinApiId::Comctl32ImagelistAddmasked => {
            comctl32::handle_image_list_add_masked(engine, state)
        }
        WinApiId::Comctl32ImagelistSetbkcolor => {
            comctl32::handle_image_list_set_bk_color(engine, state)
        }
        WinApiId::Comctl32ImagelistDestroy => comctl32::handle_image_list_destroy(engine, state),
        WinApiId::Gdi32Deleteobject => gdi32::handle_delete_object(engine),
        WinApiId::User32Destroyicon => user32::handle_destroy_icon(engine),
        WinApiId::User32Iswindow => user32::handle_is_window(engine),
        WinApiId::User32Iswindowvisible => user32::handle_is_window_visible(engine),
        WinApiId::User32Iswindowenabled => user32::handle_is_window_enabled(engine),
        WinApiId::User32Getparent => user32::handle_get_parent(engine),
        WinApiId::User32Getactivewindow => user32::handle_get_active_window(engine, state),
        WinApiId::User32Getforegroundwindow => user32::handle_get_foreground_window(engine, state),
        WinApiId::User32Showwindow => user32::handle_show_window(engine, state),
        WinApiId::User32Enablewindow => user32::handle_enable_window(engine, state),
        WinApiId::User32Setforegroundwindow => user32::handle_set_foreground_window(engine, state),
        WinApiId::User32Setactivewindow => user32::handle_set_active_window(engine, state),
        WinApiId::User32Setfocus => user32::handle_set_focus(engine, state),
        WinApiId::User32Getfocus => user32::handle_get_focus(engine, state),
        WinApiId::User32Setcapture => user32::handle_set_capture(engine, state),
        WinApiId::User32Getcapture => user32::handle_get_capture(engine, state),
        WinApiId::User32Releasecapture => user32::handle_release_capture(engine, state),
        WinApiId::User32Setcursor => user32::handle_set_cursor(engine, state),
        WinApiId::User32Updatewindow => user32::handle_update_window(engine, state),
        WinApiId::User32Invalidaterect => user32::handle_invalidate_rect(engine, state),
        WinApiId::User32Redrawwindow => user32::handle_redraw_window(engine, state),
        WinApiId::User32Setwindowtexta => user32::handle_set_window_text_a(engine, state),
        WinApiId::User32Setwindowtextw => user32::handle_set_window_text_w(engine, state),
        WinApiId::User32Getwindowtexta => user32::handle_get_window_text_a(engine, state),
        WinApiId::User32Getwindowtextw => user32::handle_get_window_text_w(engine, state),
        WinApiId::User32Getclientrect => user32::handle_get_client_rect(engine, state),
        WinApiId::User32Movewindow => user32::handle_move_window(engine, state),
        WinApiId::User32Screentoclient => user32::handle_screen_to_client(engine, state),
        WinApiId::User32Clienttoscreen => user32::handle_client_to_screen(engine, state),
        WinApiId::User32Getdesktopwindow => user32::handle_get_desktop_window(engine),
        WinApiId::User32Getsyscolor => user32::handle_get_sys_color(engine),
        WinApiId::User32Getsyscolorbrush => user32::handle_get_sys_color_brush(engine),
        WinApiId::User32Getdialogbaseunits => user32::handle_get_dialog_base_units(engine),
        WinApiId::User32Setrect => user32::handle_set_rect(engine),
        WinApiId::User32Isiconic => user32::handle_is_iconic(engine),
        WinApiId::User32Iszoomed => user32::handle_is_zoomed(engine),
        WinApiId::User32Getwindowthreadprocessid => {
            user32::handle_get_window_thread_process_id(engine)
        }
        WinApiId::User32Getdlgctrlid => user32::handle_get_dlg_ctrl_id(engine),
        WinApiId::Kernel32Getcurrentprocess => kernel32::handle_get_current_process(engine),
        WinApiId::Kernel32Sleep => kernel32::handle_sleep(engine),
        WinApiId::WinmmTimegettime => winmm::handle_time_get_time(engine, state),
        WinApiId::Kernel32Localalloc => kernel32::handle_local_alloc(engine, state),
        WinApiId::Kernel32Localfree => kernel32::handle_local_free(engine, state),
        WinApiId::Kernel32Globalalloc => kernel32::handle_global_alloc(engine, state),
        WinApiId::Kernel32Globalfree => kernel32::handle_global_free(engine, state),
        WinApiId::Kernel32Globallock => kernel32::handle_global_lock(engine, state),
        WinApiId::Kernel32Globalunlock => kernel32::handle_global_unlock(engine, state),
        WinApiId::Kernel32Globalsize => kernel32::handle_global_size(engine, state),
        WinApiId::Kernel32Muldiv => kernel32::handle_mul_div(engine),
        WinApiId::User32Getcursor => user32::handle_get_cursor(engine, state),
        WinApiId::User32Ischild => user32::handle_is_child(engine),
        WinApiId::User32Getwindow => user32::handle_get_window(engine),
        WinApiId::User32Setkeyboardstate => user32::handle_set_keyboard_state(engine, state),
        WinApiId::User32Getkeyboardstate => user32::handle_get_keyboard_state(engine, state),
        WinApiId::User32Getkeystate => user32::handle_get_key_state(engine, state),
        WinApiId::User32Mapvirtualkeya => user32::handle_map_virtual_key_a(engine),
        WinApiId::User32Setwindowlongptra => user32::handle_set_window_long_ptr_a(engine, state),
        WinApiId::User32Settimer => user32::handle_set_timer(engine, state),
        WinApiId::User32Killtimer => user32::handle_kill_timer(engine, state),
        WinApiId::User32Adjustwindowrectex => user32::handle_adjust_window_rect_ex(engine),
        WinApiId::Kernel32Globaladdatoma => kernel32::handle_global_add_atom_a(engine, state),
        WinApiId::Kernel32Globaldeleteatom => kernel32::handle_global_delete_atom(engine, state),
        WinApiId::User32Setwindowshookexw => user32::handle_set_windows_hook_ex_w(engine, state),
        WinApiId::User32Unhookwindowshookex => user32::handle_unhook_windows_hook_ex(engine, state),
        WinApiId::User32Callnexthookex => user32::handle_call_next_hook_ex(engine),
        WinApiId::Kernel32Getfullpathnamew => kernel32::handle_get_full_path_name_w(engine, state),
        WinApiId::Kernel32Getfullpathnamea => kernel32::handle_get_full_path_name_a(engine, state),
        WinApiId::Kernel32Getcurrentdirectorya => {
            kernel32::handle_get_current_directory_a(engine, state)
        }
        WinApiId::Kernel32Setcurrentdirectorya => {
            kernel32::handle_set_current_directory_a(engine, state)
        }
        WinApiId::Kernel32Createdirectoryw => kernel32::handle_create_directory_w(engine, state),
        WinApiId::Kernel32Createdirectorya => kernel32::handle_create_directory_a(engine, state),
        WinApiId::Kernel32Removefirectoryw => kernel32::handle_remove_directory_w(engine, state),
        WinApiId::Kernel32Removefirectorya => kernel32::handle_remove_directory_a(engine, state),
        WinApiId::Kernel32Deletefilew => kernel32::handle_delete_file_w(engine, state),
        WinApiId::Kernel32Deletefilea => kernel32::handle_delete_file_a(engine, state),
        WinApiId::Kernel32Movefilew => kernel32::handle_move_file_w(engine, state),
        WinApiId::Kernel32Movefilea => kernel32::handle_move_file_a(engine, state),
        WinApiId::Kernel32Gettemppathw => kernel32::handle_get_temp_path_w(engine, state),
        WinApiId::Kernel32Gettemppatha => kernel32::handle_get_temp_path_a(engine, state),
        WinApiId::Kernel32Gettempfilenamew => kernel32::handle_get_temp_file_name_w(engine, state),
        WinApiId::Kernel32Gettempfilenamea => kernel32::handle_get_temp_file_name_a(engine, state),
        WinApiId::Kernel32Getdrivetypew => kernel32::handle_get_drive_type_w(engine, state),
        WinApiId::Kernel32Getdrivetypea => kernel32::handle_get_drive_type_a(engine, state),
        WinApiId::Kernel32Getlogicaldrives => kernel32::handle_get_logical_drives(engine, state),
        WinApiId::Kernel32Getsystemdirectoryw => kernel32::handle_get_system_directory_w(engine),
        WinApiId::Kernel32Getsystemdirectorya => kernel32::handle_get_system_directory_a(engine),
        WinApiId::Kernel32Getwindowsdirectoryw => kernel32::handle_get_windows_directory_w(engine),
        WinApiId::Kernel32Getwindowsdirectorya => kernel32::handle_get_windows_directory_a(engine),
        WinApiId::Kernel32Getfilesizeex => kernel32::handle_get_file_size_ex(engine, state),
        WinApiId::Kernel32Setfilepointerex => kernel32::handle_set_file_pointer_ex(engine, state),
        WinApiId::Kernel32Setendoffile => kernel32::handle_set_end_of_file(engine, state),
        WinApiId::Kernel32Flushfilebuffers => kernel32::handle_flush_file_buffers(engine, state),
        WinApiId::D3d9Direct3dcreate9 => d3d9::handle_direct3d_create9(engine, state),
        WinApiId::D3d9Idirect3d9Getadaptercount => d3d9::handle_get_adapter_count(engine),
        WinApiId::D3d9Idirect3d9Getadaptermonitor => d3d9::handle_get_adapter_monitor(engine),
        WinApiId::D3d9Idirect3d9Getdevicecaps => d3d9::handle_get_device_caps(engine),
        WinApiId::D3d9Idirect3d9Getadapterdisplaymode => {
            d3d9::handle_get_adapter_display_mode(engine, state)
        }
        WinApiId::D3d9Idirect3d9Createdevice => d3d9::handle_create_device(engine, state),
        WinApiId::D3d9Idirect3ddevice9Setvertexshader => {
            d3d9::handle_set_vertex_shader(engine, state)
        }
        WinApiId::D3d9Idirect3ddevice9Setfvf => d3d9::handle_set_fvf(engine, state),
        WinApiId::D3d9Idirect3ddevice9Setrenderstate => {
            d3d9::handle_set_render_state(engine, state)
        }
        WinApiId::D3d9Idirect3ddevice9Settexturestagestate => {
            d3d9::handle_set_texture_stage_state(engine, state)
        }
        WinApiId::D3d9Idirect3ddevice9Setsamplerstate => {
            d3d9::handle_set_sampler_state(engine, state)
        }
        WinApiId::User32Enablemenuitem => user32::handle_enable_menu_item(engine, state),
        WinApiId::User32Checkmenuitem => user32::handle_check_menu_item(engine, state),
        WinApiId::User32Getmessagea => user32::handle_get_message_a(engine, state),
        WinApiId::User32Translatemessage => user32::handle_translate_message(engine),
        WinApiId::User32Defwindowproca => user32::handle_def_window_proc_a(engine),
        WinApiId::User32Defwindowprocw => user32::handle_def_window_proc_w(engine),
        WinApiId::User32Defframeproca => user32::handle_def_frame_proc_a(engine),
        WinApiId::User32Defframeprocw => user32::handle_def_frame_proc_w(engine),
        WinApiId::User32Defmdichildproca => user32::handle_def_mdi_child_proc_a(engine),
        WinApiId::User32Defmdichildprocw => user32::handle_def_mdi_child_proc_w(engine),
        WinApiId::User32Createmenu => user32::handle_create_menu(engine, state),
        WinApiId::User32Createpopupmenu => user32::handle_create_popup_menu(engine, state),
        WinApiId::User32Appendmenua => user32::handle_append_menu_a(engine),
        WinApiId::User32Appendmenuw => user32::handle_append_menu_w(engine),
        WinApiId::User32Setmenu => user32::handle_set_menu(engine),
        WinApiId::User32Destroymenu => user32::handle_destroy_menu(engine),
        WinApiId::User32Removemenu => user32::handle_remove_menu(engine),
        WinApiId::User32Deletemenu => user32::handle_delete_menu(engine),
        WinApiId::User32Modifymenua => user32::handle_modify_menu_a(engine),
        WinApiId::User32Modifymenuw => user32::handle_modify_menu_w(engine),
        WinApiId::User32Getsystemmenu => user32::handle_get_system_menu(engine, state),
        WinApiId::User32Trackpopupmenu => user32::handle_track_popup_menu(engine),
        WinApiId::User32Getmenuiteminfoa => user32::handle_get_menu_item_info_a(engine),
        WinApiId::User32Getmenuiteminfow => user32::handle_get_menu_item_info_w(engine),
        WinApiId::User32Setmenuiteminfoa => user32::handle_set_menu_item_info_a(engine),
        WinApiId::User32Setmenuiteminfow => user32::handle_set_menu_item_info_w(engine),
        WinApiId::User32Checkmenuradioitem => user32::handle_check_menu_radio_item(engine),
        WinApiId::User32Dispatchmessagea => user32::handle_dispatch_message_a(engine, state),
        WinApiId::D3d9Idirect3ddevice9Release => d3d9::handle_device_release(engine, state),
        WinApiId::D3d9Idirect3d9Release => d3d9::handle_direct3d9_release(engine, state),
    }
}

/// Cold-path wrapper for callers that only have library/name strings.
pub fn dispatch_winapi(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: WinApiEnvironment,
    state: &mut WinApiState,
    library: &str,
    name: &str,
) -> Result<WinApiHandlerResult> {
    if let Some(id) = resolve_winapi_id(library, name) {
        return dispatch_winapi_id(engine, environment, state, id);
    }
    // UCRT API sets (api-ms-win-crt-*.dll) + ucrtbase/msvcrt — CRT-linked PEs.
    if crate::ucrt::is_ucrt_library(library) {
        return crate::ucrt::dispatch_ucrt(engine, environment, state, name);
    }
    // Kernel32 CRT-deps not yet in the dense id table (Virtual*, Tls*).
    if library.eq_ignore_ascii_case("KERNEL32.dll")
        && let Some(r) = kernel32::dispatch_kernel32_extra(engine, environment, state, name)?
    {
        return Ok(r);
    }
    if library.eq_ignore_ascii_case("ole32.dll")
        && let Some(r) = crate::ole32::dispatch_ole32(engine, state, name)?
    {
        return Ok(r);
    }
    if library.eq_ignore_ascii_case("shell32.dll")
        && let Some(r) = crate::shell32::dispatch_shell32(engine, state, name)?
    {
        return Ok(r);
    }
    if library.eq_ignore_ascii_case("advapi32.dll")
        && let Some(r) = advapi32::dispatch_advapi32_extra(engine, state, name)?
    {
        return Ok(r);
    }
    if library.eq_ignore_ascii_case("oleaut32.dll")
        && let Some(r) = crate::oleaut32::dispatch_oleaut32(engine, state, name)?
    {
        return Ok(r);
    }
    // Mingw runtime DLLs (pthread, libstdc++).
    if library.eq_ignore_ascii_case("libwinpthread-1.dll")
        || library.eq_ignore_ascii_case("libwinpthread-1")
        || library.starts_with("libwinpthread")
    {
        return crate::mingw_dispatch::dispatch_pthread(engine, name);
    }
    if library.eq_ignore_ascii_case("libstdc++-6.dll")
        || library.eq_ignore_ascii_case("libstdc++-6")
        || library.starts_with("libstdc++")
    {
        return crate::mingw_dispatch::dispatch_stdcpp(engine, state, name);
    }
    bail!("unsupported WinAPI call: {library}!{name}");
}

/// Fast classification for the runtime loop (no string compares per call).
///
/// Packed bitflags instead of four separate bools (avoids excessive-bools lint
/// and keeps the hot-path struct one byte).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WinApiTraits {
    bits: u8,
}

impl WinApiTraits {
    const NOISY: u8 = 1 << 0;
    const FAST_VOID_SYNC: u8 = 1 << 1;
    const EXIT_PROCESS: u8 = 1 << 2;
    const GUEST_STUB: u8 = 1 << 3;

    /// No flags set.
    pub const EMPTY: Self = Self { bits: 0 };

    #[must_use]
    pub const fn with_noisy(self) -> Self {
        Self {
            bits: self.bits | Self::NOISY,
        }
    }
    #[must_use]
    pub const fn with_fast_void_sync(self) -> Self {
        Self {
            bits: self.bits | Self::FAST_VOID_SYNC,
        }
    }
    #[must_use]
    pub const fn with_exit_process(self) -> Self {
        Self {
            bits: self.bits | Self::EXIT_PROCESS,
        }
    }
    #[must_use]
    pub const fn with_guest_stub(self) -> Self {
        Self {
            bits: self.bits | Self::GUEST_STUB,
        }
    }

    #[must_use]
    pub const fn noisy(self) -> bool {
        self.bits & Self::NOISY != 0
    }
    #[must_use]
    pub const fn fast_void_sync(self) -> bool {
        self.bits & Self::FAST_VOID_SYNC != 0
    }
    #[must_use]
    pub const fn exit_process(self) -> bool {
        self.bits & Self::EXIT_PROCESS != 0
    }
    #[must_use]
    pub const fn guest_stub(self) -> bool {
        self.bits & Self::GUEST_STUB != 0
    }

    pub fn set_noisy(&mut self, on: bool) {
        if on {
            self.bits |= Self::NOISY;
        } else {
            self.bits &= !Self::NOISY;
        }
    }

    pub fn set_guest_stub(&mut self, on: bool) {
        if on {
            self.bits |= Self::GUEST_STUB;
        } else {
            self.bits &= !Self::GUEST_STUB;
        }
    }
}

impl WinApiId {
    #[must_use]
    pub const fn traits(self) -> WinApiTraits {
        match self {
            // CS must hit host handlers (owner/recursion). No in-guest VoidRet
            // and no fast_void_sync — those made Enter/Leave no-ops (MT.1).
            Self::Kernel32Entercriticalsection | Self::Kernel32Leavecriticalsection => {
                WinApiTraits::EMPTY.with_noisy()
            }
            // In-guest stubs / guest-accelerated (may still hit host fallback VAs).
            // Only APIs whose guest body matches Microsoft Learn + fixed WIE environment.
            Self::Kernel32Encodepointer
            | Self::Kernel32Decodepointer
            | Self::Kernel32Gettickcount
            | Self::Kernel32Getcurrentprocessid
            | Self::Kernel32Getcurrentthreadid
            | Self::Kernel32Sleep
            | Self::Kernel32Getacp
            | Self::Kernel32Getoemcp
            | Self::Kernel32Getsystemdefaultlangid
            | Self::Kernel32Getuserdefaultlangid
            | Self::Kernel32Getcommandlinea
            | Self::Kernel32Getcommandlinew
            | Self::Kernel32Getcurrentdirectoryw
            | Self::Kernel32Getlasterror
            | Self::Kernel32Setlasterror
            | Self::Kernel32Flsgetvalue
            | Self::Kernel32Flssetvalue
            | Self::Kernel32Heapalloc
            | Self::Kernel32Heapfree
            | Self::Kernel32Readfile
            | Self::Kernel32Setfilepointer
            | Self::Kernel32Getfilesize
            | Self::Kernel32Multibytetowidechar
            | Self::User32Getsystemmetrics
            | Self::User32Getsyscolor
            | Self::User32Getsyscolorbrush
            | Self::User32Getdesktopwindow => WinApiTraits::EMPTY.with_noisy().with_guest_stub(),
            Self::Kernel32Getfileinformationbyhandle
            | Self::Kernel32Getfiletype
            | Self::Kernel32Getprocaddress
            | Self::Kernel32Heaprealloc
            | Self::Kernel32Heapsize
            | Self::Kernel32Writefile => WinApiTraits::EMPTY.with_noisy(),
            _ => WinApiTraits::EMPTY,
        }
    }
}
