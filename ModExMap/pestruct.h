template <typename T>
struct _UNICODE_STRING_T
{
    WORD Length;
    WORD MaximumLength;
    T Buffer;
};

template <typename T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <typename T, typename NGF, int A>
struct _PEB_T
{
    typedef T type;

    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE BitField;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    T CrossProcessFlags;
    T UserSharedInfoPtr;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    T ApiSetMap;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T HotpatchInformation;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    T ActiveProcessAffinityMask;
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    DWORD FlsBitmapBits[4];
    T FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pContextData;
    T pImageHeaderHash;
    T TracingFlags;
    T CsrServerReadOnlySharedMemoryBase;
};

typedef _PEB_T<DWORD, DWORD64, 34> _PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> _PEB64;

typedef struct _STRING_32
{
    WORD Length;
    WORD MaximumLength;
    UINT32 Buffer;
} STRING32, * PSTRING32;

typedef struct _STRING_64
{
    WORD Length;
    WORD MaximumLength;
    UINT64 Buffer;
} STRING64, * PSTRING64;

typedef struct _RTL_DRIVE_LETTER_CURDIR_32
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, * PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR_64
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, * PRTL_DRIVE_LETTER_CURDIR64;

typedef struct _UNICODE_STRING_32
{
    WORD Length;
    WORD MaximumLength;
    UINT32 Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _UNICODE_STRING_64
{
    WORD Length;
    WORD MaximumLength;
    UINT64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;


typedef struct _CURDIR_32
{
    UNICODE_STRING32 DosPath;
    UINT32 Handle;
} CURDIR32, * PCURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS_32
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    UINT32 ConsoleHandle;
    ULONG ConsoleFlags;
    UINT32 StandardInput;
    UINT32 StandardOutput;
    UINT32 StandardError;
    CURDIR32 CurrentDirectory;
    UNICODE_STRING32 DllPath;
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
    UINT32 Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING32 WindowTitle;
    UNICODE_STRING32 DesktopInfo;
    UNICODE_STRING32 ShellInfo;
    UNICODE_STRING32 RuntimeData;
    RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;


typedef struct _CURDIR_64
{
    UNICODE_STRING64 DosPath;
    UINT64 Handle;
} CURDIR64, * PCURDIR64;

typedef struct _RTL_USER_PROCESS_PARAMETERS_64
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    UINT64 ConsoleHandle;
    ULONG ConsoleFlags;
    UINT64 StandardInput;
    UINT64 StandardOutput;
    UINT64 StandardError;
    CURDIR64 CurrentDirectory;
    UNICODE_STRING64 DllPath;
    UNICODE_STRING64 ImagePathName;
    UNICODE_STRING64 CommandLine;
    UINT64 Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING64 WindowTitle;
    UNICODE_STRING64 DesktopInfo;
    UNICODE_STRING64 ShellInfo;
    UNICODE_STRING64 RuntimeData;
    RTL_DRIVE_LETTER_CURDIR64 CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS64, * PRTL_USER_PROCESS_PARAMETERS64;



typedef struct _PROCESS_BASIC_INFORMATION64 {
    NTSTATUS ExitStatus;
    UINT32 Reserved0;
    UINT64 PebBaseAddress;
    UINT64 AffinityMask;
    UINT32 BasePriority;
    UINT32 Reserved1;
    UINT64 UniqueProcessId;
    UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    UINT32 PebBaseAddress;
    UINT32 AffinityMask;
    UINT32 BasePriority;
    UINT32 UniqueProcessId;
    UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;