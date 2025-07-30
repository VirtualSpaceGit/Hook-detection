#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <psapi.h>
#include <Shlwapi.h>
#include <cstdint>

#pragma warning(disable: 4996)
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef LONG NTSTATUS;
typedef HANDLE* PHANDLE;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NTAPI __stdcall

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessResourceManagement = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessConsoleHostProcess = 49,
    ProcessWindowInformation = 50,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair_Reusable = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    ThreadSwitchLegacyState = 19,
    ThreadIsTerminated = 20,
    ThreadLastSystemCall = 21,
    ThreadIoPriority = 22,
    ThreadCycleTime = 23,
    ThreadPagePriority = 24,
    ThreadActualBasePriority = 25,
    ThreadTebInformation = 26,
    ThreadCSwitchMon = 27,
    ThreadCSwitchPmu = 28,
    ThreadWow64Context = 29,
    ThreadGroupInformation = 30,
    ThreadUmsInformation = 31,
    ThreadCounterProfiling = 32,
    ThreadIdealProcessorEx = 33,
    MaxThreadInfoClass = 34
} THREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllInformation = 3,
    ObjectDataInformation = 4
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

typedef struct _API_INFO {
    std::string moduleName;
    std::string functionName;
    PVOID functionAddress;
    BYTE originalBytes[16];
    bool isHooked;
    std::string hookType;
} API_INFO, * PAPI_INFO;

class HookDetector {
private:
    std::vector<API_INFO> monitoredAPIs;
    HANDLE hConsole;
    bool monitoring;
    int scanInterval;

    const BYTE JMP_OPCODE = 0xE9;
    const BYTE NOP_OPCODE = 0x90;
    const BYTE RET_OPCODE = 0xC3;
    const BYTE PUSH_OPCODE = 0x68;
    const BYTE MOV_EAX_OPCODE = 0xB8;
    const BYTE MOV_RAX_OPCODE = 0x48;
    const BYTE CALL_OPCODE = 0xE8;
    const WORD JMP_INDIRECT = 0x25FF;

    void SetConsoleColor(WORD color) {
        SetConsoleTextAttribute(hConsole, color);
    }

    bool LoadCleanDLL(const std::string& dllPath, BYTE* buffer, SIZE_T size) {
        HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD bytesRead;
        IMAGE_DOS_HEADER dosHeader;
        ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL);

        SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        IMAGE_NT_HEADERS ntHeaders;
        ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL);

        CloseHandle(hFile);

        HMODULE hModule = LoadLibraryExA(dllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hModule) return false;

        memcpy(buffer, hModule, size);
        FreeLibrary(hModule);
        return true;
    }

    std::string DetectHookType(BYTE* bytes) {
        if (bytes[0] == JMP_OPCODE) {
            return "JMP Hook (0xE9)";
        }
        else if (bytes[0] == PUSH_OPCODE && bytes[5] == RET_OPCODE) {
            return "PUSH-RET Hook";
        }
        else if (bytes[0] == MOV_EAX_OPCODE || (bytes[0] == MOV_RAX_OPCODE && bytes[1] == 0xB8)) {
            return "MOV EAX/RAX Hook";
        }
        else if (bytes[0] == CALL_OPCODE) {
            return "CALL Hook";
        }
        else if (*(WORD*)bytes == JMP_INDIRECT) {
            return "JMP [RIP+X] Hook";
        }
        else if (bytes[0] == NOP_OPCODE && bytes[1] == NOP_OPCODE) {
            return "NOP Sled Hook";
        }
        else if (bytes[0] == RET_OPCODE) {
            return "RET Hook (Function Disabled)";
        }
        else {
            return "Unknown Hook Type";
        }
    }

    bool IsHooked(PVOID functionAddress, BYTE* originalBytes) {
        BYTE currentBytes[16] = { 0 };
        SIZE_T bytesRead;

        if (!ReadProcessMemory(GetCurrentProcess(), functionAddress, currentBytes,
            sizeof(currentBytes), &bytesRead)) {
            return false;
        }

        if (currentBytes[0] == JMP_OPCODE ||
            currentBytes[0] == CALL_OPCODE ||
            currentBytes[0] == NOP_OPCODE ||
            currentBytes[0] == RET_OPCODE ||
            currentBytes[0] == PUSH_OPCODE ||
            *(WORD*)currentBytes == JMP_INDIRECT) {
            return true;
        }

        if (memcmp(currentBytes, originalBytes, 5) != 0) {
            return true;
        }

        return false;
    }

    void InitializeAPIs() {
        struct APIEntry {
            const char* module;
            const char* function;
        } apis[] = {
            {"ntdll.dll", "NtSetInformationProcess"},
            {"ntdll.dll", "NtSetInformationThread"},
            {"ntdll.dll", "NtCreateThreadEx"},
            {"ntdll.dll", "NtQueryInformationProcess"},
            {"ntdll.dll", "NtQueryObject"},
            {"ntdll.dll", "NtClose"},
            {"ntdll.dll", "NtYieldExecution"},
            {"ntdll.dll", "NtSetDebugFilterState"},
            {"ntdll.dll", "NtCreateThread"},
            {"kernel32.dll", "CreateThread"},
            {"kernel32.dll", "CreateRemoteThread"},
            {"kernel32.dll", "CreateRemoteThreadEx"},
            {"kernel32.dll", "OutputDebugStringA"},
            {"kernel32.dll", "IsDebuggerPresent"},
            {"kernel32.dll", "CheckRemoteDebuggerPresent"}
        };

        for (const auto& api : apis) {
            HMODULE hModule = GetModuleHandleA(api.module);
            if (!hModule) {
                hModule = LoadLibraryA(api.module);
            }

            if (hModule) {
                PVOID funcAddr = GetProcAddress(hModule, api.function);
                if (funcAddr) {
                    API_INFO info;
                    info.moduleName = api.module;
                    info.functionName = api.function;
                    info.functionAddress = funcAddr;
                    info.isHooked = false;

                    SIZE_T bytesRead;
                    ReadProcessMemory(GetCurrentProcess(), funcAddr,
                        info.originalBytes, sizeof(info.originalBytes), &bytesRead);

                    monitoredAPIs.push_back(info);
                }
            }
        }
    }

    void DisplayHeader() {
        COORD coord = { 0, 0 };
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        DWORD dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
        DWORD cCharsWritten;
        FillConsoleOutputCharacter(hConsole, ' ', dwConSize, coord, &cCharsWritten);
        SetConsoleCursorPosition(hConsole, coord);

        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "==================================================\n";
        std::cout << "      ADVANCED HOOK DETECTION MONITOR v1.0        \n";
        std::cout << "==================================================\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        SYSTEMTIME st;
        GetLocalTime(&st);
        std::cout << "Last Scan: " << std::setfill('0')
            << std::setw(2) << st.wHour << ":"
            << std::setw(2) << st.wMinute << ":"
            << std::setw(2) << st.wSecond << std::setfill(' ') << "\n\n";
    }

    void DisplayResults() {
        int hookedCount = 0;

        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << std::left
            << std::setw(16) << "Module"
            << std::setw(32) << "Function"
            << std::setw(20) << "Address"
            << std::setw(12) << "Status"
            << "Hook Type\n";
        std::cout << std::string(100, '-') << "\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        for (auto& api : monitoredAPIs) {
            std::cout << std::left
                << std::setw(16) << api.moduleName
                << std::setw(32) << api.functionName;

            // Print address with hex formatting, then reset fill character
            std::cout << "0x" << std::hex << std::uppercase << std::setfill('0')
                << std::setw(16) << reinterpret_cast<uintptr_t>(api.functionAddress)
                << std::dec << std::setfill(' ') << "  ";

            if (api.isHooked) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << std::left << std::setw(10) << "HOOKED";
                std::cout << api.hookType;
                hookedCount++;
            }
            else {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << std::left << std::setw(10) << "CLEAN";
                std::cout << "-";
            }
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "\n";
        }

        std::cout << "\n" << std::string(100, '-') << "\n";

        if (hookedCount > 0) {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "\n[!] ALERT: " << hookedCount << " hooks detected! Suspicious activity present.\n";
        }
        else {
            SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "\n[+] All monitored APIs are clean. No hooks detected.\n";
        }
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

public:
    HookDetector(int interval = 4) : monitoring(true), scanInterval(interval) {
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        InitializeAPIs();
    }

    void ScanForHooks() {
        for (auto& api : monitoredAPIs) {
            BYTE currentBytes[16] = { 0 };
            SIZE_T bytesRead;

            if (ReadProcessMemory(GetCurrentProcess(), api.functionAddress,
                currentBytes, sizeof(currentBytes), &bytesRead)) {

                bool wasHooked = api.isHooked;
                api.isHooked = IsHooked(api.functionAddress, api.originalBytes);

                if (api.isHooked) {
                    api.hookType = DetectHookType(currentBytes);

                    if (!wasHooked) {
                        SYSTEMTIME st;
                        GetLocalTime(&st);
                        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                        std::cout << "\n[!] NEW HOOK DETECTED ["
                            << std::setfill('0') << std::setw(2) << st.wHour << ":"
                            << std::setw(2) << st.wMinute << ":"
                            << std::setw(2) << st.wSecond << std::setfill(' ') << "] "
                            << api.moduleName << "!" << api.functionName
                            << " (" << api.hookType << ")\n";
                        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    }
                }
            }
        }
    }

    void StartMonitoring() {
        while (monitoring) {
            DisplayHeader();
            ScanForHooks();
            DisplayResults();

            std::cout << "\n\nPress CTRL+C to exit...\n";
            std::cout << "Next scan in " << scanInterval << " seconds...\n";

            std::this_thread::sleep_for(std::chrono::seconds(scanInterval));
        }
    }

    void Stop() {
        monitoring = false;
    }
};

HookDetector* g_pDetector = nullptr;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        std::cout << "\n\n[*] Shutting down monitor...\n";
        if (g_pDetector) {
            g_pDetector->Stop();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return TRUE;
    }
    return FALSE;
}

int main() {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    SetConsoleTitleW(L"Hook Detection Monitor");

    std::cout << "==================================================\n";
    std::cout << "      ADVANCED HOOK DETECTION MONITOR v1.0        \n";
    std::cout << "==================================================\n\n";
    std::cout << "Initializing API monitoring...\n";

    const int scanInterval = 4;
    HookDetector detector(scanInterval);
    g_pDetector = &detector;

    std::cout << "Starting continuous monitoring...\n";
    std::cout << "Scan interval: " << scanInterval << " seconds\n\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    detector.StartMonitoring();

    return 0;
}
