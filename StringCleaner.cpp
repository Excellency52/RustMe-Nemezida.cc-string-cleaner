#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <iostream>
#include <conio.h>
#include <psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

const std::vector<std::string> TARGET_STRINGS = {
    "nemezida",
};

std::string ptr_to_hex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << ptr;
    return oss.str();
}

bool SetPrivilege(HANDLE hToken, LPCTSTR name) {
    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValue(nullptr, name, &tp.Privileges[0].Luid))
        return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllDebugPrivileges() {
    HANDLE ht;
    if (OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &ht))
    {
        const LPCTSTR privs[] = {
            SE_DEBUG_NAME,
            SE_BACKUP_NAME,
            SE_RESTORE_NAME,
            SE_TAKE_OWNERSHIP_NAME,
            SE_SECURITY_NAME,
            SE_MANAGE_VOLUME_NAME
        };
        for (auto p : privs) SetPrivilege(ht, p);
        CloseHandle(ht);
    }
}

std::vector<HANDLE> SuspendAllThreads(DWORD pid) {
    std::vector<HANDLE> threads;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hs == INVALID_HANDLE_VALUE) return threads;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(hs, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hT) {
                    SuspendThread(hT);
                    threads.push_back(hT);
                }
            }
        } while (Thread32Next(hs, &te));
    }
    CloseHandle(hs);
    return threads;
}

void ResumeAllThreads(const std::vector<HANDLE>& threads) {
    for (HANDLE hT : threads) {
        ResumeThread(hT);
        CloseHandle(hT);
    }
}

bool TryReadRegion(HANDLE hProc, LPCVOID base, std::vector<char>& buf, SIZE_T& outRead) {
    if (ReadProcessMemory(hProc, base, buf.data(), buf.size(), &outRead))
        return true;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, base, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    DWORD oldProt;
    if (!VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;

    bool ok = ReadProcessMemory(hProc, base, buf.data(), buf.size(), &outRead);
    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
    return ok;
}

bool TryZeroMemory(HANDLE hProc, uintptr_t addr, size_t len, std::ostringstream& log) {
    std::vector<char> zeros(len, 0);
    SIZE_T written = 0;

    if (WriteProcessMemory(hProc, (LPVOID)addr, zeros.data(), len, &written)) {
        log << "    ✔ Write OK (wrote " << written << "/" << len << " bytes)\n";
        FlushInstructionCache(hProc, (LPCVOID)addr, len);
        return written == len;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        log << "    ✘ VirtualQueryEx failed (" << GetLastError() << ")\n";
        return false;
    }

    const DWORD protections[] = {
        PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_WRITECOPY
    };

    for (DWORD prot : protections) {
        DWORD oldProt;
        if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, prot, &oldProt)) {
            if (WriteProcessMemory(hProc, (LPVOID)addr, zeros.data(), len, &written)) {
                log << "    ✔ Write after protection change (0x" << std::hex << prot << ") OK\n";
                FlushInstructionCache(hProc, (LPCVOID)addr, len);
                VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
                return written == len;
            }
            VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
        }
    }

    log << "    ✘ All protection attempts failed (LastError: " << GetLastError() << ")\n";
    return false;
}

DWORD FindProcessIdByWindow(const std::wstring& windowTitle) {
    HWND hWindow = FindWindowW(nullptr, windowTitle.c_str());
    if (hWindow == nullptr) {
        std::wcerr << L"Window '" << windowTitle << L"' not found!\n";
        return 0;
    }

    DWORD processId = 0;
    GetWindowThreadProcessId(hWindow, &processId);
    if (processId == 0) {
        std::wcerr << L"Failed to get process ID for window '" << windowTitle << L"'\n";
        return 0;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == nullptr) {
        std::wcerr << L"Failed to open process (" << processId << L")\n";
        return processId; 
    }

    WCHAR processName[MAX_PATH] = L"<unknown>";
    if (GetModuleFileNameExW(hProcess, nullptr, processName, MAX_PATH) == 0) {
        std::wcerr << L"Failed to get process name (" << GetLastError() << L")\n";
    }
    CloseHandle(hProcess);

    std::wcout << L"\nFound target process:\n";
    std::wcout << L"  Window title: " << windowTitle << L"\n";
    std::wcout << L"  Process ID:   " << processId << L"\n";
    std::wcout << L"  Process name: " << processName << L"\n\n";

    return processId;
}

struct FoundString {
    std::string content;
    uintptr_t address;
};

std::vector<FoundString> FindTargetStrings(HANDLE hProc) {
    std::vector<FoundString> found;
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);

    std::vector<std::string> lowerTargets;
    std::vector<std::wstring> wideLowerTargets;
    for (const auto& target : TARGET_STRINGS) {
        std::string lowerTarget;
        std::wstring wideLowerTarget;
        lowerTarget.reserve(target.size());
        wideLowerTarget.reserve(target.size());

        std::transform(target.begin(), target.end(), std::back_inserter(lowerTarget),
            [](char c) { return std::tolower(c); });
        std::transform(target.begin(), target.end(), std::back_inserter(wideLowerTarget),
            [](char c) { return std::tolower(c); });

        lowerTargets.push_back(lowerTarget);
        wideLowerTargets.push_back(wideLowerTarget);
    }

    const size_t MAX_BUFFER_SIZE = 2 * 1024 * 1024; 
    const bool ENABLE_UTF16_SEARCH = true;

    std::vector<MEMORY_BASIC_INFORMATION> regions;
    uintptr_t addr = (uintptr_t)sys.lpMinimumApplicationAddress;
    uintptr_t max = (uintptr_t)sys.lpMaximumApplicationAddress;

    while (addr < max) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            regions.push_back(mbi);
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    std::cout << "Scanning memory regions: 0/" << regions.size() << "\r";

    std::vector<char> buffer;
    for (size_t i = 0; i < regions.size(); ++i) {
        const auto& mbi = regions[i];
        size_t regionSize = mbi.RegionSize;
        uintptr_t currentAddr = (uintptr_t)mbi.BaseAddress;

        std::cout << "Scanning memory regions: " << (i + 1) << "/" << regions.size() << "\r";

        while (regionSize > 0) {
            size_t chunkSize = std::min<size_t>(regionSize, MAX_BUFFER_SIZE);
            buffer.resize(chunkSize);
            SIZE_T bytesRead = 0;

            if (!TryReadRegion(hProc, (LPCVOID)currentAddr, buffer, bytesRead) || bytesRead == 0) {
                break;
            }

            for (size_t t = 0; t < lowerTargets.size(); ++t) {
                const auto& target = lowerTargets[t];
                const size_t targetLen = target.size();
                if (bytesRead < targetLen) continue;

                for (size_t pos = 0; pos <= bytesRead - targetLen; ++pos) {
                    bool match = true;
                    for (size_t j = 0; j < targetLen; ++j) {
                        if (std::tolower(buffer[pos + j]) != target[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        found.push_back({
                            "[ANSI] " + TARGET_STRINGS[t],
                            currentAddr + pos
                            });
                    }
                }
            }

            if (ENABLE_UTF16_SEARCH && bytesRead >= 2) {
                const wchar_t* wbuf = reinterpret_cast<const wchar_t*>(buffer.data());
                const size_t wbufLen = bytesRead / sizeof(wchar_t);

                for (size_t t = 0; t < wideLowerTargets.size(); ++t) {
                    const auto& target = wideLowerTargets[t];
                    const size_t targetLen = target.size();
                    if (wbufLen < targetLen) continue;

                    for (size_t pos = 0; pos <= wbufLen - targetLen; ++pos) {
                        bool match = true;
                        for (size_t j = 0; j < targetLen; ++j) {
                            if (std::tolower(wbuf[pos + j]) != target[j]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            found.push_back({
                                "[UTF-16] " + TARGET_STRINGS[t],
                                currentAddr + pos * sizeof(wchar_t)
                                });
                        }
                    }
                }
            }

            currentAddr += chunkSize;
            regionSize -= chunkSize;
        }
    }

    std::cout << "\nScanning completed. Found " << found.size() << " matches.\n";
    return found;
}

std::string CleanFoundStrings(DWORD pid, const std::vector<FoundString>& found) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
        return "ERROR: Cannot open process with full access. Try running as Administrator.\r\n";

    EnableAllDebugPrivileges();
    auto suspended = SuspendAllThreads(pid);

    std::ostringstream log;
    log << "Found " << found.size() << " potential targets. Starting cleanup...\n\n";

    size_t success_count = 0;
    size_t failed_count = 0;

    for (const auto& fs : found) {
        size_t clean_size = fs.content.size();
        if (fs.content.find("[UTF-16]") == 0) {
            clean_size = (fs.content.size() - 9) * sizeof(wchar_t);
        }

        log << "Target: \"" << fs.content << "\" at " << ptr_to_hex(fs.address)
            << " (cleaning " << clean_size << " bytes)\n";

        if (TryZeroMemory(hProc, fs.address, clean_size, log)) {
            success_count++;
            log << "  ✔ Successfully cleaned\n";
        }
        else {
            failed_count++;
            log << "  ✘ Clean failed\n";
        }
        log << "----------------------------------------\n";
    }

    ResumeAllThreads(suspended);
    CloseHandle(hProc);

    log << "\nCleanup summary:\n";
    log << "  Successfully cleaned: " << success_count << "\n";
    log << "  Failed to clean: " << failed_count << "\n";
    log << "  Total targets processed: " << found.size() << "\n";

    return log.str();
}

void PrintTargetStrings() {
    std::cout << "Target strings that will be searched:\n";
    std::cout << "------------------------------------\n";
    for (const auto& str : TARGET_STRINGS) {
        std::cout << "  • " << str << "\n";
    }
    std::cout << "------------------------------------\n\n";
}

int main() {
    EnableAllDebugPrivileges();

    std::cout << "Memory String Cleaner Tool\n";
    std::cout << "==========================\n\n";

    PrintTargetStrings();

    const std::wstring targetWindowTitle = L"RustMe Client";
    std::wcout << L"Searching for window '" << targetWindowTitle << L"'...\n";

    DWORD pid = FindProcessIdByWindow(targetWindowTitle);
    if (pid == 0) {
        std::cerr << "Failed to find target process. Press any key to exit...";
        _getch();
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cerr << "Cannot open process for reading. Try running as Administrator.\n";
        std::cerr << "Press any key to exit...";
        _getch();
        return 1;
    }

    std::cout << "\nScanning process memory for target strings...\n";
    auto found = FindTargetStrings(hProc);
    CloseHandle(hProc);

    if (found.empty()) {
        std::cout << "No target strings found in process memory.\n";
    }
    else {
        std::cout << "\nFound " << found.size() << " occurrences:\n";
        for (const auto& fs : found) {
            std::cout << "  " << std::setw(20) << std::left << fs.content
                << " at " << ptr_to_hex(fs.address) << "\n";
        }

        std::cout << "\nStarting cleanup process...\n";
        std::string result = CleanFoundStrings(pid, found);
        std::cout << "\nCleanup results:\n" << result << "\n";
    }

    std::cout << "\nOperation completed. Press any key to exit...";
    _getch();

    return 0;
}