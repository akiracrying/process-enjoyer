#define _CRT_SECURE_NO_WARNINGS
#include "backend.h"

process Processes[MAX_PROC_COUNT] = { 0 };
size_t valid_proc_counter = 0;

size_t getOwnerAndSid(HANDLE hProcess)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        fprintf(stdout, "[Error]: Failed to get the process tocken - %d \n", GetLastError());
        return EXIT_FAILURE;
    }

    DWORD tokenBufferSize = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenBufferSize))
    {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_INSUFFICIENT_BUFFER || tokenBufferSize == 0)
        {
            fprintf(stdout, "[Error]: Failed to get token information size - %d \n", GetLastError());
            CloseHandle(hToken);
            return EXIT_FAILURE;
        }
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenBufferSize * sizeof(BYTE));
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenBufferSize, &tokenBufferSize))
    {
        fprintf(stdout, "[Error]: Failed to get token information - %d \n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return EXIT_FAILURE;
    }

    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    PSID pSid = (PSID)malloc(sidSize * sizeof(BYTE));
    if (pSid == NULL)
    {
        free(pTokenUser);
        CloseHandle(hToken);
        return EXIT_FAILURE;
    }

    if (!CopySid(sidSize, pSid, pTokenUser->User.Sid))
    {
        fprintf(stdout, "[Error]: Failed to copy SID - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return EXIT_FAILURE;
    }

    LPWSTR str_Sid;
    ConvertSidToStringSid(pSid, &str_Sid);
    wcscpy(Processes[valid_proc_counter].SID, str_Sid); // get SID

    TCHAR processName[256];
    DWORD nameSize = 256;
    TCHAR domain[256];
    DWORD domainSize = 256;
    SID_NAME_USE sidUse;

    if (!LookupAccountSid(NULL, pSid, processName, &nameSize, domain, &domainSize, &sidUse))
    {
        fprintf(stdout, "[Error]: Failed to lookup account SID - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return EXIT_FAILURE;
    }

    wcsncpy(Processes[valid_proc_counter].processOwner, processName, nameSize); // get Owner

    CloseHandle(hToken);
    return EXIT_SUCCESS;
}

void getDepAndAslr(HANDLE hProcess)
{
    PROCESS_MITIGATION_DEP_POLICY dep = { 0 };
    PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };

    GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep));

    if (dep.Enable)
    {
        Processes[valid_proc_counter].DEP = TRUE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (permanent)"), MAX_DETAILS);
    }
    else
    {
        Processes[valid_proc_counter].DEP = FALSE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (disabled)"), MAX_DETAILS);
    }

    GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr));

    if (aslr.EnableBottomUpRandomization && aslr.EnableHighEntropy)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (high entropy)"), MAX_DETAILS);
    }
    else if (aslr.EnableBottomUpRandomization)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR"), MAX_DETAILS);
    }
    else
    {
        Processes[valid_proc_counter].ASLR = FALSE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (disabled)"), MAX_DETAILS);
    }
}

void getParentPidAndName(DWORD processID)
{
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(h, &pe)) {
        do {
            if (pe.th32ProcessID == processID)
            {
                Processes[valid_proc_counter].parentPID = pe.th32ParentProcessID;
                HMODULE hMod;
                DWORD cbNeeded;
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Processes[valid_proc_counter].parentPID);

                if (!hProcess)
                {
                    CloseHandle(h);
                    return;
                }

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, Processes[valid_proc_counter].parentName,
                        sizeof(Processes[valid_proc_counter].parentName) / sizeof(WCHAR));
                }

                CloseHandle(hProcess);
                break;
            }
        } while (Process32Next(h, &pe));
    }

    CloseHandle(h);
}

void getIntegrityLevel(HANDLE hProcess)
{
    HANDLE tokenHandle;
    DWORD tokenIntegrityLevel;
    DWORD returnLength;

    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &tokenHandle))
    {
        if (!GetTokenInformation(tokenHandle, TokenIntegrityLevel, NULL, 0, &returnLength))
        {
            DWORD errorCode = GetLastError();
            if (errorCode != ERROR_INSUFFICIENT_BUFFER || returnLength == 0)
            {
                fprintf(stdout, "[Error]: Failed to get token information size - %d \n", GetLastError());
                CloseHandle(tokenHandle);
                return;
            }

            PTOKEN_MANDATORY_LABEL pIntegrityLevel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
            if (GetTokenInformation(tokenHandle, TokenIntegrityLevel, pIntegrityLevel, returnLength, &returnLength))
            {
                DWORD integrityLevel = *GetSidSubAuthority(pIntegrityLevel->Label.Sid, (DWORD)(UCHAR) * (GetSidSubAuthorityCount(pIntegrityLevel->Label.Sid) - 1));
                Processes[valid_proc_counter].integrityLevel = integrityLevel;

                if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
                {
                    // Low Integrity
                    wprintf(L"Low Process");
                }
                else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && integrityLevel < SECURITY_MANDATORY_HIGH_RID)
                {
                    // Medium Integrity
                    wprintf(L"Medium Process");
                }
                else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)
                {
                    // High Integrity
                    //wprintf(L"High Integrity Process");
                }
            }
            free(pIntegrityLevel);
        }
        //fprintf(stdout, "%d", GetLastError());
        CloseHandle(tokenHandle);
    }
}

void getProcName(HANDLE hProcess)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseName(hProcess, hMod, Processes[valid_proc_counter].processName,
            sizeof(Processes[valid_proc_counter].processName) / sizeof(WCHAR));
    }
}

void getProcDlls(HANDLE hProcess)
{
    DWORD cbNeeded;
    HMODULE hMods[1024];

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
        {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.

                //_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }
}

void getProcPathToExe(HANDLE hProcess)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleFileNameExW(hProcess, hMod, Processes[valid_proc_counter].pathProcessExe, MAX_PATH);
    }
}

void getProcType(HANDLE hProcess)
{
    BOOL Wow64Process = FALSE;
    if (!IsWow64Process(hProcess, &Wow64Process))
    {
        CloseHandle(hProcess);
        exit(EXIT_FAILURE);
    }

    if (!Wow64Process) // странно, но должно быть наоборот
        wcsncpy(Processes[valid_proc_counter].procType, TEXT("64-bit"), MAX_TYPE_LENGTH);
    else
        wcsncpy(Processes[valid_proc_counter].procType, TEXT("32-bit"), MAX_TYPE_LENGTH);
}

void processInfo(DWORD processID)
{
    Processes[valid_proc_counter].PID = processID; // get PID

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (!hProcess)
    {
        /* Doesn't matter - usually it's SYSTEM process*/
        return;
    }

    if (getOwnerAndSid(hProcess))
    {
        CloseHandle(hProcess);
        return;
    }

    getProcName(hProcess);

    getProcPathToExe(hProcess);

    getProcDlls(hProcess);

    getProcType(hProcess);

    getParentPidAndName(processID);

    getIntegrityLevel(hProcess);

    getDepAndAslr(hProcess);

    fprintf(stdout, "processName: %ws\n", Processes[valid_proc_counter].processName);
    fprintf(stdout, "PID: %lu\n", Processes[valid_proc_counter].PID);
    fprintf(stdout, "pathProcessExe: %ws\n", Processes[valid_proc_counter].pathProcessExe);
    fprintf(stdout, "processOwner: %ws\n", Processes[valid_proc_counter].processOwner);
    fprintf(stdout, "SID: %ws\n", Processes[valid_proc_counter].SID);
    fprintf(stdout, "procType: %ws\n", Processes[valid_proc_counter].procType);
    fprintf(stdout, "aslrDetails: %ws\n", Processes[valid_proc_counter].aslrDetails);
    fprintf(stdout, "depDetails: %ws\n", Processes[valid_proc_counter].depDetails);
    fprintf(stdout, "parentName: %ws\n", Processes[valid_proc_counter].parentName);
    fprintf(stdout, "parentPID: %lu\n", Processes[valid_proc_counter].parentPID);
    fprintf(stdout, "____________________________________________________________________\n");

    CloseHandle(hProcess);
    ++valid_proc_counter;
}

void processesDatabase()
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        fprintf(stdout, "[Error]: EnumProcesses - %d \n", GetLastError());
        exit(EXIT_FAILURE);
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (size_t i = 0; i < cProcesses; ++i)
    {
        if (aProcesses[i] != 0)
        {
            processInfo(aProcesses[i]);
        }
    }
}

BOOL turnDebugPrivilege(DWORD sePrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luidDebug;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidDebug;
    tp.Privileges[0].Attributes = sePrivilege;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        fprintf(stdout, "[Error]: ERROR_NOT_ALL_ASSIGNED");
    }

    CloseHandle(hToken);

    return TRUE;
}