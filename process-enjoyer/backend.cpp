#define _CRT_SECURE_NO_WARNINGS
#include "backend.h"

process Processes[MAX_COUNT] = { 0 };
size_t valid_proc_counter = 0;

void getOwnerAndSid(HANDLE hProcess)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        fprintf(stdout, "[Error]: OpenProcessToken - %d \n", GetLastError());
        return;
    }

    DWORD tokenBufferSize = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenBufferSize))
    {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_INSUFFICIENT_BUFFER || tokenBufferSize == 0)
        {
            fprintf(stdout, "[Error]: GetTokenInformation - %d \n", GetLastError());
            CloseHandle(hToken);
            return;
        }
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenBufferSize * sizeof(BYTE));
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenBufferSize, &tokenBufferSize))
    {
        fprintf(stdout, "[Error]: GetTokenInformation - %d \n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    PSID pSid = (PSID)malloc(sidSize * sizeof(BYTE));
    if (pSid == NULL)
    {
        fprintf(stdout, "[Error]: malloc - %d \n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    if (!CopySid(sidSize, pSid, pTokenUser->User.Sid))
    {
        fprintf(stdout, "[Error]: CopySid - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    LPWSTR str_Sid;
    ConvertSidToStringSid(pSid, &str_Sid);
    wcscpy(Processes[valid_proc_counter].SID, str_Sid);

    TCHAR processName[MAX_NAME_LENGTH];
    DWORD nameSize = MAX_NAME_LENGTH;
    TCHAR domain[MAX_NAME_LENGTH];
    DWORD domainSize = MAX_NAME_LENGTH;
    SID_NAME_USE sidUse;

    if (!LookupAccountSid(NULL, pSid, processName, &nameSize, domain, &domainSize, &sidUse))
    {
        fprintf(stdout, "[Error]: LookupAccountSid - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    wcsncpy(Processes[valid_proc_counter].processOwner, processName, nameSize);

    CloseHandle(hToken);
}

void getDepAndAslr(HANDLE hProcess)
{
    PROCESS_MITIGATION_DEP_POLICY dep = { 0 };
    PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };

    GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep));

    if (dep.Enable)
    {
        Processes[valid_proc_counter].DEP = TRUE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (permanent)"), MAX_DETAILS_LENGTH);
    }
    else
    {
        Processes[valid_proc_counter].DEP = FALSE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (disabled)"), MAX_DETAILS_LENGTH);
    }

    GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr));

    if (aslr.EnableBottomUpRandomization && aslr.EnableHighEntropy)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (high entropy)"), MAX_DETAILS_LENGTH);
    }
    else if (aslr.EnableBottomUpRandomization)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR"), MAX_DETAILS_LENGTH);
    }
    else
    {
        Processes[valid_proc_counter].ASLR = FALSE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (disabled)"), MAX_DETAILS_LENGTH);
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
    HANDLE hToken;
    DWORD returnLength;

    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
    {
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength))
        {
            DWORD errorCode = GetLastError();
            if (errorCode != ERROR_INSUFFICIENT_BUFFER || returnLength == 0)
            {
                fprintf(stdout, "[Error]: GetTokenInformation - %d\n", GetLastError());
                CloseHandle(hToken);
                return;
            }

            PTOKEN_MANDATORY_LABEL pIntegrityLevel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
            if (pIntegrityLevel != NULL)
            {
                if (GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLevel, returnLength, &returnLength))
                {
                    DWORD integrityLevel = *GetSidSubAuthority(pIntegrityLevel->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pIntegrityLevel->Label.Sid) - 1));

                    if (integrityLevel < SECURITY_MANDATORY_LOW_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Untrusted"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel == SECURITY_MANDATORY_LOW_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Low"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && integrityLevel < SECURITY_MANDATORY_HIGH_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Medium"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID && integrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("High"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("System"), MAX_DETAILS_LENGTH);
                    }
                }
                free(pIntegrityLevel);
            }
        }
        CloseHandle(hToken);
    }
}

void getProcName(HANDLE hProcess)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseName(hProcess, hMod, Processes[valid_proc_counter].processName, MAX_NAME_LENGTH);
    }
}

void getProcDlls(HANDLE hProcess)
{
    DWORD cbNeeded;
    HMODULE hMods[MAX_COUNT];

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count && i < MAX_COUNT; ++i)
        {
            if (GetModuleBaseName(hProcess, hMods[i], Processes[valid_proc_counter].processDllsName[i], MAX_NAME_LENGTH))
            {
                if (wcsstr(Processes[valid_proc_counter].processDllsName[i], TEXT("clr")) != NULL
                    || wcsstr(Processes[valid_proc_counter].processDllsName[i], TEXT("mscor")) != NULL)
                {
                    Processes[valid_proc_counter].CLR = TRUE;
                }
            }
            //_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
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

void getProcDescryption(const wchar_t* fileName)
{
    int versionInfoSize = GetFileVersionInfoSize(fileName, NULL);
    if (!versionInfoSize)
    {
        fprintf(stdout, "[Error]: GetFileVersionInfoSize - %d\n", GetLastError());
        return;
    }

    BYTE* versionInfo = (BYTE*)malloc(versionInfoSize * sizeof(BYTE));
    if (versionInfo == NULL)
    {
        fprintf(stdout, "[Error]: malloc - %d\n", GetLastError());
        return;
    }

    if (!GetFileVersionInfo(fileName, NULL, versionInfoSize, versionInfo))
    {
        fprintf(stdout, "[Error]: GetTokenInformation - %d\n", GetLastError());
        return;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *translationArray;

    UINT translationArrayByteLength = 0;
    if (!VerQueryValue(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*)&translationArray, &translationArrayByteLength))
    {
        fprintf(stdout, "[Error]: VerQueryValue - %d\n", GetLastError());
        return;
    }

    for (unsigned int i = 0; i < (translationArrayByteLength / sizeof(LANGANDCODEPAGE)); ++i)
    {
        wchar_t fileDescriptionKey[256];
        wsprintf(fileDescriptionKey, L"\\StringFileInfo\\%04x%04x\\FileDescription", translationArray[i].wLanguage, translationArray[i].wCodePage);

        UINT fileDescriptionSize;
        VerQueryValue(versionInfo, fileDescriptionKey, (LPVOID*)&Processes[valid_proc_counter].procDescryption, &fileDescriptionSize);
    }
}

void processInfo(DWORD processID)
{
    Processes[valid_proc_counter].PID = processID;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (!hProcess)
    {
        /* Doesn't matter - usually it's SYSTEM process*/
        return;
    }

    getOwnerAndSid(hProcess);

    getProcName(hProcess);

    getProcPathToExe(hProcess);

    getProcDescryption(Processes[valid_proc_counter].pathProcessExe);

    getProcDlls(hProcess);

    getProcType(hProcess);

    getParentPidAndName(processID);

    getIntegrityLevel(hProcess);

    getDepAndAslr(hProcess);

    fprintf(stdout, "procDescryption: %ws\n", Processes[valid_proc_counter].procDescryption);
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
    fprintf(stdout, "integrityLevel: %ws\n", Processes[valid_proc_counter].integrityLevel);
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

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("[Error]: OpenProcessToken - %d\n", GetLastError());
        return FALSE;
    }

    LUID luidDebug;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
    {
        printf("[Error]: LookupPrivilegeValue - %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidDebug;
    tp.Privileges[0].Attributes = sePrivilege;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("[Error]: AdjustTokenPrivileges - %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        fprintf(stdout, "[Error]: ERROR_NOT_ALL_ASSIGNED");
        CloseHandle(hToken);
        return TRUE;
    }

    CloseHandle(hToken);

    return TRUE;
}

void changeProcIntegrity(DWORD processID, wchar_t* integrity)
{
    DWORD dwProcessId = processID;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    if (hProcess == NULL)
    {
        printf("[Error]: OpenProcess - %d\n", GetLastError());
        return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &hToken))
    {
        printf("[Error]: OpenProcessToken - %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    DWORD dwSize = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize))
    {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_INSUFFICIENT_BUFFER || dwSize == 0)
        {
            printf("[Error]: GetTokenInformation - %d\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return;
        }
    }

    TOKEN_MANDATORY_LABEL* pIntegrityLabel = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLabel, dwSize, &dwSize))
    {
        printf("[Error]: GetTokenInformation - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    PSID lowSid = { 0 };
    if (!ConvertStringSidToSid(L"S-1-16-4096", &lowSid))
    {
        printf("[Error]: ConvertStringSidToSid - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    pIntegrityLabel->Label.Sid = lowSid;

    if (!SetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLabel, dwSize))
    {
        printf("[Error]: SetTokenInformation - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    free(pIntegrityLabel);
    CloseHandle(hToken);
    CloseHandle(hProcess);
}

void getFileIntegrity(const wchar_t* filePath)
{
    //LPCWSTR fileName = L"D:\\service\\log.txt";

    //PACL Sacl;
    //PSECURITY_DESCRIPTOR pSD;
    //PULONG pil = (PULONG)SECURITY_MANDATORY_MEDIUM_RID;// default LABEL

    //ULONG err = GetNamedSecurityInfoW(fileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &Sacl, &pSD);

    //printf("%d", GetLastError());

    //if (!err)
    //{
    //    if (Sacl)
    //    {
    //        union {
    //            PVOID Ace;
    //            PSYSTEM_MANDATORY_LABEL_ACE pLabel;
    //            PACE_HEADER pHeader;
    //        };

    //        err = ERROR_GEN_FAILURE;

    //        ACL_SIZE_INFORMATION asi;

    //        if (GetAclInformation(Sacl, &asi, sizeof(asi), AclSizeInformation))
    //        {
    //            PSID Sid;

    //            union {
    //                PUCHAR pc;
    //                PULONG pl;
    //            };

    //            static SID_IDENTIFIER_AUTHORITY LabelAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;

    //            switch (asi.AceCount)
    //            {
    //            case 1:
    //                if (GetAce(Sacl, 0, &Ace))
    //                {
    //                    if (pHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
    //                    {
    //                        Sid = &pLabel->SidStart;

    //                        if (pc = GetSidSubAuthorityCount(Sid))
    //                        {
    //                            if (*pc == 1 && !memcmp(&LabelAuth, GetSidIdentifierAuthority(Sid), sizeof(SID_IDENTIFIER_AUTHORITY)))
    //                            {
    //                                if (pl = GetSidSubAuthority(Sid, 0))
    //                                {
    //                                    *pil = *pl;
    //            case 0:
    //                err = ERROR_SUCCESS;
    //                                }
    //                            }
    //                        }
    //                    }
    //                }
    //                break;
    //            }
    //        }
    //    }

    //    LocalFree(pSD);
    //}
}

void changeFileIntegrity()
{
    LPCWSTR filePath = L"D:\\service\\log.txt";

    PSECURITY_DESCRIPTOR pSecurityDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"S:(ML;;NX;;;LW)", SDDL_REVISION_1, &pSecurityDescriptor, NULL))
    {
        fprintf(stdout, "[Error]: ConvertStringSecurityDescriptorToSecurityDescriptor - %d", GetLastError());
        return;
    }

    // Set the security descriptor on the file
    if (SetNamedSecurityInfo((LPWSTR)filePath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, (PACL)pSecurityDescriptor) != ERROR_SUCCESS)
    {
        fprintf(stdout, "[Error]: SetNamedSecurityInfo - %d", GetLastError());
        LocalFree(pSecurityDescriptor);
        return;
    }
    LocalFree(pSecurityDescriptor);
}

void establishPipe()
{
    HANDLE hPipe;

    hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\Pipe"),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        1024 * 16,
        1024 * 16,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        fprintf(stdout, "[Error]: CreateNamedPipe - %d\n", GetLastError());
        return;
    }

    //////////////////////// GET DATABASE OF PROCESS //////////////////////////////

    DWORD sePrivilege = SE_PRIVILEGE_ENABLED;
    turnDebugPrivilege(sePrivilege);

    processesDatabase();

    sePrivilege = 0;
    turnDebugPrivilege(sePrivilege);

    //////////////////////// SEND DATABASE TO GUI //////////////////////////////

    DWORD dwRead;
    DWORD dwWritten;
    wchar_t buffer[1024] = { 0 };

    while (1)
    {
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for GUI to connect to the pipe
        {
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
            {
                /* Just hello message to initiate the process of sending the Database */
                fprintf(stdout, "%ws", buffer);
            }

            WriteFile(hPipe, &valid_proc_counter, sizeof(valid_proc_counter), &dwWritten, NULL);

            for (size_t i = 0; i < valid_proc_counter; ++i)
            {
                WriteFile(hPipe, Processes[i].processName, sizeof(Processes[i].processName), &dwWritten, NULL);
                /*WriteFile(hPipe, &Processes[i].PID, sizeof(Processes[i].PID), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].pathProcessExe, sizeof(Processes[i].pathProcessExe), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].processOwner, sizeof(Processes[i].processOwner), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].SID, sizeof(Processes[i].SID), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].procType, sizeof(Processes[i].procType), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].aslrDetails, sizeof(Processes[i].aslrDetails), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].depDetails, sizeof(Processes[i].depDetails), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].parentName, sizeof(Processes[i].parentName), &dwWritten, NULL);
                WriteFile(hPipe, &Processes[i].parentPID, sizeof(Processes[i].parentPID), &dwWritten, NULL);
                WriteFile(hPipe, Processes[i].integrityLevel, sizeof(Processes[i].integrityLevel), &dwWritten, NULL);*/
            }

            //WriteFile(hPipe, "Hello too\n", 12, &dwWritten, NULL);
        }

        DisconnectNamedPipe(hPipe);
    }

    CloseHandle(hPipe);
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");

    //establishPipe();

    DWORD sePrivilege = SE_PRIVILEGE_ENABLED;
    turnDebugPrivilege(sePrivilege);

    getFileIntegrity(L"D:\\service\\log.txt");
    //changeFileIntegrity();
    //getFileIntegrity(L"D:\\service\\log.txt");

    processesDatabase();

    sePrivilege = 0;
    turnDebugPrivilege(sePrivilege);

    system("pause");
    return 0;
}
