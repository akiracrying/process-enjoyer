#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib,"Version.lib")

#include <psapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <winver.h>

#include <AclAPI.h>

#define MAX_COUNT 1024

#define MAX_NAME_LENGTH		64
#define MAX_DETAILS_LENGTH	32
#define MAX_TYPE_LENGTH		7

/* Get Process fields */

void getOwnerAndSid(HANDLE hProcess);
void getDepAndAslr(HANDLE hProcess);
void getParentPidAndName(DWORD processID);
void getProcName(HANDLE hProcess);
void getProcDlls(HANDLE hProcess);
void getProcPathToExe(HANDLE hProcess);
void getProcType(HANDLE hProcess);
void getProcDescryption(const wchar_t* fileName);
void getIntegrityLevel(HANDLE hProcess);
void changeProcIntegrity(DWORD processID, wchar_t* integrity);

/* Get File information */
WCHAR* getFileIntegrityLevel(WCHAR* file_name);
void changeFileIntegrityLevel(WCHAR* file_name, WCHAR* integrity);

/* Functions to collect full info about all processes */
void processInfo(DWORD processID);
void processesDatabase();

/* Sending information to GUI through pipe */
void sendDatabase(HANDLE hPipe);
void establishPipe();

/* Auxiliary function (maybe useless) */
BOOL turnDebugPrivilege();

typedef struct process
{
	DWORD PID;
	wchar_t processName[MAX_NAME_LENGTH];
	wchar_t pathProcessExe[MAX_PATH];
	wchar_t processOwner[MAX_NAME_LENGTH];
	wchar_t SID[MAX_NAME_LENGTH];
	wchar_t procType[MAX_TYPE_LENGTH];
	wchar_t integrityLevel[MAX_DETAILS_LENGTH];
	wchar_t procDescryption[MAX_NAME_LENGTH];

	BOOL CLR;
	BOOL ASLR;
	BOOL DEP;
	wchar_t aslrDetails[MAX_DETAILS_LENGTH];
	wchar_t depDetails[MAX_DETAILS_LENGTH];

	wchar_t parentName[MAX_NAME_LENGTH];
	DWORD parentPID;

	wchar_t processDllsName[MAX_COUNT][MAX_NAME_LENGTH];
}process;

enum Command
{
	DATABASE,
	CHANGE_INTEGRITY,
	MANDATORY,
	CHANGE_MANDATORY,
	DISCONNECT,
	INTEGRITY
};