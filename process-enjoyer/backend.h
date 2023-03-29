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

#define MAX_NAME_LENGTH		256
#define MAX_DETAILS_LENGTH	32
#define MAX_TYPE_LENGTH		7

/* YES, these are not getters - just load info about process to struct process */

void getOwnerAndSid(HANDLE);
void getDepAndAslr(HANDLE);
void getParentPidAndName(DWORD);
void getIntegrityLevel(HANDLE);
void getProcName(HANDLE);
void getProcDlls(HANDLE);
void getProcPathToExe(HANDLE);
void getProcType(HANDLE);

void processInfo(DWORD);
void processesDatabase();

BOOL turnDebugPrivilege(DWORD);
void changeProcIntegrity(DWORD, wchar_t*);

void getFileIntegrity(const wchar_t*);
void changeFileIntegrity();

typedef struct process
{
	DWORD PID;
	wchar_t processName[MAX_NAME_LENGTH];
	wchar_t pathProcessExe[MAX_PATH];
	wchar_t processOwner[MAX_NAME_LENGTH];
	wchar_t SID[MAX_NAME_LENGTH];
	wchar_t procType[MAX_TYPE_LENGTH];
	wchar_t integrityLevel[MAX_DETAILS_LENGTH];
	wchar_t* procDescryption;

	BOOL CLR;
	BOOL ASLR;
	BOOL DEP;
	wchar_t aslrDetails[MAX_DETAILS_LENGTH];
	wchar_t depDetails[MAX_DETAILS_LENGTH];

	wchar_t parentName[MAX_NAME_LENGTH];
	DWORD parentPID;

	wchar_t processDllsName[MAX_COUNT][MAX_NAME_LENGTH];
}process;
