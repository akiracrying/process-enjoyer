#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <sddl.h>
#include <tlhelp32.h>

#define MAX_PROC_COUNT 1024

#define MAX_NAME_LENGTH 256
#define MAX_PATH_LENGTH 512
#define MAX_DETAILS		32
#define MAX_TYPE_LENGTH 7

/* YES, these are not getters - just load info about process to struct process */

size_t getOwnerAndSid(HANDLE);
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

typedef struct process
{
	DWORD PID;
	wchar_t processName[MAX_NAME_LENGTH];
	wchar_t pathProcessExe[MAX_PATH_LENGTH];
	wchar_t processOwner[MAX_NAME_LENGTH];
	wchar_t SID[MAX_NAME_LENGTH];
	wchar_t procType[MAX_TYPE_LENGTH];
	DWORD integrityLevel;

	BOOL ASLR;
	BOOL DEP;
	wchar_t aslrDetails[MAX_DETAILS];
	wchar_t depDetails[MAX_DETAILS];

	wchar_t parentName[MAX_NAME_LENGTH];
	DWORD parentPID;

}process;
