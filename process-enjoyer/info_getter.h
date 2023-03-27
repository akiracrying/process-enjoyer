#pragma once
#include <Windows.h>
#include "processenjoyer.h"
#include "ui_processenjoyer.h"

#define MAX_COUNT 5

#define MAX_NAME_LENGTH 30
#define MAX_DETAILS_LENGTH 32
#define MAX_TYPE_LENGTH 7
enum actions{
	PID =0,
	PROCESS_NAME,
	PATH,
	OWNER,
	SID_NAME,
	TYPE,
	INT_LVL,
	CLR,
	ASLR,
	DEP,
	ASLR_DET,
	DEP_DET,
	PARENT_NAME,
	PARENT_PID,
	DLL
};
typedef struct process {
	DWORD PID;
	wchar_t processName[MAX_NAME_LENGTH];
	wchar_t pathProcessExe[MAX_PATH];
	wchar_t processOwner[MAX_NAME_LENGTH];
	wchar_t SID[MAX_NAME_LENGTH];
	wchar_t procType[MAX_TYPE_LENGTH];
	wchar_t integrityLevel[MAX_DETAILS_LENGTH];

	BOOL CLR;
	BOOL ASLR;
	BOOL DEP;
	wchar_t aslrDetails[MAX_DETAILS_LENGTH];
	wchar_t depDetails[MAX_DETAILS_LENGTH];

	wchar_t parentName[MAX_NAME_LENGTH];
	DWORD parentPID;

	wchar_t processDllsName[MAX_COUNT][MAX_COUNT];

}PROCESS;


PROCESS getProcessInfo();