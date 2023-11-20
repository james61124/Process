#ifndef MemoryProcess_H
#define MemoryProcess_H

#include "stdafx.h"
#include "AutoRun.h"
#include <aclapi.h>
#include <imagehlp.h>
#include <Sddl.h>
#include <Setupapi.h>
#include <initguid.h> 
#include <algorithm>

#include <Windows.h>
#include <Wintrust.h>
#include <Shellapi.h>
#include <Shobjidl.h>
#include <ShlGuid.h>

#include <winsock2.h>

#include <Iphlpapi.h>
#include <codecvt>

#define MAX_PATH_EX 512
#define MemoryMappedFilenameInformation 2
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define ANY_SIZE 1

struct process_info
{
	DWORD pid;
	int parent_pid;
	wstring process_name;
	time_t ProcessCreateTime;
	wstring process_path;
	wstring process_command;
	wstring user_name;
	wstring DigitalSignature;
	wstring ProductName;
	wstring FileVersion;
	wstring FileDescription;
	wstring CompanyName;
	DWORD Priority;

	
	wchar_t ProcessHash[40];
	wchar_t ParentPath[MAX_PATH_EX];
	wstring ParentProcessName;
	BOOL InjectionOther;
	BOOL InjectionPE;
	BOOL Injected;
	wstring StartRun;
	int Service;
	int AutoRun;
	BOOL HideAttribute;
	BOOL HideProcess;

	wstring Injection;
	wstring Hide;

	std::set<std::string> Abnormal_dll;
	std::set<std::string> InlineHookInfo;
	std::set<std::string> NetString;

	wstring AbnormalDll;
	wstring InlineHook;
	wstring Network;


};

typedef NTSTATUS(__stdcall* PNtQueryVirtualMemory)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	DWORD					 MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
	);

struct TCPInformation
{
	DWORD ProcessID;
	DWORD LocalAddr;
	DWORD LocalPort;
	DWORD RemoteAddr;
	DWORD RemotePort;
	DWORD State;
};

typedef struct _MIB_TCPROW_EX
{
	DWORD dwState;
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
	DWORD dwProcessId;
} MIB_TCPROW_EX, * PMIB_TCPROW_EX;
typedef struct _MIB_TCPTABLE_EX
{
	DWORD dwNumEntries;
	MIB_TCPROW_EX table[ANY_SIZE];
} MIB_TCPTABLE_EX, * PMIB_TCPTABLE_EX;
typedef DWORD(WINAPI* pAllocateAndGetTcpExTableFromStack)(
	PMIB_TCPTABLE_EX* pTcpTableEx,
	BOOL,
	HANDLE,
	DWORD,	  //0
	DWORD);	  //2

//typedef struct _MIB_TCPROW_OWNER_PID
//{
//	DWORD       dwState;
//	DWORD       dwLocalAddr;
//	DWORD       dwLocalPort;
//	DWORD       dwRemoteAddr;
//	DWORD       dwRemotePort;
//	DWORD       dwOwningPid;
//} MIB_TCPROW_OWNER_PID, * PMIB_TCPROW_OWNER_PID;

//typedef struct _MIB_TCPTABLE_OWNER_PID
//{
//	DWORD                dwNumEntries;
//	MIB_TCPROW_OWNER_PID table[ANY_SIZE];
//} MIB_TCPTABLE_OWNER_PID, * PMIB_TCPTABLE_OWNER_PID;

#define SIZEOF_TCPTABLE_OWNER_PID(X) (FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table[0]) + \
									  ((X) * sizeof(MIB_TCPROW_OWNER_PID)) + ALIGN_SIZE)







bool EnumProcess(map<DWORD,process_info> * pInfo);
void LoadProcessInfo(map<DWORD,process_info> * pInfo);
void GetProcessInfo(DWORD pid,process_info & pInfo);
void GetUserSID(HANDLE hProcess, TCHAR *szUserSID);
DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength);
DWORD GetProcessIdByProcessName(LPCWSTR pszProcessName);
string GetPriorityString(DWORD pValuse);

DWORD Md5Hash(TCHAR* FileName, TCHAR* HashStr/*,size_t HashStrlen*/);
void CheckInjectionPtn(set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE);
void LoadApiPattern(std::set<DWORD>* pApiName);
BOOL DumpExecute(DWORD pid, wchar_t* pName, set<DWORD>* pApiBace, set<DWORD>* pStr, TCHAR* pProcessPath, set<string>* pIsAbnormal_dll);
char* CStringToCharArray(wchar_t* str, UINT m_CodePage);
bool CheckDigitalSignature(TCHAR* m_Path);
void LoadBinaryStringsHash(BYTE* buf, DWORD pSize, set<DWORD>* pStrSet);
BOOL IsPESignature(BYTE* buffer, unsigned int buflen);
DWORD Process32or64(HANDLE hProcess);
int CheckIsInjection(DWORD pid, TCHAR* pProcessName);
int GetProcessMappedFileName(HANDLE ProcessHandle, PVOID BaseAddress, wchar_t* FileName);
int CheckIsStartRun(map<wstring, BOOL>* pService, set<wstring>* pStartRun, DWORD pid);
void CheckIsInlineHook(DWORD pid, set<string>* pInlineHook);
void FindFunctionAddress(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook);
void _clean_things(HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char* pErrorMessage);
void FindFunctionAddress32(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook);
char* GetOSVersion();
void GetTcpInformationXPEx(vector<TCPInformation>* pInfo);
void GetTcpInformationEx(vector<TCPInformation>* pInfo);
char* Convert2State(DWORD dwState);
void GetProcessPath(DWORD pid, TCHAR* pPath, bool IsGetTime, TCHAR* pTimeStr, TCHAR* pCTimeStr);
time_t filetime_to_timet(const FILETIME& ft);
//void SearchExecutePath(DWORD pid,wstring & pPath,TCHAR* pName);


#endif