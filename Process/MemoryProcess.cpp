#include "stdafx.h"
#include "MemoryProcess.h"
#include <psapi.h>
#include <Winternl.h>
#include <Sddl.h>
#include <TlHelp32.h>
#include "FileInfo.h"
#pragma comment(lib, "psapi.lib")
#if defined _M_X64
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined _M_IX86
typedef NTSTATUS (NTAPI *pZwQuerySystemInformation)(ULONG,PVOID,ULONG,PULONG);
#endif


typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO,*PSYSTEM_PROCESS_INFO;

bool EnumProcess(map<DWORD,process_info> * pInfo)
{
	NTSTATUS status;
    PVOID buffer;
    PSYSTEM_PROCESS_INFO spi;
 
    buffer=VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); // We need to allocate a large buffer because the process list can be large.
 
    if(!buffer)
    {
        //printf("\nError: Unable to allocate memory for process list (%d)\n",GetLastError());
        return false;
    }
 
   // printf("\nProcess list allocated at address %#x\n",buffer);
    spi=(PSYSTEM_PROCESS_INFO)buffer;
	#if defined _M_X64
    if(!NT_SUCCESS(status=NtQuerySystemInformation(SystemProcessInformation,spi,1024*1024,NULL)))
    {
        //printf("\nError: Unable to query process list (%#x)\n",status);
 
        VirtualFree(buffer,0,MEM_RELEASE);
        return false;
    }
	#elif defined _M_IX86
	pZwQuerySystemInformation ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwQuerySystemInformation");
	if(!NT_SUCCESS(status=ZwQuerySystemInformation(SystemProcessInformation,spi,1024*1024,NULL)))
    {
        //printf("\nError: Unable to query process list (%#x)\n",status);
 
        VirtualFree(buffer,0,MEM_RELEASE);
        return false;
    }
	#endif
	//time (&LoadProcessTime);
    while(spi->NextEntryOffset) // Loop over the list until we reach the last entry.
    {
		if((int)spi->ProcessId > 0)
		{
			process_info  m_Info = {0};
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = (int)spi->InheritedFromProcessId;
			m_Info.process_name = spi->ImageName.Buffer;
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			//swprintf_s(m_Info.process_name,MAX_PATH,L"%s",spi->ImageName.Buffer);
			m_Info.ProcessCreateTime = spi->CreateTime.QuadPart/ 10000000ULL - 11644473600ULL;
			if(m_Info.ProcessCreateTime < 0)
				m_Info.ProcessCreateTime = 0;
			pInfo->insert(pair<DWORD,process_info>((DWORD)m_Info.pid,m_Info));
			//SYSTEMTIME sys = TimetToSystemTimeEx((time_t)m_Ctime);
		}
		else if((int)spi->ProcessId == 0)
		{
			process_info  m_Info = {0};
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = -1;
			m_Info.process_name = L"[System Process]";
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			//swprintf_s(m_Info.process_name,MAX_PATH,L"[System Process]");
			m_Info.ProcessCreateTime = 0;
			pInfo->insert(pair<DWORD,process_info>((DWORD)m_Info.pid,m_Info));
		}
		spi=(PSYSTEM_PROCESS_INFO)((LPBYTE)spi+spi->NextEntryOffset); // Calculate the address of the next entry.
    }
     
    //printf("\nPress any key to continue.\n");
    //getchar();
    VirtualFree(buffer,0,MEM_RELEASE); // Free the allocated buffer.
	return true;
}
void LoadProcessInfo(map<DWORD,process_info> * pInfo)
{
	if(!pInfo->empty())
	{
		map<DWORD,process_info>::iterator it;
		for(it = pInfo->begin();it != pInfo->end();it++)
		{
			printf("process_id: %d\n", it->first);
			GetProcessInfo(it->first,it->second);
		}
	}
}
DWORD Md5Hash(TCHAR* FileName, TCHAR* HashStr/*,size_t HashStrlen*/)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[1024];
	DWORD cbRead = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	// LPCWSTR filename=L"C:\\Users\\RexLin\\Pictures\\Saved Pictures\\Koala.jpg";
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		// printf("Error opening file %s\nError: %d\n", FileName,dwStatus); 
		return dwStatus;
	}
	//DWORD m_Filesize = GetFileSize(hFile, NULL);
	//if(m_Filesize > SCAN_MAX_SIZE)
	//{
	//	dwStatus = 1382;
 //       printf("Exceed MAX Size: %d\n", dwStatus); 
 //       CloseHandle(hFile);
 //       return dwStatus;
	//}
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		return dwStatus;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			// printf("CryptHashData failed: %d\n", dwStatus); 
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}
	if (!bResult)
	{
		dwStatus = GetLastError();
		// printf("ReadFile failed: %d\n", dwStatus); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}
	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		// printf("MD5 hash of file %s is: ", FileName);
		for (DWORD i = 0; i < cbHash; i++)
		{
			TCHAR* cstr = new TCHAR[10];
			swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			lstrcat(HashStr, cstr);
			delete[] cstr;
			// printf("%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
			 //swprintf_s(HashStr,HashStrlen,_T("%s%c%c"),HashStr,rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
		}
		// printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		// printf("CryptGetHashParam failed: %d\n", dwStatus); 
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);
	return dwStatus;
}
void CheckInjectionPtn(set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE)
{
	//set<DWORD>::iterator it;
	//it = pStringsHash->find(3767103601);
	if ((pStringsHash->find(3767103601) != pStringsHash->end()) || (pStringsHash->find(3307083059) != pStringsHash->end()))
	{
		if ((pStringsHash->find(2707265234) != pStringsHash->end()) || (pStringsHash->find(2959245455) != pStringsHash->end())
			|| (pStringsHash->find(1588018759) != pStringsHash->end()))
		{
			if ((pStringsHash->find(2413463320) != pStringsHash->end()) || (pStringsHash->find(1863699581) != pStringsHash->end())
				|| (pStringsHash->find(748668459) != pStringsHash->end()) || (pStringsHash->find(1810605166) != pStringsHash->end()))
			{
				if ((pStringsHash->find(3481317475) != pStringsHash->end()) || (pStringsHash->find(2845710125) != pStringsHash->end()))
					pIsOther = TRUE;
			}
		}
	}

	if ((pStringsHash->find(1789965451) != pStringsHash->end()) || (pStringsHash->find(1383550409) != pStringsHash->end()))
	{
		if ((pStringsHash->find(2923117684) != pStringsHash->end()) || (pStringsHash->find(2922200202) != pStringsHash->end())
			|| (pStringsHash->find(2141139445) != pStringsHash->end()) || (pStringsHash->find(2999148978) != pStringsHash->end()))
		{
			if ((pStringsHash->find(1791678813) != pStringsHash->end()) || (pStringsHash->find(73416223) != pStringsHash->end()))
			{
				if ((pStringsHash->find(963218793) != pStringsHash->end()) || (pStringsHash->find(2806968875) != pStringsHash->end()))
				{
					if ((pStringsHash->find(1588018759) != pStringsHash->end()) || (pStringsHash->find(2707265234) != pStringsHash->end())
						|| (pStringsHash->find(2959245455) != pStringsHash->end()))
					{
						if ((pStringsHash->find(2845710125) != pStringsHash->end()) || (pStringsHash->find(3481317475) != pStringsHash->end()))
						{
							pIsPE = TRUE;
						}
					}
				}
			}
		}
	}

}
void LoadApiPattern(std::set<DWORD>* pApiName) {
	pApiName->insert(2923117684);//CreateProcessA
	pApiName->insert(2922200202);//CreateProcessW
	pApiName->insert(2413463320);//CreateRemoteThread
	pApiName->insert(1791678813);//GetThreadContext
	pApiName->insert(1588018759);//NtAllocateVirtualMemory
	pApiName->insert(2141139445);//NtCreateProcess
	pApiName->insert(2999148978);//NtCreateProcessEx
	pApiName->insert(1810605166);//NtCreateThread
	pApiName->insert(748668459);//NtCreateThreadEx
	pApiName->insert(73416223);//NtGetContextThread
	pApiName->insert(3307083059);//NtOpenProcess
	pApiName->insert(1789965451);//NtResumeThread
	pApiName->insert(2806968875);//NtSetContextThread
	pApiName->insert(2845710125);//NtWriteVirtualMemory
	pApiName->insert(3767103601);//OpenProcess
	pApiName->insert(1383550409);//ResumeThread
	pApiName->insert(1863699581);//RtlCreateUserThread
	pApiName->insert(963218793);//SetThreadContext
	pApiName->insert(2707265234);//VirtualAlloc
	pApiName->insert(2959245455);//VirtualAllocEx
	pApiName->insert(3481317475);//WriteProcessMemory
}
void LoadBinaryStringsHash(BYTE* buf, DWORD pSize, set<DWORD>* pStrSet)
{
	vector<BYTE> m_CharMap;
	for (DWORD i = 0; i < pSize; i++)
	{
		if (buf[i] > 31 && buf[i] < 127)
		{
			m_CharMap.push_back(buf[i]);
		}
		else
		{
			if (!m_CharMap.empty())
			{
				if (m_CharMap.size() >= 3)
				{
					string WriteStr;
					vector<BYTE>::iterator it;
					for (it = m_CharMap.begin(); it != m_CharMap.end(); it++)
					{
						WriteStr.push_back((*it));
					}
					if (WriteStr.size() < 256)
					{
						char* FuncName = new char[256];
						DWORD Hash = 0;
						strcpy_s(FuncName, 256, WriteStr.c_str());
						PUCHAR ptr = (PUCHAR)FuncName;
						while (*ptr)
						{
							Hash = ((Hash << 8) + Hash + *ptr) ^ (*ptr << 16);
							ptr++;
						}
						if (Hash > 0)
							pStrSet->insert(Hash);
						delete[] FuncName;
					}
					WriteStr.clear();
					m_CharMap.clear();
				}
				else
					m_CharMap.clear();
			}
		}
	}
	m_CharMap.clear();
}
char* CStringToCharArray(wchar_t* str, UINT m_CodePage)
{
	char* ptr;
#ifdef _UNICODE
	LONG len;
	len = WideCharToMultiByte(m_CodePage, 0, str, -1, NULL, 0, NULL, NULL);
	ptr = new char[len + 1];
	memset(ptr, 0, len + 1);
	WideCharToMultiByte(m_CodePage, 0, str, -1, ptr, len + 1, NULL, NULL);
#else
	ptr = new char[str.GetAllocLength() + 1];
#endif
	return ptr;
}
bool CheckDigitalSignature(TCHAR* m_Path)
{
	//wchar_t * szFileName = CharArrayToWString(m_Path,CP_ACP);
	DWORD dwEncoding, dwContentType, dwFormatType;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	BOOL fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		m_Path,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		&dwContentType,
		&dwFormatType,
		&hStore,
		&hMsg,
		NULL);
	if (!fResult)
	{
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return false;
	}
	else
	{
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return true;
	}
}
void CheckModulePath(TCHAR* pProcessPath, TCHAR* pModulePath, set<string>* pIsAbnormal_dll)
{
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (GetLongPathName(pModulePath, Longfilename, MAX_PATH_EX))
	{
		lstrcpy(m_FilePath, Longfilename);
	} 
	else
	{
		lstrcpy(m_FilePath, pModulePath);
	}
	for (int i = 0; i < (int)_tcslen(m_FilePath); i++)
	{
		if (m_FilePath[i] == ':')
		{
			if (i > 1)
				_tcscpy_s(Longfilename, MAX_PATH_EX, m_FilePath + (i - 1));
			else
				_tcscpy_s(Longfilename, MAX_PATH_EX, m_FilePath);
			break;
		}
	}
	TCHAR* TempPath = new TCHAR[MAX_PATH_EX];
	_tcscpy_s(TempPath, MAX_PATH_EX, Longfilename);
	wchar_t* pwc;
	wchar_t* next_token = NULL;
	int j = 0;
	bool isMatchSystemFolder = true;
	pwc = wcstok_s(TempPath, L"\\", &next_token);
	while (pwc != NULL)
	{
		if (j == 0)
		{
			if (_wcsicmp(pwc, L"c:"))
			{
				isMatchSystemFolder = false;
				break;
			}
		}
		else if (j == 1)
		{
			if (_wcsicmp(pwc, L"Windows") && _wcsicmp(pwc, L"Program Files") && _wcsicmp(pwc, L"Program Files (x86)"))
			{
				isMatchSystemFolder = false;
			}
			break;
		}
		j++;
		pwc = wcstok_s(NULL, L"\\", &next_token);
	}
	if (!isMatchSystemFolder)
	{
		_tcscpy_s(m_FilePath, MAX_PATH_EX, pProcessPath);
		for (int i = (int)_tcslen(m_FilePath) - 1; i >= 0; i--)
		{
			if (m_FilePath[i] == '\\')
			{
				m_FilePath[i] = '\0';
				break;
			}
		}
		for (int i = (int)_tcslen(Longfilename) - 1; i >= 0; i--)
		{
			if (Longfilename[i] == '\\')
			{
				Longfilename[i] = '\0';
				break;
			}
		}
		if (_tcsicmp(Longfilename, m_FilePath))
		{
			char* str = CStringToCharArray(pModulePath, CP_UTF8);
			char str1[MAX_PATH_EX];
			strcpy_s(str1, MAX_PATH_EX, str);
			if (CheckDigitalSignature(pModulePath))
				strcat_s(str1, MAX_PATH_EX, ":1");
			else
				strcat_s(str1, MAX_PATH_EX, ":0");
			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			DWORD MD5ret = Md5Hash(pModulePath, Md5Hashstr);
			if (MD5ret == 0)
			{
				char* Hashstr = CStringToCharArray(Md5Hashstr, CP_UTF8);
				strcat_s(str1, MAX_PATH_EX, ",");
				strcat_s(str1, MAX_PATH_EX, Hashstr);
				delete[] Hashstr;
				//lstrcpy(m_Info.ProcessHash,Md5Hashstr);
			}
			pIsAbnormal_dll->insert(str1);
			delete[] str;
		}
	}
	delete[] TempPath;
	delete[] m_FilePath;
	delete[] Longfilename;
}
BOOL DumpExecute(DWORD pid, wchar_t* pName, set<DWORD>* pApiBace, set<DWORD>* pStr, TCHAR* pProcessPath, set<string>* pIsAbnormal_dll)
{
	BOOL ret = FALSE;
	HMODULE hResult = NULL;
	HANDLE hSnapshot;
	MODULEENTRY32 me32;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				if (!_tcsicmp(me32.szModule, pName))
				{
					BYTE* buffer = new BYTE[me32.modBaseSize];
					if (Toolhelp32ReadProcessMemory(pid, me32.modBaseAddr, buffer, me32.modBaseSize, 0))
					{
						set<DWORD> StringsHash;
						LoadBinaryStringsHash(buffer, me32.modBaseSize, &StringsHash);
						set<DWORD>::iterator it1;
						set<DWORD>::iterator it2;
						for (it1 = pApiBace->begin(); it1 != pApiBace->end(); it1++)
						{
							it2 = StringsHash.find((*it1));
							if (it2 != StringsHash.end())
							{
								pStr->insert((*it1));
							}
						}
						StringsHash.clear();
						ret = TRUE;
					}
					delete[] buffer;
				}
				else
				{
					if (_tcsicmp(pProcessPath, _T("null")))
					{
						CheckModulePath(pProcessPath, me32.szExePath, pIsAbnormal_dll);
					}
				}
			} while (Module32Next(hSnapshot, &me32));
		}
		CloseHandle(hSnapshot);
	}
	return ret;
}
void GetProcessInfo(DWORD pid,process_info & pInfo)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle != NULL) {
		TCHAR *filename = new TCHAR[512];
		TCHAR *Longfilename = new TCHAR[512];
		TCHAR *m_FilePath = new TCHAR[512];
		if (GetModuleFileNameEx(processHandle, NULL, filename, 512)) {			
			if(GetLongPathName(filename,Longfilename,512)) _tcscpy_s(m_FilePath,512,Longfilename);
			else _tcscpy_s(m_FilePath,512,filename);
			for(size_t i=0;i<wcslen(m_FilePath);i++) {
				if(m_FilePath[i]==':') {
					if( (i-1) != 0) pInfo.process_path = m_FilePath+(i-1);
					else pInfo.process_path=m_FilePath;
					break;
				}
			}
		}
		if(!pInfo.process_path.empty()) {
			DigitalSignatureInfo * DSinfo = new DigitalSignatureInfo;
			if(GetDigitalSignature((TCHAR*)pInfo.process_path.c_str(),DSinfo)) pInfo.DigitalSignature = DSinfo->SignerSubjectName;
			delete DSinfo;
			wstring FileVersionStr[12];
			GetFileVersion((TCHAR*)pInfo.process_path.c_str(),FileVersionStr);
			pInfo.CompanyName = FileVersionStr[COMPANYNAME];
			pInfo.FileVersion = FileVersionStr[FILESVERSION];
			pInfo.FileDescription = FileVersionStr[FILEDESCRIPTION];
			pInfo.ProductName = FileVersionStr[PRODUCTNAME];

			// md5
			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			const wchar_t* ProcessPath = pInfo.process_path.c_str();
			TCHAR* ProcessPath_tchar = const_cast<TCHAR*>(ProcessPath);
			DWORD MD5ret = Md5Hash(ProcessPath_tchar, Md5Hashstr);
			if (MD5ret == 0) lstrcpy(pInfo.ProcessHash, Md5Hashstr);
			else lstrcpy(pInfo.ProcessHash, _T("null"));

		}
		memset(m_FilePath,0,512);
		DWORD ret1 = GetRemoteCommandLineW(processHandle,m_FilePath,512);
		if(ret1 != 0) pInfo.process_command = m_FilePath;
		_tcscpy_s(m_FilePath,512,_T("null"));
		GetUserSID(processHandle,m_FilePath);
		if(_tcscmp(m_FilePath,_T("null"))) {
			SID_NAME_USE SidType;
			TCHAR * lpName = new TCHAR[_MAX_FNAME];
			TCHAR * lpDomain = new TCHAR[_MAX_FNAME];
			DWORD dwSize = _MAX_FNAME;
			PSID Sid;// = GetBinarySid(pSIDstr);
			if(ConvertStringSidToSid(m_FilePath,&Sid)) {
				if(LookupAccountSid( NULL , Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) ) pInfo.user_name = lpName;
			}
			if(pInfo.user_name.empty()) pInfo.user_name = m_FilePath;
			LocalFree(Sid);
			delete [] lpDomain;
			delete [] lpName;
		}
		pInfo.Priority = GetPriorityClass(processHandle);

		

		delete [] m_FilePath;
		delete [] Longfilename;
		delete [] filename;
		CloseHandle(processHandle);	
	}
	else
	{
		TCHAR * m_Path = new TCHAR[512];
		GetSystemDirectory(m_Path,512);
		_tcscat_s(m_Path,512,_T("\\"));
		_tcscat_s(m_Path,512,pInfo.process_name.c_str());
		if(!_waccess(m_Path,00)) {
			pInfo.process_path = m_Path;
			DigitalSignatureInfo * DSinfo = new DigitalSignatureInfo;
			if(GetDigitalSignature((TCHAR*)pInfo.process_path.c_str(),DSinfo)) pInfo.DigitalSignature = DSinfo->SignerSubjectName;
			delete DSinfo;
			wstring FileVersionStr[12];
			GetFileVersion((TCHAR*)pInfo.process_path.c_str(),FileVersionStr);
			pInfo.CompanyName = FileVersionStr[COMPANYNAME];
			pInfo.FileVersion = FileVersionStr[FILESVERSION];
			pInfo.FileDescription = FileVersionStr[FILEDESCRIPTION];
			pInfo.ProductName = FileVersionStr[PRODUCTNAME];

			// md5
			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			const wchar_t* ProcessPath = pInfo.process_path.c_str();
			TCHAR* ProcessPath_tchar = const_cast<TCHAR*>(ProcessPath);
			DWORD MD5ret = Md5Hash(ProcessPath_tchar, Md5Hashstr);
			if (MD5ret == 0) lstrcpy(pInfo.ProcessHash, Md5Hashstr);
			else lstrcpy(pInfo.ProcessHash, _T("null"));
		}
		delete [] m_Path;
	}

	// IsWindowsProcessNormal

	std::set<DWORD> m_ApiName;
	LoadApiPattern(&m_ApiName);
	set<DWORD> ApiStringHash;
	const wchar_t* ProcessName = pInfo.process_name.c_str();
	const wchar_t* ProcessPath = pInfo.process_path.c_str();
	TCHAR* ProcessName_tchar = const_cast<TCHAR*>(ProcessName);
	TCHAR* ProcessPath_tchar = const_cast<TCHAR*>(ProcessPath);
	DumpExecute(pid, ProcessName_tchar, &m_ApiName, &ApiStringHash, ProcessPath_tchar, &pInfo.Abnormal_dll);
	pInfo.InjectionOther = FALSE;
	pInfo.InjectionPE = FALSE;
	CheckInjectionPtn(&ApiStringHash, pInfo.InjectionOther, pInfo.InjectionPE);
	std::wstring str1 = std::to_wstring(pInfo.InjectionOther);
	std::wstring str2 = std::to_wstring(pInfo.InjectionPE);
	pInfo.Injection = str1 + L"," + str2;

	pInfo.Injected = CheckIsInjection(pid, const_cast<TCHAR*>(pInfo.process_name.c_str()));

	map<wstring, BOOL> m_ServiceRun;
	set<wstring> m_StartRun;
	AutoRun* m_AutoRun = new AutoRun;
	m_AutoRun->LoadServiceStartCommand(&m_ServiceRun);
	m_AutoRun->LoadAutoRunStartCommand(&m_StartRun);
	int StartRun = CheckIsStartRun(&m_ServiceRun, &m_StartRun, pid);

	const int ServiceFlag = 1;
	const int AutoRunFlag = 2;
	pInfo.Service = (StartRun & ServiceFlag) ? 1 : 0;
	pInfo.AutoRun = (StartRun & AutoRunFlag) ? 1 : 0;
	str1 = std::to_wstring(pInfo.Service);
	str2 = std::to_wstring(pInfo.AutoRun);
	pInfo.StartRun = str1 + L"," + str2;


	pInfo.HideAttribute = FALSE;
	pInfo.HideProcess = FALSE;
	if (_tcscmp(const_cast<TCHAR*>(pInfo.process_path.c_str()), _T("null"))) {
		DWORD AttRet = GetFileAttributes(const_cast<TCHAR*>(pInfo.process_path.c_str()));
		if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN) pInfo.HideAttribute = TRUE;
	}
	str1 = std::to_wstring(pInfo.HideAttribute);
	str2 = std::to_wstring(pInfo.HideProcess);
	pInfo.Hide = str1 + L"," + str2;

	CheckIsInlineHook(pid, &pInfo.InlineHookInfo);

	vector<TCPInformation> NetInfo;
	char* OSstr = GetOSVersion();
	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0)) GetTcpInformationXPEx(&NetInfo);
	else if (strstr(OSstr, "Windows 2000") != 0) {}
	else GetTcpInformationEx(&NetInfo);
	delete[] OSstr;

	time_t NetworkClock;
	time(&NetworkClock);
	vector<TCPInformation>::iterator Tcpit;
	for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++) {
		if ((*Tcpit).ProcessID == pid) {
			WORD add1, add2, add3, add4;
			add1 = (WORD)((*Tcpit).LocalAddr & 255);
			add2 = (WORD)(((*Tcpit).LocalAddr >> 8) & 255);
			add3 = (WORD)(((*Tcpit).LocalAddr >> 16) & 255);
			add4 = (WORD)(((*Tcpit).LocalAddr >> 24) & 255);
			WORD add5, add6, add7, add8;
			add5 = (WORD)((*Tcpit).RemoteAddr & 255);
			add6 = (WORD)(((*Tcpit).RemoteAddr >> 8) & 255);
			add7 = (WORD)(((*Tcpit).RemoteAddr >> 16) & 255);
			add8 = (WORD)(((*Tcpit).RemoteAddr >> 24) & 255);
			char str[65536];
			sprintf_s(str, 65536, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%s>%lld", add1, add2, add3, add4, ntohs((u_short)(*Tcpit).LocalPort), add5, add6, add7, add8, ntohs((u_short)(*Tcpit).RemotePort), Convert2State((*Tcpit).State), NetworkClock);
			pInfo.NetString.insert(str);
		}
	}

	for (auto iter = pInfo.Abnormal_dll.begin(); iter != pInfo.Abnormal_dll.end(); ++iter) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wideString = converter.from_bytes(*iter);
		pInfo.AbnormalDll += wideString + L"\n";
	}

	for (auto iter = pInfo.InlineHookInfo.begin(); iter != pInfo.InlineHookInfo.end(); ++iter) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wideString = converter.from_bytes(*iter);
		pInfo.InlineHook += wideString + L"\n";
	}

	for (auto iter = pInfo.NetString.begin(); iter != pInfo.NetString.end(); ++iter) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wideString = converter.from_bytes(*iter);
		pInfo.Network += wideString + L"\n";
	}

}

char* Convert2State(DWORD dwState)
{
	char* result = nullptr;

	switch (dwState)
	{
	case MIB_TCP_STATE_CLOSED:
		result = new char[7]; // "x64" + null terminator
		strcpy_s(result, 7, "CLOSED");
		return result;

	case MIB_TCP_STATE_LISTEN:
		result = new char[7]; // "x64" + null terminator
		strcpy_s(result, 7, "LISTEN");
		return result;

	case MIB_TCP_STATE_SYN_SENT:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "SYN_SENT");
		return result;

	case MIB_TCP_STATE_SYN_RCVD:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "SYN_RCVD");
		return result;

	case MIB_TCP_STATE_ESTAB:
		result = new char[12]; // "x64" + null terminator
		strcpy_s(result, 12, "ESTABLISHED");
		return result;

	case MIB_TCP_STATE_FIN_WAIT1:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "FIN_WAIT1");
		return result;

	case MIB_TCP_STATE_FIN_WAIT2:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "FIN_WAIT2");
		return result;

	case MIB_TCP_STATE_CLOSE_WAIT:
		result = new char[11]; // "x64" + null terminator
		strcpy_s(result, 11, "CLOSE_WAIT");
		return result;

	case MIB_TCP_STATE_CLOSING:
		result = new char[8]; // "x64" + null terminator
		strcpy_s(result, 8, "CLOSING");
		return result;

	case MIB_TCP_STATE_LAST_ACK:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "LAST_ACK");
		return result;

	case MIB_TCP_STATE_TIME_WAIT:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "TIME_WAIT");
		return result;

	case MIB_TCP_STATE_DELETE_TCB:
		result = new char[11]; // "x64" + null terminator
		strcpy_s(result, 11, "DELETE_TCB");
		return result;

	default:
		result = new char[8]; // "x64" + null terminator
		strcpy_s(result, 8, "UNKNOWN");
		return result;
	}
}

void GetTcpInformationXPEx(vector<TCPInformation>* pInfo)
{
	pAllocateAndGetTcpExTableFromStack pGetTcpTableEx = NULL;
	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));
	if (hLib == NULL)
	{
		return;
	}
	PMIB_TCPTABLE_EX m_pBuffTcpTableEx;

	//point to the magic method
	pGetTcpTableEx = (pAllocateAndGetTcpExTableFromStack)GetProcAddress(
		hLib, "AllocateAndGetTcpExTableFromStack");
	if (pGetTcpTableEx == NULL)
	{
		return;
	}
	(pGetTcpTableEx)(&m_pBuffTcpTableEx, TRUE, GetProcessHeap(), 0, 2);

	for (int i = 0; i < (int)m_pBuffTcpTableEx->dwNumEntries; i++)
	{
		TCPInformation m_Info;
		m_Info.ProcessID = m_pBuffTcpTableEx->table[i].dwProcessId;
		m_Info.LocalAddr = m_pBuffTcpTableEx->table[i].dwLocalAddr;
		m_Info.LocalPort = m_pBuffTcpTableEx->table[i].dwLocalPort;
		m_Info.RemoteAddr = m_pBuffTcpTableEx->table[i].dwRemoteAddr;
		m_Info.RemotePort = m_pBuffTcpTableEx->table[i].dwRemotePort;
		m_Info.State = m_pBuffTcpTableEx->table[i].dwState;

		pInfo->push_back(m_Info);
	}
	FreeLibrary(hLib);
}

void GetTcpInformationEx(vector<TCPInformation>* pInfo)
{
	MIB_TCPTABLE_OWNER_PID* pTCPInfo;
	MIB_TCPROW_OWNER_PID* owner;
	DWORD size;
	DWORD dwResult;

	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));

	DWORD(WINAPI * pGetExtendedTcpTable)(
		PVOID pTcpTable,
		PDWORD pdwSize,
		BOOL bOrder,
		ULONG ulAf,
		TCP_TABLE_CLASS TableClass,
		ULONG Reserved
		);

	pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
		GetProcAddress(hLib, "GetExtendedTcpTable");

	if (!pGetExtendedTcpTable)
	{
		// printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
		 //MessageBox(0,L"Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.",0,0);
		return;
	}

	dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
	dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	if (dwResult != NO_ERROR)
	{
		//printf("Couldn't get our IP table");
		//MessageBox(0,L"Couldn't get our IP table",0,0);
		return;
	}

	//printf("Iterating though table:\n");
	for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
	{
		TCPInformation m_Info;
		owner = &pTCPInfo->table[dwLoop];
		m_Info.ProcessID = owner->dwOwningPid;
		m_Info.LocalAddr = owner->dwLocalAddr;
		m_Info.LocalPort = owner->dwLocalPort;
		m_Info.RemoteAddr = owner->dwRemoteAddr;
		m_Info.RemotePort = owner->dwRemotePort;
		m_Info.State = owner->dwState;

		pInfo->push_back(m_Info);
	}
	FreeLibrary(hLib);
	free(pTCPInfo);
	pTCPInfo = NULL;
}

char* GetOSVersion()
{
	char* MyVersion = NULL;
	HKEY hKey = NULL;
	LONG lResult;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)// return 0;
	{

		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
		LONG lRet = ::RegQueryInfoKey(hKey,
			NULL, NULL,    // lpClass, lpcClass
			NULL,          // lpReserved
			NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
			NULL,          // lpcMaxClassLen
			&dwValues,
			&dwMaxValueNameLen,
			&dwMaxValueLen,
			NULL,          // lpcbSecurityDescriptor
			NULL);         // lpftLastWriteTime
		if (ERROR_SUCCESS == lRet)
		{
			// allocate enough to fit max. length name and value
			LPTSTR pszName = new TCHAR[dwMaxValueNameLen + 1];
			LPBYTE lpData = new BYTE[dwMaxValueLen + 1];
			memset(lpData, '\0', dwMaxValueLen + 1);
			for (DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
			{
				DWORD dwNameSize = dwMaxValueNameLen + 1;
				DWORD dwValueSize = dwMaxValueLen;
				DWORD dwType;
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize,
					0, &dwType, lpData, &dwValueSize);
				if (!lstrcmp(pszName, _T("ProductName")) && REG_SZ == dwType)
				{
					//wprintf(L"%s\n",lpData);
					MyVersion = CStringToCharArray((wchar_t*)lpData, CP_UTF8);
					break;
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	if (MyVersion == NULL)
	{
		//delete [] MyVersion;
		MyVersion = new char[10];
		strcpy_s(MyVersion, 10, "Unknown");
		return MyVersion;
	}
	else
		return MyVersion;
}

void CheckIsInlineHook(DWORD pid, set<string>* pInlineHook)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess)
	{//printf("%lu\n",pid);
#ifndef _M_IX86
		DWORD sysbit = Process32or64(hProcess);
		if (sysbit != 0)
		{
			HANDLE hSnapshot;
			MODULEENTRY32 me32;
			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (hSnapshot != INVALID_HANDLE_VALUE)
			{
				me32.dwSize = sizeof(MODULEENTRY32);
				if (Module32First(hSnapshot, &me32))
				{
					do
					{
						if (sysbit == 64)
						{
							if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\kernel32.dll")))
							{
								try
								{
									FindFunctionAddress(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
								}
								catch (...) {}
							}
						}
						else
						{
							if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\SysWOW64\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\SysWOW64\\kernel32.dll")))
							{
								try
								{
									FindFunctionAddress32(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
									//CompareAddressMatch(&m_FunctionAddressInfo,me32.szExePath/*,sysbit*/);
								}
								catch (...) {}
							}
						}
					} while (Module32Next(hSnapshot, &me32));
				}
				CloseHandle(hSnapshot);
			}
			//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
		}
#else
		HANDLE hSnapshot;
		MODULEENTRY32 me32;
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			me32.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(hSnapshot, &me32))
			{
				do
				{
					if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\kernel32.dll")))
					{
						FindFunctionAddress(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
					}
				} while (Module32Next(hSnapshot, &me32));
			}
			CloseHandle(hSnapshot);
		}
		//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
#endif
	}
	CloseHandle(hProcess);
}

void FindFunctionAddress32(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook)
{
	HANDLE hFile = 0, hMapping = 0;
	DWORD FileSize = 0, ExportTableRVA = 0, ImageBase = 0;
	PBYTE pFile = 0;
	PWORD pOrdinals = 0;
	PDWORD pFuncs = 0;
	PIMAGE_DOS_HEADER ImageDosHeader = 0;
	PIMAGE_NT_HEADERS32 ImageNtHeaders = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_clean_things(NULL, NULL, NULL, "Can't open the required DLL");
		return;
	}

	FileSize = GetFileSize(hFile, NULL);
	if (FileSize == 0)
	{
		_clean_things(hFile, NULL, NULL, "FileSize is 0 !");
		return;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		_clean_things(hFile, NULL, NULL, "Can't create the file mapping !");
		return;
	}

	pFile = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFile == NULL)
	{
		_clean_things(hFile, hMapping, NULL, "Can't map the requested file !");
		return;
	}

	ImageBase = (DWORD)pFile;
	ImageDosHeader = (PIMAGE_DOS_HEADER)pFile;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
		return;
	}

	ImageNtHeaders = (PIMAGE_NT_HEADERS32)(ImageDosHeader->e_lfanew + (DWORD)ImageDosHeader);

	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
		return;
	}

	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableRVA == 0)
	{
		_clean_things(hFile, hMapping, pFile, "Export table not found !");
		return;
	}

	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportTableRVA + ImageBase);


	pOrdinals = (PWORD)(ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
	pFuncs = (PDWORD)(ImageExportDirectory->AddressOfFunctions + ImageBase);
	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;

	DWORD ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD ETUpperBoundarie = ExportTableRVA + ExportTableSize;
	BOOL Isntdll = FALSE;
	if (!_tcsicmp(file_path, _T("C:\\Windows\\SysWOW64\\ntdll.dll")))
		Isntdll = TRUE;
	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
	{
		//sprintf_s ((char *) buffer1, sizeof (buffer1), "Ord: %04lX (0x%08lX)", ImageExportDirectory->Base + i, pFuncs[i]);

		if (/*pOrdinals[i]*/i < NumOfNames)
		{
			if (i <= ImageExportDirectory->NumberOfNames)
			{
				PDWORD pNamePointerRVA = (PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
				PCHAR pFuncName = (PCHAR)(pNamePointerRVA[i] + (DWORD)ImageBase);
				if (pFuncName)
				{
					//ULONGLONG m_FunctionAddress = pFuncs[pOrdinals[i]];
					if (Isntdll)
					{
						if (!strcmp(pFuncName, "NlsAnsiCodePage"))
						{
							continue;
						}
					}
					ULONGLONG m_FunctionMemoryAddressInfo = 0;
					BYTE* mBuf = new BYTE[8];
					memset(mBuf, '\x0', 8);
					BYTE* SourceByte = new BYTE[8];
					memset(SourceByte, '\x0', 8);
					memcpy(SourceByte, pFile + pFuncs[pOrdinals[i]], 6);
					ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG*)SourceByte)[0];
					SIZE_T nread = 0;
					if (ReadProcessMemory(pProcess, pModBaseAddr + pFuncs[pOrdinals[i]], mBuf, 6, &nread))
					{
						m_FunctionMemoryAddressInfo = ((ULONGLONG*)mBuf)[0];
						if (m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
						{
							if (SourceByte[0] != mBuf[0])
							{
								if (!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
								{
									//char * cPath = CStringToCharArray(file_path,CP_UTF8);
									//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
									//delete [] cPath;
									char str[512];
									sprintf_s(str, 512, "%s:0x%016I64X -> 0x%016I64X", pFuncName, m_FunctionSourecAddressInfo, m_FunctionMemoryAddressInfo);
									pInlineHook->insert(str);
								}
							}
						}
					}
					delete[] SourceByte;
					delete[] mBuf;
				}
			}
		}
		//else
		//	break;
	}
	_clean_things(hFile, hMapping, pFile, NULL);
}

void FindFunctionAddress(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook)
{
	HANDLE hFile = 0, hMapping = 0;
	DWORD FileSize = 0;
	DWORD_PTR ImageBase = 0, ExportTableRVA = 0;
	PBYTE pFile = 0;
	PWORD pOrdinals = 0;
	PDWORD pFuncs = 0;
	PIMAGE_DOS_HEADER ImageDosHeader = 0;
	PIMAGE_NT_HEADERS ImageNtHeaders = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
	//char * cTimeDate = new char[32];
	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//wprintf(L"%s\n",file_path);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		_clean_things(NULL, NULL, NULL, "Can't open the required DLL");
		return;
	}

	FileSize = GetFileSize(hFile, NULL);
	if (FileSize == 0)
	{
		_clean_things(hFile, NULL, NULL, "FileSize is 0 !");
		return;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		_clean_things(hFile, NULL, NULL, "Can't create the file mapping !");
		return;
	}

	pFile = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFile == NULL)
	{
		_clean_things(hFile, hMapping, NULL, "Can't map the requested file !");
		return;
	}

	ImageBase = (DWORD_PTR)pFile;
	ImageDosHeader = (PIMAGE_DOS_HEADER)pFile;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
		return;
	}

	ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (DWORD_PTR)ImageDosHeader);

	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
		return;
	}

	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableRVA == 0)
	{
		_clean_things(hFile, hMapping, pFile, "Export table not found !");
		return;
	}
	//HMODULE hMod =  LoadLibraryEx(file_path, NULL, DONT_RESOLVE_DLL_REFERENCES );

	//DWORD_PTR addstr = (DWORD_PTR)GetProcAddress(hMod,(char*)NameImg->Name);
	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportTableRVA + ImageBase);
	pOrdinals = (PWORD)(ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
	pFuncs = (PDWORD)(ImageExportDirectory->AddressOfFunctions + ImageBase);
	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;
	DWORD_PTR ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD_PTR ETUpperBoundarie = ExportTableRVA + ExportTableSize;
	//wprintf(L"%s\n",file_path);
	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
	{
		if (i < NumOfNames)
		{
			if (i <= ImageExportDirectory->NumberOfNames)
			{
				PDWORD pNamePointerRVA = (PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
				PCHAR pFuncName = (PCHAR)(pNamePointerRVA[i] + (DWORD_PTR)ImageBase);
				if (pFuncName)
				{
					if (_stricmp(pFuncName, "_aexit_rtn"))
					{
						ULONGLONG m_FunctionMemoryAddressInfo = 0;
						BYTE* mBuf = new BYTE[8];
						memset(mBuf, '\x0', 8);
						BYTE* SourceByte = new BYTE[8];
						memset(SourceByte, '\x0', 8);
						memcpy(SourceByte, pFile + pFuncs[pOrdinals[i]], 6);
						ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG*)SourceByte)[0];
						SIZE_T nread = 0;
						if (ReadProcessMemory(pProcess, pModBaseAddr + pFuncs[pOrdinals[i]], mBuf, 6, &nread))
						{
							m_FunctionMemoryAddressInfo = ((ULONGLONG*)mBuf)[0];
							if (m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
							{
								if (SourceByte[0] != mBuf[0])
								{
									if (!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
									{
										//char * cPath = CStringToCharArray(file_path,CP_UTF8);
										//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
										//delete [] cPath;
										char str[512];
										sprintf_s(str, 512, "%s:0x%016I64X -> 0x%016I64X", pFuncName, m_FunctionSourecAddressInfo, m_FunctionMemoryAddressInfo);
										pInlineHook->insert(str);
									}
								}
							}
						}
						delete[] SourceByte;
						delete[] mBuf;
					}
				}
			}
		}
	}
	_clean_things(hFile, hMapping, pFile, NULL);
	//getchar();
	//return psc;
}

void _clean_things(HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char* pErrorMessage)
{
	//if (pErrorMessage != NULL)
	//	printf ("%s\n", pErrorMessage);

	if (hFile != NULL)
		CloseHandle(hFile);

	if (pFile != NULL)
		UnmapViewOfFile(pFile);

	if (hMapping != NULL)
		CloseHandle(hMapping);
}

int CheckIsStartRun(map<wstring, BOOL>* pService, set<wstring>* pStartRun, DWORD pid)
{
	int ret = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProc)
	{
		TCHAR* buffer = new TCHAR[MAX_PATH_EX];
		DWORD ret1 = GetRemoteCommandLineW(hProc, buffer, MAX_PATH_EX);
		//MessageBox(0,buffer,0,0);
		if (ret1 != 0)
		{//MessageBox(0,buffer,0,0);
			map<wstring, BOOL>::iterator ServiceIt;
			//for(ServiceIt = pService->begin();ServiceIt != pService->end();ServiceIt++)
				//MessageBox(0,(*ServiceIt).c_str(),0,0);
			ServiceIt = pService->find(buffer);
			if (ServiceIt != pService->end())
			{
				//if(!ServiceIt->second)
				//	isServiceHide = TRUE;
				ret += 1;
			}
			set<wstring>::iterator StartRunIt;
			StartRunIt = pStartRun->find(buffer);
			if (StartRunIt != pStartRun->end())
				ret += 2;
		}
		delete[] buffer;
		CloseHandle(hProc);
	}
	return ret;
}

void GetUserSID(HANDLE hProcess, TCHAR *szUserSID)
{
	HANDLE hTokenHandle = NULL ;
	if(OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenHandle))
	{
		PTOKEN_USER pUserToken = NULL ;
		DWORD dwRequiredLength = 0 ;
		if(!GetTokenInformation(hTokenHandle, TokenUser, pUserToken, 0, &dwRequiredLength))
		{
			pUserToken = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredLength) ;
			if(NULL != pUserToken)
			{
				if(GetTokenInformation(hTokenHandle, TokenUser, pUserToken, dwRequiredLength, &dwRequiredLength))
				{
					LPTSTR pszSID ;
					ConvertSidToStringSid(pUserToken->User.Sid, &pszSID) ;
					_tcscpy_s(szUserSID,128,pszSID) ; 
					//strUserSID = szSID ;
					LocalFree(pszSID) ;
				}
				HeapFree(GetProcessHeap(), 0, pUserToken) ;
			}
		}
		CloseHandle(hTokenHandle) ;
	}
}
int CheckIsInjection(DWORD pid, TCHAR* pProcessName)
{
	int ret = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!hProc)
		return ret;

#ifndef _M_IX86
	SIZE_T ptype = Process32or64(hProc);
	//if (!ptype)
	//{
	//
	//}
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
	if (ptype == 64)
	{
		maxmem = 0x7FFFFFEFFFF;
	}
#else
	SIZE_T ptype = 32;
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
#endif
	wchar_t lastfilename[MAX_PATH];
	while (startmem < maxmem)
	{
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (!size)
		{
			CloseHandle(hProc);
			return ret;
		}
		if (mbi.State == MEM_COMMIT)
		{
			SIZE_T ReadSize = 0;
			if (mbi.RegionSize < 20971520)
				ReadSize = mbi.RegionSize;
			else
				ReadSize = 20971520;
			char* buffer = new char[ReadSize];
			SIZE_T nread = 0;

			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, ReadSize/*mbi.RegionSize*/, &nread);
			if (nread == ReadSize)
			{
				if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
				{
					if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
					{
						if (IsPESignature((BYTE*)buffer, (unsigned int)ReadSize))
						{
							ret = 2;
							/*if (pMembuf != NULL)
							{*/
							//	if (mbi.RegionSize <= 20971520)
							//	{
							//		UnKnownDataInfo m_Info;
							//		m_Info.Pid = pid;
							//		if (PeUnmapper((BYTE*)buffer, mbi.RegionSize, (ULONGLONG)mbi.BaseAddress, &m_Info))
							//		{
							//			_tcscpy_s(m_Info.ProcessName, MAX_PATH, pProcessName);
							//			pMembuf->push_back(m_Info);
							//		}
							//	}
							//	//else
							//	//{
							//	//	UnKnownDataInfo m_Info;
							//	//	m_Info.Pid = pid;
							//	//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
							//	//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
							//	//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
							//	//	pMembuf->push_back(m_Info);
							//	//}
							//}
							//if (pUnKnownHash != NULL)
							//{
							//	if (mbi.RegionSize <= 20971520)
							//	{
							//		try
							//		{
							//			GetUnKnownHash((BYTE*)buffer, mbi.RegionSize, pUnKnownHash, ptype);
							//		}
							//		catch (...) {}
							//	}
							//}
						}
						else
						{
							if (ret < 2)
								ret = 1;
						}
					}
				}
				else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
				{
					if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
					{
						if (IsPESignature((BYTE*)buffer, (unsigned int)ReadSize))
						{
							ret = 2;
							//if (pMembuf != NULL)
							//{
							//	if (mbi.RegionSize <= 20971520)
							//	{
							//		UnKnownDataInfo m_Info;
							//		m_Info.Pid = pid;
							//		if (PeUnmapper((BYTE*)buffer, mbi.RegionSize, (ULONGLONG)mbi.BaseAddress, &m_Info))
							//		{
							//			_tcscpy_s(m_Info.ProcessName, MAX_PATH, pProcessName);
							//			pMembuf->push_back(m_Info);
							//		}
							//	}
							//	//else
							//	//{
							//	//	UnKnownDataInfo m_Info;
							//	//	m_Info.Pid = pid;
							//	//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
							//	//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
							//	//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
							//	//	pMembuf->push_back(m_Info);
							//	//}
							//}
							//if (pUnKnownHash != NULL)
							//{
							//	if (mbi.RegionSize <= 20971520)
							//	{
							//		try
							//		{
							//			GetUnKnownHash((BYTE*)buffer, mbi.RegionSize, pUnKnownHash, ptype);
							//		}
							//		catch (...) {}
							//	}
							//}
						}
						else
						{
							if (ret < 2)
								ret = 1;
						}
					}
				}
			}
			delete[] buffer;
		}
		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
	}
	CloseHandle(hProc);
	return ret;
}

#ifndef _M_IX86
DWORD Process32or64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;
	DWORD returnvalue;
	if (!IsWow64Process(hProcess, &bIsWow64))
	{
		returnvalue = 0;
		return returnvalue;
	}
	if (bIsWow64)
	{
		returnvalue = 32;
	}
	else
	{
		returnvalue = 64;
	}
	return returnvalue;
}
#endif

BOOL IsPESignature(BYTE* buffer, unsigned int buflen)
{
	for (unsigned int i = 0; i < buflen; i++)
	{
		if (i + 5 > buflen)
			break;
		else
		{
			if (buffer[i] == 80)
			{
				if (buffer[i + 1] == 69 && buffer[i + 2] == 0 && buffer[i + 3] == 0)
				{
					if ((buffer[i + 4] == 100 && buffer[i + 5] == 134) || (buffer[i + 4] == 76 && buffer[i + 5] == 1))
					{
						return TRUE;
					}
					else
						continue;
				}
				else
					continue;
			}
		}
	}
	return FALSE;
}

int GetProcessMappedFileName(HANDLE ProcessHandle, PVOID BaseAddress, wchar_t* FileName)
{
	HMODULE m_dll = LoadLibrary(L"ntdll.dll");
	if (m_dll == NULL)
		return 0;
	PNtQueryVirtualMemory _NtQueryVirtualMemory = (PNtQueryVirtualMemory)GetProcAddress(m_dll, "NtQueryVirtualMemory");
	NTSTATUS status;
	char* buffer;
	SIZE_T bufferSize;
	SIZE_T returnLength;
	PUNICODE_STRING unicodeString;

	bufferSize = 0x100;
	buffer = new char[bufferSize];
	status = _NtQueryVirtualMemory(
		ProcessHandle,
		BaseAddress,
		MemoryMappedFilenameInformation,
		buffer,
		bufferSize,
		&returnLength
	);

	if (status == STATUS_BUFFER_OVERFLOW)
	{
		delete[] buffer;
		bufferSize = returnLength;
		buffer = new char[bufferSize];

		status = _NtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryMappedFilenameInformation,
			buffer,
			bufferSize,
			&returnLength
		);
	}

	if (!NT_SUCCESS(status))
	{
		FileName[0] = '\x0';
		delete[] buffer;
		FreeLibrary(m_dll);
		return 0;
	}
	status = 0;
	unicodeString = (PUNICODE_STRING)buffer;
	if (unicodeString->Length > 0)
	{
		status = 1;
		size_t filename_pos = 0;

		for (size_t i = wcslen(unicodeString->Buffer); i >= 0; i--)
		{
			if (unicodeString->Buffer[i] == '\\')
			{
				filename_pos = i + 1;
				break;
			}
		}
		wcscpy_s(FileName, MAX_PATH, &unicodeString->Buffer[filename_pos]);
	}
	delete[] buffer;
	FreeLibrary(m_dll);
	return status;
}

DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
{
  typedef NTSTATUS (NTAPI* NtQueryInformationProcessPtr)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

  typedef ULONG (NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

  // Locating functions
  HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if(hNtDll == NULL)
	  return 0;
  NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
  RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

  if(!NtQueryInformationProcess || !RtlNtStatusToDosError)
  {
    //printf("Functions cannot be located.\n");
	FreeLibrary(hNtDll);
	return 0;
  }

  // Get PROCESS_BASIC_INFORMATION
  PROCESS_BASIC_INFORMATION pbi;
  ULONG len;
  NTSTATUS status = NtQueryInformationProcess(
    hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
  SetLastError(RtlNtStatusToDosError(status));
  if(NT_ERROR(status) || !pbi.PebBaseAddress)
  {
    //printf("NtQueryInformationProcess(ProcessBasicInformation) failed.\n");
	  FreeLibrary(hNtDll);
    return 0;
  }

  // Read PEB memory block
  SIZE_T bytesRead = 0;
  //PEB_INTERNAL peb;
  _PEB peb;
  if(!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
  {
    //printf("Reading PEB failed.\n");
	  FreeLibrary(hNtDll);
    return 0;
  }

  // Obtain size of commandline string
  //RTL_USER_PROCESS_PARAMETERS_I upp;
  RTL_USER_PROCESS_PARAMETERS upp;
  if(!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead))
  {
    //printf("Reading USER_PROCESS_PARAMETERS failed.\n");
	  FreeLibrary(hNtDll);
    return 0;
  }
  //printf("%x\n",peb.BeingDebugged);
  if(!upp.CommandLine.Length)
  {
    //printf("Command line length is 0.\n");
	  FreeLibrary(hNtDll);
    return 0;
  }

  // Check the buffer size
  DWORD dwNeedLength = (upp.CommandLine.Length+1) / sizeof(wchar_t) +1;
  if(bufferLength < dwNeedLength)
  {
    //printf("Not enough buffer.\n");
	  FreeLibrary(hNtDll);
    return 0;//dwNeedLength;
  }

  // Get the actual command line
  pszBuffer[dwNeedLength - 1] = L'\0';
  if(!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead))
  {
    //printf("Reading command line failed.\n");
	  FreeLibrary(hNtDll);
    return 0;
  }
  FreeLibrary(hNtDll);
  return (DWORD)bytesRead / sizeof(wchar_t);
}
DWORD GetProcessIdByProcessName(LPCWSTR pszProcessName)
{
	DWORD ret = 0;
	BOOL ContinueLoop;
	PROCESSENTRY32 pe32;
	HANDLE SnapshotHandle;
	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	pe32.dwSize = sizeof(pe32);
	ContinueLoop = Process32First(SnapshotHandle,&pe32);
	while (ContinueLoop)
	{
		if(!_tcsicmp(pe32.szExeFile,pszProcessName))
		{//wprintf(L"Match\n");
			ret = pe32.th32ProcessID;
			break;
		}
		ContinueLoop = Process32Next(SnapshotHandle,&pe32);
	}
	CloseHandle(SnapshotHandle);
	return ret;
}
string GetPriorityString(DWORD pValuse)
{
	string ret;
	if(pValuse == 0x00008000)
		ret = "ABOVE_NORMAL";
	else if(pValuse == 0x00004000)
		ret = "BELOW_NORMAL";
	else if(pValuse == 0x00000080)
		ret = "HIGH";
	else if(pValuse == 0x00000080)
		ret = "IDLE";
	else if(pValuse == 0x00000020)
		ret = "NORMAL";
	else if(pValuse == 0x00000100)
		ret = "REALTIME";
	return ret;
}