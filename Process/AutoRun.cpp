#include "AutoRun.h"
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#include <Sddl.h>
#include <Windows.h>
#include <tchar.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

AutoRun::AutoRun()
{

}
AutoRun::~AutoRun()
{

}



void AutoRun::LoadServiceStartCommand(map<wstring, BOOL>* pImagePath)
{
	map<wstring, SerivceInformation> ServiceMap;
	LoadInstallService(&ServiceMap);
	if (!ServiceMap.empty())
	{
		vector<wstring> RegHistorySerivceName;
		LoadRegHistorySubKeys(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), &RegHistorySerivceName);
		map<wstring, SerivceInformation>::iterator st;
		vector<wstring>::iterator it;
		for (it = RegHistorySerivceName.begin(); it != RegHistorySerivceName.end(); it++)
		{
			st = ServiceMap.find((*it).c_str());
			if (st == ServiceMap.end())
			{
				SerivceInformation m_info = { 0 };
				_tcscpy_s(m_info.SerivceName, 1024, (*it).c_str());
				_tcscpy_s(m_info.DisplayName, 1024, (*it).c_str());
				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
				//_tcscpy_s(m_info.SerivceName,512,_T("null"));
				m_info.dwCurrentState = 0;
				m_info.dwErrorControl = 0;
				m_info.dwServiceType = 0;
				m_info.dwStartType = 0;
				m_info.dwTagId = 0;
				m_info.IsInstall = FALSE;
				TCHAR* m_Path = new TCHAR[MAX_PATH];
				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s"), (*it).c_str());
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ImagePath"), REG_EXPAND_SZ, m_info.lpBinaryPathName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("DisplayName"), REG_SZ, m_info.DisplayName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ObjectName"), REG_SZ, m_info.lpServiceStartName);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Start"), m_info.dwStartType);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Type"), m_info.dwServiceType);
				if (_tcscmp(m_info.lpBinaryPathName, _T("null")))
				{
					ServiceMap.insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
				}
				delete[] m_Path;
				//GetRegHistoryDisplayName((*it),&ServiceMap);
			}
		}
		RegHistorySerivceName.clear();
		for (st = ServiceMap.begin(); st != ServiceMap.end(); st++)
		{
			if (_tcscmp(st->second.lpBinaryPathName, _T("null")) && (st->second.dwServiceType != 1 && st->second.dwServiceType != 2) && st->second.dwStartType != 1)
				pImagePath->insert(pair<wstring, BOOL>(st->second.lpBinaryPathName, st->second.IsInstall));
		}
	}
	ServiceMap.clear();
}

void AutoRun::LoadInstallService(map<wstring, SerivceInformation>* pServiceMap)
{
	SC_HANDLE hHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hHandle)
	{
		//ErrorDescription(GetLastError());
		return;
	}
	else
	{
		//cout << "Open SCM sucessfully" << endl;
		//wprintf(_T("Open SCM sucessfully\n"));
	}
	//map<wstring,wstring> ServiceMap;
	ENUM_SERVICE_STATUS service;

	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumedHandle = 0;
	DWORD dwServiceType = SERVICE_WIN32 | SERVICE_DRIVER;
	// Query services
	BOOL retVal = EnumServicesStatus(hHandle, dwServiceType, SERVICE_STATE_ALL,
		&service, sizeof(ENUM_SERVICE_STATUS), &dwBytesNeeded, &dwServicesReturned,
		&dwResumedHandle);
	if (!retVal)
	{
		// Need big buffer
		if (ERROR_MORE_DATA == GetLastError())
		{
			// Set the buffer
			DWORD dwBytes = sizeof(ENUM_SERVICE_STATUS) + dwBytesNeeded;
			ENUM_SERVICE_STATUS* pServices = NULL;
			pServices = new ENUM_SERVICE_STATUS[dwBytes];
			// Now query again for services
			EnumServicesStatus(hHandle, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
				pServices, dwBytes, &dwBytesNeeded, &dwServicesReturned, &dwResumedHandle);
			// now traverse each service to get information
			for (unsigned iIndex = 0; iIndex < dwServicesReturned; iIndex++)
			{
				//(pServices + iIndex)->ServiceStatus.
				SerivceInformation m_info = { 0 };
				_tcscpy_s(m_info.DisplayName, 1024, _T("null"));
				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
				_tcscpy_s(m_info.SerivceName, 1024, _T("null"));
				m_info.dwCurrentState = 0;
				m_info.dwErrorControl = 0;
				m_info.dwServiceType = 0;
				m_info.dwStartType = 0;
				m_info.dwTagId = 0;
				//(pServices + iIndex)->ServiceStatus.
				//m_info.SerivceName.Format(_T("%s"),(pServices + iIndex)->lpServiceName);
				swprintf_s(m_info.SerivceName, 1024, _T("%s"), (pServices + iIndex)->lpServiceName);
				//m_info.DisplayName.Format(_T("%s"),(pServices + iIndex)->lpDisplayName);
				swprintf_s(m_info.DisplayName, 1024, _T("%s"), (pServices + iIndex)->lpDisplayName);
				m_info.dwCurrentState = (pServices + iIndex)->ServiceStatus.dwCurrentState;
				DoQuerySvc(&m_info);
				m_info.IsInstall = TRUE;
				//wcscpy_s(ServiceName,MAX_PATH,(pServices + iIndex)->lpServiceName);
				//wcscpy_s(DisplayName,MAX_PATH,(pServices + iIndex)->lpDisplayName);
				pServiceMap->insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
			}
			delete[] pServices;
			pServices = NULL;
		}
		// there is any other reason
		else
		{
			//ErrorDescription(GetLastError());
		}
	}
	if (!CloseServiceHandle(hHandle))
	{
		//ErrorDescription(GetLastError());
	}
	else
	{
		//cout << "Close SCM sucessfully" << endl;
		//wprintf(_T("Close SCM sucessfully\n"));
	}
	// get the description of error
		//ServiceMap.clear();
}

void AutoRun::DoQuerySvc(SerivceInformation* pInfo)
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	LPQUERY_SERVICE_CONFIG lpsc = NULL;
	LPSERVICE_DESCRIPTION lpsd = NULL;
	DWORD dwBytesNeeded, cbBufSize, dwError;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		// printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,          // SCM database 
		pInfo->SerivceName,             // name of service 
		SERVICE_QUERY_CONFIG); // need query config access 

	if (schService == NULL)
	{
		// printf("OpenService failed (%d)\n", GetLastError()); 
		CloseServiceHandle(schSCManager);
		return;
	}

	// Get the configuration information.

	if (!QueryServiceConfig(
		schService,
		NULL,
		0,
		&dwBytesNeeded))
	{
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError)
		{
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
		}
		else
		{
			// printf("QueryServiceConfig failed (%d)", dwError);
			goto cleanup;
		}
	}

	if (!QueryServiceConfig(
		schService,
		lpsc,
		cbBufSize,
		&dwBytesNeeded))
	{
		//printf("QueryServiceConfig failed (%d)", GetLastError());
		goto cleanup;
	}

	if (!QueryServiceConfig2(
		schService,
		SERVICE_CONFIG_DESCRIPTION,
		NULL,
		0,
		&dwBytesNeeded))
	{
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError)
		{
			cbBufSize = dwBytesNeeded;
			lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, cbBufSize);
		}
		else
		{
			// printf("QueryServiceConfig2 failed (%d)", dwError);
			goto cleanup;
		}
	}

	if (!QueryServiceConfig2(
		schService,
		SERVICE_CONFIG_DESCRIPTION,
		(LPBYTE)lpsd,
		cbBufSize,
		&dwBytesNeeded))
	{
		// printf("QueryServiceConfig2 failed (%d)", GetLastError());
		goto cleanup;
	}

	// Print the configuration information.

   // _tprintf(TEXT("%s configuration: \n"), szSvcName);
	pInfo->dwServiceType = lpsc->dwServiceType;
	//_tprintf(TEXT("  Type: 0x%x\n"), lpsc->dwServiceType);
	pInfo->dwStartType = lpsc->dwStartType;
	//_tprintf(TEXT("  Start Type: 0x%x\n"), lpsc->dwStartType);
	pInfo->dwErrorControl = lpsc->dwErrorControl;
	//_tprintf(TEXT("  Error Control: 0x%x\n"), lpsc->dwErrorControl);
	swprintf_s(pInfo->lpBinaryPathName, 1024, _T("%s"), lpsc->lpBinaryPathName);
	//pInfo->lpBinaryPathName.Format(_T("%s"),lpsc->lpBinaryPathName);
	//_tprintf(TEXT("  Binary path: %s\n"), lpsc->lpBinaryPathName);
	swprintf_s(pInfo->lpServiceStartName, 1024, _T("%s"), lpsc->lpServiceStartName);
	//pInfo->lpServiceStartName.Format(_T("%s"),lpsc->lpServiceStartName);
	//_tprintf(TEXT("  Account: %s\n"), lpsc->lpServiceStartName);

	if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, TEXT("")) != 0)
		swprintf_s(pInfo->lpDescription, 1024, _T("%s"), lpsd->lpDescription);
	//pInfo->lpDescription.Format(_T("%s"),lpsd->lpDescription);
   // _tprintf(TEXT("  Description: %s\n"), lpsd->lpDescription);
	if (lpsc->lpLoadOrderGroup != NULL && lstrcmp(lpsc->lpLoadOrderGroup, TEXT("")) != 0)
		swprintf_s(pInfo->lpLoadOrderGroup, 1024, _T("%s"), lpsc->lpLoadOrderGroup);
	//pInfo->lpLoadOrderGroup.Format(_T("%s"),lpsc->lpLoadOrderGroup);
	//_tprintf(TEXT("  Load order group: %s\n"), lpsc->lpLoadOrderGroup);
	if (lpsc->dwTagId != 0)
		pInfo->dwTagId = lpsc->dwTagId;
	// _tprintf(TEXT("  Tag ID: %d\n"), lpsc->dwTagId);
	if (lpsc->lpDependencies != NULL && lstrcmp(lpsc->lpDependencies, TEXT("")) != 0)
		swprintf_s(pInfo->lpDependencies, 1024, _T("%s"), lpsc->lpDependencies);
	//pInfo->lpDependencies.Format(_T("%s"),lpsc->lpDependencies);
	//_tprintf(TEXT("  Dependencies: %s\n"), lpsc->lpDependencies);

	LocalFree(lpsc);
	LocalFree(lpsd);

cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

void AutoRun::LoadRegHistorySubKeys(HKEY pKey, const wchar_t* pPath, vector<wstring>* wtr)
{
	HKEY hTestKey;
	if (RegOpenKeyEx(pKey,
		pPath,
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey, wtr);
	}
	RegCloseKey(hTestKey);
}

void AutoRun::QueryKey(HKEY hKey, vector<wstring>* pSub)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	//TCHAR  achValue[MAX_VALUE_NAME]; 
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		// printf( "\nNumber of subkeys: %d\n", cSubKeys);

		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				// _tprintf(TEXT("(%d) %s\n"), i+1, achKey);
				pSub->push_back(achKey);
			}
		}
	}

	// Enumerate the key values. 
	//
	//if (cValues) 
	//{
	//    printf( "\nNumber of values: %d\n", cValues);
	//
	//    for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
	//    { 
	//        cchValue = MAX_VALUE_NAME; 
	//        achValue[0] = '\0'; 
	//        retCode = RegEnumValue(hKey, i, 
	//            achValue, 
	//            &cchValue, 
	//            NULL, 
	//            NULL,
	//            NULL,
	//            NULL);
	//
	//        if (retCode == ERROR_SUCCESS ) 
	//        { 
	//            _tprintf(TEXT("(%d) %s\n"), i+1, achValue); 
	//        } 
	//    }
	//}
}

bool AutoRun::GetRegHistoryREG_SZValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD pType, TCHAR* pValue)
{
	bool ret = true;
	//HKEY  hKey = NULL;
	//DWORD dwSize = 0;
	//DWORD dwDataType = pType;
	//LPBYTE lpValue   = NULL;
	//LPCTSTR const lpValueName = pName;
 //
	//LONG lRet = ::RegOpenKeyEx(pKey,pPath,0,KEY_QUERY_VALUE,&hKey);
	//if(ERROR_SUCCESS == lRet)
	//{
	//	::RegQueryValueEx(hKey,lpValueName,0,&dwDataType,lpValue,&dwSize); 
	//	lpValue = (LPBYTE)malloc(dwSize);
	//	lRet = ::RegQueryValueEx(hKey,lpValueName,0,&dwDataType,lpValue,&dwSize);
	//	if(ERROR_SUCCESS == lRet)
	//	{
	//		swprintf_s(pValue,512,_T("%s"),lpValue);
	//	}
	//	else
	//	{
	//		ret = false;
	//	}
	//	free(lpValue);
	//}
	//else
	//{
	//	ret = false;
	//}
	//::RegCloseKey(hKey);
	HKEY hKey = NULL;
	LONG lResult;


	lResult = RegOpenKeyEx(pKey, pPath, 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (pType == dwType && !wcscmp(pszName, pName))
				{
					swprintf_s(pValue, 512, _T("%s"), lpData);
					//memcpy(pPath,lpData,MAX_PATH);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	return ret;
}

bool AutoRun::GetRegHistoryREG_DWORDValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD& pValue)
{
	bool ret = true;
	long lRet;
	HKEY hKey;
	DWORD m_Value;
	DWORD dwType = REG_DWORD;
	DWORD dwValue;
	lRet = RegOpenKeyEx(pKey, pPath, 0, KEY_QUERY_VALUE, &hKey);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueEx(hKey, pName, 0, &dwType, (LPBYTE)&m_Value, &dwValue);
		if (lRet == ERROR_SUCCESS)
		{
			pValue = m_Value;
		}
		else
		{
			ret = false;
		}
	}
	else
	{
		ret = false;
	}
	RegCloseKey(hKey);
	return ret;
}

void AutoRun::LoadAutoRunStartCommand(set<wstring>* pImagePath)
{
	vector<AutoRunInfo> m_StartRunInfo;
	TCHAR* Pathstr = new TCHAR[MAX_PATH_EX];
	//printf("GetAllUserStartUp\n");
	if (GetAllUserStartUp(Pathstr))
	{
		SearchAutoRunFile(&m_StartRunInfo, Pathstr);
	}

	//printf("LoadRegisterAutoRun\n");
	try {
		LoadRegisterAutoRun(&m_StartRunInfo);
	}
	catch (...) {
		printf("LoadRegisterAutoRun failed\n");
	}


	//printf("delete Pathstr\n");
	delete[] Pathstr;
	vector<wstring> ThisPCAllUser;
	//printf("GetThisPCAllUser\n");
	GetThisPCAllUser(&ThisPCAllUser);
	if (!ThisPCAllUser.empty())
	{
		wchar_t* UserName = new wchar_t[256];
		vector<wstring>::iterator ut;
		for (ut = ThisPCAllUser.begin(); ut != ThisPCAllUser.end(); ut++)
		{
			swprintf_s(UserName, 256, L"%s", (*ut).c_str());
			TCHAR* m_Path = new TCHAR[MAX_PATH];
			//printf("GetUserStartUp\n");
			if (GetUserStartUp(UserName, L"Startup", m_Path))
			{
				SearchAutoRunFile(&m_StartRunInfo, m_Path);
			}
			delete[] m_Path;
			//printf("LoadRegisterAutoRunFromUser\n");
			LoadRegisterAutoRunFromUser(&m_StartRunInfo, UserName);
		}
		delete[] UserName;
	}
	ThisPCAllUser.clear();
	vector<AutoRunInfo>::iterator it;
	for (it = m_StartRunInfo.begin(); it != m_StartRunInfo.end(); it++)
	{
		if (_tcscmp((*it).m_Command, _T("null")))
			pImagePath->insert((*it).m_Command);
	}
	m_StartRunInfo.clear();
}

void AutoRun::GetThisPCAllUser(vector<wstring>* wtr)
{
	HKEY hTestKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey, wtr);
	}
	RegCloseKey(hTestKey);
}

BOOL AutoRun::GetAllUserStartUp(TCHAR* wtr)
{
	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_COMMON_STARTUP, false ))
	//	return TRUE;
	//else
	//	return FALSE;
	BOOL ret = FALSE;
	HKEY hKey = NULL;
	LONG lResult;
	TCHAR* RegPath = new TCHAR[512];
	swprintf_s(RegPath, 512, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"));
	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegPath, 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType && !wcscmp(pszName, L"Common Startup"))
				{
					ret = TRUE;
					//memcpy(wtr,lpData,MAX_PATH_EX);
					swprintf_s(wtr, MAX_PATH_EX, _T("%s"), lpData);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	delete[] RegPath;
	return ret;
}

void AutoRun::LoadRegisterAutoRunFromUser(vector<AutoRunInfo>* pInfo, wchar_t* pUserName)
{
	TCHAR* RegPath = new TCHAR[512];
#ifndef _M_IX86
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);

#else
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);

#endif
	delete[] RegPath;
}

BOOL AutoRun::GetUserStartUp(wchar_t* pUserName, const wchar_t* pDirectory, TCHAR* pPath)
{
	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_STARTUP, false ))
	//	return TRUE;
	//else
	//	return FALSE;
	BOOL ret = FALSE;
	HKEY hKey = NULL;
	LONG lResult;
	TCHAR* RegPath = new TCHAR[512];
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"), pUserName);
	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	lResult = RegOpenKeyEx(HKEY_USERS, RegPath, 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType && !wcscmp(pszName, pDirectory))
				{
					ret = TRUE;
					//memcpy(pPath,lpData,MAX_PATH);
					swprintf_s(pPath, MAX_PATH, _T("%s"), lpData);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	delete[] RegPath;
	return ret;
}



void AutoRun::LoadRegisterAutoRun(vector<AutoRunInfo>* pInfo)
{
#ifndef _M_IX86
	//printf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	//printf("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	//printf("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	//printf("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, false);
	//printf("SOFTWARE\\Microsoft\\Active Setup\\Installed Components\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, false);
	//printf("SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, false);

	//printf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("StubPath"), true, true);
	//printf("SOFTWARE\\Microsoft\\Active Setup\\Installed Components\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, true);
	//printf("\n");
#else

	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("StubPath"), true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, false);
#endif
}

void AutoRun::LoadRegisterInfo(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath)
{
	HKEY hKey = NULL;
	LONG lResult;
	lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					AutoRunInfo m_Info;
					wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
					TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
					try
					{
						//memcpy(pCom ,lpData,MAX_PATH_EX);
						swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
					}
					catch (...)
					{
						_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
					}
					if (_tcscmp(pCom, _T("null")))
					{
						ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
						/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/

						if (pKey == HKEY_USERS)
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
						}
						else if (pKey == HKEY_LOCAL_MACHINE)
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
						}
						else
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
						}
						pInfo->push_back(m_Info);
					}
					//delete [] pCom;	
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}

void AutoRun::LoadRegisterInfoEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool IsChildItem, bool Is32Bit)
{
	if (IsChildItem)
	{
		vector<wstring> strInfo;
		LoadRegisterChildItem(&strInfo, pKey, RegPath, Is32Bit);
		if (!strInfo.empty())
		{
			vector<wstring>::iterator it;
			for (it = strInfo.begin(); it != strInfo.end(); it++)
			{
				TCHAR* m_RegPath = new TCHAR[MAX_PATH_EX];
				swprintf_s(m_RegPath, MAX_PATH_EX, _T("%s\\%s"), RegPath, (*it).c_str());
				LoadRegisterDataEx(pInfo, pKey, m_RegPath, KeyStr, Is32Bit);
				delete[] m_RegPath;
			}
		}
		strInfo.clear();
	}
	else
	{
		LoadRegisterDataEx(pInfo, pKey, RegPath, KeyStr, Is32Bit);
	}
}

void AutoRun::LoadRegisterDataEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool Is32Bit)
{
	HKEY hKey = NULL;
	LONG lResult;
	if (Is32Bit)
		lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey);
	else
		lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE, &hKey);
	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					if (!_tcscmp(KeyStr, _T("*")))
					{
						AutoRunInfo m_Info;
						wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
						TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
						try
						{
							//memcpy(pCom ,lpData,MAX_PATH_EX);
							swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
						}
						catch (...)
						{
							_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
						}
						if (_tcscmp(pCom, _T("null")))
						{
							ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
							/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/
							if (Is32Bit)
							{
								if (pKey == HKEY_USERS)
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
								else if (pKey == HKEY_LOCAL_MACHINE)
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
								else
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);
								pInfo->push_back(m_Info);
							}
							else
							{
								if (pKey == HKEY_USERS)
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
								}
								else if (pKey == HKEY_LOCAL_MACHINE)
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
								}
								else
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
								}
								pInfo->push_back(m_Info);
							}
						}
					}
					else
					{
						if (!_tcsicmp(KeyStr, pszName))
						{
							AutoRunInfo m_Info;
							wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
							TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
							try
							{
								memcpy(pCom, lpData, MAX_PATH_EX);
							}
							catch (...)
							{
								_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
							}
							if (_tcscmp(pCom, _T("null")))
							{
								ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
								if (Is32Bit)
								{
									if (pKey == HKEY_USERS)
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
									else if (pKey == HKEY_LOCAL_MACHINE)
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
									else
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);
									pInfo->push_back(m_Info);
								}
								else
								{
									if (pKey == HKEY_USERS)
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
									}
									else if (pKey == HKEY_LOCAL_MACHINE)
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
									}
									else
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
									}
									pInfo->push_back(m_Info);
								}
							}
						}
					}
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}

void AutoRun::LoadRegisterChildItem(vector<wstring>* pStrInfo, HKEY pKey, const wchar_t* RegPath, bool Is32Bit)
{
	if (Is32Bit)
	{
		HKEY hTestKey;
		if (RegOpenKeyEx(pKey,
			RegPath,
			0,
			KEY_READ | KEY_WOW64_32KEY,
			&hTestKey) == ERROR_SUCCESS
			)
		{
			QueryKey(hTestKey, pStrInfo);
		}
		RegCloseKey(hTestKey);
	}
	else
	{
		HKEY hTestKey;
		if (RegOpenKeyEx(pKey,
			RegPath,
			0,
			KEY_READ,
			&hTestKey) == ERROR_SUCCESS
			)
		{
			QueryKey(hTestKey, pStrInfo);
		}
		RegCloseKey(hTestKey);
	}
}

void AutoRun::LoadRegisterInfox32(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath)
{
	HKEY hKey = NULL;
	LONG lResult;

	lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey);

	if (lResult == ERROR_SUCCESS)
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
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					AutoRunInfo m_Info;
					wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
					TCHAR* pCom = new TCHAR[MAX_PATH_EX];
					//memcpy(pCom ,lpData,MAX_PATH_EX);
					swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
					ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
					//memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);

					if (pKey == HKEY_USERS)
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
					else if (pKey == HKEY_LOCAL_MACHINE)
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
					else
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);

					delete[] pCom;
					pInfo->push_back(m_Info);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}

void AutoRun::SearchAutoRunFile(vector<AutoRunInfo>* pInfo, wchar_t* m_Path)
{
	TCHAR* szTempPath = new TCHAR[MAX_PATH_EX];
	lstrcpy(szTempPath, m_Path);
	lstrcat(szTempPath, TEXT("\\*.*"));
	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
	if (INVALID_HANDLE_VALUE != hSearch)
	{
		do
		{
			if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
			{
				TCHAR* szPath = new TCHAR[MAX_PATH_EX];
				swprintf_s(szPath, MAX_PATH_EX, L"%s\\%s", m_Path, fd.cFileName);
				try
				{
					ParsingStartupFile(pInfo, szPath, fd.cFileName);
				}
				catch (...) {}
				delete[] szPath;
			}
		} while (FindNextFile(hSearch, &fd) != FALSE);
		FindClose(hSearch);
	}
	delete[] szTempPath;
}

void AutoRun::ParsingStartupFile(vector<AutoRunInfo>* pInfo, TCHAR* m_Path, TCHAR* m_Name)
{
	TCHAR* ExtStr = new TCHAR[100];
	for (int i = (int)wcslen(m_Name) - 1; i >= 0; i--)
	{
		if (m_Name[i] == '.')
		{
			wcscpy_s(ExtStr, 100, m_Name + (i + 1));
			break;
		}
	}
	if (!_wcsicmp(ExtStr, _T("lnk")))
	{
		AutoRunInfo m_Info;
		wcscpy_s(m_Info.StartName, MAX_PATH, m_Name);
		wcscpy_s(m_Info.InfoLocation, MAX_PATH_EX, m_Path);
		CoInitialize(NULL);
		ResolveIt(NULL, m_Path, m_Info.m_Command, MAX_PATH_EX);
		CoUninitialize();
		pInfo->push_back(m_Info);
	}
	else if (!_wcsicmp(ExtStr, _T("ini")))
	{
	}
	else
	{
		AutoRunInfo m_Info;
		wcscpy_s(m_Info.m_Command, MAX_PATH_EX, m_Path);
		wcscpy_s(m_Info.StartName, MAX_PATH, m_Name);
		wcscpy_s(m_Info.InfoLocation, MAX_PATH_EX, m_Path);
		pInfo->push_back(m_Info);
	}
	delete[] ExtStr;
}

HRESULT AutoRun::ResolveIt(HWND hwnd, TCHAR* lpszLinkFile, TCHAR* lpszPath, int iPathBufferSize)
{
	HRESULT hres;
	IShellLink* psl;
	WIN32_FIND_DATA wfd;

	*lpszPath = 0; // Assume failure   

	// Get a pointer to the IShellLink interface. It is assumed that CoInitialize  
	// has already been called.   
	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
	if (SUCCEEDED(hres))
	{
		IPersistFile* ppf;

		// Get a pointer to the IPersistFile interface.   
		hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

		if (SUCCEEDED(hres))
		{
			// Add code here to check return value from MultiByteWideChar   
			// for success.  

			// Load the shortcut.   
			hres = ppf->Load(lpszLinkFile, STGM_READ);

			if (SUCCEEDED(hres))
			{
				// Resolve the link.   
				hres = psl->Resolve(hwnd, SLR_NO_UI);

				if (SUCCEEDED(hres))
				{
					// Get the path to the link target.   
					hres = psl->GetPath(lpszPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_RAWPATH);
				}
			}

			// Release the pointer to the IPersistFile interface.   
			ppf->Release();
		}

		// Release the pointer to the IShellLink interface.   
		psl->Release();
	}
	return hres;
}

