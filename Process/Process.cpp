// Process.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>
#include <map>

#include "MemoryProcess.h"
#include "stdafx.h"

//BOOL EnableDebugPrivilege(BOOL fEnable)
//{
//	BOOL fOk = FALSE;
//	HANDLE hToken;
//	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
//	{
//		TOKEN_PRIVILEGES tp;
//		tp.PrivilegeCount = 1;
//		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
//		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
//		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
//		fOk = (GetLastError() == ERROR_SUCCESS);
//		CloseHandle(hToken);
//	}
//	return (fOk);
//}

int main()
{
	map<DWORD, process_info> m_pInfo;
	if (EnumProcess(&m_pInfo)) {
		LoadProcessInfo(&m_pInfo);
		if (!m_pInfo.empty())
		{
			for (auto it = m_pInfo.begin(); it != m_pInfo.end(); it++)
			{
				//printf("%d\n", it->first);
				//sqlstr = GetProcessSQLValues(it->first,it->second);
				//WriteSQLiteDB(m_db,(char*)sqlstr.c_str());
				//wchar_t* wtr = new wchar_t[512];
				//swprintf_s(wtr, 512, L"%lu,%s|%s|%s|%s|%s|%s|0x%08x\n", it->first, it->second.process_name.c_str(), it->second.CompanyName.c_str()
				//	, it->second.FileVersion.c_str(), it->second.FileDescription.c_str(), it->second.ProductName.c_str(), it->second.process_path.c_str(),
				//	it->second.Priority);

				wprintf(L"process_id: %lu\n", it->first);
				wprintf(L"process_name: %s\n", it->second.process_name.c_str());
				wprintf(L"ProcessCreateTime: %lu\n", it->second.ProcessCreateTime);
				wprintf(L"process_command: %s\n", it->second.process_command.c_str());
				wprintf(L"user_name: %s\n", it->second.user_name.c_str());
				wprintf(L"DigitalSignature: %s\n", it->second.DigitalSignature.c_str());
				wprintf(L"parent_pid: %lu\n", it->second.parent_pid);

				wprintf(L"ParentPath: %s\n", it->second.ParentPath);
				wprintf(L"ParentProcessName: %s\n", it->second.ParentProcessName.c_str());
				
				wprintf(L"ProcessHash: %s\n", it->second.ProcessHash);
				wprintf(L"Injection: %s\n", it->second.Injection.c_str());
				wprintf(L"Injected: %d\n", it->second.Injected);
				wprintf(L"StartRun: %s\n", it->second.StartRun.c_str());
				wprintf(L"Hide: %s\n", it->second.Hide.c_str());

				wprintf(L"Abnormal_dll: %s\n", it->second.AbnormalDll.c_str());

				wprintf(L"InlineHookInfo: %s\n", it->second.InlineHook.c_str());

				wprintf(L"NetString: %s\n", it->second.Network.c_str());

				

				
				
				wprintf(L"\n");




				//MessageBox(0,wtr,0,0);
				//delete [] wtr;
				//WriteSQLstrToDB(m_db, pWorkNum, &it->second, m_SQLstr, m_Count);
			}

			//sqlite3* m_db;
			//if (!sqlite3_open16(pDBFileName, &m_db))
			//{
			//	string sqlstr;
			//	//sqlstr = "SELECT name FROM sqlite_master WHERE type='table' AND name='Process'";
			//	sqlstr = "CREATE TABLE Process (pid INTEGER NOT NULL, process_name TEXT, parent_pid INTEGER, processcreatetime INTEGER,\
			//				process_path TEXT, process_command TEXT, user_name TEXT, digitalsignature TEXT, productname TEXT,\
			//				fileversion TEXT, filedescription TEXT, companyname TEXT, priority TEXT)";
			//	WriteSQLiteDB(m_db, (char*)sqlstr.c_str());

			//	map<DWORD, process_info>::iterator it;
			//	//string m_values;
			//	string m_SQLstr;
			//	int m_Count = 0;
			//	for (it = m_pInfo.begin(); it != m_pInfo.end(); it++)
			//	{
			//		//sqlstr = GetProcessSQLValues(it->first,it->second);
			//		//WriteSQLiteDB(m_db,(char*)sqlstr.c_str());
			//		//wchar_t * wtr = new wchar_t[512];
			//		//swprintf_s(wtr,512,L"%lu,%s|%s|%s|%s|%s|%s|0x%08x\n",it->first,it->second.process_name.c_str(),it->second.CompanyName.c_str()
			//		//	,it->second.FileVersion.c_str(),it->second.FileDescription.c_str(),it->second.ProductName.c_str(),it->second.process_path.c_str(),
			//		//	it->second.Priority);
			//		//MessageBox(0,wtr,0,0);
			//		//delete [] wtr;
			//		WriteSQLstrToDB(m_db, pWorkNum, &it->second, m_SQLstr, m_Count);
			//	}
			//	if (!m_SQLstr.empty())
			//	{
			//		WriteSQLiteDB(m_db, (char*)m_SQLstr.c_str());
			//	}
			//	//wprintf(L"End\n");
			//	sqlite3_close(m_db);
			//	write_csv(pDBFileName, "Process");
			//	//printf("End\n");
			//}
		}
	}
	
}

// 執行程式: Ctrl + F5 或 [偵錯] > [啟動但不偵錯] 功能表
// 偵錯程式: F5 或 [偵錯] > [啟動偵錯] 功能表

// 開始使用的提示: 
//   1. 使用 [方案總管] 視窗，新增/管理檔案
//   2. 使用 [Team Explorer] 視窗，連線到原始檔控制
//   3. 使用 [輸出] 視窗，參閱組建輸出與其他訊息
//   4. 使用 [錯誤清單] 視窗，檢視錯誤
//   5. 前往 [專案] > [新增項目]，建立新的程式碼檔案，或是前往 [專案] > [新增現有項目]，將現有程式碼檔案新增至專案
//   6. 之後要再次開啟此專案時，請前往 [檔案] > [開啟] > [專案]，然後選取 .sln 檔案
