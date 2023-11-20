// stdafx.h : 可在此標頭檔中包含標準的系統 Include 檔，
// 或是經常使用卻很少變更的
// 專案專用 Include 檔案
//

#pragma once

//#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // 從 Windows 標頭排除不常使用的成員
#define _WINSOCK_DEPRECATED_NO_WARNINGS
// Windows 標頭檔:
#include <winsock2.h>
#include <windows.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <stdio.h>
#include <tchar.h>
#include <sstream>
#include <fstream>
#include <algorithm>
using namespace std;


//// TODO: 在此參考您的程式所需要的其他標頭
//#include "sqlite3.h"
//#if defined _M_IX86
//#pragma comment(lib,"SQLite3_x86.lib")
//#elif defined _M_X64
//#pragma comment(lib,"SQLite3_x64.lib")
//#endif