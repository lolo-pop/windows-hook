// dllmain.cpp : 定义 DLL 应用程序的入口点。
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#include "stdafx.h"  
#define PSAPI_VERSION 1
#include "HookApi.h"  
#include "easyhook.h"  
#include "ntstatus.h"  
#include <iostream>
#include <Psapi.h>
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
//#include <Ws2tcpip.h> 
#include "time.h"
#include "string.h"
#include "iostream"
#include "fstream"
#include "process.h"
#include "Psapi.h"
#include <wincrypt.h>
#include "Objbase.h"
#include "Shlwapi.h"
#include "winbase.h"
#include "wininet.h"
#include "winuser.h"
#include "winsvc.h"
#include "tlhelp32.h"
#include "psapi.h"
#include "winnls.h"
#include "winternl.h"
#include "shellapi.h"
#include "winwlx.h"
#include "winreg.h"
#include "Iphlpapi.h"
#include "Wininet.h"
#include "Lmshare.h"
#include <UrlMon.h>
#include <Wincrypt.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <shlobj.h>
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")
#define _Reserved_ 


LONG WINAPI MyRegOpenKeyExW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_In_     DWORD   ulOptions,
	_In_     REGSAM  samDesired,
	_Out_    PHKEY   phkResult
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpSubKey);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyExW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegOpenKeyExW)(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LONG WINAPI MyRegOpenKeyW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_Out_    PHKEY   phkResult
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpSubKey);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegOpenKeyW)(hKey, lpSubKey, phkResult);
}

LONG WINAPI MyRegCreateKeyExW(
	_In_       HKEY                  hKey,
	_In_       LPCWSTR               lpSubKey,
	_Reserved_ DWORD                 Reserved,
	_In_opt_   LPTSTR                lpClass,
	_In_       DWORD                 dwOptions,
	_In_       REGSAM                samDesired,
	_In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_      PHKEY                 phkResult,
	_Out_opt_  LPDWORD               lpdwDisposition
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	lpFileNamestr=WideToMutilByte(lpSubKey);
	string lpFileNamestr1="NULL";
	if (lpClass!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpClass);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyExW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<",lpClass|"<<lpFileNamestr1<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegCreateKeyExW)(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LONG WINAPI MyRegCreateKeyW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_Out_    PHKEY   phkResult
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpSubKey);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegCreateKeyW)(hKey, lpSubKey, phkResult);
}

LONG WINAPI MyRegQueryValueExW(
	_In_        HKEY    hKey,
	_In_opt_    LPCWSTR lpValueName,
	_Reserved_  LPDWORD lpReserved,
	_Out_opt_   LPDWORD lpType,
	_Out_opt_   LPBYTE  lpData,
	_Inout_opt_ LPDWORD lpcbData
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpValueName!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpValueName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueExW>,func_params=<hKey|"<<str<<",lpValueName|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegQueryValueExW)(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LONG WINAPI MyRegQueryValueW(
	_In_        HKEY    hKey,
	_In_opt_    LPCWSTR lpSubKey,
	_Out_opt_   LPWSTR  lpValue,
	_Inout_opt_ PLONG   lpcbValue
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpSubKey);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegQueryValueW)(hKey, lpSubKey, lpValue, lpcbValue);
}

LONG WINAPI MyRegSetValueExW(
	_In_             HKEY    hKey,
	_In_opt_         LPCWSTR lpValueName,
	_Reserved_       DWORD   Reserved,
	_In_             DWORD   dwType,
	_In_       const BYTE    *lpData,
	_In_             DWORD   cbData
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	string lpstr1="";
	if (lpValueName!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpValueName);
	}
	if (cbData!=0&&lpData!=NULL)
	{
		if (dwType==REG_SZ)
		{
			wstring ws=(WCHAR*)lpData;
			lpstr1=WideToMutilByte(ws);
		}
		if (dwType==REG_DWORD||dwType==REG_DWORD_LITTLE_ENDIAN)
		{
			UINT a=0;
			UINT b,c,d,e;
			b=lpData[0];
			c=lpData[1];
			d=lpData[2];
			e=lpData[3];
			a=b&0xff;
			a |=((c<<8)&0xff00);
			a |=((d<<16)&0xff0000);
			a |=((e<<24)&0xff000000);
			//a=e<<24 + d<<16 + c<<8 + b;
			char p[256];
			sprintf(p,"%d",a);
			lpstr1=string(p);
		}
		if (dwType==REG_DWORD_BIG_ENDIAN)
		{
			UINT a=0;
			UINT b,c,d,e;
			b=lpData[0];
			c=lpData[1];
			d=lpData[2];
			e=lpData[3];
			a=e&0xff;
			a |=((d<<8)&0xff00);
			a |=((c<<16)&0xff0000);
			a |=((b<<24)&0xff000000);
			//a=e<<24 + d<<16 + c<<8 + b;
			char p[256];
			sprintf(p,"%d",a);
			lpstr1=string(p);
		}
	}
	

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueExW>,func_params=<hKey|"<<str<<",lpValueName|"<<lpFileNamestr<<",dwType|"<<dwType<<",lpData|"<<lpstr1<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegSetValueExW)(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LONG WINAPI MyRegSetValueW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_In_     DWORD   dwType,
	_In_     LPCWSTR lpData,
	_In_     DWORD   cbData
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpSubKey);
	}
	string lpFileNamestr1="NULL";
	lpFileNamestr1=WideToMutilByte(lpData);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<",lpData|"<<lpFileNamestr1<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegSetValueW)(hKey, lpSubKey, dwType, lpData, cbData);
}

LONG WINAPI MyRegDeleteKeyExW(
	_In_       HKEY    hKey,
	_In_       LPCWSTR lpSubKey,
	_In_       REGSAM  samDesired,
	_Reserved_ DWORD   Reserved
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	lpFileNamestr=WideToMutilByte(lpSubKey);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyExW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegDeleteKeyExW)(hKey, lpSubKey, samDesired, Reserved);
}

LONG WINAPI MyRegDeleteKeyW(
	_In_ HKEY    hKey,
	_In_ LPCWSTR lpSubKey
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	lpFileNamestr=WideToMutilByte(lpSubKey);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegDeleteKeyW)(hKey, lpSubKey);
}

LONG WINAPI MyRegSetKeySecurity(
	_In_ HKEY                 hKey,
	_In_ SECURITY_INFORMATION SecurityInformation,
	_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetKeySecurity>,func_params=<hKey|"<<str<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegSetKeySecurity)(hKey, SecurityInformation, pSecurityDescriptor);
}

LONG WINAPI MyRegRestoreKeyW(
	_In_ HKEY    hKey,
	_In_ LPCWSTR lpFile,
	_In_ DWORD   dwFlags
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr="NULL";
	lpFileNamestr=WideToMutilByte(lpFile);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegRestoreKeyW>,func_params=<hKey|"<<str<<",lpFile|"<<lpFileNamestr<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegRestoreKeyW)(hKey, lpFile, dwFlags);
}

LONG WINAPI MyRegReplaceKeyW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_In_     LPCWSTR lpNewFile,
	_In_     LPCWSTR lpOldFile
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr1="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpSubKey);
	}
	string lpFileNamestr2="NULL";
	lpFileNamestr2=WideToMutilByte(lpNewFile);
	string lpFileNamestr3="NULL";
	lpFileNamestr3=WideToMutilByte(lpOldFile);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegReplaceKeyW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr1<<",lpNewFile|"<<lpFileNamestr2<<",lpOldFile|"<<lpFileNamestr3<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegReplaceKeyW)(hKey, lpSubKey, lpNewFile, lpOldFile);
}

LONG WINAPI MyRegLoadKeyW(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_In_     LPCWSTR lpFile
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr1="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpSubKey);
	}
	string lpFileNamestr2="NULL";
	lpFileNamestr2=WideToMutilByte(lpFile);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegLoadKeyW>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr1<<",lpFile|"<<lpFileNamestr2<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegLoadKeyW)(hKey, lpSubKey, lpFile);
}

LONG WINAPI MyRegUnLoadKey(
	_In_     HKEY    hKey,
	_In_opt_ LPCWSTR lpSubKey
	)
{
	stringstream logstream;
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string lpFileNamestr1="NULL";
	if (lpSubKey!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpSubKey);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegUnLoadKey>,func_params=<hKey|"<<str<<",lpSubKey|"<<lpFileNamestr1<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegUnLoadKey)(hKey, lpSubKey);
}