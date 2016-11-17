// dllmain.cpp : 定义 DLL 应用程序的入口点。
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#define PSAPI_VERSION 1
#include "stdafx.h"  
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
#include "HookApi.h"
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")


BOOL WINAPI MyBitBlt(_In_ HDC hdc, _In_ int x, _In_ int y, _In_ int cx, _In_ int cy, _In_opt_ HDC hdcSrc, _In_ int x1, _In_ int y1, _In_ DWORD rop)
{
	stringstream logstream;
	string s;
	logstream.clear(); 
	logstream.str("");
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<BitBlt>,func_params=<x|"<<x<<",y|"<<y<<",cx|"<<cx<<",cy|"<<cy<<">";
	s=logstream.str();
	WriteLog(s);
	return (realBitBlt)(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
}

HANDLE WINAPI MyCreateFileMappingW(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCWSTR lpName 
	)
{
	stringstream logstream;
	string lpNamestr="NULL";
	if (lpName!=NULL)
	{
		lpNamestr=WideToMutilByte(lpName);
	}
	char hFilepath[512]="NULL";
	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileMappingW>,func_params=<hFile|"<<hFilepath<<",lpName|"<<lpNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateFileMappingW)(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

HANDLE WINAPI MyOpenFileMappingW( _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName ){
	stringstream logstream;
	string lpNamestr="NULL";
	if (lpName!=NULL)
	{
		lpNamestr=WideToMutilByte(lpName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenFileMappingW>,func_params=<dwDesiredAccess|"<<dwDesiredAccess<<",bInheritHandle|"<<bInheritHandle<<",lpName|"<<lpNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOpenFileMappingW)(dwDesiredAccess,bInheritHandle,lpName);
}

BOOL WINAPI MyCryptAcquireContext(
	_Out_ HCRYPTPROV *phProv,
	_In_  LPCWSTR    pszContainer,
	_In_  LPCWSTR    pszProvider,
	_In_  DWORD      dwProvType,
	_In_  DWORD      dwFlags
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (pszContainer!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(pszContainer);
	}
	string lpFileNamestr2="NULL";
	if (pszProvider!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(pszProvider);	
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, proc_func_name=<CryptAcquireContext>,func_params=<pszContainer|"<<(pszContainer==NULL?"NULL":lpFileNamestr1)<<",pszProvider|"<<(pszProvider==NULL?"NULL":lpFileNamestr2)<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCryptAcquireContext)(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI MyDeviceIoControl(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	)
{
	stringstream logstream;

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeviceIOControl>,func_params=<dwIoControlCode|"<<dwIoControlCode<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realDeviceIoControl)(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

HWND WINAPI MyFindWindowExW(
	_In_opt_ HWND    hwndParent,
	_In_opt_ HWND    hwndChildAfter,
	_In_opt_ LPCWSTR lpszClass,
	_In_opt_ LPCWSTR lpszWindow
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszClass!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszClass);
	}
	string lpFileNamestr2="NULL";
	if (lpszWindow)
	{
		lpFileNamestr2=WideToMutilByte(lpszWindow);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowExW>,func_params=<lpszClass|"<<lpFileNamestr1<<",lpszWindow|"<<lpFileNamestr2<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realFindWindowExW)(hwndParent, hwndChildAfter, lpszClass, lpszWindow);
}

SHORT WINAPI MyGetAsyncKeyState(
	_In_ int vKey
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetAsyncKeyState>,func_params=<vKey|"<<vKey<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetAsyncKeyState)(vKey);
}

HDC WINAPI MyGetDC(
	_In_ HWND hWnd
	)
{
	stringstream logstream;
	logstream.clear();
	int len=0;
	len=GetWindowTextLengthA(hWnd);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(hWnd,win,len);
	string str(win);
	if (strcmp(str.c_str(),"NULL")==0)
	{
		return (realGetDC)(hWnd);
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetDC>,func_params=<hWnd|"<<win<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetDC)(hWnd);
}

HWND WINAPI MyGetForegroundWindow(void)
{
	stringstream logstream;
	HWND h;
	h=(realGetForegroundWindow)();
	int len=0;
	len=GetWindowTextLengthA(h);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(h,win,len);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetForegroundWindow>,func_params=<return|"<<win<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return h;
}

SHORT WINAPI MyGetKeyState(
	_In_ int nVirtKey
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetKeyState>,func_params=<nVirtKey|"<<nVirtKey<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetKeyState)(nVirtKey);
}

DWORD WINAPI MyGetTempPath(
	DWORD nBufferLength,
	LPTSTR lpBuffer 
	)
{
	stringstream logstream;
	string lpFileNamestr="NULL";
	if (lpBuffer!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpBuffer);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTempPath>,func_params=<nBufferLength|"<<nBufferLength<<",lpBuffer|"<<lpBuffer<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetTempPath)(nBufferLength, lpBuffer);
}

LPVOID WINAPI MyMapViewOfFile(
	_In_ HANDLE hFileMappingObject,
	_In_ DWORD  dwDesiredAccess,
	_In_ DWORD  dwFileOffsetHigh,
	_In_ DWORD  dwFileOffsetLow,
	_In_ SIZE_T dwNumberOfBytesToMap
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapViewOfFile>,func_params=<dwDesiredAccess|"<<dwDesiredAccess<<",dwFileOffsetHigh|"<<dwFileOffsetHigh<<",dwFileOffsetLow|"<<dwFileOffsetLow<<",dwNumberOfBytesToMap|"<<dwNumberOfBytesToMap<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realMapViewOfFile)(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

HFILE WINAPI MyOpenFile(
	_In_  LPCSTR     lpFileName,
	_Out_ LPOFSTRUCT lpReOpenBuff,
	_In_  UINT       uStyle
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenFile>,func_params=<lpFileName|"<<(lpFileName==NULL?"NULL":lpFileName)<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOpenFile)(lpFileName, lpReOpenBuff, uStyle);
}

BOOL WINAPI MyAdjustTokenPrivileges(
	_In_      HANDLE            TokenHandle,
	_In_      BOOL              DisableAllPrivileges,
	_In_opt_  PTOKEN_PRIVILEGES NewState,
	_In_      DWORD             BufferLength,
	_Out_opt_ PTOKEN_PRIVILEGES PreviousState,
	_Out_opt_ PDWORD            ReturnLength
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AdjustTokenPrivileges>,func_params=<DisableAllPrivileges|"<<DisableAllPrivileges<<",BufferLength|"<<BufferLength<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realAdjustTokenPrivileges)(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}

BOOL WINAPI MyAttachThreadInput(
	_In_ DWORD idAttach,
	_In_ DWORD idAttachTo,
	_In_ BOOL  fAttach
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AttachThreadInput>,func_params=<idAttach|"<<idAttach<<",idAttachTo|"<<idAttachTo<<",fAttach|"<<fAttach<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realAttachThreadInput)(idAttach, idAttachTo, fAttach);
}

LRESULT WINAPI MyCallNextHookEx(
	_In_opt_ HHOOK  hhk,
	_In_     int    nCode,
	_In_     WPARAM wParam,
	_In_     LPARAM lParam
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CallNextHookEx>,func_params=<nCode|"<<nCode<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCallNextHookEx)(hhk, nCode, wParam, lParam);
}

BOOL WINAPI MyCheckRemoteDebuggerPresent(
	_In_    HANDLE hProcess,
	_Inout_ PBOOL  pbDebuggerPresent
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CheckRemoteDebuggerPresent>,func_params=<hProcess|"<<buf<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCheckRemoteDebuggerPresent)(hProcess, pbDebuggerPresent);
}

BOOL WINAPI MyControlService(
	_In_  SC_HANDLE        hService,
	_In_  DWORD            dwControl,
	_Out_ LPSERVICE_STATUS lpServiceStatus
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ControlService>,func_params=<dwControl|"<<dwControl<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realControlService)(hService, dwControl, lpServiceStatus);
}

HANDLE WINAPI MyCreateRemoteThread(
	_In_  HANDLE                 hProcess,
	_In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	_In_  SIZE_T                 dwStackSize,
	_In_  LPTHREAD_START_ROUTINE lpStartAddress,
	_In_  LPVOID                 lpParameter,
	_In_  DWORD                  dwCreationFlags,
	_Out_ LPDWORD                lpThreadId
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateRemoteThread>,func_params=<hProcess|"<<buf<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateRemoteThread)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE WINAPI MyCreateToolhelp32Snapshot(
	_In_ DWORD dwFlags,
	_In_ DWORD th32ProcessID
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateToolhelp32Snapshot>,func_params=<dwFlags|"<<dwFlags<<",th32ProcessID|"<<th32ProcessID<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateToolhelp32Snapshot)(dwFlags, th32ProcessID);
}

BOOL WINAPI MyEnumProcesses(
	_Out_ DWORD *lpidProcess,
	_In_  DWORD cb,
	_Out_ LPDWORD lpcbNeeded
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">proc_func_name=<EnumProcesses>,func_params=<cb|"<<cb<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realEnumProcesses)(lpidProcess, cb, lpcbNeeded);
}

BOOL WINAPI MyEnumProcessModules(
	_In_ HANDLE hProcess,
	_Out_  HMODULE *lphModule,
	_In_   DWORD cb,
	_Out_  LPDWORD lpcbNeeded
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<EnumProcessModules>,func_params=<hProcess|"<<buf<<",cb|"<<cb<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realEnumProcessModules)(hProcess, lphModule, cb, lpcbNeeded);
}

FARPROC WINAPI MyGetProcAddress(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetProcAddress>,func_params=<lpProcName|"<<lpProcName<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetProcAddress)(hModule, lpProcName);
}

LANGID WINAPI MyGetSystemDefaultLangID(void)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetSystemDefaultLangID>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetSystemDefaultLangID)();
}

BOOL WINAPI MyGetThreadContext(
	_In_    HANDLE    hThread,
	_Inout_ LPCONTEXT lpContext
	)
{
	stringstream logstream;
	int threadid=0;
	threadid=GetThreadId(hThread);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetThreadContext>,func_params=<hTread|"<<threadid<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetThreadContext)(hThread, lpContext);
}

DWORD WINAPI MyGetTickCount(void)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTickCount>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetTickCount)();
}

BOOL WINAPI MyIsDebuggerPresent(void)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<IsDebuggerPresent>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realIsDebuggerPresent)();
}

HMODULE WINAPI MyLoadLibraryExW(
	_In_       LPCWSTR lpLibFileName,
	_Reserved_ HANDLE  hFile,
	_In_       DWORD   dwFlags
	)
{
	stringstream logstream;
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpLibFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryExW>,func_params=<lpLibFileName|"<<lpFileNamestr<<",dwFlags|"<<dwFlags<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realLoadLibraryExW)(lpLibFileName, hFile, dwFlags);
}

HGLOBAL WINAPI MyLoadResource(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
	)
{
	stringstream logstream;
	char modulestr[MAX_PATH]="NULL";
	GetModuleFileNameA(hModule,modulestr,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadResource>,func_params=<hModule|"<<modulestr<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realLoadResource)(hModule, hResInfo);
}


BOOL WINAPI MyModule32FirstW(
	_In_    HANDLE          hSnapshot,
	_Inout_ LPMODULEENTRY32W lpme
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, pid=<"<<_getpid()<<">,proc_func_name=<Module32FirstW>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realModule32FirstW)(hSnapshot, lpme);
}

BOOL WINAPI MyModule32NextW(
	_In_  HANDLE          hSnapshot,
	_Out_ LPMODULEENTRY32 lpme
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32NextW>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realModule32NextW)(hSnapshot, lpme);
}

HANDLE WINAPI MyOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL  bInheritHandle,
	_In_ DWORD dwProcessId
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenProcess>,func_params=<dwDesiredAccess|"<<dwDesiredAccess<<",bInheritHandle|"<<bInheritHandle<<",dwProcessId|"<<dwProcessId<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOpenProcess)(dwDesiredAccess, bInheritHandle, dwProcessId);
}
BOOL WINAPI MyPeekNamedPipe(
	_In_      HANDLE  hNamedPipe,
	_Out_opt_ LPVOID  lpBuffer,
	_In_      DWORD   nBufferSize,
	_Out_opt_ LPDWORD lpBytesRead,
	_Out_opt_ LPDWORD lpTotalBytesAvail,
	_Out_opt_ LPDWORD lpBytesLeftThisMessage
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<PeekNamedPipe>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realPeekNamedPipe)(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage);
}

BOOL WINAPI MyProcess32First(
	_In_    HANDLE           hSnapshot,
	_Inout_ LPPROCESSENTRY32 lppe
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32First>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realProcess32First)(hSnapshot, lppe);
}

BOOL WINAPI MyProcess32Next(
	_In_  HANDLE           hSnapshot,
	_Out_ LPPROCESSENTRY32 lppe
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32Next>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realProcess32Next)(hSnapshot, lppe);
}

BOOL WINAPI MyQueryPerformanceCounter(
	_Out_ LARGE_INTEGER *lpPerformanceCount
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32Next>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realQueryPerformanceCounter)(lpPerformanceCount);
}

DWORD WINAPI MyQueueUserAPC(
	_In_ PAPCFUNC  pfnAPC,
	_In_ HANDLE    hThread,
	_In_ ULONG_PTR dwData
	)
{
	stringstream logstream;
	int threadid=-1;
	threadid=GetThreadId(hThread);//XP下没有这个API
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<QueueUserAPC>,func_params=<hThread|"<<threadid<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realQueueUserAPC)(pfnAPC, hThread, dwData);
}

BOOL WINAPI MyReadProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ReadProcessMemory>,func_params=<hProcess|"<<buf<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realReadProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

DWORD WINAPI MyResumeThread(
	_In_ HANDLE hThread
	)
{
	stringstream logstream;
	int threadid=-1;
	threadid=GetThreadId(hThread);//XP下没有这个API
	logstream.clear();

	int mypid=_getpid();
	int tarpid=GetProcessIdOfThread(hThread);

	if (mypid==tarpid)
	{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|NULL"<<">";
	}else{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|"<<GetProPath(tarpid)<<",Tarpid|"<<tarpid<<">";
	}

	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realResumeThread)(hThread);
}

BOOL WINAPI MySetThreadContext(
	_In_       HANDLE  hThread,
	_In_ const CONTEXT *lpContext
	)
{
	stringstream logstream;
	int threadid=-1;
	threadid=GetThreadId(hThread);//XP下没有这个API
	logstream.clear();

	int mypid=_getpid();
	int tarpid=GetProcessIdOfThread(hThread);

	if (mypid==tarpid)
	{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|NULL"<<">";
	}else{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|"<<GetProPath(tarpid)<<",Tarpid|"<<tarpid<<">";
	}

	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetThreadContext>,func_params=<hThread|"<<threadid<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetThreadContext)(hThread, lpContext);
}

DWORD WINAPI MySuspendThread(
	_In_ HANDLE hThread
	)
{
	stringstream logstream;
	int threadid=0;
	threadid=GetThreadId(hThread);
	logstream.clear();

	int mypid=_getpid();
	int tarpid=GetProcessIdOfThread(hThread);

	if (mypid==tarpid)
	{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|NULL"<<">";
	}else{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|"<<GetProPath(tarpid)<<",Tarpid|"<<tarpid<<">";
	}

	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SuspendThread>,func_params=<hThread|"<<threadid<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSuspendThread)(hThread);
}

BOOL WINAPI MyThread32First(
	_In_    HANDLE          hSnapshot,
	_Inout_ LPTHREADENTRY32 lpte
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32First>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realThread32First)(hSnapshot, lpte);
}

BOOL WINAPI MyThread32Next(
	_In_  HANDLE          hSnapshot,
	_Out_ LPTHREADENTRY32 lpte
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32Next>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realThread32Next)(hSnapshot, lpte);
}

BOOL WINAPI MyToolhelp32ReadProcessMemory(
	_In_  DWORD   th32ProcessID,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  cbRead,
	_Out_ SIZE_T  lpNumberOfBytesRead
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Toolhelp32ReadProcessMemory>,func_params=<th32ProcessID|"<<th32ProcessID<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realToolhelp32ReadProcessMemory)(th32ProcessID, lpBaseAddress, lpBuffer, cbRead, lpNumberOfBytesRead);
}

LPVOID WINAPI MyVirtualAllocEx(
	_In_     HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
	)
{
	stringstream logstream;
	//LPSTR buf="NULL";
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualAllocEx>,func_params=<hProcess|"<<buf<<",flAllocationType|"<<flAllocationType<<",flProtect|"<<flProtect<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realVirtualAllocEx)(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI MyVirtualProtectEx(
	_In_  HANDLE hProcess,
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualProtectEx>,func_params=<hProcess|"<<buf<<",flNewProtect|"<<flNewProtect<<",lpflOldProtect|"<<lpflOldProtect<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realVirtualProtectEx)(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

UINT WINAPI MyWinExec(
	_In_ LPCSTR lpCmdLine,
	_In_ UINT   uCmdShow
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WinExec>,func_params=<lpCmdLine|"<<lpCmdLine<<",uCmdShow|"<<uCmdShow<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realWinExec)(lpCmdLine, uCmdShow);
}

BOOL WINAPI MyWriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteProcessMemory>,func_params=<hProcess|"<<buf<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realWriteProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI MyRegisterHotKey(
	_In_opt_ HWND hWnd,
	_In_     int  id,
	_In_     UINT fsModifiers,
	_In_     UINT vk
	)
{
	stringstream logstream;
	char win[MAX_PATH]="NULL";
	int len=0;
	if (hWnd!=NULL)
	{
		len=GetWindowTextLengthA(hWnd);
		GetWindowTextA(hWnd,win,len);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegisterHotKey>,func_params=<hWnd|"<<win<<",id|"<<id<<",fsModifiers|"<<fsModifiers<<",vk|"<<vk<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realRegisterHotKey)(hWnd, id, fsModifiers, vk);
}

BOOL WINAPI MyCreateProcessA(
	_In_opt_    LPCSTR               lpApplicationName,
	_Inout_opt_ LPSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOA         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	)
{
	stringstream logstream;
	logstream.clear();
	if (lpCommandLine!=NULL&&strstr(lpCommandLine,"MonInject")!=NULL)
	{
		return (realCreateProcessA)(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}

	string str1="NULL";
	if (lpApplicationName!=NULL)
	{
		str1=lpApplicationName;
	}

	string str2="NULL";
	if (lpCommandLine!=NULL)
	{
		str2=lpCommandLine;
	}
	string str3="NULL";
	if (lpCurrentDirectory!=NULL)
	{
		str3=lpCurrentDirectory;
	}

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessA>,func_params=<lpApplicationName|"<<str1<<",lpCommandLine|"<<str2<<",dwCreationFlags|"<<dwCreationFlags<<",lpCurrentDirectory|"<<str3<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	BOOL res=FALSE;
	res=(realCreateProcessA)(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	int pid=0;
	pid=lpProcessInformation->dwProcessId;
	int check=-1;
	check=GetProcessIsWOW64(pid);
	char easyhook32path[MAX_PATH]={0};
	char mondll32path[MAX_PATH]={0};
	char easyhook64path[MAX_PATH]={0};
	char mondll64path[MAX_PATH]={0};
	char moninject32path[MAX_PATH]={0};
	char exe1[600]={0};
	char exe2[600]={0};
	sprintf_s(easyhook32path,"%sEasyHook32.dll",dlldir);
	sprintf_s(mondll32path,"%sMonDll32.dll",dlldir);
	sprintf_s(easyhook64path,"%sEasyHook64.dll",dlldir);
	sprintf_s(mondll64path,"%sMonDll64.dll",dlldir);
	sprintf_s(exe1,"%sMonInject32.exe %sEasyHook32.dll %d",dlldir,dlldir,pid);
	sprintf_s(exe2,"%sMonInject32.exe %sMonDll32.dll %d",dlldir,dlldir,pid);
	if (check==0)//64位进程
	{
		InjectDll(easyhook64path,pid);
		//Sleep(200);
		InjectDll(mondll64path,pid);
	}else if (check==1)//32位进程
	{
		WinExec(exe1,SW_HIDE);
		//Sleep(200);
		WinExec(exe2,SW_HIDE);
	}
	return res;
}

BOOL WINAPI	MyCreateProcessW(
	_In_opt_    LPCWSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCWSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpApplicationName!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpApplicationName);
	}
	string lpFileNamestr2="NULL";
	if (lpCommandLine!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpCommandLine);
	}
	string lpFileNamestr3="NULL";
	if (lpCurrentDirectory!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpCurrentDirectory);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessW>,func_params=<lpApplicationName|"<<lpFileNamestr1<<",lpCommandLine|"<<lpFileNamestr2<<",lpCurrentDirectory|"<<lpFileNamestr3<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	BOOL res=FALSE;
	res=(realCreateProcessW)(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	int pid=0;
	pid=lpProcessInformation->dwProcessId;
	int check=-1;
	check=GetProcessIsWOW64(pid);
	char easyhook32path[MAX_PATH]={0};
	char mondll32path[MAX_PATH]={0};
	char easyhook64path[MAX_PATH]={0};
	char mondll64path[MAX_PATH]={0};
	char moninject32path[MAX_PATH]={0};
	char exe1[600]={0};
	char exe2[600]={0};
	sprintf_s(easyhook32path,"%sEasyHook32.dll",dlldir);
	sprintf_s(mondll32path,"%sMonDll32.dll",dlldir);
	sprintf_s(easyhook64path,"%sEasyHook64.dll",dlldir);
	sprintf_s(mondll64path,"%sMonDll64.dll",dlldir);
	sprintf_s(exe1,"%sMonInject32.exe %sEasyHook32.dll %d",dlldir,dlldir,pid);
	sprintf_s(exe2,"%sMonInject32.exe %sMonDll32.dll %d",dlldir,dlldir,pid);
	if (check==0)//64位进程
	{
		InjectDll(easyhook64path,pid);
		Sleep(200);
		InjectDll(mondll64path,pid);
	}else if (check==1)//32位进程
	{
		WinExec(exe1,SW_HIDE);
		Sleep(200);
		WinExec(exe2,SW_HIDE);
	}
	return res;
}

HCERTSTORE WINAPI MyCertOpenSystemStoreW(
	_In_ HCRYPTPROV_LEGACY hprov,
	_In_ LPCWSTR           szSubsystemProtocol
	)
{
	stringstream logstream;
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(szSubsystemProtocol);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CertOpenSystemStoreW>,func_params=<szSubsystemProtocol|"<<lpFileNamestr<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCertOpenSystemStoreW)(hprov, szSubsystemProtocol);
}

HANDLE WINAPI MyCreateMutexW(
	_In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_     BOOL                  bInitialOwner,
	_In_opt_ LPCWSTR               lpName
	)
{
	stringstream logstream;
	string lpFileNamestr="NULL";
	if (lpName!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateMutexW>,func_params=<bInitialOwner|"<<bInitialOwner<<",lpName|"<<lpFileNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateMutexW)(lpMutexAttributes, bInitialOwner, lpName);
}

HRSRC WINAPI MyFindResourceW(
	_In_opt_ HMODULE hModule,
	_In_     LPCWSTR lpName,
	_In_     LPCWSTR lpType
	)
{
	stringstream logstream;
	int len=0;
	char modulestr[MAX_PATH]="NULL";
	if (hModule!=NULL)
	{
		//GetModuleFileNameExA(GetCurrentProcess(),hModule,modulestr,MAX_PATH);
		//GetModuleFileNameA(hModule,modulestr,100);
	}
	OutputDebugStringA(modulestr);
	string lpFileNamestr1="NULL";
	//OutputDebugStringW(L"dddddddddddddddd\n");
	//OutputDebugStringW(lpName);
	
	//lpFileNamestr1=WideToMutilByte(lpName);
	string lpFileNamestr2="NULL";
	lpFileNamestr2=WideToMutilByte(lpType);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindResourceW>,func_params=<hModule|"<<modulestr<<",lpName|"<<(lpName==NULL?L"NULL":lpName)<<",lpType|"<<(lpType==NULL?"NULL":lpFileNamestr2)<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realFindResourceW)(hModule, lpName, lpType);
}

HWND WINAPI MyFindWindowW(
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	//lpClassName参数有可能不是一个字符串
	/*
	if (lpClassName!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpClassName);
	}
	*/
	string lpFileNamestr2="NULL";
	if (lpWindowName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpWindowName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowW>,func_params=<lpClassName|"<<lpFileNamestr1<<",lpWindowName|"<<lpFileNamestr2<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realFindWindowW)(lpClassName, lpWindowName);
}

UINT WINAPI MyGetWindowsDirectoryW(
	_Out_ LPTSTR lpBuffer,
	_In_  UINT   uSize
	)
{
	//因为参数是输出参数，所以先执行，后取参数
	UINT res=(realGetWindowsDirectoryW)(lpBuffer, uSize);
	stringstream logstream;
	string lpFileNamestr="NULL";
	if (lpBuffer!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpBuffer);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryW>,func_params=<lpBuffer|"<<(lpBuffer==NULL?"NULL":lpFileNamestr)<<",uSize|"<<uSize<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return res;
}

UINT WINAPI MyMapVirtualKeyW(
	_In_ UINT uCode,
	_In_ UINT uMapType
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapVirtualKeyW>,func_params=<uCode|"<<uCode<<",uMapType|"<<uMapType<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realMapVirtualKeyW)(uCode, uMapType);
}

HANDLE WINAPI MyOpenMutexW(
	_In_ DWORD   dwDesiredAccess,
	_In_ BOOL    bInheritHandle,
	_In_ LPCWSTR lpName
	)
{
	stringstream logstream;
	logstream.clear();
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpName);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenMutexW>,func_params=<lpName|"<<(lpName==NULL?"NULL":lpFileNamestr)<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOpenMutexW)(dwDesiredAccess, bInheritHandle, lpName);
}

SC_HANDLE WINAPI MyOpenSCManagerW(
	_In_opt_ LPCWSTR lpMachineName,
	_In_opt_ LPCWSTR lpDatabaseName,
	_In_     DWORD   dwDesiredAccess
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpMachineName!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpMachineName);
	}
	string lpFileNamestr2="NULL";
	if (lpDatabaseName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpDatabaseName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenSCManagerA>,func_params=<lpMachineName|"<<(lpMachineName==NULL?"NULL":lpFileNamestr1)<<",lpDatabaseName|"<<(lpDatabaseName==NULL?"NULL":lpFileNamestr2)<<",dwDesiredAccess|"<<dwDesiredAccess<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOpenSCManagerW)(lpMachineName, lpDatabaseName, dwDesiredAccess);
}



SC_HANDLE WINAPI MyCreateServiceW(
	_In_      SC_HANDLE hSCManager,
	_In_      LPCWSTR   lpServiceName,
	_In_opt_  LPCWSTR   lpDisplayName,
	_In_      DWORD     dwDesiredAccess,
	_In_      DWORD     dwServiceType,
	_In_      DWORD     dwStartType,
	_In_      DWORD     dwErrorControl,
	_In_opt_  LPCWSTR   lpBinaryPathName,
	_In_opt_  LPCWSTR   lpLoadOrderGroup,
	_Out_opt_ LPDWORD   lpdwTagId,
	_In_opt_  LPCWSTR   lpDependencies,
	_In_opt_  LPCWSTR   lpServiceStartName,
	_In_opt_  LPCWSTR   lpPassword
	)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpServiceName!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpServiceName);
	}
	string lpFileNamestr2="NULL";
	if (lpDisplayName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpDisplayName);
	}
	string lpFileNamestr3="NULL";
	if (lpBinaryPathName!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpBinaryPathName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateServiceW>,func_params=<lpServiceName|"<<lpFileNamestr1<<",lpDisplayName|"<<lpFileNamestr2<<",lpBinaryPathName|"<<lpFileNamestr3<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateServiceW)(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}

DWORD WINAPI MyGetModuleFileNameExW(
	_In_     HANDLE  hProcess,
	_In_opt_ HMODULE hModule,
	_Out_    LPTSTR  lpFilename,
	_In_     DWORD   nSize
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	char modulestr[MAX_PATH]="NULL";
	if (hModule!=NULL)
	{
		GetModuleFileNameA(hModule,modulestr,MAX_PATH);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleFileNameExW>,func_params=<hProcess|"<<buf<<",hModule|"<<modulestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetModuleFileNameExW)(hProcess, hModule, lpFilename, nSize);
}

HMODULE WINAPI MyGetModuleHandleW(
	_In_opt_ LPCWSTR lpModuleName
	)
{
	stringstream logstream;
	string lpFileNamestr="NULL";
	if (lpModuleName!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpModuleName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleHandleW>,func_params=<lpModuleName|"<<(lpModuleName==NULL?"NULL":lpFileNamestr)<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetModuleHandleW)(lpModuleName);
}

VOID WINAPI MyGetStartupInfoW(
	_Out_ LPSTARTUPINFOW lpStartupInfo
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetStartupInfoW>,func_params=<lpStartupInfo|"<<lpStartupInfo<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realGetStartupInfoW)(lpStartupInfo);
}

BOOL WINAPI	MyGetVersionExW(
	_Inout_ LPOSVERSIONINFO lpVersionInfo
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetVersionExW>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (GetVersionExW)(lpVersionInfo);
}

HMODULE WINAPI MyLoadLibraryW(
	_In_ LPCWSTR lpLibFileName
	)
{
	stringstream logstream;
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpLibFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryW>,func_params=<lpLibFileName|"<<lpFileNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realLoadLibraryW)(lpLibFileName);
}

void WINAPI MyOutputDebugStringW(
	_In_opt_ LPCWSTR lpOutputString
	)
{
	stringstream logstream;
	string lpFileNamestr="NULL";
	if (lpOutputString!=NULL)
	{
		lpFileNamestr=WideToMutilByte(lpOutputString);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringW>,func_params=<lpOutputString|"<<lpFileNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realOutputDebugStringW)(lpOutputString);
}

HHOOK WINAPI MySetWindowsHookExW(
	_In_ int       idHook,
	_In_ HOOKPROC  lpfn,
	_In_ HINSTANCE hMod,
	_In_ DWORD     dwThreadId
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetWindowsHookExW>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetWindowsHookExW)(idHook, lpfn, hMod, dwThreadId);
}

HINSTANCE WINAPI MyShellExecuteW(
	_In_opt_ HWND    hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_     LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_     INT     nShowCmd
	)
{
	stringstream logstream;
	int len=0;
	char win[MAX_PATH]="NULL";
	if (hwnd!=NULL)
	{
		len=GetWindowTextLengthA(hwnd);
		GetWindowTextA(hwnd,win,len);
	}
	string lpFileNamestr1="NULL";
	if (lpOperation!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpOperation);
	}
	string lpFileNamestr2="NULL";
	if (lpFile!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpFile);
	}
	string lpFileNamestr3="NULL";
	if (lpParameters!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpParameters);
	}
	string lpFileNamestr4="NULL";
	if (lpDirectory!=NULL)
	{
		lpFileNamestr4=WideToMutilByte(lpDirectory);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ShellExecuteW>,func_params=<hwnd|"<<win<<",lpOperation|"<<lpFileNamestr1<<",lpFile|"<<lpFileNamestr2<<",lpParameters|"<<lpFileNamestr3<<",lpDirectory|"<<lpFileNamestr4<<",nShowCmd|"<<nShowCmd<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realShellExecuteW)(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

BOOL WINAPI MyStartServiceCtrlDispatcherW(
	_In_ const SERVICE_TABLE_ENTRY *lpServiceStartTable
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<StartServiceCtrlDispatcherW>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realStartServiceCtrlDispatcherW)(lpServiceStartTable);
}

BOOL WINAPI MySetLocalTime(
	_In_ const SYSTEMTIME *lpSystemTime
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetLocalTime>";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetLocalTime)(lpSystemTime);
}

BOOL WINAPI MyTerminateThread(
	_Inout_ HANDLE hThread,
	_In_    DWORD  dwExitCode
	)
{
	stringstream logstream;
	int threadid=-1;
	threadid=GetThreadId(hThread);//XP下没有这个API
	logstream.clear();

	int mypid=_getpid();
	int tarpid=GetProcessIdOfThread(hThread);

	if (mypid==tarpid)
	{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|NULL"<<">";
	}else{
		logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>,func_params=<hThread|"<<threadid<<",ProcessPath|"<<GetProPath(tarpid)<<",Tarpid|"<<tarpid<<">";
	}

	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<TerminateThread>,func_params=<hThread|"<<threadid<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realTerminateThread)(hThread, dwExitCode);
}

BOOL WINAPI MyVirtualFree(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  dwFreeType
	)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualFree>,func_params=<dwFreeType|"<<dwFreeType<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realVirtualFree)(lpAddress, dwSize, dwFreeType);
}

BOOL WINAPI MySetProcessWorkingSetSize(
	_In_ HANDLE hProcess,
	_In_ SIZE_T dwMinimumWorkingSetSize,
	_In_ SIZE_T dwMaximumWorkingSetSize
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetProcessWorkingSetSize>,func_params=<hProcess|"<<buf<<",dwMinimumWorkingSetSize|"<<dwMinimumWorkingSetSize<<"dwMaximumWorkingSetSize|"<<dwMaximumWorkingSetSize<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetProcessWorkingSetSize)(hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize);
}

BOOL WINAPI MyTerminateProcess(
	_In_ HANDLE hProcess,
	_In_ UINT   uExitCode
	)
{
	stringstream logstream;
	char buf[MAX_PATH]="NULL";
	GetModuleFileNameExA(hProcess,0,buf,MAX_PATH);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<TerminateProcess>,func_params=<hProcess|"<<buf<<",uExitCode|"<<uExitCode<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realTerminateProcess)(hProcess, uExitCode);
}