#ifndef __HOOKAPI_H__
#define __HOOKAPI_H__
#include <Winsock2.h>
#include <Windows.h>  
#include <TlHelp32.h>
#include <objbase.h>
#include <Wincrypt.h>

#include <Iphlpapi.h>
#include <Wininet.h>
#include <Lm.h>
#include <Urlmon.h>
#include "easyhook.h"  
#include "ntstatus.h"  
#include <iostream>
#include <Psapi.h>
#include <windows.h>
#include <stdio.h>
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
#include "tinyxml.h"
#include "algorithm"
#include <set>
using namespace std;
#define _Reserved_ 

#ifndef _M_X64  
#pragma comment(lib, "EasyHook32.lib")  
#else  
#pragma comment(lib, "EasyHook64.lib")  
#endif  


//文件API

BOOL WINAPI MySetFileTime( _In_ HANDLE hFile, _In_opt_ CONST FILETIME * lpCreationTime, _In_opt_ CONST FILETIME * lpLastAccessTime, _In_opt_ CONST FILETIME * lpLastWriteTime );
typedef BOOL (WINAPI *ptrSetFileTime)( _In_ HANDLE hFile, _In_opt_ CONST FILETIME * lpCreationTime, _In_opt_ CONST FILETIME * lpLastAccessTime, _In_opt_ CONST FILETIME * lpLastWriteTime );

BOOL WINAPI MySetFileValidData( _In_ HANDLE hFile, _In_ LONGLONG ValidDataLength );
typedef BOOL (WINAPI *ptrSetFileValidData)( _In_ HANDLE hFile, _In_ LONGLONG ValidDataLength );

BOOL WINAPI MySetEndOfFile( _In_ HANDLE hFile );
typedef BOOL (WINAPI *ptrSetEndOfFile)( _In_ HANDLE hFile );

BOOL WINAPI MyCreateHardLinkW( _In_ LPCWSTR lpFileName, _In_ LPCWSTR lpExistingFileName, _Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes );
typedef BOOL (WINAPI *ptrCreateHardLinkW)( _In_ LPCWSTR lpFileName, _In_ LPCWSTR lpExistingFileName, _Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes );

BOOL WINAPI MySetFileAttributesW( _In_ LPCWSTR lpFileName, _In_ DWORD dwFileAttributes );
typedef BOOL (WINAPI *ptrSetFileAttributesW)( _In_ LPCWSTR lpFileName, _In_ DWORD dwFileAttributes );

BOOL WINAPI MyFindNextFileW( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW lpFindFileData );
typedef BOOL (WINAPI *ptrFindNextFileW)( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW lpFindFileData );

HANDLE WINAPI MyFindFirstFileW( _In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATAW lpFindFileData );
typedef HANDLE (WINAPI *ptrFindFirstFileW)( _In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATAW lpFindFileData );

BOOL WINAPI MyDeleteFileW( _In_ LPCWSTR lpFileName );
typedef BOOL (WINAPI *ptrDeleteFileW)( _In_ LPCWSTR lpFileName );

BOOL WINAPI MyCopyFileW( _In_ LPCWSTR lpExistingFileName, _In_ LPCWSTR lpNewFileName, _In_ BOOL bFailIfExists );
typedef BOOL (WINAPI *ptrCopyFileW)( _In_ LPCWSTR lpExistingFileName, _In_ LPCWSTR lpNewFileName, _In_ BOOL bFailIfExists );


BOOL WINAPI MyMoveFileW(
	_In_ LPCWSTR lpExistingFileName,
	_In_ LPCWSTR lpNewFileName
	);

typedef BOOL (WINAPI *ptrMoveFileW)(
	_In_ LPCWSTR lpExistingFileName,
	_In_ LPCWSTR lpNewFileName
	);

HANDLE WINAPI MyCreateFileW(  
	__in     LPCWSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	);  
typedef HANDLE (WINAPI *ptrCreateFileW)(  
	__in     LPCWSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	);  


HANDLE WINAPI MyCreateFileA(  
	__in     LPCSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	);  

typedef HANDLE (WINAPI *ptrCreateFileA)(  
	__in     LPCSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	); 

BOOL WINAPI MyReadFile(_In_        HANDLE       hFile,
					   _Out_       LPVOID       lpBuffer,
					   _In_        DWORD        nNumberOfBytesToRead,
					   _Out_opt_   LPDWORD      lpNumberOfBytesRead,
					   _Inout_opt_ LPOVERLAPPED lpOverlapped );

typedef BOOL (WINAPI *ptrReadFile)(_In_        HANDLE       hFile,
								   _Out_       LPVOID       lpBuffer,
								   _In_        DWORD        nNumberOfBytesToRead,
								   _Out_opt_   LPDWORD      lpNumberOfBytesRead,
								   _Inout_opt_ LPOVERLAPPED lpOverlapped);


typedef BOOL (WINAPI *ptrPlaySoundW)( LPCWSTR pszSound,
									 HMODULE hwnd,
									 DWORD fdwSound
									 ); 

//进程API
BOOL WINAPI MyBitBlt(_In_ HDC hdc, _In_ int x, _In_ int y, _In_ int cx, _In_ int cy, _In_opt_ HDC hdcSrc, _In_ int x1, _In_ int y1, _In_ DWORD rop);
typedef BOOL (WINAPI *ptrBitBlt)(_In_ HDC hdc, _In_ int x, _In_ int y, _In_ int cx, _In_ int cy, _In_opt_ HDC hdcSrc, _In_ int x1, _In_ int y1, _In_ DWORD rop);

HANDLE WINAPI MyCreateFileMappingW(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName 
);
typedef HANDLE (WINAPI *ptrCreateFileMappingW) (
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName 
);

HANDLE WINAPI MyOpenFileMappingW( _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName );
typedef HANDLE (WINAPI *ptrOpenFileMappingW)(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName );

BOOL WINAPI MyCryptAcquireContext(
  _Out_ HCRYPTPROV *phProv,
  _In_  LPCWSTR    pszContainer,
  _In_  LPCWSTR    pszProvider,
  _In_  DWORD      dwProvType,
  _In_  DWORD      dwFlags
);
typedef BOOL (WINAPI *ptrCryptAcquireContext)(
  _Out_ HCRYPTPROV *phProv,
  _In_  LPCWSTR    pszContainer,
  _In_  LPCWSTR    pszProvider,
  _In_  DWORD      dwProvType,
  _In_  DWORD      dwFlags
);

BOOL WINAPI MyDeviceIoControl(
  _In_        HANDLE       hDevice,
  _In_        DWORD        dwIoControlCode,
  _In_opt_    LPVOID       lpInBuffer,
  _In_        DWORD        nInBufferSize,
  _Out_opt_   LPVOID       lpOutBuffer,
  _In_        DWORD        nOutBufferSize,
  _Out_opt_   LPDWORD      lpBytesReturned,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);
typedef BOOL (WINAPI *ptrDeviceIoControl) (
  _In_        HANDLE       hDevice,
  _In_        DWORD        dwIoControlCode,
  _In_opt_    LPVOID       lpInBuffer,
  _In_        DWORD        nInBufferSize,
  _Out_opt_   LPVOID       lpOutBuffer,
  _In_        DWORD        nOutBufferSize,
  _Out_opt_   LPDWORD      lpBytesReturned,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);

HWND WINAPI MyFindWindowExW(
  _In_opt_ HWND    hwndParent,
  _In_opt_ HWND    hwndChildAfter,
  _In_opt_ LPCWSTR lpszClass,
  _In_opt_ LPCWSTR lpszWindow
);
typedef HWND (WINAPI *ptrFindWindowExW)(
  _In_opt_ HWND    hwndParent,
  _In_opt_ HWND    hwndChildAfter,
  _In_opt_ LPCWSTR lpszClass,
  _In_opt_ LPCWSTR lpszWindow
);

SHORT WINAPI MyGetAsyncKeyState(
  _In_ int vKey
);
typedef SHORT (WINAPI *ptrGetAsyncKeyState)(
  _In_ int vKey
);

HDC WINAPI MyGetDC(
  _In_ HWND hWnd
);
typedef HDC (WINAPI *ptrGetDC) (
  _In_ HWND hWnd
);

HWND WINAPI MyGetForegroundWindow(void);
typedef HWND (WINAPI *ptrGetForegroundWindow)(void);

SHORT WINAPI MyGetKeyState(
  _In_ int nVirtKey
);
typedef SHORT (WINAPI *ptrGetKeyState)(
  _In_ int nVirtKey
);

DWORD WINAPI MyGetTempPath(
  DWORD nBufferLength,
  LPTSTR lpBuffer 
);
typedef DWORD (WINAPI *ptrGetTempPath)(
  DWORD nBufferLength,
  LPTSTR lpBuffer 
);

LPVOID WINAPI MyMapViewOfFile(
  _In_ HANDLE hFileMappingObject,
  _In_ DWORD  dwDesiredAccess,
  _In_ DWORD  dwFileOffsetHigh,
  _In_ DWORD  dwFileOffsetLow,
  _In_ SIZE_T dwNumberOfBytesToMap
);
typedef LPVOID (WINAPI *ptrMapViewOfFile)(
  _In_ HANDLE hFileMappingObject,
  _In_ DWORD  dwDesiredAccess,
  _In_ DWORD  dwFileOffsetHigh,
  _In_ DWORD  dwFileOffsetLow,
  _In_ SIZE_T dwNumberOfBytesToMap
);

HFILE WINAPI MyOpenFile(
  _In_  LPCSTR     lpFileName,
  _Out_ LPOFSTRUCT lpReOpenBuff,
  _In_  UINT       uStyle
);
typedef HFILE (WINAPI *ptrOpenFile)(
  _In_  LPCSTR     lpFileName,
  _Out_ LPOFSTRUCT lpReOpenBuff,
  _In_  UINT       uStyle
);

BOOL WINAPI MyAdjustTokenPrivileges(
  _In_      HANDLE            TokenHandle,
  _In_      BOOL              DisableAllPrivileges,
  _In_opt_  PTOKEN_PRIVILEGES NewState,
  _In_      DWORD             BufferLength,
  _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
  _Out_opt_ PDWORD            ReturnLength
);
typedef BOOL (WINAPI *ptrAdjustTokenPrivileges)(
  _In_      HANDLE            TokenHandle,
  _In_      BOOL              DisableAllPrivileges,
  _In_opt_  PTOKEN_PRIVILEGES NewState,
  _In_      DWORD             BufferLength,
  _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
  _Out_opt_ PDWORD            ReturnLength
);

BOOL WINAPI MyAttachThreadInput(
  _In_ DWORD idAttach,
  _In_ DWORD idAttachTo,
  _In_ BOOL  fAttach
);
typedef BOOL (WINAPI *ptrAttachThreadInput)(
  _In_ DWORD idAttach,
  _In_ DWORD idAttachTo,
  _In_ BOOL  fAttach
);

LRESULT WINAPI MyCallNextHookEx(
  _In_opt_ HHOOK  hhk,
  _In_     int    nCode,
  _In_     WPARAM wParam,
  _In_     LPARAM lParam
);
typedef LRESULT (WINAPI *ptrCallNextHookEx)(
  _In_opt_ HHOOK  hhk,
  _In_     int    nCode,
  _In_     WPARAM wParam,
  _In_     LPARAM lParam
);

BOOL WINAPI MyCheckRemoteDebuggerPresent(
  _In_    HANDLE hProcess,
  _Inout_ PBOOL  pbDebuggerPresent
);
typedef BOOL (WINAPI *ptrCheckRemoteDebuggerPresent)(
  _In_    HANDLE hProcess,
  _Inout_ PBOOL  pbDebuggerPresent
);

BOOL WINAPI MyControlService(
  _In_  SC_HANDLE        hService,
  _In_  DWORD            dwControl,
  _Out_ LPSERVICE_STATUS lpServiceStatus
);
typedef BOOL (WINAPI *ptrControlService)(
  _In_  SC_HANDLE        hService,
  _In_  DWORD            dwControl,
  _Out_ LPSERVICE_STATUS lpServiceStatus
);

HANDLE WINAPI MyCreateRemoteThread(
  _In_  HANDLE                 hProcess,
  _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_  SIZE_T                 dwStackSize,
  _In_  LPTHREAD_START_ROUTINE lpStartAddress,
  _In_  LPVOID                 lpParameter,
  _In_  DWORD                  dwCreationFlags,
  _Out_ LPDWORD                lpThreadId
);
typedef HANDLE (WINAPI *ptrCreateRemoteThread)(
  _In_  HANDLE                 hProcess,
  _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_  SIZE_T                 dwStackSize,
  _In_  LPTHREAD_START_ROUTINE lpStartAddress,
  _In_  LPVOID                 lpParameter,
  _In_  DWORD                  dwCreationFlags,
  _Out_ LPDWORD                lpThreadId
);

HANDLE WINAPI MyCreateToolhelp32Snapshot(
  _In_ DWORD dwFlags,
  _In_ DWORD th32ProcessID
);
typedef HANDLE (WINAPI *ptrCreateToolhelp32Snapshot)(
  _In_ DWORD dwFlags,
  _In_ DWORD th32ProcessID
);

BOOL WINAPI MyEnumProcesses(
  _Out_ DWORD *lpidProcess,
  _In_  DWORD cb,
  _Out_ LPDWORD lpcbNeeded
);
typedef BOOL (WINAPI *ptrEnumProcesses)(
  _Out_ DWORD *lpidProcess,
  _In_  DWORD cb,
  _Out_ LPDWORD lpcbNeeded
);

BOOL WINAPI MyEnumProcessModules(
  _In_ HANDLE hProcess,
  _Out_  HMODULE *lphModule,
  _In_   DWORD cb,
  _Out_  LPDWORD lpcbNeeded
);
typedef BOOL (WINAPI *ptrEnumProcessModules)(
  _In_ HANDLE hProcess,
  _Out_  HMODULE *lphModule,
  _In_   DWORD cb,
  _Out_  LPDWORD lpcbNeeded
);

FARPROC WINAPI MyGetProcAddress(
  _In_ HMODULE hModule,
  _In_ LPCSTR  lpProcName
);
typedef FARPROC (WINAPI *ptrGetProcAddress)(
  _In_ HMODULE hModule,
  _In_ LPCSTR  lpProcName
);

LANGID WINAPI MyGetSystemDefaultLangID(void);
typedef LANGID (WINAPI *ptrGetSystemDefaultLangID)(void);

BOOL WINAPI MyGetThreadContext(
  _In_    HANDLE    hThread,
  _Inout_ LPCONTEXT lpContext
);
typedef BOOL (WINAPI *ptrGetThreadContext)(
  _In_    HANDLE    hThread,
  _Inout_ LPCONTEXT lpContext
);

DWORD WINAPI MyGetTickCount(void);
typedef DWORD (WINAPI *ptrGetTickCount)(void);

BOOL WINAPI MyIsDebuggerPresent(void);
typedef BOOL (WINAPI *ptrIsDebuggerPresent)(void);

HMODULE WINAPI MyLoadLibraryExW(
  _In_       LPCWSTR lpLibFileName,
  _Reserved_ HANDLE  hFile,
  _In_       DWORD   dwFlags
);
typedef HMODULE (WINAPI *ptrLoadLibraryExW)(
  _In_       LPCWSTR lpLibFileName,
  _Reserved_ HANDLE  hFile,
  _In_       DWORD   dwFlags
);

HGLOBAL WINAPI MyLoadResource(
  _In_opt_ HMODULE hModule,
  _In_     HRSRC   hResInfo
);
typedef HGLOBAL (WINAPI *ptrLoadResource)(
  _In_opt_ HMODULE hModule,
  _In_     HRSRC   hResInfo
);

BOOL WINAPI MyModule32FirstW(
  _In_    HANDLE          hSnapshot,
  _Inout_ LPMODULEENTRY32W lpme
);
typedef BOOL (WINAPI *ptrModule32FirstW)(
  _In_    HANDLE          hSnapshot,
  _Inout_ LPMODULEENTRY32W lpme
);

BOOL WINAPI MyModule32NextW(
  _In_  HANDLE          hSnapshot,
  _Out_ LPMODULEENTRY32W  lpme
);
typedef BOOL (WINAPI *ptrModule32NextW)(
  _In_  HANDLE          hSnapshot,
  _Out_ LPMODULEENTRY32W  lpme
);

HANDLE WINAPI MyOpenProcess(
  _In_ DWORD dwDesiredAccess,
  _In_ BOOL  bInheritHandle,
  _In_ DWORD dwProcessId
);
typedef HANDLE (WINAPI *ptrOpenProcess)(
  _In_ DWORD dwDesiredAccess,
  _In_ BOOL  bInheritHandle,
  _In_ DWORD dwProcessId
);

BOOL WINAPI MyPeekNamedPipe(
  _In_      HANDLE  hNamedPipe,
  _Out_opt_ LPVOID  lpBuffer,
  _In_      DWORD   nBufferSize,
  _Out_opt_ LPDWORD lpBytesRead,
  _Out_opt_ LPDWORD lpTotalBytesAvail,
  _Out_opt_ LPDWORD lpBytesLeftThisMessage
);
typedef BOOL (WINAPI *ptrPeekNamedPipe)(
  _In_      HANDLE  hNamedPipe,
  _Out_opt_ LPVOID  lpBuffer,
  _In_      DWORD   nBufferSize,
  _Out_opt_ LPDWORD lpBytesRead,
  _Out_opt_ LPDWORD lpTotalBytesAvail,
  _Out_opt_ LPDWORD lpBytesLeftThisMessage
);

BOOL WINAPI MyProcess32First(
  _In_    HANDLE           hSnapshot,
  _Inout_ LPPROCESSENTRY32 lppe
);
typedef BOOL (WINAPI *ptrProcess32First)(
  _In_    HANDLE           hSnapshot,
  _Inout_ LPPROCESSENTRY32 lppe
);

BOOL WINAPI MyProcess32Next(
  _In_  HANDLE           hSnapshot,
  _Out_ LPPROCESSENTRY32 lppe
);
typedef BOOL (WINAPI *ptrProcess32Next)(
  _In_  HANDLE           hSnapshot,
  _Out_ LPPROCESSENTRY32 lppe
);

BOOL WINAPI MyQueryPerformanceCounter(
  _Out_ LARGE_INTEGER *lpPerformanceCount
);
typedef BOOL (WINAPI *ptrQueryPerformanceCounter)(
  _Out_ LARGE_INTEGER *lpPerformanceCount
);

DWORD WINAPI MyQueueUserAPC(
  _In_ PAPCFUNC  pfnAPC,
  _In_ HANDLE    hThread,
  _In_ ULONG_PTR dwData
);
typedef DWORD (WINAPI *ptrQueueUserAPC)(
  _In_ PAPCFUNC  pfnAPC,
  _In_ HANDLE    hThread,
  _In_ ULONG_PTR dwData
);

BOOL WINAPI MyReadProcessMemory(
  _In_  HANDLE  hProcess,
  _In_  LPCVOID lpBaseAddress,
  _Out_ LPVOID  lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesRead
);
typedef BOOL (WINAPI *ptrReadProcessMemory)(
  _In_  HANDLE  hProcess,
  _In_  LPCVOID lpBaseAddress,
  _Out_ LPVOID  lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesRead
);

DWORD WINAPI MyResumeThread(
  _In_ HANDLE hThread
);
typedef DWORD (WINAPI *ptrResumeThread)(
  _In_ HANDLE hThread
);

BOOL WINAPI MySetThreadContext(
  _In_       HANDLE  hThread,
  _In_ const CONTEXT *lpContext
);
typedef BOOL (WINAPI *ptrSetThreadContext)(
  _In_       HANDLE  hThread,
  _In_ const CONTEXT *lpContext
);

DWORD WINAPI MySuspendThread(
  _In_ HANDLE hThread
);
typedef DWORD (WINAPI *ptrSuspendThread)(
  _In_ HANDLE hThread
);

BOOL WINAPI MyThread32First(
  _In_    HANDLE          hSnapshot,
  _Inout_ LPTHREADENTRY32 lpte
);
typedef BOOL (WINAPI *ptrThread32First)(
  _In_    HANDLE          hSnapshot,
  _Inout_ LPTHREADENTRY32 lpte
);

BOOL WINAPI MyThread32Next(
  _In_  HANDLE          hSnapshot,
  _Out_ LPTHREADENTRY32 lpte
);
typedef BOOL (WINAPI *ptrThread32Next)
	(
  _In_  HANDLE          hSnapshot,
  _Out_ LPTHREADENTRY32 lpte
);

BOOL WINAPI MyToolhelp32ReadProcessMemory(
  _In_  DWORD   th32ProcessID,
  _In_  LPCVOID lpBaseAddress,
  _Out_ LPVOID  lpBuffer,
  _In_  SIZE_T  cbRead,
  _Out_ SIZE_T  lpNumberOfBytesRead
);
typedef BOOL (WINAPI *ptrToolhelp32ReadProcessMemory)(
  _In_  DWORD   th32ProcessID,
  _In_  LPCVOID lpBaseAddress,
  _Out_ LPVOID  lpBuffer,
  _In_  SIZE_T  cbRead,
  _Out_ SIZE_T  lpNumberOfBytesRead
);

LPVOID WINAPI MyVirtualAllocEx(
  _In_     HANDLE hProcess,
  _In_opt_ LPVOID lpAddress,
  _In_     SIZE_T dwSize,
  _In_     DWORD  flAllocationType,
  _In_     DWORD  flProtect
);
typedef LPVOID (WINAPI *ptrVirtualAllocEx)(
  _In_     HANDLE hProcess,
  _In_opt_ LPVOID lpAddress,
  _In_     SIZE_T dwSize,
  _In_     DWORD  flAllocationType,
  _In_     DWORD  flProtect
);

BOOL WINAPI MyVirtualProtectEx(
  _In_  HANDLE hProcess,
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);
typedef BOOL (WINAPI *ptrVirtualProtectEx)(
  _In_  HANDLE hProcess,
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);

UINT WINAPI MyWinExec(
  _In_ LPCSTR lpCmdLine,
  _In_ UINT   uCmdShow
);
typedef UINT (WINAPI *ptrWinExec)(
  _In_ LPCSTR lpCmdLine,
  _In_ UINT   uCmdShow
);

BOOL WINAPI MyWriteProcessMemory(
  _In_  HANDLE  hProcess,
  _In_  LPVOID  lpBaseAddress,
  _In_  LPCVOID lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesWritten
);
typedef BOOL (WINAPI *ptrWriteProcessMemory)(
  _In_  HANDLE  hProcess,
  _In_  LPVOID  lpBaseAddress,
  _In_  LPCVOID lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesWritten
);

BOOL WINAPI MyRegisterHotKey(
  _In_opt_ HWND hWnd,
  _In_     int  id,
  _In_     UINT fsModifiers,
  _In_     UINT vk
);
typedef BOOL (WINAPI *ptrRegisterHotKey)(
  _In_opt_ HWND hWnd,
  _In_     int  id,
  _In_     UINT fsModifiers,
  _In_     UINT vk
);

BOOL WINAPI MyCreateProcessA(
  _In_opt_    LPCSTR                lpApplicationName,
  _Inout_opt_ LPSTR                 lpCommandLine,
  _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_        BOOL                  bInheritHandles,
  _In_        DWORD                 dwCreationFlags,
  _In_opt_    LPVOID                lpEnvironment,
  _In_opt_    LPCSTR               lpCurrentDirectory,
  _In_        LPSTARTUPINFOA         lpStartupInfo,
  _Out_       LPPROCESS_INFORMATION lpProcessInformation
);
typedef BOOL (WINAPI *ptrCreateProcessW)(
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
);

HCERTSTORE WINAPI MyCertOpenSystemStoreW(
  _In_ HCRYPTPROV_LEGACY hprov,
  _In_ LPCWSTR           szSubsystemProtocol
);
typedef HCERTSTORE (WINAPI *ptrCertOpenSystemStoreW)(
  _In_ HCRYPTPROV_LEGACY hprov,
  _In_ LPCWSTR           szSubsystemProtocol
);

HANDLE WINAPI MyCreateMutexW(
  _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
  _In_     BOOL                  bInitialOwner,
  _In_opt_ LPCWSTR               lpName
);
typedef HANDLE (WINAPI *ptrCreateMutexW)(
  _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
  _In_     BOOL                  bInitialOwner,
  _In_opt_ LPCWSTR               lpName
);

HRSRC WINAPI MyFindResourceW(
  _In_opt_ HMODULE hModule,
  _In_     LPCWSTR lpName,
  _In_     LPCWSTR lpType
);
typedef HRSRC (WINAPI *ptrFindResourceW)(
  _In_opt_ HMODULE hModule,
  _In_     LPCWSTR lpName,
  _In_     LPCWSTR lpType
);

HWND WINAPI MyFindWindowW(
  _In_opt_ LPCWSTR lpClassName,
  _In_opt_ LPCWSTR lpWindowName
);
typedef HWND (WINAPI *ptrFindWindowW)(
  _In_opt_ LPCWSTR lpClassName,
  _In_opt_ LPCWSTR lpWindowName
);

UINT WINAPI MyGetWindowsDirectoryW(
  _Out_ LPTSTR lpBuffer,
  _In_  UINT   uSize
);
typedef UINT (WINAPI *ptrGetWindowsDirectoryW)(
  _Out_ LPTSTR lpBuffer,
  _In_  UINT   uSize
);

UINT WINAPI MyMapVirtualKeyW(
  _In_ UINT uCode,
  _In_ UINT uMapType
);
typedef UINT (WINAPI *ptrMapVirtualKeyW)(          
  _In_ UINT uCode,
  _In_ UINT uMapType
);

HANDLE WINAPI MyOpenMutexW(
  _In_ DWORD   dwDesiredAccess,
  _In_ BOOL    bInheritHandle,
  _In_ LPCWSTR lpName
);
typedef HANDLE (WINAPI *ptrOpenMutexW)(
  _In_ DWORD   dwDesiredAccess,
  _In_ BOOL    bInheritHandle,
  _In_ LPCWSTR lpName
);

SC_HANDLE WINAPI MyOpenSCManagerW(
  _In_opt_ LPCWSTR lpMachineName,
  _In_opt_ LPCWSTR lpDatabaseName,
  _In_     DWORD   dwDesiredAccess
);
typedef SC_HANDLE (WINAPI *ptrOpenSCManagerW)(
  _In_opt_ LPCWSTR lpMachineName,
  _In_opt_ LPCWSTR lpDatabaseName,
  _In_     DWORD   dwDesiredAccess
);

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
);
typedef BOOL (WINAPI *ptrCreateProcessA)(
  _In_opt_    LPCSTR               lpApplicationName,
  _Inout_opt_ LPSTR                lpCommandLine,
  _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_        BOOL                  bInheritHandles,
  _In_        DWORD                 dwCreationFlags,
  _In_opt_    LPVOID                lpEnvironment,
  _In_opt_    LPCSTR               lpCurrentDirectory,
  _In_        LPSTARTUPINFOA        lpStartupInfo,
  _Out_       LPPROCESS_INFORMATION lpProcessInformation
);

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
);
typedef SC_HANDLE (WINAPI *ptrCreateServiceW)(
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
);

DWORD WINAPI MyGetModuleFileNameExW(
  _In_     HANDLE  hProcess,
  _In_opt_ HMODULE hModule,
  _Out_    LPTSTR  lpFilename,
  _In_     DWORD   nSize
);
typedef DWORD (WINAPI *ptrGetModuleFileNameExW)(
  _In_     HANDLE  hProcess,
  _In_opt_ HMODULE hModule,
  _Out_    LPTSTR  lpFilename,
  _In_     DWORD   nSize
);

HMODULE WINAPI MyGetModuleHandleW(
  _In_opt_ LPCWSTR lpModuleName
);
typedef HMODULE (WINAPI *ptrGetModuleHandleW)(
  _In_opt_ LPCWSTR lpModuleName
);

VOID WINAPI MyGetStartupInfoW(
  _Out_ LPSTARTUPINFO lpStartupInfo
);
typedef VOID (WINAPI *ptrGetStartupInfoW)(
  _Out_ LPSTARTUPINFO lpStartupInfo
);

BOOL WINAPI	MyGetVersionExW(
  _Inout_ LPOSVERSIONINFO lpVersionInfo
);
typedef BOOL (WINAPI *ptrGetVersionExW)(
  _Inout_ LPOSVERSIONINFO lpVersionInfo
);

HMODULE WINAPI MyLoadLibraryW(
  _In_ LPCWSTR lpLibFileName
);
typedef HMODULE (WINAPI *ptrLoadLibraryW)(
  _In_ LPCWSTR lpFileName
);

void WINAPI MyOutputDebugStringW(
  _In_opt_ LPCWSTR lpOutputString
);
typedef VOID (WINAPI *ptrOutputDebugStringW)(
  _In_opt_ LPCWSTR lpOutputString
);

HHOOK WINAPI MySetWindowsHookExW(
  _In_ int       idHook,
  _In_ HOOKPROC  lpfn,
  _In_ HINSTANCE hMod,
  _In_ DWORD     dwThreadId
);
typedef HHOOK (WINAPI *ptrSetWindowsHookExW)(
  _In_ int       idHook,
  _In_ HOOKPROC  lpfn,
  _In_ HINSTANCE hMod,
  _In_ DWORD     dwThreadId
);

HINSTANCE WINAPI MyShellExecuteW(
  _In_opt_ HWND    hwnd,
  _In_opt_ LPCWSTR lpOperation,
  _In_     LPCWSTR lpFile,
  _In_opt_ LPCWSTR lpParameters,
  _In_opt_ LPCWSTR lpDirectory,
  _In_     INT     nShowCmd
);
typedef HINSTANCE (WINAPI *ptrShellExecuteW)(
  _In_opt_ HWND    hwnd,
  _In_opt_ LPCWSTR lpOperation,
  _In_     LPCWSTR lpFile,
  _In_opt_ LPCWSTR lpParameters,
  _In_opt_ LPCWSTR lpDirectory,
  _In_     INT     nShowCmd
);

BOOL WINAPI MyStartServiceCtrlDispatcherW(
  _In_ const SERVICE_TABLE_ENTRY *lpServiceStartTable
);
typedef BOOL (WINAPI *ptrStartServiceCtrlDispatcherW)(
  _In_ const SERVICE_TABLE_ENTRY *lpServiceTable
);

BOOL WINAPI MySetLocalTime(
  _In_ const SYSTEMTIME *lpSystemTime
);
typedef BOOL (WINAPI *ptrSetLocalTime)(
  _In_ const SYSTEMTIME *lpSystemTime
);

BOOL WINAPI MyTerminateThread(
  _Inout_ HANDLE hThread,
  _In_    DWORD  dwExitCode
);
typedef BOOL (WINAPI *ptrTerminateThread)(
  _Inout_ HANDLE hThread,
  _In_    DWORD  dwExitCode
);

BOOL WINAPI MyVirtualFree(
  _In_ LPVOID lpAddress,
  _In_ SIZE_T dwSize,
  _In_ DWORD  dwFreeType
);
typedef BOOL (WINAPI *ptrVirtualFree)(
  _In_ LPVOID lpAddress,
  _In_ SIZE_T dwSize,
  _In_ DWORD  dwFreeType
);

BOOL WINAPI MySetProcessWorkingSetSize(
  _In_ HANDLE hProcess,
  _In_ SIZE_T dwMinimumWorkingSetSize,
  _In_ SIZE_T dwMaximumWorkingSetSize
);
typedef BOOL (WINAPI *ptrSetProcessWorkingSetSize)(
  _In_ HANDLE hProcess,
  _In_ SIZE_T dwMinimumWorkingSetSize,
  _In_ SIZE_T dwMaximumWorkingSetSize
);

BOOL WINAPI MyTerminateProcess(
  _In_ HANDLE hProcess,
  _In_ UINT   uExitCode
);
typedef BOOL (WINAPI *ptrTerminateProcess)(
  _In_ HANDLE hProcess,
  _In_ UINT   uExitCode
);

//注册表
LONG WINAPI MyRegOpenKeyExW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     DWORD   ulOptions,
  _In_     REGSAM  samDesired,
  _Out_    PHKEY   phkResult
);
typedef LONG (WINAPI *ptrRegOpenKeyExW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     DWORD   ulOptions,
  _In_     REGSAM  samDesired,
  _Out_    PHKEY   phkResult
);

LONG WINAPI MyRegOpenKeyW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _Out_    PHKEY   phkResult
);
typedef LONG (WINAPI *ptrRegOpenKeyW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _Out_    PHKEY   phkResult
);

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
);
typedef LONG (WINAPI *ptrRegCreateKeyExW)(
  _In_       HKEY                  hKey,
  _In_       LPCWSTR               lpSubKey,
  _Reserved_ DWORD                 Reserved,
  _In_opt_   LPTSTR                lpClass,
  _In_       DWORD                 dwOptions,
  _In_       REGSAM                samDesired,
  _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _Out_      PHKEY                 phkResult,
  _Out_opt_  LPDWORD               lpdwDisposition
);

LONG WINAPI MyRegCreateKeyW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _Out_    PHKEY   phkResult
);
typedef LONG (WINAPI *ptrRegCreateKeyW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _Out_    PHKEY   phkResult
);

LONG WINAPI MyRegQueryValueExW(
  _In_        HKEY    hKey,
  _In_opt_    LPCWSTR lpValueName,
  _Reserved_  LPDWORD lpReserved,
  _Out_opt_   LPDWORD lpType,
  _Out_opt_   LPBYTE  lpData,
  _Inout_opt_ LPDWORD lpcbData
);
typedef LONG (WINAPI *ptrRegQueryValueExW)(
  _In_        HKEY    hKey,
  _In_opt_    LPCWSTR lpValueName,
  _Reserved_  LPDWORD lpReserved,
  _Out_opt_   LPDWORD lpType,
  _Out_opt_   LPBYTE  lpData,
  _Inout_opt_ LPDWORD lpcbData
);

LONG WINAPI MyRegQueryValueW(
  _In_        HKEY    hKey,
  _In_opt_    LPCWSTR lpSubKey,
  _Out_opt_   LPTSTR  lpValue,
  _Inout_opt_ PLONG   lpcbValue
);
typedef LONG (WINAPI *ptrRegQueryValueW)(
  _In_        HKEY    hKey,
  _In_opt_    LPCWSTR lpSubKey,
  _Out_opt_   LPTSTR  lpValue,
  _Inout_opt_ PLONG   lpcbValue
);

LONG WINAPI MyRegSetValueExW(
  _In_             HKEY    hKey,
  _In_opt_         LPCWSTR lpValueName,
  _Reserved_       DWORD   Reserved,
  _In_             DWORD   dwType,
  _In_       const BYTE    *lpData,
  _In_             DWORD   cbData
);
typedef LONG (WINAPI *ptrRegSetValueExW)(
  _In_             HKEY    hKey,
  _In_opt_         LPCWSTR lpValueName,
  _Reserved_       DWORD   Reserved,
  _In_             DWORD   dwType,
  _In_       const BYTE    *lpData,
  _In_             DWORD   cbData
);

LONG WINAPI MyRegSetValueW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     DWORD   dwType,
  _In_     LPCWSTR lpData,
  _In_     DWORD   cbData
);
typedef LONG (WINAPI *ptrRegSetValueW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     DWORD   dwType,
  _In_     LPCWSTR lpData,
  _In_     DWORD   cbData
);

LONG WINAPI MyRegDeleteKeyExW(
  _In_       HKEY    hKey,
  _In_       LPCWSTR lpSubKey,
  _In_       REGSAM  samDesired,
  _Reserved_ DWORD   Reserved
);
typedef LONG (WINAPI *ptrRegDeleteKeyExW)(
  _In_       HKEY    hKey,
  _In_       LPCWSTR lpSubKey,
  _In_       REGSAM  samDesired,
  _Reserved_ DWORD   Reserved
);

LONG WINAPI MyRegDeleteKeyW(
  _In_ HKEY    hKey,
  _In_ LPCWSTR lpSubKey
);
typedef LONG (WINAPI *ptrRegDeleteKeyW)(
  _In_ HKEY    hKey,
  _In_ LPCWSTR lpSubKey
);

LONG WINAPI MyRegSetKeySecurity(
  _In_ HKEY                 hKey,
  _In_ SECURITY_INFORMATION SecurityInformation,
  _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
);
typedef LONG (WINAPI *ptrRegSetKeySecurity)(
  _In_ HKEY                 hKey,
  _In_ SECURITY_INFORMATION SecurityInformation,
  _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
);

LONG WINAPI MyRegRestoreKeyW(
  _In_ HKEY    hKey,
  _In_ LPCWSTR lpFile,
  _In_ DWORD   dwFlags
);
typedef LONG (WINAPI *ptrRegRestoreKeyW)(
  _In_ HKEY    hKey,
  _In_ LPCWSTR lpFile,
  _In_ DWORD   dwFlags
);

LONG WINAPI MyRegReplaceKeyW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     LPCWSTR lpNewFile,
  _In_     LPCWSTR lpOldFile
);
typedef LONG (WINAPI *ptrRegReplaceKeyW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     LPCWSTR lpNewFile,
  _In_     LPCWSTR lpOldFile
);

LONG WINAPI MyRegLoadKeyW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     LPCWSTR lpFile
);
typedef LONG (WINAPI *ptrRegLoadKeyW)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey,
  _In_     LPCWSTR lpFile
);

LONG WINAPI MyRegUnLoadKey(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey
);
typedef LONG (WINAPI *ptrRegUnLoadKey)(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey
);
//网络
SOCKET WINAPI Myaccept(
  _In_    SOCKET          s,
  _Out_   struct sockaddr *addr,
  _Inout_ int             *addrlen
);
typedef SOCKET  (WINAPI *ptraccept)(
  _In_    SOCKET          s,
  _Out_   struct sockaddr *addr,
  _Inout_ int             *addrlen
);

int WINAPI Mysend(
  _In_       SOCKET s,
  _In_ const char   *buf,
  _In_       int    len,
  _In_       int    flags
);
typedef int (WINAPI *ptrsend)(
  _In_       SOCKET s,
  _In_ const char   *buf,
  _In_       int    len,
  _In_       int    flags
);

int WINAPI Mybind(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);
typedef int (WINAPI *ptrbind)(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);

int WINAPI Myconnect(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);
typedef int (WINAPI *ptrconnect)(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);

BOOL WINAPI MyConnectNamedPipe(
  _In_        HANDLE       hNamedPipe,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);
typedef BOOL (WINAPI *ptrConnectNamedPipe)(
  _In_        HANDLE       hNamedPipe,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);

/*
ULONG WINAPI MyGetAdaptersInfo(
  _Out_   PIP_ADAPTER_INFO pAdapterInfo,
  _Inout_ PULONG           SizePointer
);
typedef ULONG (WINAPI *ptrGetAdaptersInfo)(
  _Out_   PIP_ADAPTER_INFO pAdapterInfo,
  _Inout_ PULONG           SizePointer
);
extern ptrGetAdaptersInfo realGetAdaptersInfo;
*/
/*struct hostent* FAR Mygethostbyname(
  _In_ const char *name
);
*/
int WINAPI Mygethostname(
  _Out_ char *name,
  _In_  int  namelen
);
typedef int (WINAPI *ptrgethostname)(
  _Out_ char *name,
  _In_  int  namelen
);

unsigned long WINAPI Myinet_addr(
  _In_ const char *cp
);
typedef unsigned long (WINAPI *ptrinet_addr)(
  _In_ const char *cp
);

BOOL WINAPI MyInternetReadFile(
  _In_  HINTERNET hFile,
  _Out_ LPVOID    lpBuffer,
  _In_  DWORD     dwNumberOfBytesToRead,
  _Out_ LPDWORD   lpdwNumberOfBytesRead
);
typedef BOOL (WINAPI *ptrInternetReadFile)(
  _In_  HINTERNET hFile,
  _Out_ LPVOID    lpBuffer,
  _In_  DWORD     dwNumberOfBytesToRead,
  _Out_ LPDWORD   lpdwNumberOfBytesRead
);

BOOL WINAPI MyInternetWriteFile(
  _In_  HINTERNET hFile,
  _In_  LPCVOID   lpBuffer,
  _In_  DWORD     dwNumberOfBytesToWrite,
  _Out_ LPDWORD   lpdwNumberOfBytesWritten
);
typedef BOOL (WINAPI *ptrInternetWriteFile)(
  _In_  HINTERNET hFile,
  _In_  LPCVOID   lpBuffer,
  _In_  DWORD     dwNumberOfBytesToWrite,
  _Out_ LPDWORD   lpdwNumberOfBytesWritten
);

NET_API_STATUS WINAPI MyNetShareEnum(
  _In_    LPWSTR  servername,
  _In_    DWORD   level,
  _Out_   LPBYTE  *bufptr,
  _In_    DWORD   prefmaxlen,
  _Out_   LPDWORD entriesread,
  _Out_   LPDWORD totalentries,
  _Inout_ LPDWORD resume_handle
);
typedef NET_API_STATUS (WINAPI *ptrNetShareEnum)(
  _In_    LPWSTR  servername,
  _In_    DWORD   level,
  _Out_   LPBYTE  *bufptr,
  _In_    DWORD   prefmaxlen,
  _Out_   LPDWORD entriesread,
  _Out_   LPDWORD totalentries,
  _Inout_ LPDWORD resume_handle
);

int WINAPI Myrecv(
  SOCKET s,
  char FAR* buf,
  int len,
  int flags
);
typedef int (WINAPI *ptrrecv)(
  SOCKET s,
  char FAR* buf,
  int len,
  int flags
);

int WINAPI MyWSAStartup(
  _In_  WORD      wVersionRequested,
  _Out_ LPWSADATA lpWSAData
);
typedef int (WINAPI *ptrWSAStartup)(
  _In_  WORD      wVersionRequested,
  _Out_ LPWSADATA lpWSAData
);

HINTERNET WINAPI MyInternetOpenW(
  _In_ LPCWSTR lpszAgent,
  _In_ DWORD   dwAccessType,
  _In_ LPCWSTR lpszProxy,
  _In_ LPCWSTR lpszProxyBypass,
  _In_ DWORD   dwFlags
);
typedef HINTERNET (WINAPI *ptrInternetOpenW)(
  _In_ LPCWSTR lpszAgent,
  _In_ DWORD   dwAccessType,
  _In_ LPCWSTR lpszProxy,
  _In_ LPCWSTR lpszProxyBypass,
  _In_ DWORD   dwFlags
);

HINTERNET WINAPI MyInternetOpenUrlW(
  _In_ HINTERNET hInternet,
  _In_ LPCWSTR   lpszUrl,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);
typedef HINTERNET (WINAPI *ptrInternetOpenUrlW)(
  _In_ HINTERNET hInternet,
  _In_ LPCWSTR   lpszUrl,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);

HRESULT WINAPI MyURLDownloadToFileW(
             LPUNKNOWN            pCaller,
             LPCWSTR              szURL,
             LPCWSTR              szFileName,
  _Reserved_ DWORD                dwReserved,
             LPBINDSTATUSCALLBACK lpfnCB
);
typedef HRESULT (WINAPI *ptrURLDownloadToFileW)(
             LPUNKNOWN            pCaller,
             LPCWSTR              szURL,
             LPCWSTR              szFileName,
  _Reserved_ DWORD                dwReserved,
             LPBINDSTATUSCALLBACK lpfnCB
);

BOOL WINAPI MyFtpPutFileW(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszLocalFile,
  _In_ LPCWSTR   lpszNewRemoteFile,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);
typedef BOOL (WINAPI *ptrFtpPutFileW)(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszLocalFile,
  _In_ LPCWSTR   lpszNewRemoteFile,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);

BOOL WINAPI MyHttpSendRequestW(
  _In_ HINTERNET hRequest,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ LPVOID    lpOptional,
  _In_ DWORD     dwOptionalLength
);
typedef BOOL (WINAPI *ptrHttpSendRequestW)(
  _In_ HINTERNET hRequest,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ LPVOID    lpOptional,
  _In_ DWORD     dwOptionalLength
);

BOOL WINAPI MyHttpSendRequestExW(
  _In_  HINTERNET          hRequest,
  _In_  LPINTERNET_BUFFERS lpBuffersIn,
  _Out_ LPINTERNET_BUFFERS lpBuffersOut,
  _In_  DWORD              dwFlags,
  _In_  DWORD_PTR          dwContext
);
typedef BOOL (WINAPI *ptrHttpSendRequestExW)(
  _In_  HINTERNET          hRequest,
  _In_  LPINTERNET_BUFFERS lpBuffersIn,
  _Out_ LPINTERNET_BUFFERS lpBuffersOut,
  _In_  DWORD              dwFlags,
  _In_  DWORD_PTR          dwContext
);


HINTERNET WINAPI MyHttpOpenRequestW(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszVerb,
  _In_ LPCWSTR   lpszObjectName,
  _In_ LPCWSTR   lpszVersion,
  _In_ LPCWSTR   lpszReferer,
  _In_ LPCWSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);
typedef HINTERNET (WINAPI *ptrHttpOpenRequestW)(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszVerb,
  _In_ LPCWSTR   lpszObjectName,
  _In_ LPCWSTR   lpszVersion,
  _In_ LPCWSTR   lpszReferer,
  _In_ LPCWSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);

HINTERNET WINAPI MyInternetConnectW(
  _In_ HINTERNET     hInternet,
  _In_ LPCWSTR       lpszServerName,
  _In_ INTERNET_PORT nServerPort,
  _In_ LPCWSTR       lpszUsername,
  _In_ LPCWSTR       lpszPassword,
  _In_ DWORD         dwService,
  _In_ DWORD         dwFlags,
  _In_ DWORD_PTR     dwContext
);
typedef HINTERNET (WINAPI *ptrInternetConnectW)(
  _In_ HINTERNET     hInternet,
  _In_ LPCWSTR       lpszServerName,
  _In_ INTERNET_PORT nServerPort,
  _In_ LPCWSTR       lpszUsername,
  _In_ LPCWSTR       lpszPassword,
  _In_ DWORD         dwService,
  _In_ DWORD         dwFlags,
  _In_ DWORD_PTR     dwContext
);


int WINAPI Mylisten(
  _In_ SOCKET s,
  _In_ int    backlog
);
typedef int (WINAPI *ptrlisten)(
  _In_ SOCKET s,
  _In_ int    backlog
);

HINTERNET WINAPI MyInternetOpenUrlA( _In_ HINTERNET hInternet, _In_ LPCSTR lpszUrl, _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext );
typedef HINTERNET (WINAPI *ptrInternetOpenUrlA)( _In_ HINTERNET hInternet, _In_ LPCSTR lpszUrl, _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext);

HINTERNET WINAPI MyHttpOpenRequestA( _In_ HINTERNET hConnect, _In_opt_ LPCSTR lpszVerb, _In_opt_ LPCSTR lpszObjectName, _In_opt_ LPCSTR lpszVersion, _In_opt_ LPCSTR lpszReferrer, _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext );
typedef HINTERNET (WINAPI *ptrHttpOpenRequestA)(_In_ HINTERNET hConnect, _In_opt_ LPCSTR lpszVerb, _In_opt_ LPCSTR lpszObjectName, _In_opt_ LPCSTR lpszVersion, _In_opt_ LPCSTR lpszReferrer, _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext );

//新增API
DWORD WINAPI MySetFilePointer( _In_ HANDLE hFile, _In_ LONG lDistanceToMove, _Inout_opt_ PLONG lpDistanceToMoveHigh, _In_ DWORD dwMoveMethod );
typedef DWORD (WINAPI *ptrSetFilePointer)( _In_ HANDLE hFile, _In_ LONG lDistanceToMove, _Inout_opt_ PLONG lpDistanceToMoveHigh, _In_ DWORD dwMoveMethod );

BOOL WINAPI MyMoveFileExW( _In_ LPCWSTR lpExistingFileName, _In_opt_ LPCWSTR lpNewFileName, _In_ DWORD dwFlags );
typedef BOOL (WINAPI *ptrMoveFileExW)( _In_ LPCWSTR lpExistingFileName, _In_opt_ LPCWSTR lpNewFileName, _In_ DWORD dwFlags );

BOOL WINAPI MyWriteFile( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped );
typedef BOOL (WINAPI *ptrWriteFile)( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped );

BOOL WINAPI MyWriteFileEx( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Inout_ LPOVERLAPPED lpOverlapped, _In_opt_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
typedef BOOL (WINAPI *ptrWriteFileEx)( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Inout_ LPOVERLAPPED lpOverlapped, _In_opt_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );

BOOL MyShellExecuteExW(_Inout_ SHELLEXECUTEINFOW *pExecInfo);
typedef BOOL (*ptrShellExecuteExW)(_Inout_ SHELLEXECUTEINFOW *pExecInfo);

VOID WINAPI MyExitProcess( _In_ UINT uExitCode );
typedef VOID (WINAPI *ptrExitProcess)( _In_ UINT uExitCode );

BOOL WINAPI MyVirtualProtect( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect );
typedef BOOL (WINAPI *ptrVirtualProtect)( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect );

BOOL WINAPI MyCreateProcessInternalW( HANDLE 	hUserToken,
									 LPCWSTR 	lpApplicationName,
									 LPWSTR 	lpCommandLine,
									 LPSECURITY_ATTRIBUTES 	lpProcessAttributes,
									 LPSECURITY_ATTRIBUTES 	lpThreadAttributes,
									 BOOL 	bInheritHandles,
									 DWORD 	dwCreationFlags,
									 LPVOID 	lpEnvironment,
									 LPCWSTR 	lpCurrentDirectory,
									 LPSTARTUPINFOW 	lpStartupInfo,
									 LPPROCESS_INFORMATION 	lpProcessInformation,
									 PHANDLE 	hNewToken 
									 );
typedef BOOL (WINAPI *ptrCreateProcessInternalW)( HANDLE 	hUserToken,
												 LPCWSTR 	lpApplicationName,
												 LPWSTR 	lpCommandLine,
												 LPSECURITY_ATTRIBUTES 	lpProcessAttributes,
												 LPSECURITY_ATTRIBUTES 	lpThreadAttributes,
												 BOOL 	bInheritHandles,
												 DWORD 	dwCreationFlags,
												 LPVOID 	lpEnvironment,
												 LPCWSTR 	lpCurrentDirectory,
												 LPSTARTUPINFOW 	lpStartupInfo,
												 LPPROCESS_INFORMATION 	lpProcessInformation,
												 PHANDLE 	hNewToken 
												 );
//新增API
BOOL WINAPI MyMoveFileA( _In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName );
typedef BOOL (WINAPI *ptrMoveFileA)( _In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName );

BOOL WINAPI MyMoveFileExA( _In_ LPCSTR lpExistingFileName, _In_opt_ LPCSTR lpNewFileName, _In_ DWORD dwFlags );
typedef BOOL (WINAPI *ptrMoveFileExA)( _In_ LPCSTR lpExistingFileName, _In_opt_ LPCSTR lpNewFileName, _In_ DWORD dwFlags );

LONG WINAPI MyRegQueryValueExA( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName, _Reserved_ LPDWORD lpReserved, _Out_opt_ LPDWORD lpType, _Out_opt_ LPBYTE lpData,  _Inout_opt_ LPDWORD lpcbData );
typedef LONG (WINAPI *ptrRegQueryValueExA)( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName, _Reserved_ LPDWORD lpReserved, _Out_opt_ LPDWORD lpType, _Out_opt_ LPBYTE lpData,  _Inout_opt_ LPDWORD lpcbData );

LONG WINAPI MyRegQueryValueA( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_opt_ LPSTR lpData, _Inout_opt_ PLONG lpcbData );
typedef LONG (WINAPI *ptrRegQueryValueA)( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_opt_ LPSTR lpData, _Inout_opt_ PLONG lpcbData );

LONG WINAPI MyRegDeleteValueA( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName );
typedef LONG (WINAPI *ptrRegDeleteValueA)( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName );

LONG WINAPI MyRegDeleteValueW( _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName );
typedef LONG (WINAPI *ptrRegDeleteValueW)( _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName );

LONG WINAPI MyRegDeleteKeyExA( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _In_ REGSAM samDesired, _Reserved_ DWORD Reserved );
typedef LONG (WINAPI *ptrRegDeleteKeyExA)( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _In_ REGSAM samDesired, _Reserved_ DWORD Reserved );

LONG WINAPI MyRegCreateKeyExA( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _Reserved_ DWORD Reserved, _In_opt_ LPSTR lpClass, _In_ DWORD dwOptions, _In_ REGSAM samDesired, _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, _Out_ PHKEY phkResult, _Out_opt_ LPDWORD lpdwDisposition );
typedef LONG (WINAPI *ptrRegCreateKeyExA)( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _Reserved_ DWORD Reserved, _In_opt_ LPSTR lpClass, _In_ DWORD dwOptions, _In_ REGSAM samDesired, _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, _Out_ PHKEY phkResult, _Out_opt_ LPDWORD lpdwDisposition );

LONG WINAPI MyRegCreateKeyA( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_ PHKEY phkResult );
typedef LONG (WINAPI *ptrRegCreateKeyA)( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_ PHKEY phkResult );

HHOOK WINAPI MySetWindowsHookExA(_In_ int idHook, _In_ HOOKPROC lpfn, _In_opt_ HINSTANCE hmod, _In_ DWORD dwThreadId);
typedef HHOOK (WINAPI *ptrSetWindowsHookExA)(_In_ int idHook, _In_ HOOKPROC lpfn, _In_opt_ HINSTANCE hmod, _In_ DWORD dwThreadId);

SC_HANDLE WINAPI MyCreateServiceA( _In_ SC_HANDLE hSCManager, _In_ LPCSTR lpServiceName, _In_opt_ LPCSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCSTR lpBinaryPathName, _In_opt_ LPCSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCSTR lpDependencies, _In_opt_ LPCSTR lpServiceStartName, _In_opt_ LPCSTR lpPassword );
typedef SC_HANDLE (WINAPI *ptrCreateServiceA)( _In_ SC_HANDLE hSCManager, _In_ LPCSTR lpServiceName, _In_opt_ LPCSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCSTR lpBinaryPathName, _In_opt_ LPCSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCSTR lpDependencies, _In_opt_ LPCSTR lpServiceStartName, _In_opt_ LPCSTR lpPassword );

BOOL WINAPI MyProcess32FirstW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
typedef BOOL (WINAPI *ptrProcess32FirstW)( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );

BOOL WINAPI MyProcess32NextW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
typedef BOOL (WINAPI *ptrProcess32NextW)( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );

BOOL WINAPI MyDeleteFileA( _In_ LPCSTR lpFileName );
typedef BOOL (WINAPI *ptrDeleteFileA)( _In_ LPCSTR lpFileName );

HANDLE WINAPI MyFindFirstFileA( _In_ LPCSTR lpFileName, _Out_ LPWIN32_FIND_DATAA lpFindFileData );
typedef HANDLE (WINAPI *ptrFindFirstFileA)( _In_ LPCSTR lpFileName, _Out_ LPWIN32_FIND_DATAA lpFindFileData );

BOOL WINAPI MyFindNextFileA( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAA lpFindFileData );
typedef BOOL (WINAPI *ptrFindNextFileA)( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAA lpFindFileData );

LRESULT WINAPI MySendMessageA(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);
typedef LRESULT (WINAPI *ptrSendMessageA)(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);

LRESULT WINAPI MySendMessageW(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);
typedef LRESULT (WINAPI *ptrSendMessageW)(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);

BOOL WINAPI MyPostMessageA(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef BOOL (WINAPI *ptrPostMessageA)(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);

BOOL WINAPI MyPostMessageW(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef BOOL (WINAPI *ptrPostMessageW)(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);


extern ptrBitBlt realBitBlt;
extern  ptrCreateFileMappingW realCreateFileMappingW;
extern  ptrOpenFileMappingW realOpenFileMappingW;
extern  ptrCryptAcquireContext realCryptAcquireContext ;
extern  ptrDeviceIoControl realDeviceIoControl;
extern ptrFindWindowExW realFindWindowExW;
extern  ptrGetAsyncKeyState realGetAsyncKeyState;
extern  ptrGetDC realGetDC;
extern  ptrGetKeyState realGetKeyState;
extern  ptrGetForegroundWindow realGetForegroundWindow;
extern  ptrGetTempPath realGetTempPath;
extern  ptrMapViewOfFile realMapViewOfFile;

extern	  ptrCreateFileW realCreateFileW ;  
extern	  ptrCreateFileA realCreateFileA ;  
extern	  ptrReadFile realReadFile;
extern	  ptrMoveFileW realMoveFileW;
extern	  ptrCopyFileW realCopyFileW;
extern	  ptrDeleteFileW realDeleteFileW;
extern	  ptrFindFirstFileW realFindFirstFileW;
extern	  ptrFindNextFileW realFindNextFileW;
extern	  ptrSetFileAttributesW realSetFileAttributesW;
extern	  ptrCreateHardLinkW realCreateHardLinkW;
extern	  ptrSetEndOfFile realSetEndOfFile;
extern	  ptrSetFileValidData realSetFileValidData;
extern	  ptrSetFileTime realSetFileTime;

//文件API

extern	  ptrOpenFile realOpenFile;
extern	  ptrAdjustTokenPrivileges realAdjustTokenPrivileges;
extern	  ptrAttachThreadInput realAttachThreadInput;
extern	  ptrCallNextHookEx realCallNextHookEx;
extern	  ptrCheckRemoteDebuggerPresent realCheckRemoteDebuggerPresent;
extern	  ptrControlService realControlService;
extern	  ptrCreateRemoteThread realCreateRemoteThread;
extern	  ptrCreateToolhelp32Snapshot realCreateToolhelp32Snapshot;
extern	  ptrEnumProcesses realEnumProcesses;
extern	  ptrEnumProcessModules realEnumProcessModules;
extern	  ptrGetProcAddress realGetProcAddress;
extern	  ptrGetSystemDefaultLangID realGetSystemDefaultLangID;
extern	  ptrGetThreadContext realGetThreadContext;
extern	  ptrGetTickCount realGetTickCount ;
extern	  ptrIsDebuggerPresent realIsDebuggerPresent;
extern	  ptrLoadLibraryExW realLoadLibraryExW;
extern	  ptrLoadResource realLoadResource;
extern	  ptrModule32FirstW realModule32FirstW;
extern	  ptrModule32NextW realModule32NextW;
extern	  ptrOpenProcess realOpenProcess;
extern	  ptrPeekNamedPipe realPeekNamedPipe;
extern	  ptrProcess32First realProcess32First;
extern	  ptrProcess32Next realProcess32Next;
extern	  ptrQueryPerformanceCounter realQueryPerformanceCounter;
extern	  ptrQueueUserAPC realQueueUserAPC;
extern	  ptrReadProcessMemory realReadProcessMemory;
extern	  ptrResumeThread realResumeThread;
extern	  ptrSetThreadContext realSetThreadContext;
extern	  ptrSuspendThread realSuspendThread;
	//ptrsystem realsystem;
extern	  ptrThread32First realThread32First;
extern	  ptrThread32Next realThread32Next;
extern	  ptrToolhelp32ReadProcessMemory realToolhelp32ReadProcessMemory;
extern	  ptrVirtualAllocEx realVirtualAllocEx;
extern	  ptrVirtualProtectEx realVirtualProtectEx;
extern	  ptrWinExec realWinExec;
extern	  ptrWriteProcessMemory realWriteProcessMemory;
extern	  ptrRegisterHotKey realRegisterHotKey;
extern	  ptrCreateProcessA realCreateProcessA;
extern	  ptrCertOpenSystemStoreW realCertOpenSystemStoreW;
extern	  ptrCreateMutexW realCreateMutexW;
extern	  ptrFindResourceW realFindResourceW;
extern	  ptrFindWindowW realFindWindowW;
extern	  ptrGetWindowsDirectoryW realGetWindowsDirectoryW;
extern	  ptrMapVirtualKeyW realMapVirtualKeyW;
extern	  ptrOpenMutexW realOpenMutexW;
extern	  ptrOpenSCManagerW realOpenSCManagerW;
extern	  ptrCreateProcessW realCreateProcessW;
extern	  ptrCreateServiceW realCreateServiceW;
extern	  ptrGetModuleFileNameExW realGetModuleFileNameExW;
extern	  ptrGetModuleHandleW realGetModuleHandleW;
extern	  ptrGetStartupInfoW realGetStartupInfoW;
extern	  ptrGetVersionExW realGetVersionExW;
extern	  ptrLoadLibraryW realLoadLibraryW;
extern	  ptrOutputDebugStringW realOutputDebugStringW;
extern	  ptrSetWindowsHookExW realSetWindowsHookExW;
extern	  ptrShellExecuteW realShellExecuteW;
extern	  ptrStartServiceCtrlDispatcherW realStartServiceCtrlDispatcherW;
extern	  ptrSetLocalTime realSetLocalTime;
extern	  ptrTerminateThread realTerminateThread;
extern	  ptrVirtualFree realVirtualFree;
extern	  ptrSetProcessWorkingSetSize realSetProcessWorkingSetSize;
extern	  ptrTerminateProcess realTerminateProcess;
	//注册表
extern	  ptrRegOpenKeyExW realRegOpenKeyExW;
extern	  ptrRegOpenKeyW realRegOpenKeyW;
extern	  ptrRegCreateKeyExW realRegCreateKeyExW;
extern	  ptrRegCreateKeyW realRegCreateKeyW;
extern	  ptrRegQueryValueExW realRegQueryValueExW;
extern	  ptrRegQueryValueW realRegQueryValueW;
extern	  ptrRegSetValueExW realRegSetValueExW;
extern	  ptrRegSetValueW realRegSetValueW;
extern	  ptrRegDeleteKeyExW realRegDeleteKeyExW;
extern	  ptrRegDeleteKeyW realRegDeleteKeyW;
extern	  ptrRegSetKeySecurity realRegSetKeySecurity;
extern	  ptrRegRestoreKeyW realRegRestoreKeyW;
extern	  ptrRegReplaceKeyW realRegReplaceKeyW;
extern	  ptrRegLoadKeyW realRegLoadKeyW;
extern	  ptrRegUnLoadKey realRegUnLoadKey;
	//网络
extern	  ptraccept realaccept;
extern	  ptrsend realsend;
extern	  ptrbind realbind;
extern	  ptrconnect realconnect;
extern	  ptrConnectNamedPipe realConnectNamedPipe;
extern	  ptrgethostname realgethostname;
extern	  ptrinet_addr realinet_addr;
extern	  ptrInternetReadFile realInternetReadFile;
extern	  ptrInternetWriteFile realInternetWriteFile;
extern	  ptrNetShareEnum realNetShareEnum;
extern	  ptrrecv realrecv;
extern	  ptrWSAStartup realWSAStartup;
extern	  ptrInternetOpenW realInternetOpenW;
extern	  ptrInternetOpenUrlW realInternetOpenUrlW;
extern	  ptrURLDownloadToFileW realURLDownloadToFileW;
extern	  ptrFtpPutFileW realFtpPutFileW;
extern	  ptrHttpSendRequestW realHttpSendRequestW;
extern	  ptrHttpSendRequestExW realHttpSendRequestExW;
extern	  ptrHttpOpenRequestW realHttpOpenRequestW;
extern	  ptrInternetConnectW realInternetConnectW;
extern	  ptrlisten reallisten;
extern    ptrInternetOpenUrlA realInternetOpenUrlA;
extern    ptrHttpOpenRequestA realHttpOpenRequestA;

//新增API
extern    ptrSetFilePointer realSetFilePointer;
extern	  ptrMoveFileExW realMoveFileExW;
extern    ptrWriteFile realWriteFile;
extern    ptrWriteFileEx realWriteFileEx;
extern    ptrShellExecuteExW realShellExecuteExW;
extern    ptrExitProcess realExitProcess;
extern	  ptrVirtualProtect realVirtualProtect;

//新增的API
extern	  ptrCreateProcessInternalW realCreateProcessInternalW;
extern    ptrMoveFileA realMoveFileA;
extern    ptrMoveFileExA realMoveFileExA;
extern	  ptrRegQueryValueExA realRegQueryValueExA;
extern    ptrRegQueryValueA realRegQueryValueA;
extern    ptrRegDeleteValueA realRegDeleteValueA;
extern    ptrRegDeleteValueW realRegDeleteValueW;
extern    ptrRegDeleteKeyExA realRegDeleteKeyExA;
extern    ptrRegCreateKeyExA realRegCreateKeyExA;
extern    ptrRegCreateKeyA realRegCreateKeyA;
extern    ptrSetWindowsHookExA realSetWindowsHookExA;
extern    ptrCreateServiceA realCreateServiceA;
extern    ptrProcess32FirstW realProcess32FirstW;
extern    ptrProcess32NextW realProcess32NextW;
extern	  ptrDeleteFileA realDeleteFileA;
extern    ptrFindFirstFileA realFindFirstFileA;
extern    ptrFindNextFileA realFindNextFileA;
extern    ptrSendMessageA realSendMessageA;
extern    ptrSendMessageW realSendMessageW;
extern    ptrPostMessageA realPostMessageA;
extern    ptrPostMessageW realPostMessageW;

extern	char g_log_path[255];
extern	char log_path[255];
extern	char strBuffer[256];//用户名
extern	char hostname[128];//主机名
extern	char spy[6];//监测层，监测程序代号，监测程序模块
extern	char ProcessName[255];
extern	string Log[100];
extern	char dat[100];
extern	char tim[50];
extern	TCHAR pathname[MAX_PATH];
extern	char path[MAX_PATH];
extern  char dlldir[MAX_PATH];
extern  char propath[MAX_PATH];


void GetProcessName(char* szProcessName,int* nLen);

char * GetDate();
//宽字符转化为多字节
string WideToMutilByte(const wstring& _src);

//根据HKEY对象获取注册表键的路径
string GetKeyPathFromKKEY(HKEY key);

//根据SOCKET对象获取ip
char * GetIPbySocket(SOCKET s);

//获取当前时间

char * LogTime();
//获取进程路径名

char * GetProcessPath();

//提权
int EnableDebugPriv(const char* name);

//注入
BOOL InjectDll(const char *DllFullPath,const DWORD dwRemoteProcessId);

//判断是否是64位进程
int GetProcessIsWOW64(DWORD pid);

//根据文件句柄获取文件名
//int GetFileNameByHandle(HANDLE hFile,LPTSTR buff,DWORD size);
typedef DWORD (WINAPI *MyGetMappedFileName)(HANDLE,LPVOID,LPTSTR,DWORD);
int GetFileNameByHandle(HANDLE hFile,LPSTR buff,DWORD size);

//写日志函数
void WriteLog(string s);

//判断是否是跨进程操作
bool Acpro_Operation (int threadid);

char * GetProPath(DWORD pid);
#endif