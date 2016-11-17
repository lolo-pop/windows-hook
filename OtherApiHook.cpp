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
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")

DWORD WINAPI MySetFilePointer( _In_ HANDLE hFile, _In_ LONG lDistanceToMove, _Inout_opt_ PLONG lpDistanceToMoveHigh, _In_ DWORD dwMoveMethod ){
	
	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFilePointer>,func_params=<hFile|"<<hFilepath<<",lDistanceToMove|"<<lDistanceToMove<<",dwMoveMethod|"<<dwMoveMethod<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realSetFilePointer)(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
}

BOOL WINAPI MyMoveFileExW( _In_ LPCWSTR lpExistingFileName, _In_opt_ LPCWSTR lpNewFileName, _In_ DWORD dwFlags ){

	string lpFileNamestr1;
	lpFileNamestr1=WideToMutilByte(lpExistingFileName);
	string lpFileNamestr2="NULL";
	if (lpNewFileName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpNewFileName);
	}

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileExW>,func_params=<lpExistingFileName|"<<lpFileNamestr1<<",lpNewFileName|"<<lpFileNamestr2<<",dwFlags|"<<dwFlags<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realMoveFileExW)(lpExistingFileName,lpNewFileName,dwFlags);
}

BOOL WINAPI MyWriteFile( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped ){

	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	if (strcmp(hFilepath,"NULL")==0)
	{
		return (realWriteFile)(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
	}
	if (strcmp(hFilepath,g_log_path)==0)
	{
		return (realWriteFile)(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFile>,func_params=<hFile|"<<hFilepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realWriteFile)(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
}

BOOL WINAPI MyWriteFileEx( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Inout_ LPOVERLAPPED lpOverlapped, _In_opt_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine ){

	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}

	if (strcmp(hFilepath,g_log_path)==0)
	{
		return (realWriteFileEx)(hFile,lpBuffer,nNumberOfBytesToWrite,lpOverlapped,lpCompletionRoutine);
	}

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFileEx>,func_params=<hFile|"<<hFilepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realWriteFileEx)(hFile,lpBuffer,nNumberOfBytesToWrite,lpOverlapped,lpCompletionRoutine);
}

BOOL MyShellExecuteExW(_Inout_ SHELLEXECUTEINFOW *pExecInfo){

	/*
	char str1[512]="NULL";
	string str2="NULL";
	if (pExecInfo!=NULL)
	{
		strcpy_s(str1,strlen(pExecInfo->lpFile),pExecInfo->lpFile);
	}
	*/
	return (realShellExecuteExW)(pExecInfo);
}

VOID WINAPI MyExitProcess( _In_ UINT uExitCode ){

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ExitProcess>,func_params=<uExitCode|"<<uExitCode<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realExitProcess)(uExitCode);
}

BOOL WINAPI MyVirtualProtect( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect ){

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualProtect>,func_params=<lpAddress|"<<lpAddress<<",dwSize|"<<dwSize<<",flNewProtect|"<<flNewProtect<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realVirtualProtect)(lpAddress,dwSize,flNewProtect,lpflOldProtect);
}

BOOL WINAPI MyCreateProcessInternalW(IN HANDLE hUserToken, IN LPCWSTR lpApplicationName, IN LPWSTR lpCommandLine, IN LPSECURITY_ATTRIBUTES lpProcessAttributes, IN LPSECURITY_ATTRIBUTES lpThreadAttributes, IN BOOL bInheritHandles, IN DWORD dwCreationFlags, IN LPVOID lpEnvironment, IN LPCWSTR lpCurrentDirectory, IN LPSTARTUPINFOW lpStartupInfo, IN LPPROCESS_INFORMATION lpProcessInformation, OUT PHANDLE hNewToken )
{
	stringstream logstream;
	logstream.clear();
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
	BOOL res=FALSE;
	res = (realCreateProcessInternalW)(hUserToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation,hNewToken);
	int pid=0;
	pid = lpProcessInformation->dwProcessId;
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
		//InjectDll(easyhook64path,pid);
		//Sleep(200);
		InjectDll(mondll64path,pid);
	}else if (check==1)//32位进程
	{
		//WinExec(exe1,SW_HIDE);
		//Sleep(200);
		WinExec(exe2,SW_HIDE);
	}
	string st,sm;
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<CreateProcessInternalW>,func_params=<lpApplicationName|"<<lpFileNamestr1<<",lpCommandLine|"<<lpFileNamestr2<<",lpCurrentDirectory|"<<lpFileNamestr3<<">";
	//dwCreationFlags加进去
	sm=logstream.str();
	WriteLog(sm);
	return res;
}

BOOL WINAPI MyMoveFileA( _In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName )
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<MoveFileA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realMoveFileA)(lpExistingFileName,lpNewFileName);
}

BOOL WINAPI MyMoveFileExA( _In_ LPCSTR lpExistingFileName, _In_opt_ LPCSTR lpNewFileName, _In_ DWORD dwFlags )
{	
	stringstream logstream;
	logstream.clear();
	string str1="NULL";
	if (lpNewFileName!=NULL)
	{
		str1=lpNewFileName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<MoveFileExA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<str1<<",dwFlags|"<<dwFlags<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realMoveFileExA)(lpExistingFileName,lpNewFileName,dwFlags);
}

LONG WINAPI MyRegQueryValueExA( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName, _Reserved_ LPDWORD lpReserved, _Out_opt_ LPDWORD lpType, _Out_opt_ LPBYTE lpData,  _Inout_opt_ LPDWORD lpcbData )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	if (lpValueName!=NULL)
	{
		str1=lpValueName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegQueryValueExA>,func_params=<hKey|"<<str<<",lpValueName|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegQueryValueExA)(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}

LONG WINAPI MyRegQueryValueA( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_opt_ LPSTR lpData, _Inout_opt_ PLONG lpcbData )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	if (lpSubKey!=NULL)
	{
		str1=lpSubKey;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegQueryValueA>,func_params=<hKey|"<<str<<",lpSubKey|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegQueryValueA)(hKey,lpSubKey,lpData,lpcbData);
}

LONG WINAPI MyRegDeleteValueA( _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	if (lpValueName!=NULL)
	{
		str1=lpValueName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegDeleteValueA>,func_params=<hKey|"<<str<<",lpValueName|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);	
	return (realRegDeleteValueA)(hKey,lpValueName);
}

LONG WINAPI MyRegDeleteValueW( _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	if (lpValueName!=NULL)
	{
		str1=WideToMutilByte(lpValueName);
	}

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegDeleteValueW>,func_params=<hKey|"<<str<<",lpValueName|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegDeleteValueW)(hKey,lpValueName);
}

LONG WINAPI MyRegDeleteKeyExA( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _In_ REGSAM samDesired, _Reserved_ DWORD Reserved )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	str1=lpSubKey;

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegDeleteKeyExA>,func_params=<hKey|"<<str<<",lpSubKey|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegDeleteKeyExA)(hKey,lpSubKey,samDesired,Reserved);
}

LONG WINAPI MyRegCreateKeyExA( _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _Reserved_ DWORD Reserved, _In_opt_ LPSTR lpClass, _In_ DWORD dwOptions, _In_ REGSAM samDesired, _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, _Out_ PHKEY phkResult, _Out_opt_ LPDWORD lpdwDisposition )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	str1=lpSubKey;

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegCreateKeyExA>,func_params=<hKey|"<<str<<",lpSubKey|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegCreateKeyExA)(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,phkResult,lpdwDisposition);
}

LONG WINAPI MyRegCreateKeyA( _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_ PHKEY phkResult )
{
	stringstream logstream;
	logstream.clear();
	string str="NULL";
	str=GetKeyPathFromKKEY(hKey);
	string str1="NULL";
	if (lpSubKey!=NULL)
	{
		str1=lpSubKey;
	}

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<RegCreateKeyA>,func_params=<hKey|"<<str<<",lpSubKey|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realRegCreateKeyA)(hKey,lpSubKey,phkResult);
}

HHOOK WINAPI MySetWindowsHookExA(_In_ int idHook, _In_ HOOKPROC lpfn, _In_opt_ HINSTANCE hmod, _In_ DWORD dwThreadId)
{
	stringstream logstream;
	logstream.clear();

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<SetWindowsHookExA>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realSetWindowsHookExA)(idHook,lpfn,hmod,dwThreadId);
}

SC_HANDLE WINAPI MyCreateServiceA( _In_ SC_HANDLE hSCManager, _In_ LPCSTR lpServiceName, _In_opt_ LPCSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCSTR lpBinaryPathName, _In_opt_ LPCSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCSTR lpDependencies, _In_opt_ LPCSTR lpServiceStartName, _In_opt_ LPCSTR lpPassword )
{
	stringstream logstream;
	logstream.clear();
	string lpFileNamestr1="NULL";
	if (lpServiceName!=NULL)
	{
		lpFileNamestr1=lpServiceName;
	}
	string lpFileNamestr2="NULL";
	if (lpDisplayName!=NULL)
	{
		lpFileNamestr2=lpDisplayName;
	}
	string lpFileNamestr3="NULL";
	if (lpBinaryPathName!=NULL)
	{
		lpFileNamestr3=lpBinaryPathName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<CreateServiceA>,func_params=<lpServiceName|"<<lpFileNamestr1<<",lpDisplayName|"<<lpFileNamestr2<<",lpBinaryPathName|"<<lpFileNamestr3<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realCreateServiceA)(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}

BOOL WINAPI MyProcess32FirstW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe )
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<Process32FirstW>";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realProcess32FirstW)(hSnapshot,lppe);
}

BOOL WINAPI MyProcess32NextW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe )
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<Process32NextW>";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);	
	return (realProcess32NextW)(hSnapshot,lppe);
}

BOOL WINAPI MyDeleteFileA( _In_ LPCSTR lpFileName )
{
	stringstream logstream;
	logstream.clear();
	string str1;
	if (lpFileName!=NULL)
	{
		str1=lpFileName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<DeleteFileA>,func_params=<lpFileName|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realDeleteFileA)(lpFileName);
}

HANDLE WINAPI MyFindFirstFileA( _In_ LPCSTR lpFileName, _Out_ LPWIN32_FIND_DATAA lpFindFileData )
{
	stringstream logstream;
	logstream.clear();
	string str1;
	if (lpFileName!=NULL)
	{
		str1=lpFileName;
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<FindFirstFileA>,func_params=<lpFileName|"<<str1<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realFindFirstFileA)(lpFileName,lpFindFileData);
}

BOOL WINAPI MyFindNextFileA( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAA lpFindFileData )
{
	stringstream logstream;
	logstream.clear();
	char hFilepath[512]="NULL";
	if (hFindFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFindFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<FindNextFileA>,func_params=<hFindFile|"<<hFilepath<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realFindNextFileA)(hFindFile,lpFindFileData);
}

LRESULT WINAPI MySendMessageA(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam)
{
	stringstream logstream;
	logstream.clear();
	int len=0;
	len=GetWindowTextLengthA(hWnd);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(hWnd,win,len);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<SendMessageA>,func_params=<hWnd|"<<win<<",Msg|"<<Msg<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realSendMessageA)(hWnd,Msg,wParam,lParam);
}

LRESULT WINAPI MySendMessageW(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam)
{
	stringstream logstream;
	logstream.clear();
	int len=0;
	len=GetWindowTextLengthA(hWnd);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(hWnd,win,len);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<SendMessageW>,func_params=<hWnd|"<<win<<",Msg|"<<Msg<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realSendMessageW)(hWnd,Msg,wParam,lParam);
}

BOOL WINAPI MyPostMessageA(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam)
{
	stringstream logstream;
	logstream.clear();
	int len=0;
	len=GetWindowTextLengthA(hWnd);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(hWnd,win,len);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<PostMessageA>,func_params=<hWnd|"<<win<<",Msg|"<<Msg<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realPostMessageA)(hWnd,Msg,wParam,lParam);
}

BOOL WINAPI MyPostMessageW(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam)
{
	stringstream logstream;
	logstream.clear();
	int len=0;
	len=GetWindowTextLengthA(hWnd);
	char win[MAX_PATH]="NULL";
	GetWindowTextA(hWnd,win,len);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()
		<<">,proc_func_name=<PostMessageW>,func_params=<hWnd|"<<win<<",Msg|"<<Msg<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realPostMessageW)(hWnd,Msg,wParam,lParam);
}