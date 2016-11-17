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



BOOL WINAPI MyReadFile(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped)
{
	//hFile是CreateFile返回的句柄，或者是socket，accept的句柄
	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}

	//添加针对日志文件的过滤
	if (strcmp(hFilepath,g_log_path)==0)
	{
		return (realReadFile)(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
	}
	logstream.clear();

	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ReadFile>,func_params=<hFile|"<<hFilepath<<",nNumberOfBytesToRead|"<<nNumberOfBytesToRead<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realReadFile)(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
}

BOOL WINAPI MySetFileTime( _In_ HANDLE hFile, _In_opt_ CONST FILETIME * lpCreationTime, _In_opt_ CONST FILETIME * lpLastAccessTime, _In_opt_ CONST FILETIME * lpLastWriteTime ){
	stringstream logstream;
	char hFilepath[512]="NULL";
	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFileTime>,func_params=<hFile|"<<hFilepath<<"lpCreationTime|"<<lpCreationTime<<",lpLastAccessTime|"<<lpLastAccessTime<<",lpLastWriteTime|"<<lpLastWriteTime<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetFileTime)(hFile,lpCreationTime,lpLastAccessTime,lpLastWriteTime);
}

BOOL WINAPI MySetFileValidData( _In_ HANDLE hFile, _In_ LONGLONG ValidDataLength ){
	stringstream logstream;
	char hFilepath[512]="NULL";
	if (hFile!=NULL)
	{
		//GetFileNameFromHandle(hFile,hFilepath);
		GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFileValidData>,func_params=<hFile|"<<hFilepath<<",ValidDataLength|"<<ValidDataLength<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetFileValidData)(hFile,ValidDataLength);
}

BOOL WINAPI MySetEndOfFile( _In_ HANDLE hFile ){

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
		OutputDebugStringA(hFilepath);
		return (realSetEndOfFile)(hFile);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetEndOfFile>,func_params=<hFile|"<<hFilepath<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetEndOfFile)(hFile);
}

BOOL WINAPI MyCreateHardLinkW( _In_ LPCWSTR lpFileName, _In_ LPCWSTR lpExistingFileName, _Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes ){
	stringstream logstream;

	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpFileName);

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateHardLinkW>,func_params=<lpFileName|"<<lpFileNamestr<<",lpExistingFileName|"<<lpExistingFileName<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateHardLinkW)(lpFileName,lpExistingFileName,lpSecurityAttributes);
}

BOOL WINAPI MySetFileAttributesW( _In_ LPCWSTR lpFileName, _In_ DWORD dwFileAttributes ){
	stringstream logstream;

	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpFileName);

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFileAttributesW>,func_params=<lpFileName|"<<lpFileNamestr<<",dwFileAttributes|"<<dwFileAttributes<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realSetFileAttributesW)(lpFileName,dwFileAttributes);
}

BOOL WINAPI MyFindNextFileW( _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW lpFindFileData ){
	stringstream logstream;
	char hFilepath[512]="NULL";
	if (hFindFile!=NULL)
	{
		//GetFileNameFromHandle(hFindFile,hFilepath);
		GetFinalPathNameByHandleA(hFindFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFindFile,hFilepath,MAX_PATH);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindNextFileW>,func_params=<hFindFile|"<<hFilepath<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realFindNextFileW)(hFindFile,lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW( _In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATAW lpFindFileData ){
	stringstream logstream;
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindFirstFileW>,func_params=<lpFileName|"<<lpFileNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realFindFirstFileW)(lpFileName,lpFindFileData);
}

BOOL WINAPI MyDeleteFileW( _In_ LPCWSTR lpFileName ){
	stringstream logstream;
	string lpFileNamestr;
	lpFileNamestr=WideToMutilByte(lpFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFileW>,func_params=<lpFileName|"<<lpFileNamestr<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realDeleteFileW)(lpFileName);
}

BOOL WINAPI MyCopyFileW( _In_ LPCWSTR lpExistingFileName, _In_ LPCWSTR lpNewFileName, _In_ BOOL bFailIfExists ){
	stringstream logstream;
	string lpFileNamestr1;
	lpFileNamestr1=WideToMutilByte(lpExistingFileName);
	string lpFileNamestr2;
	lpFileNamestr2=WideToMutilByte(lpNewFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CopyFileW>,func_params=<lpExistingFileName|"<<lpFileNamestr1<<",lpNewFileName|"<<lpFileNamestr2<<",bFailIfExists|"<<bFailIfExists<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCopyFileW)(lpExistingFileName,lpNewFileName,bFailIfExists);
}

BOOL WINAPI MyMoveFileW( _In_ LPCWSTR lpExistingFileName, _In_ LPCWSTR lpNewFileName ){
	stringstream logstream;
	string lpFileNamestr1;
	lpFileNamestr1=WideToMutilByte(lpExistingFileName);
	string lpFileNamestr2;
	lpFileNamestr2=WideToMutilByte(lpNewFileName);
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileW>,func_params=<lpExistingFileName|"<<lpFileNamestr1<<",lpNewFileName|"<<lpFileNamestr2<<">";

	string s;
	s=logstream.str();
	WriteLog(s);
	return (realMoveFileW)(lpExistingFileName,lpNewFileName);

}

HANDLE WINAPI MyCreateFileW(  
	__in     LPCWSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	)  
{  
	//OutputDebugString(lpFileName);
	string tmp="NULL";
	if (lpFileName!=NULL)
	{
		tmp=WideToMutilByte(lpFileName);
	}
	//加过滤，过滤日志文件的路径
	if (strcmp(tmp.c_str(),g_log_path)==0)
	{
		return (realCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,  
			lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);  
	}
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileW>,func_params=<lpFileName|"<<tmp<<">";
	string s;
	s=logstream.str();
	WriteLog(s);
	return (realCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,  
		lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);  

}  

//文件API
HANDLE WINAPI MyCreateFileA(  
	__in     LPCSTR lpFileName,  
	__in     DWORD dwDesiredAccess,  
	__in     DWORD dwShareMode,  
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
	__in     DWORD dwCreationDisposition,  
	__in     DWORD dwFlagsAndAttributes,  
	__in_opt HANDLE hTemplateFile  
	)  
{  

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s;
	s=logstream.str();
	WriteLog(s); 
	return (realCreateFileA)(lpFileName, dwDesiredAccess, dwShareMode,  
		lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);   
}
