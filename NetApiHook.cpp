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
 

SOCKET WINAPI Myaccept(
  _In_    SOCKET          s,
  _Out_   struct sockaddr *addr,
  _Inout_ int             *addrlen
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<accept>,func_params=<s|"<<ip<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realaccept)(s, addr, addrlen);
}

int WINAPI Mysend(
  _In_       SOCKET s,
  _In_ const char   *buf,
  _In_       int    len,
  _In_       int    flags
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<send>,func_params=<s|"<<ip<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realsend)(s, buf, len, flags);
}

int WINAPI Mybind(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<bind>,func_params=<s|"<<ip<<",namelen|"<<namelen<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realbind)(s, name, namelen);
}

int WINAPI Myconnect(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<connect>,func_params=<s|"<<ip<<",namelen|"<<namelen<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realconnect)(s, name, namelen);
}

BOOL WINAPI MyConnectNamedPipe(
  _In_        HANDLE       hNamedPipe,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ConnectNamedPipe>";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realConnectNamedPipe)(hNamedPipe, lpOverlapped);
}
/*
ULONG WINAPI MyGetAdaptersInfo(
  _Out_   PIP_ADAPTER_INFO pAdapterInfo,
  _Inout_ PULONG           SizePointer
)
{
	OutputDebugStringA("GetAdaptersInfo\n");
	return (realGetAdaptersInfo)(pAdapterInfo, SizePointer);
}
*/
int WINAPI Mygethostname(
  _Out_ char *name,
  _In_  int  namelen
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<gethostname>,func_params=<namelen|"<<namelen<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realgethostname)(name, namelen);
}

unsigned long WINAPI Myinet_addr(
  _In_ const char *cp
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<inet_addr>,func_params=<cp|"<<cp<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realinet_addr)(cp);
}

BOOL WINAPI MyInternetReadFile(
  _In_  HINTERNET hFile,
  _Out_ LPVOID    lpBuffer,
  _In_  DWORD     dwNumberOfBytesToRead,
  _Out_ LPDWORD   lpdwNumberOfBytesRead
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetReadFile>,func_params=<dwNumberOfBytesToRead|"<<dwNumberOfBytesToRead<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetReadFile)(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI MyInternetWriteFile(
  _In_  HINTERNET hFile,
  _In_  LPCVOID   lpBuffer,
  _In_  DWORD     dwNumberOfBytesToWrite,
  _Out_ LPDWORD   lpdwNumberOfBytesWritten
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetWriteFile>,func_params=<dwNumberOfBytesToWrite|"<<dwNumberOfBytesToWrite<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetWriteFile)(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
}

NET_API_STATUS WINAPI MyNetShareEnum(
  _In_    LPWSTR  servername,
  _In_    DWORD   level,
  _Out_   LPBYTE  *bufptr,
  _In_    DWORD   prefmaxlen,
  _Out_   LPDWORD entriesread,
  _Out_   LPDWORD totalentries,
  _Inout_ LPDWORD resume_handle
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<NetShareEnum>,func_params=<servername|"<<servername<<",level|"<<level<<",prefmaxlen|"<<prefmaxlen<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realNetShareEnum)(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}

int WINAPI Myrecv(
  SOCKET s,
  char FAR* buf,
  int len,
  int flags
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<recv>,func_params=<s|"<<ip<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realrecv)(s, buf, len, flags);
}

int WINAPI MyWSAStartup(
  _In_  WORD      wVersionRequested,
  _Out_ LPWSADATA lpWSAData
)
{
	stringstream logstream;
	int res=0;
	res=(realWSAStartup)(wVersionRequested, lpWSAData);

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WSAStartup>,func_params=<wVersionRequested|"<<wVersionRequested<<">";
    
	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return res;
}

HINTERNET WINAPI MyInternetOpenW(
  _In_ LPCWSTR lpszAgent,
  _In_ DWORD   dwAccessType,
  _In_ LPCWSTR lpszProxy,
  _In_ LPCWSTR lpszProxyBypass,
  _In_ DWORD   dwFlags
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszAgent!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszAgent);
	}
	string lpFileNamestr2="NULL";
	if (lpszProxy!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpszProxy);
	}
	string lpFileNamestr3="NULL";
	if (lpszProxyBypass!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpszProxyBypass);
	}
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenW>,func_params=<lpszAgent|"<<(lpszAgent==NULL?"NULL":lpFileNamestr1)<<",dwAccessType|"<<dwAccessType<<",lpszProxy|"<<(lpszProxy==NULL?"NULL":lpFileNamestr2)<<",lpszProxyBypass|"<<(lpszProxyBypass==NULL?"NULL":lpFileNamestr3)<<",dwFlags|"<<dwFlags<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetOpenW)(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI MyInternetOpenUrlW(
  _In_ HINTERNET hInternet,
  _In_ LPCWSTR   lpszUrl,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszUrl!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszUrl);
	}
	string lpFileNamestr2="NULL";
	if (lpszHeaders!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpszHeaders);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlW>,func_params=<lpszUrl|"<<lpFileNamestr1<<",lpszHeaders|"<<lpFileNamestr2<<",dwHeadersLength|"<<dwHeadersLength<<",dwFlags|"<<dwFlags<<",dwContext|"<<dwContext<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetOpenUrlW)(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

HRESULT WINAPI MyURLDownloadToFileW(
             LPUNKNOWN            pCaller,
             LPCWSTR              szURL,
             LPCWSTR              szFileName,
  _Reserved_ DWORD                dwReserved,
             LPBINDSTATUSCALLBACK lpfnCB
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (szURL!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(szURL);
	}
	string lpFileNamestr2="NULL";
	if (szFileName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(szFileName);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<URLDownloadToFileW>,func_params=<szURL|"<<lpFileNamestr1<<",szFileName|"<<lpFileNamestr2<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realURLDownloadToFileW)(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

BOOL WINAPI MyFtpPutFileW(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszLocalFile,
  _In_ LPCWSTR   lpszNewRemoteFile,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszLocalFile!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszLocalFile);
	}
	string lpFileNamestr2="NULL";
	if (lpszNewRemoteFile!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpszNewRemoteFile);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FtpPutFileW>,func_params=<lpszLocalFile|"<<lpFileNamestr1<<",lpszNewRemoteFile|"<<lpFileNamestr2<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realFtpPutFileW)(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
}

BOOL WINAPI MyHttpSendRequestW(
  _In_ HINTERNET hRequest,
  _In_ LPCWSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ LPVOID    lpOptional,
  _In_ DWORD     dwOptionalLength
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszHeaders!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszHeaders);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<HttpSendRequestW>,func_params=<lpszHeaders|"<<lpFileNamestr1<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realHttpSendRequestW)(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI MyHttpSendRequestExW(
  _In_  HINTERNET          hRequest,
  _In_  LPINTERNET_BUFFERS lpBuffersIn,
  _Out_ LPINTERNET_BUFFERS lpBuffersOut,
  _In_  DWORD              dwFlags,
  _In_  DWORD_PTR          dwContext
)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<HttpSendRequestExW>";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realHttpSendRequestExW)(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
}

HINTERNET WINAPI MyHttpOpenRequestW(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR   lpszVerb,
  _In_ LPCWSTR   lpszObjectName,
  _In_ LPCWSTR   lpszVersion,
  _In_ LPCWSTR   lpszReferer,
  _In_ LPCWSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszVerb!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszVerb);
	}
	string lpFileNamestr2="NULL";
	if (lpszObjectName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpszObjectName);
	}
	string lpFileNamestr3="NULL";
	if (lpszVersion!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpszVersion);
	}
	string lpFileNamestr4="NULL";
	if (lpszReferer!=NULL)
	{
		lpFileNamestr4=WideToMutilByte(lpszReferer);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<HttpOpenRequestW>,func_params=<lpszVerb|"<<lpFileNamestr1<<",lpszObjectName|"<<lpFileNamestr2<<",lpszVersion|"<<lpFileNamestr3<<",lpszReferer|"<<lpFileNamestr4<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realHttpOpenRequestW)(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
}

HINTERNET WINAPI MyInternetConnectW(
  _In_ HINTERNET     hInternet,
  _In_ LPCWSTR       lpszServerName,
  _In_ INTERNET_PORT nServerPort,
  _In_ LPCWSTR       lpszUsername,
  _In_ LPCWSTR       lpszPassword,
  _In_ DWORD         dwService,
  _In_ DWORD         dwFlags,
  _In_ DWORD_PTR     dwContext
)
{
	stringstream logstream;
	string lpFileNamestr1="NULL";
	if (lpszServerName!=NULL)
	{
		lpFileNamestr1=WideToMutilByte(lpszServerName);
	}
	string lpFileNamestr2="NULL";
	if (lpszUsername!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpszUsername);
	}
	string lpFileNamestr3="NULL";
	if (lpszPassword!=NULL)
	{
		lpFileNamestr3=WideToMutilByte(lpszPassword);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetConnectW>,func_params=<lpszServerName|"<<lpFileNamestr1<<",lpszUsername|"<<lpFileNamestr2<<",lpszPassword|"<<lpFileNamestr3<<">";

	string s,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetConnectW)(hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext);
}

int WINAPI Mylisten(
  _In_ SOCKET s,
  _In_ int    backlog
)
{
	stringstream logstream;
	string ip="NULL";
	if (s!=NULL)
	{
		ip=GetIPbySocket(s);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<listen>,func_params=<s|"<<ip<<",backlog|"<<backlog<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (reallisten)(s, backlog);
}

HINTERNET WINAPI MyInternetOpenUrlA( _In_ HINTERNET hInternet, _In_ LPCSTR lpszUrl, _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext ){

	stringstream logstream;
	logstream.clear();
	//lpszHeaders可能为空
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlA>,func_params=<lpszUrl|"<<lpszUrl<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realInternetOpenUrlA)(hInternet,lpszUrl,lpszHeaders,dwHeadersLength,dwFlags,dwContext);
}

HINTERNET WINAPI MyHttpOpenRequestA( _In_ HINTERNET hConnect, _In_opt_ LPCSTR lpszVerb, _In_opt_ LPCSTR lpszObjectName, _In_opt_ LPCSTR lpszVersion, _In_opt_ LPCSTR lpszReferrer, _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes, _In_ DWORD dwFlags, _In_opt_ DWORD_PTR dwContext ){
	stringstream logstream;
	string str1;
	if (lpszVerb==NULL)
	{
		str1="NULL";
	}else{
		str1=lpszVerb;
	}
	string str2;
	if(lpszObjectName==NULL)
	{
		str2="NULL";
	}else{
		str2=lpszObjectName;
	}
	string str3;
	if(lpszVersion==NULL)
	{
		str3="NULL";
	}else{
		str3=lpszVersion;
	}
	string str4;
	if (lpszReferrer==NULL)
	{
		str4="NULL";
	}else{
		str4=lpszReferrer;
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<HttpOpenRequestA>,func_params=<lpszVerb|"<<str1<<",lpszObjectName|"<<str2<<",lpszVersion|"<<str3<<",lpszReferrer|"<<str4<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);
	return (realHttpOpenRequestA)(hConnect,lpszVerb,lpszObjectName,lpszVersion,lpszReferrer,lplpszAcceptTypes,dwFlags,dwContext);
}