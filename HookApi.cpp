#include "HookApi.h"


char * GetProcessPath(){
	DWORD pid=(DWORD)_getpid();
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
	GetModuleFileNameEx(hProcess,NULL,pathname,MAX_PATH);
	int iLength ;
	iLength = WideCharToMultiByte(CP_ACP, 0, pathname, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, pathname, -1, path, iLength, NULL, NULL);
	//OpenProcess֮��һ��Ҫ��סclose
	CloseHandle(hProcess);
	return path;
}

char * LogTime(){
	time_t t=time(NULL);
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(tim,"%4d-%02d-%02d-%02d-%02d-%02d-%03d:\0",sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond,sys.wMilliseconds);
	return tim;
}

//���ַ�ת��Ϊ���ֽ�
string WideToMutilByte(const wstring& _src)
{
	if (&_src==NULL)
	{
		return "NULL";
	}
	int nBufSize = WideCharToMultiByte(GetACP(), 0, _src.c_str(),-1, NULL, 0, NULL, NULL);
	char *szBuf = new char[nBufSize];
	WideCharToMultiByte(GetACP(), 0, _src.c_str(),-1, szBuf, nBufSize, NULL, NULL);
	string strRet(szBuf);
	delete []szBuf;
	szBuf = NULL;
	return strRet;
}

char * GetDate(){
	time_t t=time(NULL);
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(dat,"%4d%02d%02d",sys.wYear,sys.wMonth,sys.wDay);
	return dat;
}

void GetProcessName(char* szProcessName,int* nLen){
	DWORD dwProcessID = GetCurrentProcessId();  
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,dwProcessID);   
	if(hProcess)  
	{  
		HMODULE hMod;  
		DWORD   dwNeeded;   
		if(EnumProcessModules(hProcess,&hMod,sizeof(hMod),&dwNeeded))  
		{  
			GetModuleBaseNameA(hProcess,hMod,szProcessName,*nLen);  
		}  
	}
	CloseHandle(hProcess);
}

std::string GetKeyPathFromKKEY(HKEY key)
{
	std::wstring keyPath;
	if (key==NULL)
	{
		return "NULL";
	}
	if (key != NULL)
	{
		HMODULE dll = LoadLibrary(L"ntdll.dll");
		if (dll != NULL) {
			typedef DWORD (__stdcall *ZwQueryKeyType)(
				HANDLE  KeyHandle,
				int KeyInformationClass,
				PVOID  KeyInformation,
				ULONG  Length,
				PULONG  ResultLength);

			ZwQueryKeyType func = reinterpret_cast<ZwQueryKeyType>(::GetProcAddress(dll, "ZwQueryKey"));

			if (func != NULL) {
				DWORD size = 0;
				DWORD result = 0;
				result = func(key, 3, 0, 0, &size);
				if (result == STATUS_BUFFER_TOO_SMALL)
				{
					size = size + 2;
					wchar_t* buffer = new (std::nothrow) wchar_t[size];
					if (buffer != NULL)
					{
						result = func(key, 3, buffer, size, &size);
						if (result == STATUS_SUCCESS)
						{
							buffer[size / sizeof(wchar_t)] = L'\0';
							keyPath = std::wstring(buffer + 2);
						}

						delete[] buffer;
					}
				}
			}

			FreeLibrary(dll);
		}
	}
	return WideToMutilByte(keyPath);
}

char * GetIPbySocket(SOCKET s){
	char *sock_ip;
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	sock_ip=inet_ntoa(sock.sin_addr);
	return sock_ip;
}

int EnableDebugPriv(const char* name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	//�򿪽������ƻ�
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);
	//��ý��̱���ΨһID
	if(!LookupPrivilegeValueA(NULL,name,&luid))
	{
		//printf("LookupPrivilegeValueAʧ��");
	}
	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=luid;
	//����Ȩ��
	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		//printf("AdjustTokenPrivilegesʧ��");
	}
	CloseHandle(hToken);
	return 0;
}

BOOL InjectDll(const char *DllFullPath,const DWORD dwRemoteProcessId)
{
	HANDLE hRemoteProcess;
	EnableDebugPriv("SeDebugPrivilege");
	//��Զ���߳�
	hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	if (hRemoteProcess==NULL)
	{
		return FALSE;
	}
	char *pszLibFileRemote;
	//ʹ��VirtualAllocEx������Զ�̽��̵��ڴ��ַ�ռ����DLL�ļ����ռ�
	pszLibFileRemote=(char *)VirtualAllocEx(hRemoteProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	if (pszLibFileRemote==NULL)
	{
		CloseHandle(hRemoteProcess);
		return FALSE;
	}
	//ʹ��WriteProcessMemory������DLL��·����д�뵽Զ�̽��̵��ڴ�
	WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);
	DWORD dwID;
	LPVOID pFunc = LoadLibraryA;
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, pszLibFileRemote, 0, &dwID );
	if (hRemoteThread==NULL)
	{
		CloseHandle(hRemoteProcess);
		return FALSE;
	}
	//�ͷž��
	CloseHandle(hRemoteProcess);
	CloseHandle(hRemoteThread);
	return TRUE;
}

//�жϽ����Ƿ���64λ�������64λ����0�������32λ����1
int GetProcessIsWOW64(DWORD pid)
{
	int nRet=-1;
	EnableDebugPriv("SeDebugPrivilege");
	HANDLE hProcess;

	//��Զ���߳�
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	BOOL bRet;
	DWORD nError;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle(L"kernel32"),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		bRet=fnIsWow64Process(hProcess,&bIsWow64);
		if (bRet==0)
		{
			nError=GetLastError();
			nRet=-2;
		}
		else
		{
			if (bIsWow64)
			{
				nRet=1;
			}
			else
			{
				nRet=0;
			}
		}
	} 
	CloseHandle(hProcess);
	return nRet;
}

void WriteLog(string s){
	s=s+"\n";
	extern HANDLE g_handleMailServer;
	extern LPTSTR g_strInjectMailSlot;
	//cout<<s<<endl;
	if (g_handleMailServer != INVALID_HANDLE_VALUE)
	{
		DWORD cbWritten = 0;
		BOOL result = realWriteFile?realWriteFile(g_handleMailServer,s.c_str(),s.length(),&cbWritten,NULL):WriteFile(g_handleMailServer,s.c_str(),s.length(),&cbWritten,NULL);
		//�ɹ��Ļ���ֱ���˳�
		//////////////////////////////////////////////////////////////////////////
		// to do :���ɹ��Ļ�������һ���жϣ�������������Ѿ��˳�����g_handleMailServer��Ϊ��Ч
		//////////////////////////////////////////////////////////////////////////
		if(result)
			return;
	}
	//ofstream f("C:\\test.txt",ios::app);
	ofstream f(log_path,ios::app);
	f<<s;
	f.close();
}

bool Acpro_Operation (int threadid)
{
	char Buff[9];
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	int processid = GetCurrentProcessId();
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, processid);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		OutputDebugString(L"CreateToolhelp32Snapshot failed");
		return false;
	}
	THREADENTRY32 te32 = {sizeof(te32)};
	if (Thread32First(hProcessSnap, &te32))
	{
		do {
			if (processid == te32.th32OwnerProcessID)
			{
				if (threadid == te32.th32ThreadID)
					return false;
			}
		} while (Thread32Next(hProcessSnap, &te32));
		return true;
	}
}
char * GetProPath(DWORD pid)
{
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	GetModuleFileNameEx(hProcess, NULL, pathname, MAX_PATH);
	int iLength ;
	iLength = WideCharToMultiByte(CP_ACP, 0, pathname, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, pathname, -1, propath, iLength, NULL, NULL);

	CloseHandle(hProcess);
	return propath;
}