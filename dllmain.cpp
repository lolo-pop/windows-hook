// dllmain.cpp : 定义 DLL 应用程序的入口点。
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#include "stdafx.h"  
#include "HookApi.h"  
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")

char g_log_path[255];
LPTSTR g_strInjectMailSlot = TEXT("\\\\.\\mailslot\\inject_server_mailslot");
HANDLE g_handleMailServer = INVALID_HANDLE_VALUE;
char log_path[255];
char strBuffer[256];//用户名
char hostname[128];//主机名
char spy[6];//监测层，监测程序代号，监测程序模块
char ProcessName[255];
string Log[100];
char dat[100];
char tim[50];
TCHAR pathname[MAX_PATH];
char path[MAX_PATH];
char dlldir[MAX_PATH];
char propath[MAX_PATH];


//文件
  ptrCreateFileW realCreateFileW ;  
  ptrCreateFileA realCreateFileA ;  
  ptrReadFile realReadFile;
  ptrMoveFileW realMoveFileW;
  ptrCopyFileW realCopyFileW;
  ptrDeleteFileW realDeleteFileW;
  ptrFindFirstFileW realFindFirstFileW;
  ptrFindNextFileW realFindNextFileW;
  ptrSetFileAttributesW realSetFileAttributesW;
  ptrCreateHardLinkW realCreateHardLinkW;
  ptrSetEndOfFile realSetEndOfFile;
  ptrSetFileValidData realSetFileValidData;
  ptrSetFileTime realSetFileTime;

  //进程API
  ptrBitBlt realBitBlt;
  ptrCreateFileMappingW realCreateFileMappingW;
  ptrOpenFileMappingW realOpenFileMappingW;
  ptrCryptAcquireContext realCryptAcquireContext ;
  ptrDeviceIoControl realDeviceIoControl;
  ptrFindWindowExW realFindWindowExW;
  ptrGetAsyncKeyState realGetAsyncKeyState;
  ptrGetDC realGetDC;
  ptrGetKeyState realGetKeyState;
  ptrGetForegroundWindow realGetForegroundWindow;
  ptrGetTempPath realGetTempPath;
  ptrMapViewOfFile realMapViewOfFile;
  ptrOpenFile realOpenFile;
  ptrAdjustTokenPrivileges realAdjustTokenPrivileges;
  ptrAttachThreadInput realAttachThreadInput;
  ptrCallNextHookEx realCallNextHookEx;
  ptrCheckRemoteDebuggerPresent realCheckRemoteDebuggerPresent;
  ptrControlService realControlService;
  ptrCreateRemoteThread realCreateRemoteThread;
  ptrCreateToolhelp32Snapshot realCreateToolhelp32Snapshot;
  ptrEnumProcesses realEnumProcesses;
  ptrEnumProcessModules realEnumProcessModules;
  ptrGetProcAddress realGetProcAddress;
  ptrGetSystemDefaultLangID realGetSystemDefaultLangID;
  ptrGetThreadContext realGetThreadContext;
  ptrGetTickCount realGetTickCount ;
  ptrIsDebuggerPresent realIsDebuggerPresent;
  ptrLoadLibraryExW realLoadLibraryExW;
  ptrLoadResource realLoadResource;
  ptrModule32FirstW realModule32FirstW;
  ptrModule32NextW realModule32NextW;
  ptrOpenProcess realOpenProcess;
  ptrPeekNamedPipe realPeekNamedPipe;
  ptrProcess32First realProcess32First;
  ptrProcess32Next realProcess32Next;
  ptrQueryPerformanceCounter realQueryPerformanceCounter;
  ptrQueueUserAPC realQueueUserAPC;
  ptrReadProcessMemory realReadProcessMemory;
  ptrResumeThread realResumeThread;
  ptrSetThreadContext realSetThreadContext;
  ptrSuspendThread realSuspendThread;
//ptrsystem realsystem;
  ptrThread32First realThread32First;
  ptrThread32Next realThread32Next;
  ptrToolhelp32ReadProcessMemory realToolhelp32ReadProcessMemory;
  ptrVirtualAllocEx realVirtualAllocEx;
  ptrVirtualProtectEx realVirtualProtectEx;
  ptrWinExec realWinExec;
  ptrWriteProcessMemory realWriteProcessMemory;
  ptrRegisterHotKey realRegisterHotKey;
  ptrCreateProcessA realCreateProcessA;
  ptrCertOpenSystemStoreW realCertOpenSystemStoreW;
  ptrCreateMutexW realCreateMutexW;
  ptrFindResourceW realFindResourceW;
  ptrFindWindowW realFindWindowW;
  ptrGetWindowsDirectoryW realGetWindowsDirectoryW;
  ptrMapVirtualKeyW realMapVirtualKeyW;
  ptrOpenMutexW realOpenMutexW;
  ptrOpenSCManagerW realOpenSCManagerW;
  ptrCreateProcessW realCreateProcessW;
  ptrCreateServiceW realCreateServiceW;
  ptrGetModuleFileNameExW realGetModuleFileNameExW;
  ptrGetModuleHandleW realGetModuleHandleW;
  ptrGetStartupInfoW realGetStartupInfoW;
  ptrGetVersionExW realGetVersionExW;
  ptrLoadLibraryW realLoadLibraryW;
  ptrOutputDebugStringW realOutputDebugStringW;
  ptrSetWindowsHookExW realSetWindowsHookExW;
  ptrShellExecuteW realShellExecuteW;
  ptrStartServiceCtrlDispatcherW realStartServiceCtrlDispatcherW;
  ptrSetLocalTime realSetLocalTime;
  ptrTerminateThread realTerminateThread;
  ptrVirtualFree realVirtualFree;
  ptrSetProcessWorkingSetSize realSetProcessWorkingSetSize;
  ptrTerminateProcess realTerminateProcess;
//注册表
  ptrRegOpenKeyExW realRegOpenKeyExW;
  ptrRegOpenKeyW realRegOpenKeyW;
  ptrRegCreateKeyExW realRegCreateKeyExW;
  ptrRegCreateKeyW realRegCreateKeyW;
  ptrRegQueryValueExW realRegQueryValueExW;
  ptrRegQueryValueW realRegQueryValueW;
  ptrRegSetValueExW realRegSetValueExW;
  ptrRegSetValueW realRegSetValueW;
  ptrRegDeleteKeyExW realRegDeleteKeyExW;
  ptrRegDeleteKeyW realRegDeleteKeyW;
  ptrRegSetKeySecurity realRegSetKeySecurity;
  ptrRegRestoreKeyW realRegRestoreKeyW;
  ptrRegReplaceKeyW realRegReplaceKeyW;
  ptrRegLoadKeyW realRegLoadKeyW;
  ptrRegUnLoadKey realRegUnLoadKey;
//网络
  ptraccept realaccept;
  ptrsend realsend;
  ptrbind realbind;
  ptrconnect realconnect;
  ptrConnectNamedPipe realConnectNamedPipe;
  ptrgethostname realgethostname;
  ptrinet_addr realinet_addr;
  ptrInternetReadFile realInternetReadFile;
  ptrInternetWriteFile realInternetWriteFile;
  ptrNetShareEnum realNetShareEnum;
  ptrrecv realrecv;
  ptrWSAStartup realWSAStartup;
  ptrInternetOpenW realInternetOpenW;
  ptrInternetOpenUrlW realInternetOpenUrlW;
  ptrURLDownloadToFileW realURLDownloadToFileW;
  ptrFtpPutFileW realFtpPutFileW;
  ptrHttpSendRequestW realHttpSendRequestW;
  ptrHttpSendRequestExW realHttpSendRequestExW;
  ptrHttpOpenRequestW realHttpOpenRequestW;
  ptrInternetConnectW realInternetConnectW;
  ptrlisten reallisten;
  ptrInternetOpenUrlA realInternetOpenUrlA;
  ptrHttpOpenRequestA realHttpOpenRequestA;

  //其他
  ptrSetFilePointer realSetFilePointer;
  ptrMoveFileExW realMoveFileExW;
  ptrWriteFile realWriteFile;
  ptrWriteFileEx realWriteFileEx;
  ptrShellExecuteExW realShellExecuteExW;
  ptrExitProcess realExitProcess;
  ptrVirtualProtect realVirtualProtect;

  //新增API
  ptrCreateProcessInternalW realCreateProcessInternalW;
  ptrMoveFileA realMoveFileA;
  ptrMoveFileExA realMoveFileExA;
  ptrRegQueryValueExA realRegQueryValueExA;
  ptrRegQueryValueA realRegQueryValueA;
  ptrRegDeleteValueA realRegDeleteValueA;
  ptrRegDeleteValueW realRegDeleteValueW;
  ptrRegDeleteKeyExA realRegDeleteKeyExA;
  ptrRegCreateKeyExA realRegCreateKeyExA;
  ptrRegCreateKeyA realRegCreateKeyA;
  ptrSetWindowsHookExA realSetWindowsHookExA;
  ptrCreateServiceA realCreateServiceA;
  ptrProcess32FirstW realProcess32FirstW;
  ptrProcess32NextW realProcess32NextW;
  ptrDeleteFileA realDeleteFileA;
  ptrFindFirstFileA realFindFirstFileA;
  ptrFindNextFileA realFindNextFileA;
  ptrSendMessageA realSendMessageA;
  ptrSendMessageW realSendMessageW;
  ptrPostMessageA realPostMessageA;
  ptrPostMessageW realPostMessageW;

//ptrMessageBeep realMessageBeep = NULL;
//ptrPlaySoundW   realPlaySoundW = NULL;

//HMODULE                 hKernel32 = NULL; 
//文件
//HMODULE                 hKernel32 = NULL; 
//文件
TRACED_HOOK_HANDLE      hHookCreateFileW = new HOOK_TRACE_INFO() ;  
TRACED_HOOK_HANDLE      hHookCreateFileA = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookPlaySoundW  = new HOOK_TRACE_INFO(); 
TRACED_HOOK_HANDLE      hHookReadFile  = new HOOK_TRACE_INFO(); 
TRACED_HOOK_HANDLE		hHookMoveFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookCopyFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookDeleteFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindFirstFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindNextFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileAttributesW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookCreateHardLinkW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetEndOfFile =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileValidData =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileTime =new HOOK_TRACE_INFO();

//进程API
TRACED_HOOK_HANDLE      hHookBitBlt = new HOOK_TRACE_INFO();
//TRACED_HOOK_HANDLE      hHookCoCreateInstance = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateFileMappingW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenFileMappingW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCryptAcquireContext = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookDeviceIoControl = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindWindowExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetAsyncKeyState = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetDC = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetForegroundWindow = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetKeyState = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetTempPath= new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookMapViewOfFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookAdjustTokenPrivileges = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookAttachThreadInput = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCallNextHookEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCheckRemoteDebuggerPresent = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookControlService = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateRemoteThread = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateToolhelp32Snapshot = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookEnumProcesses = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookEnumProcessModules = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetProcAddress = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetSystemDefaultLangID = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetThreadContext = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetTickCount = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookIsDebuggerPresent = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadLibraryExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadResource = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookModule32FirstW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookModule32NextW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenProcess = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookPeekNamedPipe = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookProcess32First = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookProcess32Next = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookQueryPerformanceCounter = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookQueueUserAPC = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookReadProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookResumeThread = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookSetThreadContext = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookSuspendThread = new HOOK_TRACE_INFO();  
//TRACED_HOOK_HANDLE      hHooksystem = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookThread32First = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookThread32Next = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookToolhelp32ReadProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookVirtualAllocEx = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookVirtualProtectEx = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookWinExec = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookWriteProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookRegisterHotKey = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookCreateProcessA = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookCertOpenSystemStoreW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateMutexW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindResourceW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindWindowW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetWindowsDirectoryW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookMapVirtualKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenMutexW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenSCManagerW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateProcessW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateServiceW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetModuleFileNameExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetModuleHandleW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetStartupInfoW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetVersionExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadLibraryW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOutputDebugStringW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetWindowsHookExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookShellExecuteW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookStartServiceCtrlDispatcherW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetLocalTime = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookTerminateThread = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookVirtualFree = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetProcessWorkingSetSize = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookTerminateProcess = new HOOK_TRACE_INFO();
//注册表
TRACED_HOOK_HANDLE      hHookRegOpenKeyExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegOpenKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegCreateKeyExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegCreateKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegQueryValueExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegQueryValueW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetValueExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetValueW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegDeleteKeyExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegDeleteKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetKeySecurity = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegRestoreKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegReplaceKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegLoadKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegUnLoadKey = new HOOK_TRACE_INFO();
//网络
TRACED_HOOK_HANDLE      hHookaccept = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHooksend = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookbind = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookconnect = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookConnectNamedPipe = new HOOK_TRACE_INFO();
//TRACED_HOOK_HANDLE      hHookGetAdaptersInfo = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookgethostname = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookinet_addr = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetReadFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetWriteFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookNetShareEnum = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookrecv = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookWSAStartup = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenUrlW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookURLDownloadToFileW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFtpPutFileW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpSendRequestW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpSendRequestExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpOpenRequestW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetConnectW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHooklisten = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenUrlA = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpOpenRequestA = new HOOK_TRACE_INFO();

//其他
TRACED_HOOK_HANDLE		hHookSetFilePoint = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookMoveFileExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookWriteFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookWriteFileEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookShellExecuteExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookExitProcess = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookVirtualProtect = new HOOK_TRACE_INFO();

//新增API
TRACED_HOOK_HANDLE		hHookCreateProcessInternalW=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookMoveFileA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookMoveFileExA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegQueryValueExA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegQueryValueA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegDeleteValueA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegDeleteValueW=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegDeleteKeyExA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegCreateKeyExA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookRegCreateKeyA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetWindowsHookExA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookCreateServiceA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookProcess32FirstW=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookProcess32NextW=new HOOK_TRACE_INFO();
//新增API
TRACED_HOOK_HANDLE		hHookDeleteFileA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindFirstFileA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindNextFileA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSendMessageA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSendMessageW=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookPostMessageA=new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookPostMessageW=new HOOK_TRACE_INFO();



NTSTATUS                statue;  
//文件API
ULONG                   HookCreateFileW_ACLEntries[1] = {0};  
ULONG                   HookCreateFileA_ACLEntries[1] = {0};  
ULONG                   HookReadFile_ACLEntries[1] = {0};  
ULONG                   HookPlaySoundW_ACLEntries[1]   = {0};  
ULONG                   HookMoveFileW_ACLEntries[1]   = {0}; 
ULONG                   HookCopyFileW_ACLEntries[1]   = {0}; 
ULONG                   HookDeleteFileW_ACLEntries[1]   = {0}; 
ULONG                   HookFindFirstFileW_ACLEntries[1]   = {0}; 
ULONG                   HookFindNextFileW_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileAttributesW_ACLEntries[1]   = {0}; 
ULONG                   HookCreateHardLinkW_ACLEntries[1]   = {0}; 
ULONG                   HookSetEndOfFile_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileValidData_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileTime_ACLEntries[1]   = {0}; 

//进程API
ULONG                   HookBitBlt_ACLEntries[1] = {0};  
//ULONG                   HookCoCreateInstance_ACLEntries[1] = {0};  
ULONG                   HookCreateFileMappingW_ACLEntries[1] = {0};  
ULONG					HookOpenFileMappingW_ACLEntries[1] = {0}; 
ULONG                   HookCryptAcquireContext_ACLEntries[1] = {0}; 
ULONG                   HookDeviceIoControl_ACLEntries[1] = {0};  
ULONG                   HookFindWindowExW_ACLEntries[1] = {0};  
ULONG                   HookGetAsyncKeyState_ACLEntries[1] = {0};  
ULONG                   HookGetDC_ACLEntries[1] = {0};  
ULONG                   HookGetForegroundWindow_ACLEntries[1] = {0};  
ULONG                   HookGetKeyState_ACLEntries[1] = {0};  
ULONG                   HookGetTempPath_ACLEntries[1] = {0};  
ULONG                   HookMapViewOfFile_ACLEntries[1] = {0};  
ULONG                   HookOpenFile_ACLEntries[1] = {0};  
ULONG                   HookAdjustTokenPrivileges_ACLEntries[1] = {0};  
ULONG                   HookAttachThreadInput_ACLEntries[1] = {0};  
ULONG                   HookCallNextHookEx_ACLEntries[1] = {0};  
ULONG                   HookCheckRemoteDebuggerPresent_ACLEntries[1] = {0};  
ULONG                   HookControlService_ACLEntries[1] = {0};  
ULONG                   HookCreateRemoteThread_ACLEntries[1] = {0};  
ULONG                   HookCreateToolhelp32Snapshot_ACLEntries[1] = {0};  
ULONG                   HookEnumProcesses_ACLEntries[1] = {0};  
ULONG                   HookEnumProcessModules_ACLEntries[1] = {0};  
ULONG                   HookGetProcAddress_ACLEntries[1] = {0};  
ULONG                   HookGetSystemDefaultLangID_ACLEntries[1] = {0}; 
ULONG                   HookGetThreadContext_ACLEntries[1] = {0}; 
ULONG                   HookGetTickCount_ACLEntries[1] = {0}; 
ULONG                   HookIsDebuggerPresent_ACLEntries[1] = {0}; 
ULONG                   HookLoadLibraryExW_ACLEntries[1] = {0}; 
ULONG                   HookLoadResource_ACLEntries[1] = {0}; 
ULONG                   HookModule32FirstW_ACLEntries[1] = {0}; 
ULONG                   HookModule32NextW_ACLEntries[1] = {0}; 
ULONG                   HookOpenProcess_ACLEntries[1] = {0}; 
ULONG                   HookPeekNamedPipe_ACLEntries[1] = {0}; 
ULONG                   HookProcess32First_ACLEntries[1] = {0}; 
ULONG                   HookProcess32Next_ACLEntries[1] = {0}; 
ULONG                   HookQueryPerformanceCounter_ACLEntries[1] = {0}; 
ULONG                   HookQueueUserAPC_ACLEntries[1] = {0}; 
ULONG                   HookReadProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookResumeThread_ACLEntries[1] = {0}; 
ULONG                   HookSetThreadContext_ACLEntries[1] = {0}; 
ULONG                   HookSuspendThread_ACLEntries[1] = {0}; 
//ULONG                   Hooksystem_ACLEntries[1] = {0}; 
ULONG                   HookThread32First_ACLEntries[1] = {0}; 
ULONG                   HookThread32Next_ACLEntries[1] = {0}; 
ULONG                   HookToolhelp32ReadProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookVirtualAllocEx_ACLEntries[1] = {0}; 
ULONG                   HookVirtualProtectEx_ACLEntries[1] = {0}; 
ULONG                   HookWinExec_ACLEntries[1] = {0}; 
ULONG                   HookWriteProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookRegisterHotKey_ACLEntries[1] = {0}; 
ULONG                   HookCreateProcessA_ACLEntries[1] = {0}; 
ULONG                   HookCertOpenSystemStoreW_ACLEntries[1] = {0}; 
ULONG                   HookCreateMutexW_ACLEntries[1] = {0}; 
ULONG                   HookFindResourceW_ACLEntries[1] = {0}; 
ULONG                   HookFindWindowW_ACLEntries[1] = {0}; 
ULONG                   HookGetWindowsDirectoryW_ACLEntries[1] = {0}; 
ULONG                   HookMapVirtualKeyW_ACLEntries[1] = {0}; 
ULONG                   HookOpenMutexW_ACLEntries[1] = {0}; 
ULONG                   HookOpenSCManagerW_ACLEntries[1] = {0}; 
ULONG                   HookCreateProcessW_ACLEntries[1] = {0}; 
ULONG                   HookCreateServiceW_ACLEntries[1] = {0}; 
ULONG                   HookGetModuleFileNameExW_ACLEntries[1] = {0}; 
ULONG                   HookGetModuleHandleW_ACLEntries[1] = {0}; 
ULONG                   HookGetStartupInfoW_ACLEntries[1] = {0}; 
ULONG                   HookGetVersionExW_ACLEntries[1] = {0}; 
ULONG                   HookLoadLibraryW_ACLEntries[1] = {0}; 
ULONG                   HookOutputDebugStringW_ACLEntries[1] = {0}; 
ULONG                   HookSetWindowsHookExW_ACLEntries[1] = {0}; 
ULONG                   HookShellExecuteW_ACLEntries[1] = {0}; 
ULONG                   HookStartServiceCtrlDispatcherW_ACLEntries[1] = {0}; 
ULONG                   HookSetLocalTime_ACLEntries[1] = {0}; 
ULONG                   HookTerminateThread_ACLEntries[1] = {0}; 
ULONG                   HookVirtualFree_ACLEntries[1] = {0}; 
ULONG                   HookSetProcessWorkingSetSize_ACLEntries[1] = {0}; 
ULONG                   HookTerminateProcess_ACLEntries[1] = {0}; 
//注册表
ULONG                   HookRegOpenKeyExW_ACLEntries[1] = {0}; 
ULONG                   HookRegOpenKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegCreateKeyExW_ACLEntries[1] = {0}; 
ULONG                   HookRegCreateKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegQueryValueExW_ACLEntries[1] = {0}; 
ULONG                   HookRegQueryValueW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetValueExW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetValueW_ACLEntries[1] = {0}; 
ULONG                   HookRegDeleteKeyExW_ACLEntries[1] = {0}; 
ULONG                   HookRegDeleteKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetKeySecurity_ACLEntries[1] = {0}; 
ULONG                   HookRegRestoreKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegReplaceKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegLoadKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegUnLoadKey_ACLEntries[1] = {0}; 
//网络
ULONG                   Hookaccept_ACLEntries[1] = {0}; 
ULONG                   Hooksend_ACLEntries[1] = {0}; 
ULONG                   Hookbind_ACLEntries[1] = {0}; 
ULONG                   Hookconnect_ACLEntries[1] = {0}; 
ULONG                   HookConnectNamedPipe_ACLEntries[1] = {0}; 
//ULONG                   HookGetAdaptersInfo_ACLEntries[1] = {0}; 
ULONG                   Hookgethostname_ACLEntries[1] = {0}; 
ULONG                   Hookinet_addr_ACLEntries[1] = {0}; 
ULONG                   HookInternetReadFile_ACLEntries[1] = {0}; 
ULONG                   HookInternetWriteFile_ACLEntries[1] = {0}; 
ULONG                   HookNetShareEnum_ACLEntries[1] = {0}; 
ULONG                   Hookrecv_ACLEntries[1] = {0}; 
ULONG                   HookWSAStartup_ACLEntries[1] = {0}; 
ULONG                   HookInternetOpenW_ACLEntries[1] = {0}; 
ULONG                   HookInternetOpenUrlW_ACLEntries[1] = {0}; 
ULONG                   HookURLDownloadToFileW_ACLEntries[1] = {0}; 
ULONG                   HookFtpPutFileW_ACLEntries[1] = {0}; 
ULONG                   HookHttpSendRequestW_ACLEntries[1] = {0}; 
ULONG                   HookHttpSendRequestExW_ACLEntries[1] = {0}; 
ULONG                   HookHttpOpenRequestW_ACLEntries[1] = {0}; 
ULONG                   HookInternetConnectW_ACLEntries[1] = {0}; 
ULONG                   Hooklisten_ACLEntries[1] = {0}; 
ULONG					HookInternetOpenUrlA_ACLEntries[1]={0};
ULONG					HookHttpOpenRequestA_ACLEntries[1]={0};
//新增API
ULONG					HookSetFilePoint_ACLEntries[1]={0};
ULONG					HookMoveFileExW_ACLEntries[1]={0};
ULONG					HookWriteFile_ACLEntries[1]={0};
ULONG					HookWriteFileEx_ACLEntries[1]={0};
ULONG					HookShellExecuteExW_ACLEntries[1]={0};
ULONG					HookExitProcess_ACLEntries[1]={0};
ULONG					HookVirtualProtect_ACLEntries[1]={0};
//新增API
ULONG					HookCreateProcessInternalW_ACLEntries[1]={0};
ULONG					HookMoveFileA_ACLEntries[1]={0};
ULONG					HookMoveFileExA_ACLEntries[1]={0};
ULONG					HookRegQueryValueExA_ACLEntries[1]={0};
ULONG					HookRegQueryValueA_ACLEntries[1]={0};
ULONG					HookRegDeleteValueA_ACLEntries[1]={0};
ULONG					HookRegDeleteValueW_ACLEntries[1]={0};
ULONG					HookRegDeleteKeyExA_ACLEntries[1]={0};
ULONG					HookRegCreateKeyExA_ACLEntries[1]={0};
ULONG					HookRegCreateKeyA_ACLEntries[1]={0};
ULONG					HookSetWindowsHookExA_ACLEntries[1]={0};
ULONG					HookCreateServiceA_ACLEntries[1]={0};
ULONG					HookProcess32FirstW_ACLEntries[1]={0};
ULONG					HookProcess32NextW_ACLEntries[1]={0};
//新增API
ULONG					HookDeleteFileA_ACLEntries[1]={0};
ULONG					HookFindFirstFileA_ACLEntries[1]={0};
ULONG					HookFindNextFileA_ACLEntries[1]={0};
ULONG					HookSendMessageA_ACLEntries[1]={0};
ULONG					HookSendMessageW_ACLEntries[1]={0};
ULONG					HookPostMessageA_ACLEntries[1]={0};
ULONG					HookPostMessageW_ACLEntries[1]={0};


int PrepareRealApiEntry()  
{  
	
	//初始化
	OutputDebugString(L"PrepareRealApiEntry()\n");  

	// 获取真实函数地址  
	//HMODULE hws_232=LoadLibrary(L"");
	HMODULE hKernel32 = LoadLibrary(L"Kernel32.dll");
	HMODULE hUser32 = LoadLibrary(L"User32.dll");
	HMODULE hGdi32 = LoadLibrary(L"Gdi32.dll");
	HMODULE hOle32 = LoadLibrary(L"Ole32.dll");
	HMODULE hAdvapi32 = LoadLibrary(L"Advapi32.dll");
	HMODULE hCrypt32 = LoadLibrary(L"Crypt32.dll");
	HMODULE hWininet = LoadLibrary(L"Wininet.dll");
	HMODULE hNetapi32 = LoadLibrary(L"Netapi32.dll");
	HMODULE hWs2_32 = LoadLibrary(L"Ws2_32.dll");
	HMODULE hIphlpapi = LoadLibrary(L"Iphlpapi.dll");
	HMODULE hShell32 = LoadLibrary(L"Shell32.dll");
	HMODULE hUrlmon  = LoadLibrary(L"Urlmon.dll");
	if (hKernel32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") OK\n");  
	if (hUser32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"User32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"User32.dll\") OK\n"); 
	if (hGdi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Gdi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Gdi32.dll\") OK\n");  
	if (hOle32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Ole32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Ole32.dll\") OK\n"); 
	if (hAdvapi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Advapi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Advapi32.dll\") OK\n");
	if (hCrypt32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Crypt32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Crypt32.dll\") OK\n");
	if (hWininet == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Wininet.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Wininet.dll\") OK\n");
	if (hNetapi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Netapi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Netapi32.dll\") OK\n");
	if (hWs2_32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Ws2_32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Ws2_32.dll\") OK\n");
	if (hIphlpapi == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Iphlpapi.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Iphlpapi.dll\") OK\n");
	if (hShell32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Shell32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Shell32.dll\") OK\n");
	if (hUrlmon == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Urlmon.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Urlmon.dll\") OK\n");
	//文件API
	realSetFileTime=(ptrSetFileTime)GetProcAddress(hGdi32,"SetFileTime");
	realSetFileValidData=(ptrSetFileValidData)GetProcAddress(hKernel32,"SetFileValidData");
	realSetEndOfFile=(ptrSetEndOfFile)GetProcAddress(hKernel32,"SetEndOfFile");
	realCreateHardLinkW=(ptrCreateHardLinkW)GetProcAddress(hKernel32,"CreateHardLinkW");
	realSetFileAttributesW=(ptrSetFileAttributesW)GetProcAddress(hKernel32,"SetFileAttributesW");
	realFindNextFileW=(ptrFindNextFileW)GetProcAddress(hKernel32,"FindNextFileW");
	realFindFirstFileW=(ptrFindFirstFileW)GetProcAddress(hKernel32,"FindFirstFileW");
	realDeleteFileW=(ptrDeleteFileW)GetProcAddress(hKernel32,"DeleteFileW");
	realCopyFileW=(ptrCopyFileW)GetProcAddress(hKernel32,"CopyFileW");
    realMoveFileW=(ptrMoveFileW)GetProcAddress(hKernel32,"MoveFileW");
	realCreateFileW = (ptrCreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	realCreateFileA = (ptrCreateFileA)GetProcAddress(hKernel32, "CreateFileA");  
	realReadFile= (ptrReadFile)GetProcAddress(hKernel32,"ReadFile");
	//进程API
	realBitBlt= (ptrBitBlt)GetProcAddress(hGdi32,"BitBlt");
	//realCoCreateInstance= (ptrCoCreateInstance)GetProcAddress(hOle32,"CoCreateInstance");
	realCreateFileMappingW= (ptrCreateFileMappingW)GetProcAddress(hKernel32,"CreateFileMappingW");
	realOpenFileMappingW= (ptrOpenFileMappingW)GetProcAddress(hKernel32,"OpenFileMappingW");
	realCryptAcquireContext= (ptrCryptAcquireContext)GetProcAddress(hAdvapi32,"CryptAcquireContextW");
	realDeviceIoControl= (ptrDeviceIoControl)GetProcAddress(hKernel32,"DeviceIoControl");
	realFindWindowExW= (ptrFindWindowExW)GetProcAddress(hUser32,"FindWindowExW");
	realGetAsyncKeyState= (ptrGetAsyncKeyState)GetProcAddress(hUser32,"GetAsyncKeyState");
	realGetDC= (ptrGetDC)GetProcAddress(hUser32,"GetDC");
	realGetForegroundWindow= (ptrGetForegroundWindow)GetProcAddress(hUser32,"GetForegroundWindow");
	realGetKeyState= (ptrGetKeyState)GetProcAddress(hUser32,"GetKeyState");
	realGetTempPath= (ptrGetTempPath)GetProcAddress(hKernel32,"GetTempPath");
	realMapViewOfFile= (ptrMapViewOfFile)GetProcAddress(hKernel32,"MapViewOfFile");
	realOpenFile= (ptrOpenFile)GetProcAddress(hKernel32,"OpenFile");
	realAdjustTokenPrivileges= (ptrAdjustTokenPrivileges)GetProcAddress(hAdvapi32,"AdjustTokenPrivileges");
	realAttachThreadInput= (ptrAttachThreadInput)GetProcAddress(hUser32,"AttachThreadInput");
	realCallNextHookEx= (ptrCallNextHookEx)GetProcAddress(hUser32,"CallNextHookEx");
	realCheckRemoteDebuggerPresent= (ptrCheckRemoteDebuggerPresent)GetProcAddress(hKernel32,"CheckRemoteDebuggerPresent");
	realControlService= (ptrControlService)GetProcAddress(hAdvapi32,"ControlService");
	realCreateRemoteThread= (ptrCreateRemoteThread)GetProcAddress(hKernel32,"CreateRemoteThread");
	realCreateToolhelp32Snapshot= (ptrCreateToolhelp32Snapshot)GetProcAddress(hKernel32,"CreateToolhelp32Snapshot");
	realEnumProcesses= (ptrEnumProcesses)GetProcAddress(hKernel32,"EnumProcesses");
	realEnumProcessModules= (ptrEnumProcessModules)GetProcAddress(hKernel32,"EnumProcessModules");
	realGetProcAddress= (ptrGetProcAddress)GetProcAddress(hKernel32,"GetProcAddress");
	realGetSystemDefaultLangID= (ptrGetSystemDefaultLangID)GetProcAddress(hKernel32,"GetSystemDefaultLangID");
	realGetThreadContext= (ptrGetThreadContext)GetProcAddress(hKernel32,"GetThreadContext");
	realGetTickCount= (ptrGetTickCount)GetProcAddress(hKernel32,"GetTickCount");
	realIsDebuggerPresent= (ptrIsDebuggerPresent)GetProcAddress(hKernel32,"IsDebuggerPresent");
	realLoadLibraryExW= (ptrLoadLibraryExW)GetProcAddress(hKernel32,"LoadLibraryExW");
	realLoadResource= (ptrLoadResource)GetProcAddress(hKernel32,"LoadResource");
	realModule32FirstW= (ptrModule32FirstW)GetProcAddress(hKernel32,"Module32FirstW");
	realModule32NextW= (ptrModule32NextW)GetProcAddress(hKernel32,"Module32NextW");
	realOpenProcess= (ptrOpenProcess)GetProcAddress(hKernel32,"OpenProcess");
	realPeekNamedPipe= (ptrPeekNamedPipe)GetProcAddress(hKernel32,"PeekNamedPipe");
	realProcess32First= (ptrProcess32First)GetProcAddress(hKernel32,"Process32FirstW");
	realProcess32Next= (ptrProcess32Next)GetProcAddress(hKernel32,"Process32NextW");
	realQueryPerformanceCounter= (ptrQueryPerformanceCounter)GetProcAddress(hKernel32,"QueryPerformanceCounter");
	realQueueUserAPC= (ptrQueueUserAPC)GetProcAddress(hKernel32,"QueueUserAPC");
	realReadProcessMemory= (ptrReadProcessMemory)GetProcAddress(hKernel32,"ReadProcessMemory");
	realResumeThread= (ptrResumeThread)GetProcAddress(hKernel32,"ResumeThread");
	realSetThreadContext= (ptrSetThreadContext)GetProcAddress(hKernel32,"SetThreadContext");
	realSuspendThread= (ptrSuspendThread)GetProcAddress(hKernel32,"SuspendThread");
	//realsystem= (ptrsystem)GetProcAddress(hKernel32,"system");
	realThread32First= (ptrThread32First)GetProcAddress(hKernel32,"Thread32First");
	realThread32Next= (ptrThread32Next)GetProcAddress(hKernel32,"Thread32Next");
	realToolhelp32ReadProcessMemory= (ptrToolhelp32ReadProcessMemory)GetProcAddress(hKernel32,"Toolhelp32ReadProcessMemory");
	realVirtualAllocEx= (ptrVirtualAllocEx)GetProcAddress(hKernel32,"VirtualAllocEx");
	realVirtualProtectEx= (ptrVirtualProtectEx)GetProcAddress(hKernel32,"VirtualProtectEx");
	realWinExec= (ptrWinExec)GetProcAddress(hKernel32,"WinExec");
	realWriteProcessMemory= (ptrWriteProcessMemory)GetProcAddress(hKernel32,"WriteProcessMemory");
	realRegisterHotKey= (ptrRegisterHotKey)GetProcAddress(hUser32,"RegisterHotKey");
	realCreateProcessA= (ptrCreateProcessA)GetProcAddress(hKernel32,"CreateProcessA");
	realCertOpenSystemStoreW= (ptrCertOpenSystemStoreW)GetProcAddress(hCrypt32,"CertOpenSystemStoreW");
	realCreateMutexW= (ptrCreateMutexW)GetProcAddress(hKernel32,"CreateMutexW");
	realFindResourceW= (ptrFindResourceW)GetProcAddress(hKernel32,"FindResourceW");
	realFindWindowW= (ptrFindWindowW)GetProcAddress(hUser32,"FindWindowW");
	realGetWindowsDirectoryW= (ptrGetWindowsDirectoryW)GetProcAddress(hKernel32,"GetWindowsDirectoryW");
	realMapVirtualKeyW= (ptrMapVirtualKeyW)GetProcAddress(hUser32,"MapVirtualKeyW");
	realOpenMutexW= (ptrOpenMutexW)GetProcAddress(hKernel32,"OpenMutexW");
	realOpenSCManagerW= (ptrOpenSCManagerW)GetProcAddress(hAdvapi32,"OpenSCManagerW");
	realCreateProcessW= (ptrCreateProcessW)GetProcAddress(hKernel32,"CreateProcessW");
	realCreateServiceW= (ptrCreateServiceW)GetProcAddress(hAdvapi32,"CreateServiceW");
	realGetModuleFileNameExW= (ptrGetModuleFileNameExW)GetProcAddress(hKernel32,"GetModuleFileNameExW");
	realGetModuleHandleW= (ptrGetModuleHandleW)GetProcAddress(hKernel32,"GetModuleHandleW");
	realGetStartupInfoW= (ptrGetStartupInfoW)GetProcAddress(hKernel32,"GetStartupInfoW");
	realGetVersionExW= (ptrGetVersionExW)GetProcAddress(hKernel32,"GetVersionExW");
	realLoadLibraryW= (ptrLoadLibraryW)GetProcAddress(hKernel32,"LoadLibraryW");
	realOutputDebugStringW= (ptrOutputDebugStringW)GetProcAddress(hKernel32,"OutputDebugStringW");
	realSetWindowsHookExW= (ptrSetWindowsHookExW)GetProcAddress(hUser32,"SetWindowsHookExW");
	realShellExecuteW= (ptrShellExecuteW)GetProcAddress(hShell32,"ShellExecuteW");
	realStartServiceCtrlDispatcherW= (ptrStartServiceCtrlDispatcherW)GetProcAddress(hAdvapi32,"StartServiceCtrlDispatcherW");
	realSetLocalTime= (ptrSetLocalTime)GetProcAddress(hKernel32,"SetLocalTime");
	realTerminateThread= (ptrTerminateThread)GetProcAddress(hKernel32,"TerminateThread");
	realVirtualFree= (ptrVirtualFree)GetProcAddress(hKernel32,"VirtualFree");
	realSetProcessWorkingSetSize= (ptrSetProcessWorkingSetSize)GetProcAddress(hKernel32,"SetProcessWorkingSetSize");
	realTerminateProcess= (ptrTerminateProcess)GetProcAddress(hKernel32,"TerminateProcess");
	realRegOpenKeyExW= (ptrRegOpenKeyExW)GetProcAddress(hAdvapi32,"RegOpenKeyExW");
	realRegOpenKeyW= (ptrRegOpenKeyW)GetProcAddress(hAdvapi32,"RegOpenKeyW");
	realRegCreateKeyExW= (ptrRegCreateKeyExW)GetProcAddress(hAdvapi32,"RegCreateKeyExW");
	realRegCreateKeyW= (ptrRegCreateKeyW)GetProcAddress(hAdvapi32,"RegCreateKeyW");
	realRegQueryValueExW= (ptrRegQueryValueExW)GetProcAddress(hAdvapi32,"RegQueryValueExW");
	realRegQueryValueW= (ptrRegQueryValueW)GetProcAddress(hAdvapi32,"RegQueryValueW");
	realRegSetValueExW= (ptrRegSetValueExW)GetProcAddress(hAdvapi32,"RegSetValueExW");
	realRegSetValueW= (ptrRegSetValueW)GetProcAddress(hAdvapi32,"RegSetValueW");
	realRegDeleteKeyExW= (ptrRegDeleteKeyExW)GetProcAddress(hAdvapi32,"RegDeleteKeyExW");
	realRegDeleteKeyW= (ptrRegDeleteKeyW)GetProcAddress(hAdvapi32,"RegDeleteKeyW");
	realRegSetKeySecurity= (ptrRegSetKeySecurity)GetProcAddress(hAdvapi32,"RegSetKeySecurity");
	realRegRestoreKeyW= (ptrRegRestoreKeyW)GetProcAddress(hAdvapi32,"RegRestoreKeyW");
	realRegReplaceKeyW= (ptrRegReplaceKeyW)GetProcAddress(hAdvapi32,"RegReplaceKeyW");
	realRegLoadKeyW= (ptrRegLoadKeyW)GetProcAddress(hAdvapi32,"RegLoadKeyW");
	realRegUnLoadKey= (ptrRegUnLoadKey)GetProcAddress(hAdvapi32,"RegUnLoadKeyW");
	//网络
	realaccept= (ptraccept)GetProcAddress(hWs2_32,"accept");
	realsend= (ptrsend)GetProcAddress(hWs2_32,"send");
	realbind= (ptrbind)GetProcAddress(hWs2_32,"bind");
	realconnect= (ptrconnect)GetProcAddress(hWs2_32,"connect");
	realConnectNamedPipe= (ptrConnectNamedPipe)GetProcAddress(hKernel32,"ConnectNamedPipe");
	//realGetAdaptersInfo= (ptrGetAdaptersInfo)GetProcAddress(hIphlpapi,"GetAdaptersInfo");
	realgethostname= (ptrgethostname)GetProcAddress(hWs2_32,"gethostname");
	realinet_addr= (ptrinet_addr)GetProcAddress(hWs2_32,"inet_addr");
	realInternetReadFile= (ptrInternetReadFile)GetProcAddress(hWininet,"InternetReadFile");
	realInternetWriteFile= (ptrInternetWriteFile)GetProcAddress(hWininet,"InternetWriteFile");
	realNetShareEnum= (ptrNetShareEnum)GetProcAddress(hNetapi32,"NetShareEnum");
	realrecv= (ptrrecv)GetProcAddress(hWs2_32,"recv");
	realWSAStartup= (ptrWSAStartup)GetProcAddress(hWs2_32,"WSAStartup");
	realInternetOpenW= (ptrInternetOpenW)GetProcAddress(hWininet,"InternetOpenW");
	realInternetOpenUrlW= (ptrInternetOpenUrlW)GetProcAddress(hWininet,"InternetOpenUrlW");
	realURLDownloadToFileW= (ptrURLDownloadToFileW)GetProcAddress(hUrlmon,"URLDownloadToFileW");
	realFtpPutFileW= (ptrFtpPutFileW)GetProcAddress(hWininet,"FtpPutFileW");
	realHttpSendRequestW= (ptrHttpSendRequestW)GetProcAddress(hWininet,"HttpSendRequestW");
	realHttpSendRequestExW= (ptrHttpSendRequestExW)GetProcAddress(hWininet,"HttpSendRequestExW");
	realHttpOpenRequestW= (ptrHttpOpenRequestW)GetProcAddress(hWininet,"HttpOpenRequestW");
	reallisten= (ptrlisten)GetProcAddress(hWs2_32,"listen");
	realInternetOpenUrlA = (ptrInternetOpenUrlA)GetProcAddress(hWininet,"InternetOpenUrlA");
	realHttpOpenRequestA = (ptrHttpOpenRequestA)GetProcAddress(hWininet,"HttpOpenRequestA");
	//新增API
	realSetFilePointer = (ptrSetFilePointer)GetProcAddress(hKernel32,"SetFilePointer");
	realMoveFileExW = (ptrMoveFileExW)GetProcAddress(hKernel32,"MoveFileExW");
	realWriteFile = (ptrWriteFile)GetProcAddress(hKernel32,"WriteFile");
	realWriteFileEx = (ptrWriteFileEx)GetProcAddress(hKernel32,"WriteFileEx");
	realShellExecuteExW = (ptrShellExecuteExW)GetProcAddress(hKernel32,"ShellExecuteExW");
	realExitProcess = (ptrExitProcess)GetProcAddress(hKernel32,"ExitProcess");
	realVirtualProtect = (ptrVirtualProtect)GetProcAddress(hKernel32,"VirtualProtect");

	//新增API
	realCreateProcessInternalW = (ptrCreateProcessInternalW)GetProcAddress(hKernel32,"CreateProcessInternalW");
	realMoveFileA = (ptrMoveFileA)GetProcAddress(hKernel32,"MoveFileA");
	realMoveFileExA = (ptrMoveFileExA)GetProcAddress(hKernel32,"MoveFileExA");
	realRegQueryValueExA = (ptrRegQueryValueExA)GetProcAddress(hAdvapi32,"RegQueryValueExA");
	realRegQueryValueA = (ptrRegQueryValueA)GetProcAddress(hAdvapi32,"RegQueryValueA");
	realRegDeleteValueA = (ptrRegDeleteValueA)GetProcAddress(hAdvapi32,"RegDeleteValueA");
	realRegDeleteValueW = (ptrRegDeleteValueW)GetProcAddress(hAdvapi32,"RegDeleteValueW");
	realRegDeleteKeyExA = (ptrRegDeleteKeyExA)GetProcAddress(hAdvapi32,"RegDeleteKeyExA");
	realRegCreateKeyExA = (ptrRegCreateKeyExA)GetProcAddress(hAdvapi32,"RegCreateKeyExA");
	realRegCreateKeyA = (ptrRegCreateKeyA)GetProcAddress(hAdvapi32,"RegCreateKeyA");
	realSetWindowsHookExA = (ptrSetWindowsHookExA)GetProcAddress(hUser32,"SetWindowsHookExA");
	realCreateServiceA = (ptrCreateServiceA)GetProcAddress(hAdvapi32,"CreateServiceA");
	realProcess32FirstW = (ptrProcess32FirstW)GetProcAddress(hKernel32,"Process32FirstW");
	realProcess32NextW = (ptrProcess32NextW)GetProcAddress(hKernel32,"Process32NextW");
	//新增API
	realDeleteFileA = (ptrDeleteFileA)GetProcAddress(hKernel32,"DeleteFileA");
	realFindFirstFileA = (ptrFindFirstFileA)GetProcAddress(hKernel32,"FindFirstFileA");
	realFindNextFileA = (ptrFindNextFileA)GetProcAddress(hKernel32,"FindNextFileA");
	realSendMessageA = (ptrSendMessageA)GetProcAddress(hUser32,"SendMessageA");
	realSendMessageW = (ptrSendMessageW)GetProcAddress(hUser32,"SendMessageW");
	realPostMessageA = (ptrPostMessageA)GetProcAddress(hUser32,"PostMessageA");
	realPostMessageW = (ptrPostMessageW)GetProcAddress(hUser32,"PostMessageW");


	/*
	FreeLibrary(hKernel32);
	FreeLibrary(hUser32);
	FreeLibrary(hGdi32);
	FreeLibrary(hOle32);
	FreeLibrary(hAdvapi32);
	FreeLibrary(hCrypt32);
	FreeLibrary(hWininet);
	FreeLibrary(hNetapi32);
	FreeLibrary(hWs2_32);
	FreeLibrary(hIphlpapi);
	FreeLibrary(hShell32);
	FreeLibrary(hUrlmon);
	*/
	return 0;  
}

int api[200];

void DoHook()  
{  
	OutputDebugString(L"DoHook()\n"); 
	TiXmlDocument doc,black;
	char configpath[MAX_PATH]={0};
	char blacklistpath[MAX_PATH]={0};
	sprintf(configpath,"%sconfig.xml",dlldir);
	sprintf_s(blacklistpath,"%sblacklist.xml",dlldir);
	if(!doc.LoadFile(configpath)) 
	{
		///OutputDebugStringA(doc.ErrorDesc()+"\n");
		//ftest<<doc.ErrorDesc()<<endl;
	}
	if(!black.LoadFile(blacklistpath))
	{

	}
	memset(api,0,200*sizeof(api[0]));
	TiXmlElement* root = doc.FirstChildElement();
	TiXmlElement* blacklistroot = black.FirstChildElement();
	if(root == NULL)
	{
		//ftest<< "Failed to load file: No root element."<<endl;
		doc.Clear();
	}
	if (blacklistroot == NULL)
	{
		black.Clear();
	}
	int count=0;
	string s=GetProcessPath(),procName;
	//OutputDebugStringA(s.c_str());
	//OutputDebugStringA("\n");
	int dirPos = s.find_last_of('\\');

	set<string> blacklist;
	//获取黑名单

	if (dirPos!= -1)
	{
		for (TiXmlElement* elem = blacklistroot->FirstChildElement(); elem!=NULL ;elem=elem->NextSiblingElement())
		{
			string filter = elem->FirstChild()->ToText()->Value();
			blacklist.insert(filter);
			//cout<<filter<<endl;
		}
	}

	if (dirPos != -1)
	{
		procName = s.substr(dirPos+1,s.length()-dirPos-1);
		for(TiXmlElement* elem = root->FirstChildElement(); elem != NULL; elem = elem->NextSiblingElement())
		{
			//过滤几个与自己系统相关的程序
			//////////////////////////////////////////////////////////////////////////
			//to do :这里的比较应该考虑大小写问题
			//////////////////////////////////////////////////////////////////////////

			if (strcmp(procName.c_str(),"SysLogUpload.exe") == 0 
				|| strcmp(procName.c_str(),"MonInject32.exe") == 0
				|| strcmp(procName.c_str(),"MonInject64.exe") == 0
				|| strcmp(procName.c_str(),"UnloadDll32.exe") == 0
				|| strcmp(procName.c_str(),"UnloadDll64.exe") == 0
				|| strcmp(procName.c_str(),"UsMon.exe") == 0
				|| strcmp(procName.c_str(),"SysMonsTray.exe") == 0
				)
			{
				api[count++] = 0;
				continue;
			}

			//cout<<elem->Attribute("name")<<endl;
			TiXmlElement* e1=elem->FirstChildElement("isMonitored");
			//ftest<<atoi(e1->FirstChild()->ToText()->Value())<<endl;
			api[count]=atoi(e1->FirstChild()->ToText()->Value());

			for(TiXmlElement* elem1 = e1->NextSiblingElement();elem1 != NULL; elem1 = elem1->NextSiblingElement())
			{
				string filter = elem1->FirstChild()->ToText()->Value();
				if(-1 == filter.find_first_of('\\'))
				{
					if(strcmp(procName.c_str(),filter.c_str()) == 0)
					{
						//找到之后就退出当前循环
						api[count]=0;
						break;
					}

				}
				else
				{
					if(strcmp(filter.c_str(),s.c_str())==0) 
					{
						api[count]=0;
						break;
					}
				}
				//获取到的进程的路径格式是：F:\Program Files\AnyDesk\AnyDesk.exe  单斜杆
			}

			count++;
		}
	}
	else
	{
		for(TiXmlElement* elem = root->FirstChildElement(); elem != NULL; elem = elem->NextSiblingElement())
		{
			//cout<<elem->Attribute("name")<<endl;
			TiXmlElement* e1=elem->FirstChildElement("isMonitored");
			//ftest<<atoi(e1->FirstChild()->ToText()->Value())<<endl;
			api[count]=atoi(e1->FirstChild()->ToText()->Value());

			for(TiXmlElement* elem1 = e1->NextSiblingElement();elem1 != NULL; elem1 = elem1->NextSiblingElement())
			{
				if(strcmp(elem1->FirstChild()->ToText()->Value(),s.c_str())==0) 
				{
					api[count]=0;
				}
				//获取到的进程的路径格式是：F:\Program Files\AnyDesk\AnyDesk.exe  单斜杆
			}

			count++;
		}
	}

	//如果在黑名单中就过滤
	if(blacklist.count(procName)>0){
		//cout<<procName<<" is filtered"<<endl;
		memset(api,0,200*sizeof(api[0]));
	}

	for (int i=0;i<=151;i++)
	{
		//api[i]=1;//测试完了要去掉
		char out[100];
		sprintf_s(out,"%d %d\n",i,api[i]);
		OutputDebugStringA(out);
	}
	/*
	statue = LhInstallHook(realCreateFileA,  MyCreateFileA, NULL, hHookCreateFileA); 
	LhInstallHook(realReadFile,MyReadFile,NULL,hHookReadFile);
	if(!SUCCEEDED(statue))  
	{  
		switch (statue)  
		{  
		case STATUS_NO_MEMORY:  
			OutputDebugString(L"STATUS_NO_MEMORY\n");  
			break;  
		case STATUS_NOT_SUPPORTED:  
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");  
			break;  
		case STATUS_INSUFFICIENT_RESOURCES:  
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");  
			break;  
		default:  
			WCHAR dbgstr[512] = {0};  
			wsprintf(dbgstr, L"%d\n", statue);  
			OutputDebugString(dbgstr);  
		}  
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");  
		return;  
	}  
	OutputDebugString(L"Hook CreateFileA OK\n"); 
	*/
	//文件API
	if (api[0]==1&&realCreateFileA!=NULL)
	{
		LhInstallHook(realCreateFileA,MyCreateFileA,NULL,hHookCreateFileA);
		LhSetExclusiveACL(HookCreateFileA_ACLEntries, 1, hHookCreateFileA);
	}
	if (api[1]==1&&realReadFile!=NULL)
	{
		LhInstallHook(realReadFile,MyReadFile,NULL,hHookReadFile);
		LhSetExclusiveACL(HookReadFile_ACLEntries,1,hHookReadFile);
	}
	if (api[2]==1&&realCreateFileW!=NULL)
	{
		LhInstallHook(realCreateFileW,MyCreateFileW,NULL,hHookCreateFileW);
		LhSetExclusiveACL(HookCreateFileW_ACLEntries,1,hHookCreateFileW);
	}   
	if (api[3]==1&&realMoveFileW!=NULL)
	{
		LhInstallHook(realMoveFileW,MyMoveFileW,NULL,hHookMoveFileW);
		LhSetExclusiveACL(HookMoveFileW_ACLEntries,1,hHookMoveFileW);
	}
	if (api[4]==1&&realCopyFileW!=NULL)
	{
		LhInstallHook(realCopyFileW,MyCopyFileW,NULL,hHookCopyFileW);
		LhSetExclusiveACL(HookCopyFileW_ACLEntries,1,hHookCopyFileW);
	}
	if (api[5]==1&&realDeleteFileW!=NULL)
	{
		LhInstallHook(realDeleteFileW,MyDeleteFileW,NULL,hHookDeleteFileW);
		LhSetExclusiveACL(HookDeleteFileW_ACLEntries,1,hHookDeleteFileW);
	}
	if (api[6]==1&&realFindFirstFileW!=NULL)
	{
		LhInstallHook(realFindFirstFileW,MyFindFirstFileW,NULL,hHookFindFirstFileW);
		LhSetExclusiveACL(HookFindFirstFileW_ACLEntries,1,hHookFindFirstFileW);
	}
	if (api[7]==1&&realFindNextFileW!=NULL)
	{
		LhInstallHook(realFindNextFileW,MyFindNextFileW,NULL,hHookFindNextFileW);
		LhSetExclusiveACL(HookFindNextFileW_ACLEntries,1,hHookFindNextFileW);
	}
	if (api[8]==1&&realSetFileAttributesW!=NULL)
	{
		LhInstallHook(realSetFileAttributesW,MySetFileAttributesW,NULL,hHookSetFileAttributesW);
		LhSetExclusiveACL(HookSetFileAttributesW_ACLEntries,1,hHookSetFileAttributesW);
	}
	if (api[9]==1&&realCreateHardLinkW!=NULL)
	{
		LhInstallHook(realCreateHardLinkW,MyCreateHardLinkW,NULL,hHookCreateHardLinkW);
		LhSetExclusiveACL(HookCreateHardLinkW_ACLEntries,1,hHookCreateHardLinkW);
	}
	if (api[10]==1&&realSetEndOfFile!=NULL)
	{
		
		LhInstallHook(realSetEndOfFile,MySetEndOfFile,NULL,hHookSetEndOfFile);
		LhSetExclusiveACL(HookSetEndOfFile_ACLEntries,1,hHookSetEndOfFile);
		
	}
	//进程API
	if (api[11]==1&&realBitBlt!=NULL)
	{
	    //据说捕获屏幕的时候会调用，但是调用过于频繁
		
		//LhInstallHook(realBitBlt,MyBitBlt,NULL,hHookBitBlt);
		//LhSetExclusiveACL(HookBitBlt_ACLEntries, 1, hHookBitBlt);
		
	}
	if (api[12]==1&&realCreateFileMappingW!=NULL)
	{
		OutputDebugStringA("CreateFileMappingW is ok\n");
		LhInstallHook(realCreateFileMappingW,MyCreateFileMappingW,NULL,hHookCreateFileMappingW);
		LhSetExclusiveACL(HookCreateFileMappingW_ACLEntries, 1, hHookCreateFileMappingW);
	}else{
		OutputDebugStringA("CreateFileMappingW is not ok\n");
	}
	if (api[13]==1&&realOpenFileMappingW!=NULL)
	{
		OutputDebugStringA("OpenFileMappingW is ok\n");
		LhInstallHook(realOpenFileMappingW,MyOpenFileMappingW,NULL,hHookOpenFileMappingW);
		LhSetExclusiveACL(HookOpenFileMappingW_ACLEntries,1,hHookOpenFileMappingW);
	}else{
		OutputDebugStringA("OpenFileMappingW is not ok\n");
	}
	if (api[14]==1&&realCryptAcquireContext!=NULL)
	{
		LhInstallHook(realCryptAcquireContext,MyCryptAcquireContext,NULL,hHookCryptAcquireContext);
		LhSetExclusiveACL(HookCryptAcquireContext_ACLEntries, 1, hHookCryptAcquireContext);
	}
	if (api[15]==1&&realDeviceIoControl!=NULL)
	{
		LhInstallHook(realDeviceIoControl,MyDeviceIoControl,NULL,hHookDeviceIoControl);
		LhSetExclusiveACL(HookDeviceIoControl_ACLEntries, 1, hHookDeviceIoControl);
	}
	if (api[16]==1&&realFindWindowExW!=NULL)
	{
		LhInstallHook(realFindWindowExW,MyFindWindowExW,NULL,hHookFindWindowExW);
		LhSetExclusiveACL(HookFindWindowExW_ACLEntries, 1, hHookFindWindowExW);
	}
	if (api[17]==1&&realGetAsyncKeyState!=NULL)
	{
		LhInstallHook(realGetAsyncKeyState,MyGetAsyncKeyState,NULL,hHookGetAsyncKeyState);
		LhSetExclusiveACL(HookGetAsyncKeyState_ACLEntries, 1, hHookGetAsyncKeyState);
	}
	if (api[18]==1&&realGetDC!=NULL)
	{
		
		//LhInstallHook(realGetDC,MyGetDC,NULL,hHookGetDC);
		//LhSetExclusiveACL(HookGetDC_ACLEntries, 1, hHookGetDC);
		
	}
	//下面的抛出异常
	
	if (api[19]==1&&realGetForegroundWindow!=NULL)//抛出这样的异常，0x000000007757CD02 (user32.dll) (explorer.exe 中)处的第一机会异常: 0xC0000005: 写入位置 0x000007FEEEC441B4 时发生访问冲突。
	{
		//LhInstallHook(realGetForegroundWindow,MyGetForegroundWindow,NULL,hHookGetForegroundWindow);
		//LhSetExclusiveACL(HookGetForegroundWindow_ACLEntries, 1, hHookGetForegroundWindow);
	}
	if (api[20]==1&&realGetKeyState!=NULL)
	{
		
		//LhInstallHook(realGetKeyState,MyGetKeyState,NULL,hHookGetKeyState);
		//LhSetExclusiveACL(HookGetKeyState_ACLEntries, 1, hHookGetKeyState);
		
	}
	if (api[21]==1&&realGetTempPath!=NULL)
	{
		LhInstallHook(realGetTempPath,MyGetTempPath,NULL,hHookGetTempPath);
		LhSetExclusiveACL(HookGetTempPath_ACLEntries, 1, hHookGetTempPath);
	}	
	if (api[22]==1&&realMapViewOfFile!=NULL)
	{
		
		//LhInstallHook(realMapViewOfFile,MyMapViewOfFile,NULL,hHookMapViewOfFile);
		//LhSetExclusiveACL(HookMapViewOfFile_ACLEntries, 1, hHookMapViewOfFile);
		
	}
	if (api[23]==1&&realOpenFile!=NULL)
	{
		LhInstallHook(realOpenFile,MyOpenFile,NULL,hHookOpenFile);
		LhSetExclusiveACL(HookOpenFile_ACLEntries, 1, hHookOpenFile);
	}
	if (api[24]==1&&realAdjustTokenPrivileges!=NULL)
	{
		LhInstallHook(realAdjustTokenPrivileges,MyAdjustTokenPrivileges,NULL,hHookAdjustTokenPrivileges);
		LhSetExclusiveACL(HookAdjustTokenPrivileges_ACLEntries, 1, hHookAdjustTokenPrivileges);
	}
	if (api[25]==1&&realAttachThreadInput!=NULL)
	{
		LhInstallHook(realAttachThreadInput,MyAttachThreadInput,NULL,hHookAttachThreadInput);
		LhSetExclusiveACL(HookAttachThreadInput_ACLEntries, 1, hHookAttachThreadInput);
	}
	if (api[26]==1&&realCallNextHookEx!=NULL)
	{
		LhInstallHook(realCallNextHookEx,MyCallNextHookEx,NULL,hHookCallNextHookEx);
		LhSetExclusiveACL(HookCallNextHookEx_ACLEntries, 1, hHookCallNextHookEx);
	}
	if (api[27]==1&&realCheckRemoteDebuggerPresent!=NULL)
	{
		LhInstallHook(realCheckRemoteDebuggerPresent,MyCheckRemoteDebuggerPresent,NULL,hHookCheckRemoteDebuggerPresent);
		LhSetExclusiveACL(HookCheckRemoteDebuggerPresent_ACLEntries, 1, hHookCheckRemoteDebuggerPresent);
	}
	if (api[28]==1&&realControlService!=NULL)
	{
		LhInstallHook(realControlService,MyControlService,NULL,hHookControlService);
		LhSetExclusiveACL(HookControlService_ACLEntries, 1, hHookControlService);
	}
	if (api[29]==1&&realCreateRemoteThread!=NULL)
	{
		LhInstallHook(realCreateRemoteThread,MyCreateRemoteThread,NULL,hHookCreateRemoteThread);
		LhSetExclusiveACL(HookCreateRemoteThread_ACLEntries, 1, hHookCreateRemoteThread);
	}
	if (api[30]==1&&realCreateToolhelp32Snapshot!=NULL)
	{
		LhInstallHook(realCreateToolhelp32Snapshot,MyCreateToolhelp32Snapshot,NULL,hHookCreateToolhelp32Snapshot);
		LhSetExclusiveACL(HookCreateToolhelp32Snapshot_ACLEntries, 1, hHookCreateToolhelp32Snapshot);
	}
	if (api[31]==1&&realEnumProcesses!=NULL)
	{
		LhInstallHook(realEnumProcesses,MyEnumProcesses,NULL,hHookEnumProcesses);
		LhSetExclusiveACL(HookEnumProcesses_ACLEntries, 1, hHookEnumProcesses);
	}
	if (api[32]==1&&realEnumProcessModules!=NULL)
	{
		LhInstallHook(realEnumProcessModules,MyEnumProcessModules,NULL,hHookEnumProcessModules);
		LhSetExclusiveACL(HookEnumProcessModules_ACLEntries, 1, hHookEnumProcessModules);
	}
	if (api[33]==1&&realGetProcAddress!=NULL)
	{
		//LhInstallHook(realGetProcAddress,MyGetProcAddress,NULL,hHookGetProcAddress);
		//LhSetExclusiveACL(HookGetProcAddress_ACLEntries, 1, hHookGetProcAddress);
	}
	if (api[34]==1&&realGetSystemDefaultLangID!=NULL)
	{
		LhInstallHook(realGetSystemDefaultLangID,MyGetSystemDefaultLangID,NULL,hHookGetSystemDefaultLangID);
		LhSetExclusiveACL(HookGetSystemDefaultLangID_ACLEntries, 1, hHookGetSystemDefaultLangID);
	}
	if (api[35]==1&&realGetThreadContext!=NULL)////导致Explorer.exe崩溃,执行GetThreadId(hThread)发生崩溃
	{
		//LhInstallHook(realGetThreadContext,MyGetThreadContext,NULL,hHookGetThreadContext);
		//LhSetExclusiveACL(HookGetThreadContext_ACLEntries, 1, hHookGetThreadContext);
	}
    if (api[36]==1&&realGetTickCount!=NULL)
	{
		LhInstallHook(realGetTickCount,MyGetTickCount,NULL,hHookGetTickCount);
		LhSetExclusiveACL(HookGetTickCount_ACLEntries, 1, hHookGetTickCount);
	}
    if (api[37]==1&&realIsDebuggerPresent!=NULL)
	{
		LhInstallHook(realIsDebuggerPresent,MyIsDebuggerPresent,NULL,hHookIsDebuggerPresent);
		LhSetExclusiveACL(HookIsDebuggerPresent_ACLEntries, 1, hHookIsDebuggerPresent);
	}
    if (api[38]==1&&realLoadLibraryExW!=NULL)
	{
		LhInstallHook(realLoadLibraryExW,MyLoadLibraryExW,NULL,hHookLoadLibraryExW);
		LhSetExclusiveACL(HookLoadLibraryExW_ACLEntries, 1, hHookLoadLibraryExW);
	}
    if (api[39]==1&&realLoadResource!=NULL)
	{
		LhInstallHook(realLoadResource,MyLoadResource,NULL,hHookLoadResource);
		LhSetExclusiveACL(HookLoadResource_ACLEntries, 1, hHookLoadResource);
	}
    if (api[40]==1&&realModule32FirstW!=NULL)
	{
		LhInstallHook(realModule32FirstW,MyModule32FirstW,NULL,hHookModule32FirstW);
		LhSetExclusiveACL(HookModule32FirstW_ACLEntries, 1, hHookModule32FirstW);
	}
    if (api[41]==1&&realModule32NextW!=NULL)
	{
		LhInstallHook(realModule32NextW,MyModule32NextW,NULL,hHookModule32NextW);
		LhSetExclusiveACL(HookModule32NextW_ACLEntries, 1, hHookModule32NextW);
	}
	if (api[42]==1&&realOpenProcess!=NULL)
	{
		LhInstallHook(realOpenProcess,MyOpenProcess,NULL,hHookOpenProcess);
		LhSetExclusiveACL(HookOpenProcess_ACLEntries, 1, hHookOpenProcess);
	}
	if (api[43]==1&&realPeekNamedPipe!=NULL)
	{
		LhInstallHook(realPeekNamedPipe,MyPeekNamedPipe,NULL,hHookPeekNamedPipe);
		LhSetExclusiveACL(HookPeekNamedPipe_ACLEntries, 1, hHookPeekNamedPipe);
	}
	if (api[44]==1&&realProcess32First!=NULL)
	{
		LhInstallHook(realProcess32First,MyProcess32First,NULL,hHookProcess32First);
		LhSetExclusiveACL(HookProcess32First_ACLEntries, 1, hHookProcess32First);
	}
	//下面有问题
	if (api[45]==1&&realProcess32Next!=NULL)
	{
		LhInstallHook(realProcess32Next,MyProcess32Next,NULL,hHookProcess32Next);
		LhSetExclusiveACL(HookProcess32Next_ACLEntries, 1, hHookProcess32Next);
	}
	if (api[46]==1&&realQueryPerformanceCounter!=NULL)
	{
		LhInstallHook(realQueryPerformanceCounter,MyQueryPerformanceCounter,NULL,hHookQueryPerformanceCounter);
		LhSetExclusiveACL(HookQueryPerformanceCounter_ACLEntries, 1, hHookQueryPerformanceCounter);
	}
	if (api[47]==1&&realQueueUserAPC!=NULL)
	{
		LhInstallHook(realQueueUserAPC,MyQueueUserAPC,NULL,hHookQueueUserAPC);
		LhSetExclusiveACL(HookQueueUserAPC_ACLEntries, 1, hHookQueueUserAPC);
	}
	if (api[48]==1&&realReadProcessMemory!=NULL)
	{
		LhInstallHook(realReadProcessMemory,MyReadProcessMemory,NULL,hHookReadProcessMemory);
		LhSetExclusiveACL(HookReadProcessMemory_ACLEntries, 1, hHookReadProcessMemory);
	}
	if (api[49]==1&&realResumeThread!=NULL)
	{
		LhInstallHook(realResumeThread,MyResumeThread,NULL,hHookResumeThread);
		LhSetExclusiveACL(HookResumeThread_ACLEntries, 1, hHookResumeThread);
	}
	if (api[50]==1&&realSetThreadContext!=NULL)
	{
		LhInstallHook(realSetThreadContext,MySetThreadContext,NULL,hHookSetThreadContext);
		LhSetExclusiveACL(HookSetThreadContext_ACLEntries, 1, hHookSetThreadContext);
	}
	if (api[51]==1&&realSuspendThread!=NULL)
	{
		LhInstallHook(realSuspendThread,MySuspendThread,NULL,hHookSuspendThread);
		LhSetExclusiveACL(HookSuspendThread_ACLEntries, 1, hHookSuspendThread);
	}
	if (api[52]==1&&realThread32First!=NULL)
	{
		LhInstallHook(realThread32First,MyThread32First,NULL,hHookThread32First);
		LhSetExclusiveACL(HookThread32First_ACLEntries, 1, hHookThread32First);
	}
	if (api[53]==1&&realThread32Next!=NULL)
	{
		LhInstallHook(realThread32Next,MyThread32Next,NULL,hHookThread32Next);
		LhSetExclusiveACL(HookThread32Next_ACLEntries, 1, hHookThread32Next);
	}
	if (api[54]==1&&realToolhelp32ReadProcessMemory!=NULL)
	{
		LhInstallHook(realToolhelp32ReadProcessMemory,MyToolhelp32ReadProcessMemory,NULL,hHookToolhelp32ReadProcessMemory);
		LhSetExclusiveACL(HookToolhelp32ReadProcessMemory_ACLEntries, 1, hHookToolhelp32ReadProcessMemory);
	}
	if (api[55]==1&&realVirtualAllocEx!=NULL)
	{
		LhInstallHook(realVirtualAllocEx,MyVirtualAllocEx,NULL,hHookVirtualAllocEx);
		LhSetExclusiveACL(HookVirtualAllocEx_ACLEntries, 1, hHookVirtualAllocEx);
	}
	if (api[56]==1&&realVirtualProtectEx!=NULL)
	{
		LhInstallHook(realVirtualProtectEx,MyVirtualProtectEx,NULL,hHookVirtualProtectEx);
		LhSetExclusiveACL(HookVirtualProtectEx_ACLEntries, 1, hHookVirtualProtectEx);
	}
	if (api[57]==1&&realWinExec!=NULL)
	{
		LhInstallHook(realWinExec,MyWinExec,NULL,hHookWinExec);
		LhSetExclusiveACL(HookWinExec_ACLEntries, 1, hHookWinExec);
	}
	if (api[58]==1&&realWriteProcessMemory!=NULL)
	{
		LhInstallHook(realWriteProcessMemory,MyWriteProcessMemory,NULL,hHookWriteProcessMemory);
		LhSetExclusiveACL(HookWriteProcessMemory_ACLEntries, 1, hHookWriteProcessMemory);
	}
	if (api[59]==1&&realRegisterHotKey!=NULL)//抛出异常点：0x000000007757CD02 (user32.dll) (explorer.exe 中)处的第一机会异常: 0xC0000005: 写入位置 0x000007FEED531B10 时发生访问冲突。
	{
		//LhInstallHook(realRegisterHotKey,MyRegisterHotKey,NULL,hHookRegisterHotKey);
		//LhSetExclusiveACL(HookRegisterHotKey_ACLEntries, 1, hHookRegisterHotKey);
	}
	if (api[60]==1&&realCreateProcessA!=NULL)
	{
		LhInstallHook(realCreateProcessA,MyCreateProcessA,NULL,hHookCreateProcessA);
		LhSetExclusiveACL(HookCreateProcessA_ACLEntries, 1, hHookCreateProcessA);
	}
	if (api[61]==1&&realCertOpenSystemStoreW!=NULL)
	{
		LhInstallHook(realCertOpenSystemStoreW,MyCertOpenSystemStoreW,NULL,hHookCertOpenSystemStoreW);
		LhSetExclusiveACL(HookCertOpenSystemStoreW_ACLEntries, 1, hHookCertOpenSystemStoreW);
	}
	
	if (api[62]==1&&realCreateMutexW!=NULL)
	{
		LhInstallHook(realCreateMutexW,MyCreateMutexW,NULL,hHookCreateMutexW);
		LhSetExclusiveACL(HookCreateMutexW_ACLEntries, 1, hHookCreateMutexW);
	}
	if (api[63]==1&&realFindResourceW!=NULL) //导致Explorer.exe崩溃k
	{
		//LhInstallHook(realFindResourceW,MyFindResourceW,NULL,hHookFindResourceW);
		//LhSetExclusiveACL(HookFindResourceW_ACLEntries, 1, hHookFindResourceW);
	}
	if (api[64]==1&&realFindWindowW!=NULL)
	{
		LhInstallHook(realFindWindowW,MyFindWindowW,NULL,hHookFindWindowW);
		LhSetExclusiveACL(HookFindWindowW_ACLEntries, 1, hHookFindWindowW);
	}
	
	if (api[65]==1&&realGetWindowsDirectoryW!=NULL)
	{
		LhInstallHook(realGetWindowsDirectoryW,MyGetWindowsDirectoryW,NULL,hHookGetWindowsDirectoryW);
		LhSetExclusiveACL(HookGetWindowsDirectoryW_ACLEntries, 1, hHookGetWindowsDirectoryW);
	}
	if (api[66]==1&&realMapVirtualKeyW!=NULL)
	{
		LhInstallHook(realMapVirtualKeyW,MyMapVirtualKeyW,NULL,hHookMapVirtualKeyW);
		LhSetExclusiveACL(HookMapVirtualKeyW_ACLEntries, 1, hHookMapVirtualKeyW);
	}
	if (api[67]==1&&realOpenMutexW!=NULL)
	{
		LhInstallHook(realOpenMutexW,MyOpenMutexW,NULL,hHookOpenMutexW);
		LhSetExclusiveACL(HookOpenMutexW_ACLEntries, 1, hHookOpenMutexW);
	}
	if (api[68]==1&&realOpenSCManagerW!=NULL)
	{
		LhInstallHook(realOpenSCManagerW,MyOpenSCManagerW,NULL,hHookOpenSCManagerW);
		LhSetExclusiveACL(HookOpenSCManagerW_ACLEntries, 1, hHookOpenSCManagerW);
	}
	if (api[69]==1&&realCreateProcessW!=NULL)
	{
		LhInstallHook(realCreateProcessW,MyCreateProcessW,NULL,hHookCreateProcessW);
		LhSetExclusiveACL(HookCreateProcessW_ACLEntries, 1, hHookCreateProcessW);
	}
	if (api[70]==1&&realCreateServiceW!=NULL)
	{
		LhInstallHook(realCreateServiceW,MyCreateServiceW,NULL,hHookCreateServiceW);
		LhSetExclusiveACL(HookCreateServiceW_ACLEntries, 1, hHookCreateServiceW);
	}
	if (api[71]==1&&realGetModuleFileNameExW!=NULL)
	{
		LhInstallHook(realGetModuleFileNameExW,MyGetModuleFileNameExW,NULL,hHookGetModuleFileNameExW);
		LhSetExclusiveACL(HookGetModuleFileNameExW_ACLEntries, 1, hHookGetModuleFileNameExW);
	}
	if (api[72]==1&&realGetModuleHandleW!=NULL)
	{
		LhInstallHook(realGetModuleHandleW,MyGetModuleHandleW,NULL,hHookGetModuleHandleW);
		LhSetExclusiveACL(HookGetModuleHandleW_ACLEntries, 1, hHookGetModuleHandleW);
	}
	if (api[73]==1&&realGetStartupInfoW!=NULL)
	{
		LhInstallHook(realGetStartupInfoW,MyGetStartupInfoW,NULL,hHookGetStartupInfoW);
		LhSetExclusiveACL(HookGetStartupInfoW_ACLEntries, 1, hHookGetStartupInfoW);
	}
	if (api[74]==1&&realGetVersionExW!=NULL)
	{
		LhInstallHook(realGetVersionExW,MyGetVersionExW,NULL,hHookGetVersionExW);
		LhSetExclusiveACL(HookGetVersionExW_ACLEntries, 1, hHookGetVersionExW);
	}
	if (api[75]==1&&realLoadLibraryW!=NULL)
	{
		LhInstallHook(realLoadLibraryW,MyLoadLibraryW,NULL,hHookLoadLibraryW);
		LhSetExclusiveACL(HookLoadLibraryW_ACLEntries, 1, hHookLoadLibraryW);
	}
	if (api[76]==1&&realOutputDebugStringW!=NULL)
	{
		LhInstallHook(realOutputDebugStringW,MyOutputDebugStringW,NULL,hHookOutputDebugStringW);
		LhSetExclusiveACL(HookOutputDebugStringW_ACLEntries, 1, hHookOutputDebugStringW);
	}
	if (api[77]==1&&realSetWindowsHookExW!=NULL)
	{
		LhInstallHook(realSetWindowsHookExW,MySetWindowsHookExW,NULL,hHookSetWindowsHookExW);
		LhSetExclusiveACL(HookSetWindowsHookExW_ACLEntries, 1, hHookSetWindowsHookExW);
	}
	if (api[78]==1&&realShellExecuteW!=NULL)
	{
		LhInstallHook(realShellExecuteW,MyShellExecuteW,NULL,hHookShellExecuteW);
		LhSetExclusiveACL(HookShellExecuteW_ACLEntries, 1, hHookShellExecuteW);
	}
	if (api[79]==1&&realStartServiceCtrlDispatcherW!=NULL)
	{
		LhInstallHook(realStartServiceCtrlDispatcherW,MyStartServiceCtrlDispatcherW,NULL,hHookStartServiceCtrlDispatcherW);
		LhSetExclusiveACL(HookStartServiceCtrlDispatcherW_ACLEntries, 1, hHookStartServiceCtrlDispatcherW);
	}
	if (api[80]==1&&realSetLocalTime!=NULL)
	{
		LhInstallHook(realSetLocalTime,MySetLocalTime,NULL,hHookSetLocalTime);
		LhSetExclusiveACL(HookSetLocalTime_ACLEntries, 1, hHookSetLocalTime);
	}
	if (api[81]==1&&realTerminateThread!=NULL)
	{
		LhInstallHook(realTerminateThread,MyTerminateThread,NULL,hHookTerminateThread);
		LhSetExclusiveACL(HookTerminateThread_ACLEntries, 1, hHookTerminateThread);
	}
	if (api[82]==1&&realVirtualFree!=NULL)
	{
		LhInstallHook(realVirtualFree,MyVirtualFree,NULL,hHookVirtualFree);
		LhSetExclusiveACL(HookVirtualFree_ACLEntries, 1, hHookVirtualFree);
	}
	if (api[83]==1&&realSetProcessWorkingSetSize!=NULL)
	{
		LhInstallHook(realSetProcessWorkingSetSize,MySetProcessWorkingSetSize,NULL,hHookSetProcessWorkingSetSize);
		LhSetExclusiveACL(HookSetProcessWorkingSetSize_ACLEntries, 1, hHookSetProcessWorkingSetSize);
	}
	if (api[84]==1&&realTerminateProcess!=NULL)
	{
		LhInstallHook(realTerminateProcess,MyTerminateProcess,NULL,hHookTerminateProcess);
		LhSetExclusiveACL(HookTerminateProcess_ACLEntries, 1, hHookTerminateProcess);
	}
	//问题在下面
	
	//注册表
	
	if (api[85]==1&&realRegOpenKeyExW!=NULL)
	{
		LhInstallHook(realRegOpenKeyExW,MyRegOpenKeyExW,NULL,hHookRegOpenKeyExW);
		LhSetExclusiveACL(HookRegOpenKeyExW_ACLEntries, 1, hHookRegOpenKeyExW);
	}
	
	//还有API有问题，上面这个API有问题
	
	if (api[86]==1&&realRegOpenKeyW!=NULL)
	{
		LhInstallHook(realRegOpenKeyW,MyRegOpenKeyW,NULL,hHookRegOpenKeyW);
		LhSetExclusiveACL(HookRegOpenKeyW_ACLEntries, 1, hHookRegOpenKeyW);
	}
	//问题在上面
	if (api[87]==1&&realRegCreateKeyExW!=NULL)
	{
		LhInstallHook(realRegCreateKeyExW,MyRegCreateKeyExW,NULL,hHookRegCreateKeyExW);
		LhSetExclusiveACL(HookRegCreateKeyExW_ACLEntries, 1, hHookRegCreateKeyExW);
	}
	if (api[88]==1&&realRegCreateKeyW!=NULL)
	{
		LhInstallHook(realRegCreateKeyW,MyRegCreateKeyW,NULL,hHookRegCreateKeyW);
		LhSetExclusiveACL(HookRegCreateKeyW_ACLEntries, 1, hHookRegCreateKeyW);
	}
	//问题在上面
	if (api[89]==1&&realRegQueryValueExW!=NULL)
	{
		LhInstallHook(realRegQueryValueExW,MyRegQueryValueExW,NULL,hHookRegQueryValueExW);
		LhSetExclusiveACL(HookRegQueryValueExW_ACLEntries, 1, hHookRegQueryValueExW);
	}
	if (api[90]==1&&realRegQueryValueW!=NULL)
	{
		LhInstallHook(realRegQueryValueW,MyRegQueryValueW,NULL,hHookRegQueryValueW);
		LhSetExclusiveACL(HookRegQueryValueW_ACLEntries, 1, hHookRegQueryValueW);
	}
	if (api[91]==1&&realRegSetValueExW!=NULL)
	{
		LhInstallHook(realRegSetValueExW,MyRegSetValueExW,NULL,hHookRegSetValueExW);
		LhSetExclusiveACL(HookRegSetValueExW_ACLEntries, 1, hHookRegSetValueExW);
	}
	if (api[92]==1&&realRegSetValueW!=NULL)
	{
		LhInstallHook(realRegSetValueW,MyRegSetValueW,NULL,hHookRegSetValueW);
		LhSetExclusiveACL(HookRegSetValueW_ACLEntries, 1, hHookRegSetValueW);
	}
	
	//问题在上面
	if (api[93]==1&&realRegDeleteKeyExW!=NULL)
	{
		LhInstallHook(realRegDeleteKeyExW,MyRegDeleteKeyExW,NULL,hHookRegDeleteKeyExW);
		LhSetExclusiveACL(HookRegDeleteKeyExW_ACLEntries, 1, hHookRegDeleteKeyExW);
	}
	if (api[94]==1&&realRegDeleteKeyW!=NULL)
	{
		LhInstallHook(realRegDeleteKeyW,MyRegDeleteKeyW,NULL,hHookRegDeleteKeyW);
		LhSetExclusiveACL(HookRegDeleteKeyW_ACLEntries, 1, hHookRegDeleteKeyW);
	}
	if (api[95]==1&&realRegSetKeySecurity!=NULL)
	{
		LhInstallHook(realRegSetKeySecurity,MyRegSetKeySecurity,NULL,hHookRegSetKeySecurity);
		LhSetExclusiveACL(HookRegSetKeySecurity_ACLEntries, 1, hHookRegSetKeySecurity);
	}
	if (api[96]==1&&realRegRestoreKeyW!=NULL)
	{
		LhInstallHook(realRegRestoreKeyW,MyRegRestoreKeyW,NULL,hHookRegRestoreKeyW);
		LhSetExclusiveACL(HookRegRestoreKeyW_ACLEntries, 1, hHookRegRestoreKeyW);
	}
	if (api[97]==1&&realRegReplaceKeyW!=NULL)
	{
		LhInstallHook(realRegReplaceKeyW,MyRegReplaceKeyW,NULL,hHookRegReplaceKeyW);
		LhSetExclusiveACL(HookRegReplaceKeyW_ACLEntries, 1, hHookRegReplaceKeyW);
	}
	if (api[98]==1&&realRegLoadKeyW!=NULL)
	{
		LhInstallHook(realRegLoadKeyW,MyRegLoadKeyW,NULL,hHookRegLoadKeyW);
		LhSetExclusiveACL(HookRegLoadKeyW_ACLEntries, 1, hHookRegLoadKeyW);
	}
	if (api[99]==1&&realRegUnLoadKey!=NULL)
	{
		LhInstallHook(realRegUnLoadKey,MyRegUnLoadKey,NULL,hHookRegUnLoadKey);
		LhSetExclusiveACL(HookRegUnLoadKey_ACLEntries, 1, hHookRegUnLoadKey);
	}
	//问题在上面
	//网络相关API
	if (api[100]==1&&realaccept!=NULL)
	{
		LhInstallHook(realaccept,Myaccept,NULL,hHookaccept);
		LhSetExclusiveACL(Hookaccept_ACLEntries, 1, hHookaccept);
	}
	if (api[101]==1&&realsend!=NULL)
	{
		LhInstallHook(realsend,Mysend,NULL,hHooksend);
		LhSetExclusiveACL(Hooksend_ACLEntries, 1, hHooksend);
	}
	if (api[102]==1&&realbind!=NULL)
	{
		LhInstallHook(realbind,Mybind,NULL,hHookbind);
		LhSetExclusiveACL(Hookbind_ACLEntries, 1, hHookbind);
	}
	if (api[103]==1&&realconnect!=NULL)
	{
		LhInstallHook(realconnect,Myconnect,NULL,hHookconnect);
		LhSetExclusiveACL(Hookconnect_ACLEntries, 1, hHookconnect);
	}
	if (api[104]==1&&realConnectNamedPipe!=NULL)
	{
		LhInstallHook(realConnectNamedPipe,MyConnectNamedPipe,NULL,hHookConnectNamedPipe);
		LhSetExclusiveACL(HookConnectNamedPipe_ACLEntries, 1, hHookConnectNamedPipe);
	}
	
	//if (api[105]==1&&realGetAdaptersInfo!=NULL)
	//{
		//LhInstallHook(realGetAdaptersInfo,MyGetAdaptersInfo,NULL,hHookGetAdaptersInfo);
		//LhSetExclusiveACL(HookGetAdaptersInfo_ACLEntries, 1, hHookGetAdaptersInfo);
	//}
	if (api[106]==1&&realgethostname!=NULL)
	{
		LhInstallHook(realgethostname,Mygethostname,NULL,hHookgethostname);
		LhSetExclusiveACL(Hookgethostname_ACLEntries, 1, hHookgethostname);
	}
	if (api[107]==1&&realinet_addr!=NULL)
	{
		LhInstallHook(realinet_addr,Myinet_addr,NULL,hHookinet_addr);
		LhSetExclusiveACL(Hookinet_addr_ACLEntries, 1, hHookinet_addr);
	}
	if (api[108]==1&&realInternetReadFile!=NULL)
	{
		OutputDebugStringA("InternetReadFile is ok\n");
		LhInstallHook(realInternetReadFile,MyInternetReadFile,NULL,hHookInternetReadFile);
		LhSetExclusiveACL(HookInternetReadFile_ACLEntries, 1, hHookInternetReadFile);
	}
	if (api[109]==1&&realInternetWriteFile!=NULL)
	{
		OutputDebugStringA("InternetWriteFile is ok\n");
		LhInstallHook(realInternetWriteFile,MyInternetWriteFile,NULL,hHookInternetWriteFile);
		LhSetExclusiveACL(HookInternetWriteFile_ACLEntries, 1, hHookInternetWriteFile);
	}
	if (api[110]==1&&realNetShareEnum!=NULL)
	{
		LhInstallHook(realNetShareEnum,MyNetShareEnum,NULL,hHookNetShareEnum);
		LhSetExclusiveACL(HookNetShareEnum_ACLEntries, 1, hHookNetShareEnum);
	}
	if (api[111]==1&&realrecv!=NULL)
	{
		LhInstallHook(realrecv,Myrecv,NULL,hHookrecv);
		LhSetExclusiveACL(Hookrecv_ACLEntries, 1, hHookrecv);
	}
	if (api[112]==1&&realWSAStartup!=NULL)
	{
		//LhInstallHook(realWSAStartup,MyWSAStartup,NULL,hHookWSAStartup);
		//LhSetExclusiveACL(HookWSAStartup_ACLEntries, 1, hHookWSAStartup);
	}
	if (api[113]==1&&realInternetOpenW!=NULL)
	{
		LhInstallHook(realInternetOpenW,MyInternetOpenW,NULL,hHookInternetOpenW);
		LhSetExclusiveACL(HookInternetOpenW_ACLEntries, 1, hHookInternetOpenW);
	}
	if (api[114]==1&&realInternetOpenUrlW!=NULL)
	{
		OutputDebugStringA("InternetOpenUrlW is ok");
		LhInstallHook(realInternetOpenUrlW,MyInternetOpenUrlW,NULL,hHookInternetOpenUrlW);
		LhSetExclusiveACL(HookInternetOpenUrlW_ACLEntries, 1, hHookInternetOpenUrlW);
	}
	if (api[115]==1&&realURLDownloadToFileW!=NULL)
	{
		LhInstallHook(realURLDownloadToFileW,MyURLDownloadToFileW,NULL,hHookURLDownloadToFileW);
		LhSetExclusiveACL(HookURLDownloadToFileW_ACLEntries, 1, hHookURLDownloadToFileW);
	}
	if (api[116]==1&&realFtpPutFileW!=NULL)
	{
		LhInstallHook(realFtpPutFileW,MyFtpPutFileW,NULL,hHookFtpPutFileW);
		LhSetExclusiveACL(HookFtpPutFileW_ACLEntries, 1, hHookFtpPutFileW);
	}
	if (api[117]==1&&realHttpSendRequestW!=NULL)
	{
		OutputDebugStringA("HttpSendRequestW is ok\n");
		LhInstallHook(realHttpSendRequestW,MyHttpSendRequestW,NULL,hHookHttpSendRequestW);
		LhSetExclusiveACL(HookHttpSendRequestW_ACLEntries, 1, hHookHttpSendRequestW);
	}
	if (api[118]==1&&realHttpSendRequestExW!=NULL)
	{
		OutputDebugStringA("HttpSendRequestExW is ok\n");
		LhInstallHook(realHttpSendRequestExW,MyHttpSendRequestExW,NULL,hHookHttpSendRequestExW);
		LhSetExclusiveACL(HookHttpSendRequestExW_ACLEntries, 1, hHookHttpSendRequestExW);
	}
	if (api[119]==1&&realHttpOpenRequestW!=NULL)
	{
		LhInstallHook(realHttpOpenRequestW,MyHttpOpenRequestW,NULL,hHookHttpOpenRequestW);
		LhSetExclusiveACL(HookHttpOpenRequestW_ACLEntries, 1, hHookHttpOpenRequestW);
	}
	if (api[120]==1&&realInternetConnectW!=NULL)
	{
		LhInstallHook(realInternetConnectW,MyInternetConnectW,NULL,hHookInternetConnectW);
		LhSetExclusiveACL(HookInternetConnectW_ACLEntries, 1, hHookInternetConnectW);
	}
	if (api[121]==1&&reallisten!=NULL)
	{
		LhInstallHook(reallisten,Mylisten,NULL,hHooklisten);
		LhSetExclusiveACL(Hooklisten_ACLEntries, 1, hHooklisten);
	}
	if (api[122]==1&&realInternetOpenUrlA!=NULL)
	{
		LhInstallHook(realInternetOpenUrlA,MyInternetOpenUrlA,NULL,hHookInternetOpenUrlA);
		LhSetExclusiveACL(HookInternetOpenUrlA_ACLEntries,1,hHookInternetOpenUrlA);
	}
	if (api[123]==1&&realHttpOpenRequestA!=NULL)
	{
		LhInstallHook(realHttpOpenRequestA,MyHttpOpenRequestA,NULL,hHookHttpOpenRequestA);
		LhSetExclusiveACL(HookHttpOpenRequestA_ACLEntries,1,hHookHttpOpenRequestA);
	}
	
	//问题在上面
	
	//新增API
	if (api[124]==1&&realSetFilePointer!=NULL)
	{
		LhInstallHook(realSetFilePointer,MySetFilePointer,NULL,hHookSetFilePoint);
		LhSetExclusiveACL(HookSetFilePoint_ACLEntries,1,hHookSetFilePoint);
	}
	if (api[125]==1&&realMoveFileExW!=NULL)
	{
		LhInstallHook(realMoveFileExW,MyMoveFileExW,NULL,hHookMoveFileExW);
		LhSetExclusiveACL(HookMoveFileExW_ACLEntries,1,hHookMoveFileExW);
	}
	if (api[126]==1&&realWriteFile!=NULL)
	{
		LhInstallHook(realWriteFile,MyWriteFile,NULL,hHookWriteFile);
		LhSetExclusiveACL(HookWriteFile_ACLEntries,1,hHookWriteFile);
	}
	if (api[127]==1&&realWriteFileEx!=NULL)
	{
		LhInstallHook(realWriteFileEx,MyWriteFileEx,NULL,hHookWriteFileEx);
		LhSetExclusiveACL(HookWriteFileEx_ACLEntries,1,hHookWriteFileEx);
	}
	if (api[128]==1&&realShellExecuteExW!=NULL)
	{
		LhInstallHook(realShellExecuteExW,MyShellExecuteExW,NULL,hHookShellExecuteExW);
		LhSetExclusiveACL(HookShellExecuteExW_ACLEntries,1,hHookShellExecuteExW);
	}
	if (api[129]==1&&realExitProcess!=NULL)
	{
		LhInstallHook(realExitProcess,MyExitProcess,NULL,hHookExitProcess);
		LhSetExclusiveACL(HookExitProcess_ACLEntries,1,hHookExitProcess);
	}
	if (api[130]==1&&realVirtualProtect!=NULL)
	{
		LhInstallHook(realVirtualProtect,MyVirtualProtect,NULL,hHookVirtualProtect);
		LhSetExclusiveACL(HookVirtualProtectEx_ACLEntries,1,hHookVirtualProtect);
	}

	 
	//新增API
	if (api[131]==1&&realCreateProcessInternalW!=NULL)
	{
		LhInstallHook(realCreateProcessInternalW,MyCreateProcessInternalW,NULL,hHookCreateProcessInternalW);
		LhSetExclusiveACL(HookCreateProcessInternalW_ACLEntries,1,hHookCreateProcessInternalW);
	}
	if (api[132]==1&&realMoveFileA!=NULL)
	{
		LhInstallHook(realMoveFileA,MyMoveFileA,NULL,hHookMoveFileA);
		LhSetExclusiveACL(HookMoveFileA_ACLEntries,1,hHookMoveFileA);
	}
	if (api[133]==1&&realMoveFileExA!=NULL)
	{
		LhInstallHook(realMoveFileExA,MyMoveFileExA,NULL,hHookMoveFileExA);
		LhSetExclusiveACL(HookMoveFileA_ACLEntries,1,hHookMoveFileExA);
	}
	//问题在上面
	if (api[134]==1&&realRegQueryValueExA!=NULL)
	{
		LhInstallHook(realRegQueryValueExA,MyRegQueryValueExA,NULL,hHookRegQueryValueExA);
		LhSetExclusiveACL(HookRegQueryValueExA_ACLEntries,1,hHookRegQueryValueExA);
	}
	if (api[135]==1&&realRegQueryValueA!=NULL)
	{
		LhInstallHook(realRegQueryValueA,MyRegQueryValueA,NULL,hHookRegQueryValueA);
		LhSetExclusiveACL(HookRegQueryValueA_ACLEntries,1,hHookRegQueryValueA);
	}
	if (api[136]==1&&realRegDeleteValueA!=NULL)
	{
		LhInstallHook(realRegDeleteValueA,MyRegDeleteValueA,NULL,hHookRegDeleteValueA);
		LhSetExclusiveACL(HookRegDeleteValueA_ACLEntries,1,hHookRegDeleteValueA);
	}
	if (api[137]==1&&realRegDeleteValueW!=NULL)
	{
		LhInstallHook(realRegDeleteValueW,MyRegDeleteValueW,NULL,hHookRegDeleteValueW);
		LhSetExclusiveACL(HookRegDeleteValueW_ACLEntries,1,hHookRegDeleteValueW);
	}
	if (api[138]==1&&realRegDeleteKeyExA!=NULL)
	{
		LhInstallHook(realRegDeleteKeyExA,MyRegDeleteKeyExA,NULL,hHookRegDeleteKeyExA);
		LhSetExclusiveACL(HookRegDeleteKeyExA_ACLEntries,1,hHookRegDeleteKeyExA);
	}
	if (api[139]==1&&realRegCreateKeyExA!=NULL)
	{
		LhInstallHook(realRegCreateKeyExA,MyRegCreateKeyExA,NULL,hHookRegCreateKeyExA);
		LhSetExclusiveACL(HookRegCreateKeyA_ACLEntries,1,hHookRegCreateKeyExA);
	}
	if (api[140]==1&&realRegCreateKeyA!=NULL)
	{
		LhInstallHook(realRegCreateKeyA,MyRegCreateKeyA,NULL,hHookRegCreateKeyA);
		LhSetExclusiveACL(HookRegCreateKeyA_ACLEntries,1,hHookRegCreateKeyA);
	}
	if (api[141]==1&&realSetWindowsHookExA!=NULL)
	{
		LhInstallHook(realSetWindowsHookExA,MySetWindowsHookExA,NULL,hHookSetWindowsHookExA);
		LhSetExclusiveACL(HookSetWindowsHookExA_ACLEntries,1,hHookSetWindowsHookExA);
	}
	if (api[142]==1&&realCreateServiceA!=NULL)
	{
		LhInstallHook(realCreateServiceA,MyCreateServiceA,NULL,hHookCreateServiceA);
		LhSetExclusiveACL(HookCreateServiceA_ACLEntries,1,hHookCreateServiceA);
	}
	if (api[143]==1&&realProcess32FirstW!=NULL)
	{
		LhInstallHook(realProcess32FirstW,MyProcess32FirstW,NULL,hHookProcess32FirstW);
		LhSetExclusiveACL(HookProcess32FirstW_ACLEntries,1,hHookProcess32FirstW);
	}
	if (api[144]==1&&realProcess32NextW!=NULL)
	{
		LhInstallHook(realProcess32NextW,MyProcess32NextW,NULL,hHookProcess32NextW);
		LhSetExclusiveACL(HookProcess32NextW_ACLEntries,1,hHookProcess32NextW);
	}
	

	/*
	//新增API
	if (api[145]==1&&realDeleteFileA!=NULL)
	{
		LhInstallHook(realDeleteFileA,MyDeleteFileA,NULL,hHookDeleteFileA);
		LhSetExclusiveACL(HookDeleteFileA_ACLEntries,1,hHookDeleteFileA);
	}
	if (api[146]==1&&realFindFirstFileA!=NULL)
	{
		LhInstallHook(realFindFirstFileA,MyFindFirstFileA,NULL,hHookFindFirstFileA);
		LhSetExclusiveACL(HookFindFirstFileA_ACLEntries,1,hHookFindFirstFileA);
	}
	if (api[147]==1&&realFindNextFileA!=NULL)
	{
		LhInstallHook(realFindNextFileA,MyFindNextFileA,NULL,hHookFindNextFileA);
		LhSetExclusiveACL(HookFindNextFileA_ACLEntries,1,hHookFindNextFileA);
	}
	if (api[148]==1&&realSendMessageA!=NULL)
	{
		LhInstallHook(realSendMessageA,MySendMessageA,NULL,hHookSendMessageA);
		LhSetExclusiveACL(HookSendMessageA_ACLEntries,1,hHookSendMessageA);
	}
	if (api[149]==1&&realSendMessageW!=NULL)
	{
		LhInstallHook(realSendMessageW,MySendMessageW,NULL,hHookSendMessageW);
		LhSetExclusiveACL(HookSendMessageW_ACLEntries,1,hHookSendMessageW);
	}
	if (api[150]==1&&realPostMessageA!=NULL)
	{
		LhInstallHook(realPostMessageA,MyPostMessageA,NULL,hHookPostMessageA);
		LhSetExclusiveACL(HookPostMessageA_ACLEntries,1,hHookPostMessageA);
	}
	if (api[151]==1&&realPostMessageW!=NULL)
	{
		LhInstallHook(realPostMessageW,MyPostMessageW,NULL,hHookPostMessageW);
		LhSetExclusiveACL(HookPostMessageW_ACLEntries,1,hHookPostMessageW);
	}
	*/
}  

void DoneHook()  
{  
	OutputDebugString(L"DoneHook()\n");  

	// this will also invalidate "hHook", because it is a traced handle...  
	LhUninstallAllHooks();  

	// this will do nothing because the hook is already removed...  
	//  
	//LhUninstallHook(hHookReadFile);

	//文件API
	if (api[0]==1&&realCreateFileA!=NULL)
	{
		LhUninstallHook(hHookCreateFileA);
		delete hHookCreateFileA;
		hHookCreateFileA=NULL;
	}
	if (api[1]==1&&realReadFile!=NULL)
	{
		LhUninstallHook(hHookReadFile);
		delete hHookReadFile;
		hHookReadFile=NULL;
	}
	if (api[2]==1&&realCreateFileW!=NULL)
	{
		LhUninstallHook(hHookCreateFileW);
		delete hHookCreateFileW;
		hHookCreateFileW=NULL;
	}
	if (api[3]==1&&realMoveFileW!=NULL)
	{
		LhUninstallHook(hHookMoveFileW);
		delete hHookMoveFileW;
		hHookMoveFileW=NULL;
	}
	if (api[4]==1&&realCopyFileW!=NULL)
	{
		LhUninstallHook(hHookCopyFileW);
		delete hHookCopyFileW;
		hHookCopyFileW=NULL;
	}
	if (api[5]==1&&realDeleteFileW!=NULL)
	{
		LhUninstallHook(hHookDeleteFileW);
		delete hHookDeleteFileW;
		hHookDeleteFileW=NULL;
	}
	if (api[6]==1&&realFindFirstFileW!=NULL)
	{
		LhUninstallHook(hHookFindFirstFileW);
		delete hHookFindFirstFileW;
		hHookFindFirstFileW=NULL;
	}
	if (api[7]==1&&realFindNextFileW!=NULL)
	{
		LhUninstallHook(hHookFindNextFileW);
		delete hHookFindNextFileW;
		hHookFindNextFileW=NULL;
	}
	if (api[8]==1&&realSetFileAttributesW!=NULL)
	{
		LhUninstallHook(hHookSetFileAttributesW);
		delete hHookSetFileAttributesW;
		hHookSetFileAttributesW=NULL;
	}
	if (api[9]==1&&realCreateHardLinkW!=NULL)
	{
		LhUninstallHook(hHookCreateHardLinkW);
		delete hHookCreateHardLinkW;
		hHookCreateHardLinkW=NULL;
	}
	if (api[10]==1&&realSetEndOfFile!=NULL)
	{
		LhUninstallHook(hHookSetEndOfFile);
		delete hHookSetEndOfFile;
		hHookSetEndOfFile=NULL;
	}
	//进程API
	if (api[11]==1&&realBitBlt!=NULL)
	{
		LhUninstallHook(hHookBitBlt);
		delete hHookBitBlt;
		hHookBitBlt=NULL;
	}
    if (api[12]==1&&realCreateFileMappingW!=NULL)
	{
		LhUninstallHook(hHookCreateFileMappingW);
		delete hHookCreateFileMappingW;
		hHookCreateFileMappingW=NULL;
	}
	if (api[13]==1&&realOpenFileMappingW!=NULL)
	{
		LhUninstallHook(hHookOpenFileMappingW);
		delete hHookOpenFileMappingW;
		hHookOpenFileMappingW=NULL;
	}
    if (api[14]==1&&realCryptAcquireContext!=NULL)
	{
		LhUninstallHook(hHookCryptAcquireContext);
		delete hHookCryptAcquireContext;
		hHookCryptAcquireContext=NULL;
	}
    if (api[15]==1&&realDeviceIoControl!=NULL)
	{
		LhUninstallHook(hHookDeviceIoControl);
		delete hHookDeviceIoControl;
		hHookDeviceIoControl=NULL;
	}
    if (api[16]==1&&realFindWindowExW!=NULL)
	{
		LhUninstallHook(hHookFindWindowExW);
		delete hHookFindWindowExW;
		hHookFindWindowExW=NULL;
    } 
    if (api[17]==1&&realGetAsyncKeyState!=NULL)
	{
		LhUninstallHook(hHookGetAsyncKeyState);
		delete hHookGetAsyncKeyState;
		hHookGetAsyncKeyState=NULL;
	}
    if (api[18]==1&&realGetDC!=NULL)
	{
		LhUninstallHook(hHookGetDC);
		delete hHookGetDC;
		hHookGetDC=NULL;
	}
    if (api[19]==1&&realGetForegroundWindow!=NULL)
	{
		LhUninstallHook(hHookGetForegroundWindow);
		delete hHookGetForegroundWindow;
		hHookGetForegroundWindow=NULL;
	}
    if (api[20]==1&&realGetKeyState!=NULL)
	{
		LhUninstallHook(hHookGetKeyState);
		delete hHookGetKeyState;
		hHookGetKeyState=NULL;
	}
    if (api[21]==1&&realGetTempPath!=NULL)
	{
		LhUninstallHook(hHookGetTempPath);
		delete hHookGetTempPath;
		hHookGetTempPath=NULL;
	}
    if (api[22]==1&&realMapViewOfFile!=NULL)
	{
		LhUninstallHook(hHookMapViewOfFile);
		delete hHookMapViewOfFile;
		hHookMapViewOfFile=NULL;
	}
    if (api[23]==1&&realOpenFile!=NULL)
	{
		LhUninstallHook(hHookOpenFile);
		delete hHookOpenFile;
		hHookOpenFile=NULL;
	}
    if (api[24]==1&&realAdjustTokenPrivileges!=NULL)
	{
		LhUninstallHook(hHookAdjustTokenPrivileges);
		delete hHookAdjustTokenPrivileges;
		hHookAdjustTokenPrivileges=NULL;
	}
    if (api[25]==1&&realAttachThreadInput!=NULL)
	{
		LhUninstallHook(hHookAttachThreadInput);
		delete hHookAttachThreadInput;
		hHookAttachThreadInput=NULL;
	}
    if (api[26]==1&&realCallNextHookEx!=NULL)
	{
		LhUninstallHook(hHookCallNextHookEx);
		delete hHookCallNextHookEx;
		hHookCallNextHookEx=NULL;
	}
    if (api[27]==1&&realCheckRemoteDebuggerPresent!=NULL)
	{
		LhUninstallHook(hHookCheckRemoteDebuggerPresent);
		delete hHookCheckRemoteDebuggerPresent;
		hHookCheckRemoteDebuggerPresent=NULL;
	}
    if (api[28]==1&&realControlService!=NULL)
	{
		LhUninstallHook(hHookControlService);
		delete hHookControlService;
		hHookControlService=NULL;
	}
    if (api[29]==1&&realCreateRemoteThread!=NULL)
	{
		LhUninstallHook(hHookCreateRemoteThread);
		delete hHookCreateRemoteThread;
		hHookCreateRemoteThread=NULL;
	}
    if (api[30]==1&&realCreateToolhelp32Snapshot!=NULL)
	{
		LhUninstallHook(hHookCreateToolhelp32Snapshot);
		delete hHookCreateToolhelp32Snapshot;
		hHookCreateToolhelp32Snapshot=NULL;
	}
    if (api[31]==1&&realEnumProcesses!=NULL)
	{
		LhUninstallHook(hHookEnumProcesses);
		delete hHookEnumProcesses;
		hHookEnumProcesses=NULL;
	}
    if (api[32]==1&&realEnumProcessModules!=NULL)
	{
		LhUninstallHook(hHookEnumProcessModules);
		delete hHookEnumProcessModules;
		hHookEnumProcessModules=NULL;
	}
	/*
    if (api[33]==1&&realGetProcAddress!=NULL)
	{
		LhUninstallHook(hHookGetProcAddress);
		delete hHookGetProcAddress;
		hHookGetProcAddress=NULL;
	}
	*/
    if (api[34]==1&&realGetSystemDefaultLangID!=NULL)
	{
		LhUninstallHook(hHookGetSystemDefaultLangID);
		delete hHookGetSystemDefaultLangID;
		hHookGetSystemDefaultLangID=NULL;
	}
    if (api[35]==1&&realGetThreadContext!=NULL)
	{
		LhUninstallHook(hHookGetThreadContext);
		delete hHookGetThreadContext;
		hHookGetThreadContext=NULL;
	}
    
    if (api[36]==1&&realGetTickCount!=NULL)
	{
		LhUninstallHook(hHookGetTickCount);
		delete hHookGetTickCount;
		hHookGetTickCount=NULL;
	}
    if (api[37]==1&&realIsDebuggerPresent!=NULL)
	{
		LhUninstallHook(hHookIsDebuggerPresent);
		delete hHookIsDebuggerPresent;
		hHookIsDebuggerPresent=NULL;
	}
    if (api[38]==1&&realLoadLibraryExW!=NULL)
	{
		LhUninstallHook(hHookLoadLibraryExW);
		delete hHookLoadLibraryExW;
		hHookLoadLibraryExW=NULL;
	}
    if (api[39]==1&&realLoadResource!=NULL)
	{
		LhUninstallHook(hHookLoadResource);
		delete hHookLoadResource;
		hHookLoadResource=NULL;
	}
    if (api[40]==1&&realModule32FirstW!=NULL)
	{
		LhUninstallHook(hHookModule32FirstW);
		delete hHookModule32FirstW;
		hHookModule32FirstW=NULL;
	}
    if (api[41]==1&&realModule32NextW!=NULL)
	{
		LhUninstallHook(hHookModule32NextW);
		delete hHookModule32NextW;
		hHookModule32NextW=NULL;
	}
	if (api[42]==1&&realOpenProcess!=NULL)
	{
		LhUninstallHook(hHookOpenProcess);
		delete hHookOpenProcess;
		hHookOpenProcess=NULL;
	}
	if (api[43]==1&&realPeekNamedPipe!=NULL)
	{
		LhUninstallHook(hHookPeekNamedPipe);
		delete hHookPeekNamedPipe;
		hHookPeekNamedPipe=NULL;
	}
	if (api[44]==1&&realProcess32First!=NULL)
	{
		LhUninstallHook(hHookProcess32First);
		delete hHookProcess32First;
		hHookProcess32First=NULL;
	}
	if (api[45]==1&&realProcess32Next!=NULL)
	{
		LhUninstallHook(hHookProcess32Next);
		delete hHookProcess32Next;
		hHookProcess32Next=NULL;
	}
	if (api[46]==1&&realQueryPerformanceCounter!=NULL)
	{
		LhUninstallHook(hHookQueryPerformanceCounter);
		delete hHookQueryPerformanceCounter;
		hHookQueryPerformanceCounter=NULL;
	}
	if (api[47]==1&&realQueueUserAPC!=NULL)
	{
		LhUninstallHook(hHookQueueUserAPC);
		delete hHookQueueUserAPC;
		hHookQueueUserAPC=NULL;
	}
	if (api[48]==1&&realReadProcessMemory!=NULL)
	{
		LhUninstallHook(hHookReadProcessMemory);
		delete hHookReadProcessMemory;
		hHookReadProcessMemory=NULL;
	}
	if (api[49]==1&&realResumeThread!=NULL)
	{
		LhUninstallHook(hHookResumeThread);
		delete hHookResumeThread;
		hHookResumeThread=NULL;
	}
	if (api[50]==1&&realSetThreadContext!=NULL)
	{
		LhUninstallHook(hHookSetThreadContext);
		delete hHookSetThreadContext;
		hHookSetThreadContext=NULL;
	}
	if (api[51]==1&&realSuspendThread!=NULL)
	{
		LhUninstallHook(hHookSuspendThread);
		delete hHookSuspendThread;
		hHookSuspendThread=NULL;
	}
	if (api[52]==1&&realThread32First!=NULL)
	{
		LhUninstallHook(hHookThread32First);
		delete hHookThread32First;
		hHookThread32First=NULL;
	}
	if (api[53]==1&&realThread32Next!=NULL)
	{
		LhUninstallHook(hHookThread32Next);
		delete hHookThread32Next;
		hHookThread32Next=NULL;
	}
	if (api[54]==1&&realToolhelp32ReadProcessMemory!=NULL)
	{
		LhUninstallHook(hHookToolhelp32ReadProcessMemory);
		delete hHookToolhelp32ReadProcessMemory;
		hHookToolhelp32ReadProcessMemory=NULL;
	}
	if (api[55]==1&&realVirtualAllocEx!=NULL)
	{
		LhUninstallHook(hHookVirtualAllocEx);
		delete hHookVirtualAllocEx;
		hHookVirtualAllocEx=NULL;
	}
	if (api[56]==1&&realVirtualProtectEx!=NULL)
	{
		LhUninstallHook(hHookVirtualProtectEx);
		delete hHookVirtualProtectEx;
		hHookVirtualProtectEx=NULL;
	}
	if (api[57]==1&&realWinExec!=NULL)
	{
		LhUninstallHook(hHookWinExec);
		delete hHookWinExec;
		hHookWinExec=NULL;
	}
	if (api[58]==1&&realWriteProcessMemory!=NULL)
	{
		LhUninstallHook(hHookWriteProcessMemory);
		delete hHookWriteProcessMemory;
		hHookWriteProcessMemory=NULL;
	}
	if (api[59]==1&&realRegisterHotKey!=NULL)
	{
		LhUninstallHook(hHookRegisterHotKey);
		delete hHookRegisterHotKey;
		hHookRegisterHotKey=NULL;
	}
	if (api[60]==1&&realCreateProcessA!=NULL)
	{
		LhUninstallHook(hHookCreateProcessA);
		delete hHookCreateProcessA;
		hHookCreateProcessA=NULL;
	}
	if (api[61]==1&&realCertOpenSystemStoreW!=NULL)
	{
		LhUninstallHook(hHookCertOpenSystemStoreW);
		delete hHookCertOpenSystemStoreW;
		hHookCertOpenSystemStoreW=NULL;
	}
	if (api[62]==1&&realCreateMutexW!=NULL)
	{
		LhUninstallHook(hHookCreateMutexW);
		delete hHookCreateMutexW;
		hHookCreateMutexW=NULL;
	}
	if (api[63]==1&&realFindResourceW!=NULL)
	{
		LhUninstallHook(hHookFindResourceW);
		delete hHookFindResourceW;
		hHookFindResourceW=NULL;
	}
	if (api[64]==1&&realFindWindowW!=NULL)
	{
		LhUninstallHook(hHookFindWindowW);
		delete hHookFindWindowW;
		hHookFindWindowW=NULL;
	}
	if (api[65]==1&&realGetWindowsDirectoryW!=NULL)
	{
		LhUninstallHook(hHookGetWindowsDirectoryW);
		delete hHookGetWindowsDirectoryW;
		hHookGetWindowsDirectoryW=NULL;
	}
	if (api[66]==1&&realMapVirtualKeyW!=NULL)
	{
		LhUninstallHook(hHookMapVirtualKeyW);
		delete hHookMapVirtualKeyW;
		hHookMapVirtualKeyW=NULL;
	}
	if (api[67]==1&&realOpenMutexW!=NULL)
	{
		LhUninstallHook(hHookOpenMutexW);
		delete hHookOpenMutexW;
		hHookOpenMutexW=NULL;
	}
	if (api[68]==1&&realOpenSCManagerW!=NULL)
	{
		LhUninstallHook(hHookOpenSCManagerW);
		delete hHookOpenSCManagerW;
		hHookOpenSCManagerW=NULL;
	}
	if (api[69]==1&&realCreateProcessW!=NULL)
	{
		LhUninstallHook(hHookCreateProcessW);
		delete hHookCreateProcessW;
		hHookCreateProcessW=NULL;
	}
	if (api[70]==1&&realCreateServiceW!=NULL)
	{
		LhUninstallHook(hHookCreateServiceW);
		delete hHookCreateServiceW;
		hHookCreateServiceW=NULL;
	}
	if (api[71]==1&&realGetModuleFileNameExW!=NULL)
	{
		LhUninstallHook(hHookGetModuleFileNameExW);
		delete hHookGetModuleFileNameExW;
		hHookGetModuleFileNameExW=NULL;
	}
	if (api[72]==1&&realGetModuleHandleW!=NULL)
	{
		LhUninstallHook(hHookGetModuleHandleW);
		delete hHookGetModuleHandleW;
		hHookGetModuleHandleW=NULL;
	}
	if (api[73]==1&&realGetStartupInfoW!=NULL)
	{
		LhUninstallHook(hHookGetStartupInfoW);
		delete hHookGetStartupInfoW;
		hHookGetStartupInfoW=NULL;
	}
	if (api[74]==1&&realGetVersionExW!=NULL)
	{
		LhUninstallHook(hHookGetVersionExW);
		delete hHookGetVersionExW;
		hHookGetVersionExW=NULL;
	}
	if (api[75]==1&&realLoadLibraryW!=NULL)
	{
		LhUninstallHook(hHookLoadLibraryW);
		delete hHookLoadLibraryW;
		hHookLoadLibraryW=NULL;
	}
	if (api[76]==1&&realOutputDebugStringW!=NULL)
	{
		LhUninstallHook(hHookOutputDebugStringW);
		delete hHookOutputDebugStringW;
		hHookOutputDebugStringW=NULL;
	}
	if (api[77]==1&&realSetWindowsHookExW!=NULL)
	{
		LhUninstallHook(hHookSetWindowsHookExW);
		delete hHookSetWindowsHookExW;
		hHookSetWindowsHookExW=NULL;
	}
	if (api[78]==1&&realShellExecuteW!=NULL)
	{
		LhUninstallHook(hHookShellExecuteW);
		delete hHookShellExecuteW;
		hHookShellExecuteW=NULL;
	}
	if (api[79]==1&&realStartServiceCtrlDispatcherW!=NULL)
	{
		LhUninstallHook(hHookStartServiceCtrlDispatcherW);
		delete hHookStartServiceCtrlDispatcherW;
		hHookStartServiceCtrlDispatcherW=NULL;
	}
	if (api[80]==1&&realSetLocalTime!=NULL)
	{
		LhUninstallHook(hHookSetLocalTime);
		delete hHookSetLocalTime;
		hHookSetLocalTime=NULL;
	}
	if (api[81]==1&&realTerminateThread!=NULL)
	{
		LhUninstallHook(hHookTerminateThread);
		delete hHookTerminateThread;
		hHookTerminateThread=NULL;
	}
	if (api[82]==1&&realVirtualFree!=NULL)
	{
		LhUninstallHook(hHookVirtualFree);
		delete hHookVirtualFree;
		hHookVirtualFree=NULL;
	}
	if (api[83]==1&&realSetProcessWorkingSetSize!=NULL)
	{
		LhUninstallHook(hHookSetProcessWorkingSetSize);
		delete hHookSetProcessWorkingSetSize;
		hHookSetProcessWorkingSetSize=NULL;
	}
	if (api[84]==1&&realTerminateProcess!=NULL)
	{
		LhUninstallHook(hHookTerminateProcess);
		delete hHookTerminateProcess;
		hHookTerminateProcess=NULL;
	}
	if (api[85]==1&&realRegOpenKeyExW!=NULL)
	{
		LhUninstallHook(hHookRegOpenKeyExW);
		delete hHookRegOpenKeyExW;
		hHookRegOpenKeyExW=NULL;
	}
	if (api[86]==1&&realRegOpenKeyW!=NULL)
	{
		LhUninstallHook(hHookRegOpenKeyW);
		delete hHookRegOpenKeyW;
		hHookRegOpenKeyW=NULL;
	}
	if (api[87]==1&&realRegCreateKeyExW!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyExW);
		delete hHookRegCreateKeyExW;
		hHookRegCreateKeyExW=NULL;
	}
	if (api[88]==1&&realRegCreateKeyW!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyW);
		delete hHookRegCreateKeyW;
		hHookRegCreateKeyW=NULL;
	}
	if (api[89]==1&&realRegQueryValueExW!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueExW);
		delete hHookRegQueryValueExW;
		hHookRegQueryValueExW=NULL;
	}
	if (api[90]==1&&realRegQueryValueW!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueW);
		delete hHookRegQueryValueW;
		hHookRegQueryValueW=NULL;
	}
	if (api[91]==1&&realRegSetValueExW!=NULL)
	{
		LhUninstallHook(hHookRegSetValueExW);
		delete hHookRegSetValueExW;
		hHookRegSetValueExW=NULL;
	}
	if (api[92]==1&&realRegSetValueW!=NULL)
	{
		LhUninstallHook(hHookRegSetValueW);
		delete hHookRegSetValueW;
		hHookRegSetValueW=NULL;
	}
	if (api[93]==1&&realRegDeleteKeyExW!=NULL)
	{
		LhUninstallHook(hHookRegDeleteKeyExW);
		delete hHookRegDeleteKeyExW;
		hHookRegDeleteKeyExW=NULL;
	}
	if (api[94]==1&&realRegDeleteKeyW!=NULL)
	{
		LhUninstallHook(hHookRegDeleteKeyW);
		delete hHookRegDeleteKeyW;
		hHookRegDeleteKeyW=NULL;
	}
	if (api[95]==1&&realRegSetKeySecurity!=NULL)
	{
		LhUninstallHook(hHookRegSetKeySecurity);
		delete hHookRegSetKeySecurity;
		hHookRegSetKeySecurity=NULL;
	}
	if (api[96]==1&&realRegRestoreKeyW!=NULL)
	{
		LhUninstallHook(hHookRegRestoreKeyW);
		delete hHookRegRestoreKeyW;
		hHookRegRestoreKeyW=NULL;
	}
	if (api[97]==1&&realRegReplaceKeyW!=NULL)
	{
		LhUninstallHook(hHookRegReplaceKeyW);
		delete hHookRegReplaceKeyW;
		hHookRegReplaceKeyW=NULL;
	}
	if (api[98]==1&&realRegLoadKeyW!=NULL)
	{
		LhUninstallHook(hHookRegLoadKeyW);
		delete hHookRegLoadKeyW;
		hHookRegLoadKeyW=NULL;
	}
	if (api[99]==1&&realRegUnLoadKey!=NULL)
	{
		LhUninstallHook(hHookRegUnLoadKey);
		delete hHookRegUnLoadKey;
		hHookRegUnLoadKey=NULL;
	}
	if (api[100]==1&&realaccept!=NULL)
	{
		LhUninstallHook(hHookaccept);
		delete hHookaccept;
		hHookaccept=NULL;
	}
	if (api[101]==1&&realsend!=NULL)
	{
		LhUninstallHook(hHooksend);
		delete hHooksend;
		hHooksend=NULL;
	}
	if (api[102]==1&&realbind!=NULL)
	{
		LhUninstallHook(hHookbind);
		delete hHookbind;
		hHookbind=NULL;
	}
	if (api[103]==1&&realconnect!=NULL)
	{
		LhUninstallHook(hHookconnect);
		delete hHookconnect;
		hHookconnect=NULL;
	}
	if (api[104]==1&&realConnectNamedPipe!=NULL)
	{
		LhUninstallHook(hHookConnectNamedPipe);
		delete hHookConnectNamedPipe;
		hHookConnectNamedPipe=NULL;
	}
	/*
	if (api[105]==1&&realGetAdaptersInfo!=NULL)
	{
		LhUninstallHook(hHookGetAdaptersInfo);
		delete hHookGetAdaptersInfo;
		hHookGetAdaptersInfo=NULL;
	}
	*/
	if (api[106]==1&&realgethostname!=NULL)
	{
		LhUninstallHook(hHookgethostname);
		delete hHookgethostname;
		hHookgethostname=NULL;
	}
	if (api[107]==1&&realinet_addr!=NULL)
	{
		LhUninstallHook(hHookinet_addr);
		delete hHookinet_addr;
		hHookinet_addr=NULL;
	}
	if (api[108]==1&&realInternetReadFile!=NULL)
	{
		LhUninstallHook(hHookInternetReadFile);
		delete hHookInternetReadFile;
		hHookInternetReadFile=NULL;
	}
	if (api[109]==1&&realInternetWriteFile!=NULL)
	{
		LhUninstallHook(hHookInternetWriteFile);
		delete hHookInternetWriteFile;
		hHookInternetWriteFile=NULL;
	}
	if (api[110]==1&&realNetShareEnum!=NULL)
	{
		LhUninstallHook(hHookNetShareEnum);
		delete hHookNetShareEnum;
		hHookNetShareEnum=NULL;
	}
	if (api[111]==1&&realrecv!=NULL)
	{
		LhUninstallHook(hHookrecv);
		delete hHookrecv;
		hHookrecv=NULL;
	}
	if (api[112]==1&&realWSAStartup!=NULL)
	{
		LhUninstallHook(hHookWSAStartup);
		delete hHookWSAStartup;
		hHookWSAStartup=NULL;
	}
	if (api[113]==1&&realInternetOpenW!=NULL)
	{
		LhUninstallHook(hHookInternetOpenW);
		delete hHookInternetOpenW;
		hHookInternetOpenW=NULL;
	}
	if (api[114]==1&&realInternetOpenUrlW!=NULL)
	{
		LhUninstallHook(hHookInternetOpenUrlW);
		delete hHookInternetOpenUrlW;
		hHookInternetOpenUrlW=NULL;
	}
	if (api[115]==1&&realURLDownloadToFileW!=NULL)
	{
		LhUninstallHook(hHookURLDownloadToFileW);
		delete hHookURLDownloadToFileW;
		hHookURLDownloadToFileW=NULL;
	}
	if (api[116]==1&&realFtpPutFileW!=NULL)
	{
		LhUninstallHook(hHookFtpPutFileW);
		delete hHookFtpPutFileW;
		hHookFtpPutFileW=NULL;
	}
	if (api[117]==1&&realHttpSendRequestW!=NULL)
	{
		LhUninstallHook(hHookHttpSendRequestW);
		delete hHookHttpSendRequestW;
		hHookHttpSendRequestW=NULL;
	}
	if (api[118]==1&&realHttpSendRequestExW!=NULL)
	{
		LhUninstallHook(hHookHttpSendRequestExW);
		delete hHookHttpSendRequestExW;
		hHookHttpSendRequestExW=NULL;
	}
	if (api[119]==1&&realHttpOpenRequestW!=NULL)
	{
		LhUninstallHook(hHookHttpOpenRequestW);
		delete hHookHttpOpenRequestW;
		hHookHttpOpenRequestW=NULL;
	}
	if (api[120]==1&&realInternetConnectW!=NULL)
	{
		LhUninstallHook(hHookInternetConnectW);
		delete hHookInternetConnectW;
		hHookInternetConnectW=NULL;
	}
	if (api[121]==1&&reallisten!=NULL)
	{
		LhUninstallHook(hHooklisten);
		delete hHooklisten;
		hHooklisten=NULL;
	}
	if (api[122]==1&&realInternetOpenUrlA!=NULL)
	{
		LhUninstallHook(hHookInternetOpenUrlA);
		delete hHookInternetOpenUrlA;
		hHookInternetOpenUrlA=NULL;
	}
	if (api[123]==1&&realHttpOpenRequestA!=NULL)
	{
		LhUninstallHook(hHookHttpOpenRequestA);
		delete hHookHttpOpenRequestA;
		hHookHttpOpenRequestA=NULL;
	}

	//新增API
	if (api[124]==1&&realSetFilePointer!=NULL)
	{
		LhUninstallHook(hHookSetFilePoint);
		delete hHookSetFilePoint;
		hHookSetFilePoint=NULL;
	}
	if (api[125]==1&&realMoveFileExW!=NULL)
	{
		LhUninstallHook(hHookMoveFileExW);
		delete hHookMoveFileExW;
		hHookMoveFileExW=NULL;
	}
	if (api[126]==1&&realWriteFile!=NULL)
	{
		LhUninstallHook(hHookWriteFile);
		delete hHookWriteFile;
		hHookWriteFile=NULL;
	}
	if (api[127]==1&&realWriteFileEx!=NULL)
	{
		LhUninstallHook(hHookWriteFileEx);
		delete hHookWriteFileEx;
		hHookWriteFileEx=NULL;
	}
	if (api[128]==1&&realShellExecuteExW!=NULL)
	{
		LhUninstallHook(hHookShellExecuteExW);
		delete hHookShellExecuteExW;
		hHookShellExecuteExW=NULL;
	}
	if (api[129]==1&&realExitProcess!=NULL)
	{
		LhUninstallHook(hHookExitProcess);
		delete hHookExitProcess;
		hHookExitProcess=NULL;
	}
	if (api[130]==1&&realVirtualProtect!=NULL)
	{
		LhUninstallHook(hHookVirtualProtect);
		delete hHookVirtualProtect;
		hHookVirtualProtect=NULL;
	}

	//新增API
	if (api[131]==1&&realCreateProcessInternalW!=NULL)
	{
		LhUninstallHook(hHookCreateProcessInternalW);
		delete hHookCreateProcessInternalW;
		hHookCreateProcessInternalW=NULL;
	}
	if (api[132]==1&&realMoveFileA!=NULL)
	{
		LhUninstallHook(hHookMoveFileA);
		delete hHookMoveFileA;
		hHookMoveFileA=NULL;
	}
	if (api[133]==1&&realMoveFileExA!=NULL)
	{
		LhUninstallHook(hHookMoveFileExA);
		delete hHookMoveFileExA;
		hHookMoveFileExA=NULL;
	}
	if (api[134]==1&&realRegQueryValueExA!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueExA);
		delete hHookRegQueryValueExA;
		hHookRegQueryValueExA=NULL;
	}
	if (api[135]==1&&realRegQueryValueA!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueA);
		delete hHookRegQueryValueA;
		hHookRegQueryValueA=NULL;
	}
	if (api[136]==1&&realRegDeleteValueA!=NULL)
	{
		LhUninstallHook(hHookRegDeleteValueA);
		delete hHookRegDeleteValueA;
		hHookRegDeleteValueA=NULL;
	}
	if (api[137]==1&&realRegDeleteValueW!=NULL)
	{
		LhUninstallHook(hHookRegDeleteValueW);
		delete hHookRegDeleteValueW;
		hHookRegDeleteValueW=NULL;
	}
	if (api[138]==1&&realRegDeleteKeyExA!=NULL)
	{
		LhUninstallHook(hHookRegDeleteKeyExA);
		delete hHookRegDeleteKeyExA;
		hHookRegDeleteKeyExA=NULL;
	}
	if (api[139]==1&&realRegCreateKeyExA!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyExA);
		delete hHookRegCreateKeyExA;
		hHookRegCreateKeyExA=NULL;
	}
	if (api[140]==1&&realRegCreateKeyA!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyA);
		delete hHookRegCreateKeyA;
		hHookRegCreateKeyA=NULL;
	}
	if (api[141]==1&&realSetWindowsHookExA!=NULL)
	{
		LhUninstallHook(hHookSetWindowsHookExA);
		delete hHookSetWindowsHookExA;
		hHookSetWindowsHookExA=NULL;
	}
	if (api[142]==1&&realCreateServiceA!=NULL)
	{
		LhUninstallHook(hHookCreateServiceA);
		delete hHookCreateServiceA;
		hHookCreateServiceA=NULL;
	}
	if (api[143]==1&&realProcess32FirstW!=NULL)
	{
		LhUninstallHook(hHookProcess32FirstW);
		delete hHookProcess32FirstW;
		hHookProcess32FirstW=NULL;
	}
	if (api[144]==1&&realProcess32NextW!=NULL)
	{
		LhUninstallHook(hHookProcess32NextW);
		delete hHookProcess32NextW;
		hHookProcess32NextW=NULL;
	}


	//新增API
	/*
	if (api[145]==1&&realDeleteFileA!=NULL)
	{
		LhUninstallHook(hHookDeleteFileA);
		delete hHookDeleteFileA;
		hHookDeleteFileA=NULL;
	}
	if (api[146]==1&&realFindFirstFileA!=NULL)
	{
		LhUninstallHook(hHookFindFirstFileA);
		delete hHookFindFirstFileA;
		hHookFindFirstFileA=NULL;
	}
	if (api[147]==1&&realFindNextFileA!=NULL)
	{
		LhUninstallHook(hHookFindNextFileA);
		delete hHookFindNextFileA;
		hHookFindNextFileA=NULL;
	}
	if (api[148]==1&&realSendMessageA!=NULL)
	{
		LhUninstallHook(hHookSendMessageA);
		delete hHookSendMessageA;
		hHookSendMessageA=NULL;
	}
	if (api[149]==1&&realSendMessageW!=NULL)
	{
		LhUninstallHook(hHookSendMessageW);
		delete hHookSendMessageW;
		hHookSendMessageW=NULL;
	}
	if (api[150]==1&&realPostMessageA!=NULL)
	{
		LhUninstallHook(hHookPostMessageA);
		delete hHookPostMessageA;
		hHookPostMessageA=NULL;
	}
	if (api[151]==1&&realPostMessageW!=NULL)
	{
		LhUninstallHook(hHookPostMessageW);
		delete hHookPostMessageW;
		hHookPostMessageW=NULL;
	}
	*/

	LhWaitForPendingRemovals();  
}  

BOOL APIENTRY DllMain( HMODULE hModule,  
					  DWORD  ul_reason_for_call,  
					  LPVOID lpReserved  
					  )  
{  
	//ofstream ftest("C:\\Log\\test.txt",ios::app);
	//MessageBox(0, L"DllMain！", L"好了！", MB_OK); 
	switch (ul_reason_for_call)  
	{  
	case DLL_PROCESS_ATTACH:  
		{  
			OutputDebugString(L"DllMain::DLL_PROCESS_ATTACH\n");  
			//获取当前dll的路径
			char dllpath[MAX_PATH]={0};
			GetModuleFileNameA(hModule,dllpath,MAX_PATH);
			string str1(dllpath);
			//cout<<dllpath<<endl;
			string str2=str1.substr(0,strlen(dllpath)-12);
			//OutputDebugStringA(str2.c_str());
			strcpy(dlldir,str2.c_str());
			//OutputDebugStringA("\n");

			DWORD dwSize = 256;
			int len=200;
			GetUserNameA(strBuffer,&dwSize);//获取用户名
			WSAData wsaData;
			WSAStartup(MAKEWORD(1,1), &wsaData); 
			g_handleMailServer =  CreateFile(g_strInjectMailSlot,
				GENERIC_WRITE,      // 可写  
				FILE_SHARE_READ|FILE_SHARE_WRITE, 
				(LPSECURITY_ATTRIBUTES) NULL,   
				OPEN_EXISTING,      // 打开一个已经存在的mailslot，应该由服务端已经创建
				FILE_ATTRIBUTE_NORMAL,   
				(HANDLE) NULL); 
			gethostname(hostname,128);//获取主机名
			GetProcessName(ProcessName,&len);//获取进程名
			sprintf(log_path,"%sLog64.txt",dlldir);//获取日志路径
			//cout<<log_path<<endl;
			strcpy(spy,"00000");//获取监测层
			/*cout<<ProcessName<<endl;
			cout<<hostname<<endl;
			cout<<strBuffer<<endl;*/

			// 准备好原始地址与目的地址  
			int errCode = PrepareRealApiEntry();  
			if (errCode != 0)  
			{  
				OutputDebugString(L"PrepareRealApiEntry() Error\n");  
				return FALSE;  
			}  

			// 开始挂钩  
			DoHook();  

			break;  
		}  
	case DLL_THREAD_ATTACH:  
		{  
			OutputDebugString(L"DllMain::DLL_THREAD_ATTACH\n");  

			break;  
		}  
	case DLL_THREAD_DETACH:  
		{  
			OutputDebugString(L"DllMain::DLL_THREAD_DETACH\n");  

			break;  
		}  

	case DLL_PROCESS_DETACH:  
		{  
			OutputDebugString(L"DllMain::DLL_PROCESS_DETACH\n");  

			// 卸载钩子  
			DoneHook();  

			//退出前关闭邮箱槽客户端
			if(g_handleMailServer != INVALID_HANDLE_VALUE)
				CloseHandle(g_handleMailServer);


			break;  
		}  
	}  
	return TRUE;  
}  
