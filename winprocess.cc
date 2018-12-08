#include "uv.h"
#include <node.h>
#include <node_buffer.h>
#include <windows.h>
#include <string>
#include <iostream>
#include "winprocess.h"
#include <tlhelp32.h>
#include "LoadLibraryR.h"
#include "GetProcAddressR.h"

#pragma comment(lib,"Advapi32.lib")

#pragma comment( lib, "psapi" )

#include <psapi.h>

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }

using namespace v8;
using namespace node;
using namespace std;

Persistent<Function> WinProcess::constructor;

void myFree (char * bu, void *hint) {
	
}

void EnableDebugPriv()
{

    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken);
}

DWORD_PTR GetProcessBaseAddress(HANDLE processHandle)
{
    DWORD_PTR   baseAddress = 0;
    //HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE     *moduleArray;
    LPBYTE      moduleArrayBytes;
    DWORD       bytesRequired;

    if ( processHandle )
    {
        if ( EnumProcessModules( processHandle, NULL, 0, &bytesRequired ) )
        {
            if ( bytesRequired )
            {
                moduleArrayBytes = (LPBYTE)LocalAlloc( LPTR, bytesRequired );

                if ( moduleArrayBytes )
                {
                    unsigned int moduleCount;

                    moduleCount = bytesRequired / sizeof( HMODULE );
                    moduleArray = (HMODULE *)moduleArrayBytes;

                    if ( EnumProcessModules( processHandle, moduleArray, bytesRequired, &bytesRequired ) )
                    {
                        baseAddress = (DWORD_PTR)moduleArray[0];
                    }

                    LocalFree( moduleArrayBytes );
                }
            }
        }

        CloseHandle( processHandle );
    }

    return baseAddress;
}

std::string GetLastErrorAsString()
{
    //Get the error message, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0)
        return "No error message has been recorded";

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    return message;
}

int getProcessId(const char * procname){
	 EnableDebugPriv();
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, procname) == 0)
            {
            	CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
	return -1;
}

void getProcessIdNode(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = args.GetIsolate();  
 	v8::String::Utf8Value procn(args[0]->ToString());   
    std::string y2 = std::string(*procn);
	const char * procname = y2.c_str();
	int pid = getProcessId(procname);
  	args.GetReturnValue().Set(Number::New(isolate, pid));
}

void getProcessIdByWindow(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = args.GetIsolate();  
 	v8::String::Utf8Value param1(args[0]->ToString());
	std::string processName = std::string(*param1);
	HWND hWnd = FindWindow(processName.c_str(), NULL);
	if (hWnd != 0) {
		DWORD pId;
		GetWindowThreadProcessId(hWnd, &pId);
		args.GetReturnValue().Set(Number::New(isolate, pId));
	}
  	args.GetReturnValue().Set(Boolean::New(isolate, false));
}

void getActiveWindowName(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = args.GetIsolate();  
 	char wnd_title[256];
	HWND hwnd=GetForegroundWindow(); // get handle of currently active window
	GetWindowText(hwnd,wnd_title,sizeof(wnd_title));	
  	args.GetReturnValue().Set(String::NewFromUtf8(isolate, wnd_title));
}

WinProcess::WinProcess(DWORD pid) : _pid(pid), _handle(INVALID_HANDLE_VALUE) {
}

WinProcess::~WinProcess() {
	delete _handle;
}

void WinProcess::Init(Local<Object> exports) {
Isolate* isolate = Isolate::GetCurrent();
 
  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "Process"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
 
  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "open", Open);
  NODE_SET_PROTOTYPE_METHOD(tpl, "readMemory", ReadMemory);
  NODE_SET_PROTOTYPE_METHOD(tpl, "writeMemory", WriteMemory);
  NODE_SET_PROTOTYPE_METHOD(tpl, "inject", Inject);
  NODE_SET_PROTOTYPE_METHOD(tpl, "injectReflective", InjectReflective);
  NODE_SET_PROTOTYPE_METHOD(tpl, "terminate", Terminate);
  NODE_SET_PROTOTYPE_METHOD(tpl, "readMultiLevelPointerMemory", ReadMultiLevelPointerMemory);
  NODE_SET_PROTOTYPE_METHOD(tpl, "getBaseAddress", getBaseAddress);
  NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
  
  
  constructor.Reset(isolate, tpl->GetFunction());
  exports->Set(String::NewFromUtf8(isolate, "Process"),tpl->GetFunction());
  NODE_SET_METHOD(exports, "getProcessId", getProcessIdNode);
  NODE_SET_METHOD(exports, "getProcessIdByWindow", getProcessIdByWindow);
  NODE_SET_METHOD(exports, "getActiveWindowName", getActiveWindowName);
}

void WinProcess::New(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	if (args.IsConstructCall()) {
	    // Invoked as constructor: `new Process(...)`
	    DWORD id = args[0]->IsUndefined() ? 0 : (DWORD)args[0]->NumberValue();
	    WinProcess* obj = new WinProcess(id);
	    obj->Wrap(args.This());
	    args.GetReturnValue().Set(args.This());
	  } else {
	    // Invoked as plain function `Process(...)`, turn into construct call.
	    const int argc = 1;
	    Local<Value> argv[argc] = { args[0] };
	    Local<Function> cons = Local<Function>::New(isolate, constructor);
	    args.GetReturnValue().Set(cons->NewInstance(argc, argv));
	  }
}

void WinProcess::Open(const FunctionCallbackInfo<Value>& args) 
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
    EnableDebugPriv();
    obj->_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, obj->_pid);
    args.GetReturnValue().Set(Number::New(isolate, (uint64_t)obj->_handle));
}

void WinProcess::Terminate(const FunctionCallbackInfo<Value>& args) 
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
    args.GetReturnValue().Set(Boolean::New(isolate, TerminateProcess(obj->_handle, 1)));
}
 
 void WinProcess::ReadMemory(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
  
  	if (args.Length() < 2)
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
  
  	if (!args[0]->IsNumber() || !args[1]->IsNumber())
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong arguments")));
        return;
    }
  
  	WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
	int length = (int)args[1]->IntegerValue();	
  	char *buffer = new char[length];
  	SIZE_T bytesRead;
	if (ReadProcessMemory(obj->_handle, (void *)args[0]->IntegerValue(), buffer, length, &bytesRead))
    {
        args.GetReturnValue().Set(Buffer::New(isolate, buffer, (size_t)length, myFree, NULL).ToLocalChecked());
    }
    else
    {
        args.GetReturnValue().Set(Number::New(isolate, GetLastError()));
    }
}

 void WinProcess::ReadMultiLevelPointerMemory(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
  
  	if (args.Length() < 1)
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
  
  	WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
	DWORD base = (DWORD) args[1]->IntegerValue();
	DWORD cur = base;
	DWORD offset = 0;
	if (ReadProcessMemory(obj->_handle, (void*)(cur + offset), &cur, 4, 0) == 0) {
		 args.GetReturnValue().Set(Number::New(isolate, 0));
		 return;
	 }
	for(int i = 2; i < args.Length() ; i++) {
		DWORD offset = (DWORD) args[1]->IntegerValue();
		if (ReadProcessMemory(obj->_handle, (void*)(cur + offset), &cur, 4, 0) == 0) {
			 args.GetReturnValue().Set(Number::New(isolate, 0));
			 return;
		}
	}
	args.GetReturnValue().Set(Number::New(isolate, cur));
}


void WinProcess::WriteMemory(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
	
	WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
	size_t packetLen = Buffer::Length(args[1]);
	char* packet = Buffer::Data(args[1]);	
	
	if(WriteProcessMemory(obj->_handle, (void*)args[0]->IntegerValue(), packet, packetLen, NULL)){
		args.GetReturnValue().Set(Boolean::New(isolate, true));	
	}
	else{
		args.GetReturnValue().Set(Number::New(isolate, GetLastError()));
	}
}

/* Load DLL into remote process
* Gets LoadLibraryA address from current process, which is guaranteed to be same for single boot session across processes
* Allocated memory in remote process for DLL path name
* CreateRemoteThread to run LoadLibraryA in remote process. Address of DLL path in remote memory as argument
*/
void WinProcess::Inject(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
	WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
	
	v8::String::Utf8Value dllPathUtf8(args[0]->ToString());   
    std::string dllPath = std::string(*dllPathUtf8);
	
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, obj->_pid);		//TODO There is no need to open the handle again. Use obj->_handle.	(This didnt just work out of the box).
	//HANDLE handle = obj->_handle;
	
	if( !handle ){
		//printf( "Failed to open the target process" );
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Failed to open the target process.")));
		args.GetReturnValue().Set(Number::New(isolate, 0));
		return;
	}
	
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(handle, NULL, dllPath.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) {
		//printf("[---] VirtualAllocEx unsuccessful. %d \n", GetLastError());
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "VirtualAllocEx unsuccessful.")));
		args.GetReturnValue().Set(Number::New(isolate, 0));
		return;
	}

	// Write DLL's path name to remote process
	BOOL succeededWriting = WriteProcessMemory(handle, dllPathAddressInRemoteMemory, dllPath.c_str(), dllPath.size(), NULL);

	if (!succeededWriting) {
		//printf("[---] WriteProcessMemory unsuccessful. %d\n", GetLastError());
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "WriteProcessMemory unsuccessful.")));
		args.GetReturnValue().Set(Number::New(isolate, 0));
		return;
	} else {
		// Returns a pointer to the LoadLibrary address. This will be the same on the remote process as in our current process.
		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (loadLibraryAddress == NULL) {
			//printf("[---] LoadLibrary not found in process. %d\n", GetLastError());
			isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "LoadLibrary not found in process.")));
			args.GetReturnValue().Set(Number::New(isolate, 0));
			return;
		} else {
			HANDLE remoteThread = CreateRemoteThread(handle, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
			if (remoteThread == NULL) {
				//printf("[---] CreateRemoteThread unsuccessful. %d\n", GetLastError());
				isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "CreateRemoteThread unsuccessful.")));
				args.GetReturnValue().Set(Number::New(isolate, 0));
				return;
			}
		}
	}

	CloseHandle(handle);
	args.GetReturnValue().Set(Number::New(isolate, 1));
}



void WinProcess::InjectReflective(const FunctionCallbackInfo<Value>& args) {
 	Isolate* isolate = args.GetIsolate();  
 	HandleScope scope(isolate); 
    WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
    
 	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	TOKEN_PRIVILEGES priv = {0};

	v8::String::Utf8Value dllName3(args[0]->ToString());
	std::string dllName2 = std::string(*dllName3);
	const char * cpDllFile = dllName2.c_str();


	do
	{
		hFile = CreateFileA( cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if( hFile == INVALID_HANDLE_VALUE ){
			BREAK_WITH_ERROR( "Failed to open the DLL file" );
		}
		dwLength = GetFileSize( hFile, NULL );
		if( dwLength == INVALID_FILE_SIZE || dwLength == 0 ){
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );
		}
		lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
		if( !lpBuffer ){
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );
		}
		if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE ){
			BREAK_WITH_ERROR( "Failed to alloc a buffer!" );
		}
		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) ){
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );
			}
			CloseHandle( hToken );
		}
		//hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, obj->_pid );
		if( !obj->_handle ){BREAK_WITH_ERROR( "Failed to open the target process" );}
		hModule = LoadRemoteLibraryR( obj->_handle, lpBuffer, dwLength, NULL );
		if( !hModule ){BREAK_WITH_ERROR( "Failed to inject the DLL" );}
		printf( "[+] Injected the '%s' DLL into process %d.", cpDllFile, obj->_pid );
		WaitForSingleObject( hModule, -1 );
	} while( 0 );

	if( lpBuffer ){HeapFree( GetProcessHeap(), 0, lpBuffer );}
	if( obj->_handle ){CloseHandle( obj->_handle );}
	if( hFile ){CloseHandle( hFile );}
	args.GetReturnValue().Set(Boolean::New(isolate, false));
}

void WinProcess::getBaseAddress(const FunctionCallbackInfo<Value>& args) 
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate); 
    WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
	if(obj->_handle){
		DWORD_PTR bAddr = GetProcessBaseAddress(obj->_handle);
		args.GetReturnValue().Set(Number::New(isolate, bAddr));
	}
}
 
void WinProcess::Close(const FunctionCallbackInfo<Value>& args) 
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate); 
    WinProcess* obj = ObjectWrap::Unwrap<WinProcess>(args.Holder());
    if (obj->_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(obj->_handle);
    }
}

NODE_MODULE(addon, WinProcess::Init)