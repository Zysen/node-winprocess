#ifndef Process_H
#define Process_H
 
#include <windows.h>
 
#include <node.h>
#include <node_object_wrap.h>
 
class WinProcess : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
 
 private:
  explicit WinProcess(DWORD pid = 0);
  ~WinProcess();
 
  HANDLE _handle;
  DWORD _pid;
 
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Open(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ReadMemory(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void WriteMemory(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ReadMultiLevelPointerMemory(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Inject(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void getBaseAddress(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Terminate(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Close(const v8::FunctionCallbackInfo<v8::Value>& args);
  static v8::Persistent<v8::Function> constructor;
  
};
 
#endif