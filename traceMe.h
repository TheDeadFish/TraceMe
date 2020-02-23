// TraceMe V1.30, 14/03/2014
// DeadFish Shitware

#include <windows.h>
//#include "void.h"

class TraceMe
{
public:
	static void Init(void);
	static void Trace(PCONTEXT context);
	static void Begin(PCONTEXT context, Void breakPoint);
	static void Begin(Void breakPoint = 0);
	
	static void OnWrite(Void address);
	
	
	static PVOID displayIns(PVOID excpAddr, PCONTEXT context);

private:
	TraceMe(){}
	static PVOID Handler;
	static volatile char inTrace;
	static void* breakPoint;
	
	static DWORD WINAPI traceMe(LPVOID myThread_);
	static LONG CALLBACK excpHdlr(
		PEXCEPTION_POINTERS excpInfo);
	static int readInt(char*& text);
	static bool testStr(const char* str, char*& text);
	static void memoryDump(PCONTEXT context);
};
