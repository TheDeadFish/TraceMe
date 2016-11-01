// TraceMe V1.30, 14/03/2014
// DeadFish Shitware

#include <windows.h>
#include "stdshit.h"

class TraceMe
{
public:
	static void Begin(PCONTEXT context);
	static void Begin(Void breakPoint = 0);
	static void End(void);
	static PVOID DefCB(PVOID excpAddr, PCONTEXT context);
	static PVOID (*callBack)(
		PVOID excpAddr, PCONTEXT context);

private:
	TraceMe(){}
	static PVOID Handler;
	static volatile char inTrace;
	static void* breakPoint;
	static void* breakPointPrev;
	
	static DWORD WINAPI traceMe(LPVOID myThread_);
	static LONG CALLBACK excpHdlr(
		PEXCEPTION_POINTERS excpInfo);
	static int readInt(char*& text);
	static bool testStr(const char* str, char*& text);
	static void memoryDump(PCONTEXT context);
};
