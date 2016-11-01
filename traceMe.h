// TraceMe V1.41, 01/11/2016
// DeadFish Shitware

#include <windows.h>

class TraceMe
{
public:
	template <class T> static void Begin(T 
		breakPoint) { Begin((void*)breakPoint); }
	static void Begin(void* breakPoint = 0);
	static void End(void);
	static PVOID DefCB(PVOID excpAddr, PCONTEXT context);
	static PVOID (*callBack)(
		PVOID excpAddr, PCONTEXT context);

private:
	TraceMe(){}
	static volatile PVOID Handler;
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
