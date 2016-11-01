// Minimal Win32 Tracing
#include <windows.h>

class TraceMe
{
public:
	template <class T>
	static void Begin(T breakPoint);
	static void Begin_(void* breakPoint);
	static void End(void);
	static void DefCB(PVOID excpAddr, PCONTEXT context);
	static void (*callBack)(
		PVOID excpAddr, PCONTEXT context);

private:
	TraceMe(){}
	static bool inTrace;
	static bool pastBreak;
	static void* breakPoint;
	static DWORD WINAPI traceMe(LPVOID myThread_);
	static LONG CALLBACK excpHdlr(
		PEXCEPTION_POINTERS excpInfo);
};

template <class T>
void TraceMe::Begin(T breakPoint)
{
	Begin_((void*)breakPoint);
}
