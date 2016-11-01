#define _WIN32_WINNT 0x0500
#include "traceMe.h"
#include <conio.h>
#include <udis86.h>

bool TraceMe::inTrace = false;
bool TraceMe::pastBreak;
void* TraceMe::breakPoint;
void (*TraceMe::callBack)
	(PVOID excpAddr, PCONTEXT context) = &TraceMe::DefCB;

void TraceMe::Begin_(void* breakPoint)
{
	// setup breakpoint
	pastBreak = true;
	if(breakPoint != 0)
	{
		pastBreak = false;
		TraceMe::breakPoint = breakPoint;
	}

	// enable trace bit
	if(!inTrace)
	{
		inTrace = true;
		traceMe(0);
	}
}

void TraceMe::End(void)
{
	if(inTrace)
	{
		inTrace = false;
		RemoveVectoredExceptionHandler((PVOID)excpHdlr);
	}
}

void TraceMe::DefCB(PVOID excpAddr, PCONTEXT context)
{
	// Display dissasembly
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	ud_set_input_buffer(&ud_obj, (uint8_t*)excpAddr, 32);
	ud_set_pc(&ud_obj, (uint64_t)excpAddr);
	ud_disassemble(&ud_obj);
	char* asmText = ud_insn_asm(&ud_obj);
	_cprintf("%8X: %s\n", excpAddr, asmText);
	
USER_INPUT:
	switch(getch())
	{
	case ' ':
		// Register dump
		_cprintf("\teax:%08X ebx:%08X ecx:%08X edx:%08X\n"
				"\tesi:%08X esi:%08X ebp:%08X esp:%08X\n",
				context->Eax, context->Ebx, context->Ecx, context->Edx,
				context->Esi, context->Edi, context->Ebp, context->Esp
		);
		goto USER_INPUT;
		
	case 27:
		// Continue
		TraceMe::End();
		break;
	case 8:
		// Step over
		if(strncmp(asmText, "call", 4) == 0)
			TraceMe::Begin((char*)(excpAddr) + ud_insn_len(&ud_obj));
		break;
	}
}

DWORD WINAPI TraceMe::traceMe(LPVOID myThread_)
{
	HANDLE myThread = (HANDLE)myThread_;
	if(myThread == 0)
	{
		// Setup trace handler
		if(AddVectoredExceptionHandler(1, &excpHdlr) == 0)
			goto FATAL_ERROR;
	
		// Open thine thread
		myThread = OpenThread(THREAD_ALL_ACCESS, 0,
			GetCurrentThreadId());
		if(myThread == 0)
			goto FATAL_ERROR;
	
		// Create the thread
		HANDLE theThread = CreateThread(
			0, 0, &traceMe, myThread, 0, 0);
		if(theThread == 0)
			goto FATAL_ERROR;
		
		// Let thread do its stuff
		WaitForSingleObject(theThread, INFINITE);
		CloseHandle(theThread);
		CloseHandle(myThread);
		return 0;
	}
	else
	{
		// set the trace bit
		CONTEXT context;
		context.ContextFlags = CONTEXT_CONTROL;
		if(SuspendThread(myThread) < 0)
			goto FATAL_ERROR;
		if(GetThreadContext(myThread, &context) == 0)
			goto FATAL_ERROR;
		context.EFlags |= 0x100;
		if(SetThreadContext(myThread, &context) == 0)
			goto FATAL_ERROR;
		if(ResumeThread(myThread) < 0)
			goto FATAL_ERROR;	
		return 0;
	}
	
FATAL_ERROR:
	MessageBox(NULL, "TraceMe:Error", "TraceMe:Error", MB_OK);
	ExitProcess(-1);
}

LONG CALLBACK TraceMe::excpHdlr(PEXCEPTION_POINTERS excpInfo)
{
	// Find a reason to return
	if(excpInfo->ExceptionRecord->ExceptionCode
	!= EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;
	if(!inTrace)
		return EXCEPTION_CONTINUE_EXECUTION;
	
	if(!pastBreak)
	{
		if(excpInfo->ExceptionRecord->ExceptionAddress ==
			breakPoint)
		pastBreak = true;
	}
	if(pastBreak)
	{
		callBack(excpInfo->ExceptionRecord->ExceptionAddress,
			excpInfo->ContextRecord);
	}
	if(inTrace)
		excpInfo->ContextRecord->EFlags |= 0x100;
	return EXCEPTION_CONTINUE_EXECUTION;
}
