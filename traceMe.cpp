// TraceMe V1.41, 01/11/2016
// DeadFish Shitware

#define _WIN32_WINNT 0x0501
#include "traceme.h"
#include <conio.h>
#include <udis86.h>

volatile PVOID TraceMe::Handler = NULL;
volatile char TraceMe::inTrace = false;
void* TraceMe::breakPoint;
void* TraceMe::breakPointPrev;
PVOID (*TraceMe::callBack)
	(PVOID excpAddr, PCONTEXT context) = &TraceMe::DefCB;

void TraceMe::Begin(void* breakPoint)
{
	if(breakPoint == 0)
		breakPoint = __builtin_return_address(0);
	TraceMe::breakPoint = breakPoint;
	TraceMe::traceMe(0);
}

void TraceMe::End(void)
{
	PVOID oldHandler = __sync_lock_test_and_set(&Handler, 0);
	if(oldHandler) RemoveVectoredExceptionHandler(oldHandler);
}

int TraceMe::readInt(char*& text)
{
	// try decimal
	int result, len;
	if(sscanf(text, "%u%n", &result, &len) == 0)
	{
		_cprintf("\tbad number: %s\n", text);
		return -1;
	}
	if(strspn(text+len, "ABCDEFXH") == 0)
	{
		text += len;
		return result;
	}
	
	// probably hex
	if(text[len] == 'X')
		text += len+1;
	sscanf(text, "%x%n", &result, &len);
	if(text[len] == 'H')
		len++;
	text += len;
	return result;
}

bool TraceMe::testStr(const char* str, char*& text)
{
	int len = strlen(str);
	if(strncmp(str, text, len) != 0)
		return false;
	text += len;
	return true;
}

void TraceMe::memoryDump(PCONTEXT context)
{
	// get the argument
	_cprintf("Enter Addr expression: ");
	char arg[100] = { 100 };
	_cgets(arg);
	for(int i = 0; arg[i]; i++)
		arg[i] = toupper(arg[i]);
	char* text = arg+2;
		
	// get type
	char type = 4; // default int
	if(testStr("ADDR", text))		 	type = 'a';
	else if(testStr("INT", text))	 	type = 4;
	else if(testStr("BYTE", text))	 	type = 1;
	else if(testStr("DOUBLE", text)) 	type = 8;

	// get length
	int len = 1; // default 1
	if((text > arg+2) && (text[0] == '['))
	{
		if((type != 4) && (type != 1))
		{
			_cprintf("array for byte,int only\n");
			return;
		}
		text += 1;
		len = readInt(text);
		if(len < 0) return;
		text += 1;
	}
	
	// get address
	int address = 0;
	bool subMode;
	while(text[0] != 0)
	{	
		char ch = *text++;
		switch(ch)
		{
		case '-':
			subMode = true;
		case '+':
			subMode = false;
		case ' ':
			continue;
		default:
			text--;
		}
			
		// check for reg argment
		int offset;
		for(int i = 0; i < 11; i++)
		{
			const char* const regs[] = {
				"EDI", "ESI", "EBX", "EDX",	"ECX",
				"EAX", "EBP","EIP", "CS", "EF", "ESP" };
			if(testStr(regs[i], text))
			{
				offset = ((int*)&context->Edi)[i];
				goto WAS_REGISTER;
			}
		}
		
		// probaly number
		offset = readInt(text);
		if(offset < 0) return;
WAS_REGISTER:
		address += subMode ?
			-offset : offset;
	}
	
	// display address
	if(type == 'a')
	{
		_cprintf("\tAddress: %X\n", address);
		return;
	}
	if(IsBadReadPtr((PVOID)address, len*type ))
	{
		_cprintf("\tInvalid Address Range: %X, %X\n",
			address, address+len*type);
		return;
	}
	if( type == 'd' )
	{
		_cprintf("\tDouble @ %X: %g\n", address, *(double*)address);
		return;
	}
	
	while(len > 0)
	{
		_cprintf("    %08X: ", address);
		int count = len;
		if(type == 1)
		{
			if(count > 16)
				count = 16;
			len -= count;
			while(count--)
			{
				_cprintf("%02X ", *(BYTE*)address);
				address += 1;
			}
		}
		else
		{
			if(count > 4)
				count = 4;
			len -= count;
			while(count--)
			{
				_cprintf("%08X ", *(DWORD*)address);
				address += 4;
			}
		}
		_cprintf("\n");
	}
}

PVOID TraceMe::DefCB(PVOID excpAddr, PCONTEXT context)
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
		_cprintf("    eax:%08X ebx:%08X ecx:%08X edx:%08X\n"
				"    esi:%08X esi:%08X ebp:%08X esp:%08X\n",
				context->Eax, context->Ebx, context->Ecx, context->Edx,
				context->Esi, context->Edi, context->Ebp, context->Esp
		);
		goto USER_INPUT;

	case 'f':
		// Floating point dump
		_cprintf("    fp0:%-13g fp1:%-13g fp2:%-13g fp3:%-13g\n"
				"    fp4:%-13g fp5:%-13g fp6:%-13g fp7:%-13g\n",
				(double)((long double*)context->FloatSave.RegisterArea)[0],
				(double)((long double*)context->FloatSave.RegisterArea)[1],
				(double)((long double*)context->FloatSave.RegisterArea)[2],
				(double)((long double*)context->FloatSave.RegisterArea)[3],
				(double)((long double*)context->FloatSave.RegisterArea)[4],
				(double)((long double*)context->FloatSave.RegisterArea)[5],
				(double)((long double*)context->FloatSave.RegisterArea)[6],
				(double)((long double*)context->FloatSave.RegisterArea)[7]);
		goto USER_INPUT;
		
	case 'd':
		// Memory dump
		TraceMe::memoryDump(context);
		goto USER_INPUT;
	
	case 13:
		// Continue
		return breakPointPrev;
	
	case 27:
		// End trace
		TraceMe::End();
		break;
	case 8:
		// Step over
		if(strncmp(asmText, "call", 4) == 0)
			TraceMe::Begin((char*)(excpAddr) + ud_insn_len(&ud_obj));
		break;
	}
	return NULL;
}

DWORD WINAPI TraceMe::traceMe(LPVOID myThread_)
{
	HANDLE myThread = (HANDLE)myThread_;
	if(myThread == 0)
	{
		// Setup trace handler
		if(Handler != NULL)
			return 0;
		Handler = AddVectoredExceptionHandler(1, &excpHdlr);
		if(Handler == NULL)
			goto FATAL_ERROR;
		if(inTrace) 
			return 0;
	
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
	if((excpInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
	||(excpInfo->ContextRecord->Dr6 & 15))
		return EXCEPTION_CONTINUE_SEARCH;
	if(!Handler)
		return EXCEPTION_CONTINUE_EXECUTION;

	// Execute stepping handler
	if((breakPoint == NULL)
	||( breakPoint == excpInfo->ExceptionRecord->ExceptionAddress))
	{
		if(breakPoint) breakPointPrev = breakPoint;	inTrace = true;
		breakPoint = callBack(excpInfo->ExceptionRecord->ExceptionAddress,
			excpInfo->ContextRecord); inTrace = false;
	}
	if(Handler)
		excpInfo->ContextRecord->EFlags |= 0x100;
	return EXCEPTION_CONTINUE_EXECUTION;
}
