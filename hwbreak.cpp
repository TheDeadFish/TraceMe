#include <stdshit.h>
#include "hwbreak.h"

struct selfCtxEdit_ctx {
	HANDLE myThread; 
	Delegate<bool,PCONTEXT> cb; };

static
DWORD WINAPI selfCtxEdit_thread(selfCtxEdit_ctx* ctx)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
	if(SuspendThread(ctx->myThread) < 0) fatalError("tracMe3");
	if(!GetThreadContext(ctx->myThread, &context)) fatalError("tracMe4");
	if(!ctx->cb(&context)) fatalError("tracMe");
	if(!SetThreadContext(ctx->myThread, &context)) fatalError("tracMe5");
	if(ResumeThread(ctx->myThread) < 0) fatalError("tracMe6");
	return 0;	
}

static
void selfCtxEdit(Delegate<bool,PCONTEXT> cb)
{
	// Open thine thread
	HANDLE myThread = OpenThread(THREAD_ALL_ACCESS,
		0, GetCurrentThreadId());
	if(!myThread) fatalError("tracMe1");
	selfCtxEdit_ctx ctx = {myThread, cb};
	HANDLE theThread = CreateThread(0, 0, 
		Void(&selfCtxEdit_thread), &ctx, 0, 0);
	if(!theThread) fatalError("tracMe2");
	
	// Let thread do its stuff
	WaitForSingleObject(theThread, INFINITE);
	CloseHandle(theThread);
	CloseHandle(myThread);
}

static
void threadCtxEdit(DWORD threadId, 
	Delegate<bool,PCONTEXT> cb)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, threadId);
	if(!hThread) fatalError("hwbreak1");
	selfCtxEdit_ctx ctx = {hThread, cb};
	selfCtxEdit_thread(&ctx);
	CloseHandle(hThread);
}

void WINAPI hwbreak_setDbgReg(PCONTEXT ctx,  int regNo, 
	int size, int mode, void* addr)
{
	(&ctx->Dr0)[regNo] = (size_t)addr;
	ctx->Dr7 &= ~(3 << regNo*2);
	ctx->Dr7 &= ~(0xFF0000 << regNo*4);
	
	if(addr) {
		ctx->Dr7 |= (1 << regNo*2);
		ctx->Dr7 |= mode << (16+regNo*4);
		ctx->Dr7 |= (size-1) << (18+regNo*4);
	}
}

// helper function: setDbgReg, calling thread
struct setDbg_Break_ctx { int regNo, size, mode; Void addr; };
static
bool WINAPI setDbg_Break_cb(setDbg_Break_ctx* cbCtx, PCONTEXT ctx) {
	hwbreak_setDbgReg(ctx, cbCtx->regNo, cbCtx->size, 
	cbCtx->mode, cbCtx->addr); return true; }
void WINAPI hwbreak_setDbgReg(int regNo, int size, int mode, void* addr) {
	setDbg_Break_ctx ctx = {regNo, size, mode, addr};
	selfCtxEdit(MakeDelegate(&ctx, setDbg_Break_cb)); }
void WINAPI hwbreak_setDbgReg(DWORD threadId, int regNo, int size, int mode, void* addr) {
	setDbg_Break_ctx ctx = {regNo, size, mode, addr};
	threadCtxEdit(threadId, MakeDelegate(&ctx, setDbg_Break_cb)); }


