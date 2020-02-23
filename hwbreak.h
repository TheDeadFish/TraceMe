#pragma once

void WINAPI hwbreak_setDbgReg(PCONTEXT ctx,  int regNo, int size, int mode, void* addr);
void WINAPI hwbreak_setDbgReg(int regNo, int size, int mode, void* addr);
void WINAPI hwbreak_setDbgReg(DWORD threadId, int regNo, int size, int mode, void* addr);

// helper function: setDbg_Break
static void WINAPI setDbg_Break(PCONTEXT ctx, int regNo, Void addr) {
	hwbreak_setDbgReg(ctx, regNo, 1, 0, addr); }
static void WINAPI setDbg_Break(int regNo, Void addr) {	
	hwbreak_setDbgReg(regNo, 1, 0, addr); }
static void WINAPI setDbg_Break(DWORD threadId, int regNo, Void addr) {	
	hwbreak_setDbgReg(threadId, regNo, 1, 0, addr); }
	
// helper function: setDbg_Write
static void WINAPI setDbg_Write(PCONTEXT ctx, int regNo, Void addr) {
	hwbreak_setDbgReg(ctx, regNo, 4, 0, addr); }
static void WINAPI setDbg_Write(int regNo, Void addr) {	
	hwbreak_setDbgReg(regNo, 4, 1, addr); }
static void WINAPI setDbg_Write(DWORD threadId, int regNo, Void addr) {	
	hwbreak_setDbgReg(threadId, regNo, 4, 1, addr); }
