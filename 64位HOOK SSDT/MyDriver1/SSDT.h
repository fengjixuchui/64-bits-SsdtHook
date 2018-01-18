#pragma once
#ifndef SSDTHOOK_H
#define SSDTHOOK_H
#include <ntddk.h>

#define IndexOfNtTerminateProcess 41

typedef struct _SYSTEM_SERVICE_TABLE
{
	PUINT32 ServiceTableBase;
	PUINT32 ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

extern UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

extern unsigned __int64 __readmsr(int register);				//读取msr寄存器

extern unsigned __int64 __readcr0(void);			//读取cr0的值

extern void __writecr0(unsigned __int64 Data);		//写入cr0

extern void __debugbreak();							//断点，类似int 3

extern void _disable(void);							//屏蔽中断

extern void _enable(void);							//允许中断

VOID PageProtectOff();

VOID PageProtectOn();

ULONG_PTR GetSsdtBase();							//获取SSDT基址

ULONG_PTR GetFuncAddress(PWSTR FuncName);			//根据函数名字获取函数地址（必须是ntoskrnl导出的）

VOID UnHookKeBugCheckEx();

VOID HookKeBugCheckEx();

VOID StartHook();									//开始SSDT HOOK

VOID StopHook();									//关闭SSDT HOOK

typedef NTSTATUS(__fastcall *NTTERMINATEPROCESS)(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

NTSTATUS __fastcall MyNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

ULONG_PTR old_NtTerminateProcess;

ULONG old_ValueOnNtTerminateProcess;

//\x48\xB8+8字节代表mov rax,*****  \xFF\xE0代表着jmp rax跨模块跳转
UCHAR jmp_code[12] = { '\x48','\xB8','\xFF','\xFF','\xFF','\xFF','\xFF','\xFF','\xFF','\xFF','\xFF','\xE0' };	
UCHAR old_code[12];
#endif

