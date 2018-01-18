#include "SSDT.h"

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	_disable();											//屏蔽中断
	cr0 = __readcr0();									//读取cr0
	cr0 &= 0xfffffffffffeffff;							//对页写入保护位进行清零
	__writecr0(cr0);									//写入cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//读取cr0
	cr0 |= 0x10000;										//还原页保护位
	__writecr0(cr0);									//写入cr0
	_enable();											//允许接收中断请求
}

ULONG_PTR GetSsdtBase()
{
	ULONG_PTR SystemCall64;								//从msr中读取到的SystemCall64的地址
	ULONG_PTR StartAddress;								//搜寻的起始地址就是SystemCall64的起始地址
	ULONG_PTR EndAddress;								//搜寻的终结地址
	UCHAR *p;											//用来判断的特征码
	ULONG_PTR SsdtBast;									//SSDT基址

	SystemCall64 = __readmsr(0xC0000082);
	StartAddress = SystemCall64;
	EndAddress = StartAddress + 0x500;
	while (StartAddress < EndAddress)
	{
		p = (UCHAR*)StartAddress;
		if (MmIsAddressValid(p) && MmIsAddressValid(p + 1) && MmIsAddressValid(p + 2))
		{
			if (*p == 0x4c && *(p + 1) == 0x8d && *(p + 2) == 0x15)
			{
				SsdtBast = (ULONG_PTR)(*(ULONG*)(p + 3)) + (ULONG_PTR)(p + 7);
				break;
			}
		}
		++StartAddress;
	}

	return SsdtBast;
}

ULONG_PTR GetFuncAddress(PWSTR FuncName)
{
	UNICODE_STRING uFunctionName;
	RtlInitUnicodeString(&uFunctionName, FuncName);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&uFunctionName);
}

VOID HookKeBugCheckEx()
{
	ULONG_PTR KeBugCheckExAddress;

	KeBugCheckExAddress = GetFuncAddress(L"KeBugCheckEx");

	*(ULONG_PTR*)(jmp_code + 2) = (ULONG_PTR)MyNtTerminateProcess;

	PageProtectOff();

	RtlCopyMemory(old_code, (PVOID)KeBugCheckExAddress, sizeof(old_code));					//保存原本的十二个值

	RtlCopyMemory((PVOID)KeBugCheckExAddress, jmp_code, sizeof(jmp_code));					//替换新的值过去

	PageProtectOn();
}

VOID UnHookKeBugCheckEx()
{
	ULONG_PTR KeBugCheckExAddress;

	KeBugCheckExAddress = GetFuncAddress(L"KeBugCheckEx");

	PageProtectOff();

	RtlCopyMemory((PVOID)KeBugCheckExAddress, old_code, sizeof(old_code));					//替换新的值过去

	PageProtectOn();
}

VOID StartHook()
{
	PSYSTEM_SERVICE_TABLE SsdtInfo;

	ULONG_PTR KeBugCheckExAddress;

	ULONG Offset;

	SsdtInfo = (PSYSTEM_SERVICE_TABLE)GetSsdtBase();

	old_ValueOnNtTerminateProcess = SsdtInfo->ServiceTableBase[IndexOfNtTerminateProcess];

	old_NtTerminateProcess = (ULONG_PTR)(old_ValueOnNtTerminateProcess >> 4) + (ULONG_PTR)SsdtInfo->ServiceTableBase;

	//KdPrint(("old_ValueOnNtTerminateProcess = %x\n", old_ValueOnNtTerminateProcess));
	//KdPrint(("old_NtTerminateProcess = %llx\n", old_NtTerminateProcess));

	HookKeBugCheckEx();

	KeBugCheckExAddress = GetFuncAddress(L"KeBugCheckEx");

	//KdPrint(("KeBugCheckEx = %llx\n", KeBugCheckExAddress));

	Offset = (ULONG)(KeBugCheckExAddress - (ULONG_PTR)SsdtInfo->ServiceTableBase);

	Offset = Offset << 4;

	PageProtectOff();

	SsdtInfo->ServiceTableBase[IndexOfNtTerminateProcess] = Offset;

	PageProtectOn();
}

VOID StopHook()
{
	PSYSTEM_SERVICE_TABLE SsdtInfo;

	SsdtInfo = (PSYSTEM_SERVICE_TABLE)GetSsdtBase();

	PageProtectOff();

	SsdtInfo->ServiceTableBase[IndexOfNtTerminateProcess] = old_ValueOnNtTerminateProcess;

	PageProtectOn();

	UnHookKeBugCheckEx();
}

NTSTATUS __fastcall MyNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	PEPROCESS CurrentProcess;

	NTSTATUS status;

	BOOLEAN Flag;							//标志位，如果是TRUE代表需要对句柄进行解除引用，否则不需要

	if (ProcessHandle != NULL)
	{
		status = ObReferenceObjectByHandle(
			ProcessHandle,
			0,
			*PsProcessType,
			KernelMode,
			&CurrentProcess,
			NULL);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("获取进程对象失败！status = %x\n", status));
			return STATUS_UNSUCCESSFUL;
		}
		Flag = TRUE;
	}
	else
	{
		Flag = FALSE;
		CurrentProcess = PsGetCurrentProcess();
	}
	KdPrint(("将要关闭的进程的名字是：%s\n", PsGetProcessImageFileName(CurrentProcess)));

	if (strstr(PsGetProcessImageFileName(CurrentProcess), "calc"))
	{
		KdPrint(("拒绝关闭计算器！\n"));

		if (Flag)
			ObDereferenceObject(CurrentProcess);

		return STATUS_ACCESS_DENIED;
	}

	if (Flag)
		ObDereferenceObject(CurrentProcess);

	return ((NTTERMINATEPROCESS)(old_NtTerminateProcess))(ProcessHandle, ExitStatus);
}

/*NTSTATUS __fastcall MyNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	PEPROCESS CurrentProcess;

	NTSTATUS status;

	BOOLEAN Flag;							//标志位，如果是TRUE代表需要对句柄进行解除引用，否则不需要

	status = ObReferenceObjectByHandle(
		ProcessHandle,
		0,
		*PsProcessType,
		KernelMode,
		&CurrentProcess,
		NULL);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("获取进程对象失败！status = %x\n", status));
		return STATUS_ACCESS_DENIED;
	}
	Flag = TRUE;

	KdPrint(("将要关闭的进程的名字是：%s\n", PsGetProcessImageFileName(CurrentProcess)));

	if (strstr(PsGetProcessImageFileName(CurrentProcess), "calc"))
	{
		KdPrint(("拒绝关闭计算器！\n"));

		if (Flag)
			ObDereferenceObject(CurrentProcess);

		return STATUS_ACCESS_DENIED;
	}

	if (Flag)
		ObDereferenceObject(CurrentProcess);

	return ((NTTERMINATEPROCESS)(old_NtTerminateProcess))(ProcessHandle, ExitStatus);
}*/

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));

	StopHook();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	StartHook();
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}