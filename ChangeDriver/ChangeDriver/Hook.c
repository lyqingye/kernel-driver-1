#include <Hook.h>

//全局变量 
ULONG MemServiceTable = 0; 
ULONG FileServiceTable = 0;


//
//初始化Hook框架
//
PSSDT_HOOK_LIST_HEADER InitializaHook(PHOOK_VALUE phookValue)

{


	//
	//参数检查
	//

	if (!MmIsAddressValid((PVOID)MemServiceTable))
	{

		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return NULL;
	}
	if (!MmIsAddressValid((PVOID)FileServiceTable))
	{

		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return NULL;
	}


	if (!MmIsAddressValid(phookValue))
	{

		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return NULL;
	}


	if (!MmIsAddressValid((PVOID)phookValue->NewProc))
	{
		
		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return NULL;
	}
	if (!MmIsAddressValid(phookValue->CallBackProc))
	{

		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	if (phookValue->pListHeader)
	{
		if (!MmIsAddressValid(phookValue->pListHeader))
		{
			RstatusPrint(HK_STATUS_INVALID_PARAMETE);
			return NULL;
		}
	}


	//逻辑检查
	if (phookValue->Clock)
	{
		if (phookValue->Cycle_ns == 0 || phookValue->CallBackProc == NULL)
		{
			return NULL;
		}
	}

	//判断是否需要初始化链表
	if (phookValue->pListHeader == NULL)
	{
		//初始化链表
		phookValue->pListHeader = InitializaHookList();

	}



	//旧的Proc
	ULONG OldProc = 0;
	
	//插入链表后的新HOOK对象
	PSSDT_HOOK_LIST_ENTRY InserListEntry;

	//新的HOOK对象
	SSDT_HOOK_LIST_ENTRY NewListEntry ; 
	


	//获取OldProc以便恢复hook
	RtlCopyMemory(&OldProc, (PVOID)(MemServiceTable + phookValue->ServicesIndex * sizeof(ULONG)), sizeof(ULONG));

	//Hook对象信息设置
	NewListEntry.hookProcIndex = phookValue->ServicesIndex;
	NewListEntry.NewProc = phookValue->NewProc;
	NewListEntry.OldProc = OldProc;
	NewListEntry.pNextEntry = NULL;


	//将数据插入全局HOOK链表
	InserListEntry = IncreaseHookList(phookValue->pListHeader, &NewListEntry);


	phookValue->pNewListEntry = InserListEntry;

	//判断是否需要时钟
	if (phookValue->Clock)
	{
		//初始化时钟
		DelayTimerInit((PDELAYCLOCK)InserListEntry->pDelayClock, phookValue->CallBackProc);
		DelaySetTimer((PDELAYCLOCK)InserListEntry->pDelayClock, phookValue->Cycle_ns, NULL);
	}
	else{
		//不需要时钟
		EnableHook(phookValue->pNewListEntry);
	}

	return phookValue->pListHeader;
}



//
//设置Hook
//

ULONG EnableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry)

{	
	
	//
	//参数检查
	//
	if (!MmIsAddressValid(pNewListEntry))
	{
		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid((PVOID)pNewListEntry->NewProc))
	{
		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return 0;
	}
	

	if (MemServiceTable == 0)
	{
		//没有安装Hook框架
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	//遍历链表


	//初始化 HOOK数据
	DWORD32 NewProc = 0;
	DWORD32 HookPoint = 0;

	NewProc = pNewListEntry->NewProc;

	//Hook地址
	HookPoint = MemServiceTable + sizeof(ULONG)*pNewListEntry->hookProcIndex;

	//挂钩SSDT
	EnableWrite();
	RtlCopyMemory((PVOID)HookPoint, &NewProc, sizeof(ULONG));
	DisableWrite();


	return 1;
}

//
//恢复Hook
//
ULONG DisableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry, BOOLEAN IsOldProc, BOOLEAN IsClock)
{
	if (FileServiceTable == 0 || MemServiceTable == 0)
	{
		//没有安装Hook引擎
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;

	}

	if (!MmIsAddressValid(pNewListEntry))
	{
		
		RstatusPrint(HK_STATUS_INVALID_PARAMETE);
		return 0;

	}
	if (!MmIsAddressValid((PVOID)pNewListEntry->OldProc))
	{
		//OldProcInvalid,还原原始地址
		IsOldProc = FALSE;
	}

	//初始化恢复挂钩数据
	ULONG  SourseProc = 0;
	ULONG  RestorePoint = 0;
	ULONG  OldProc = 0;

	OldProc = pNewListEntry->OldProc;
	

	RtlCopyMemory(&SourseProc, (PVOID)(FileServiceTable + sizeof(ULONG)*pNewListEntry->hookProcIndex), sizeof(ULONG));

	RestorePoint = MemServiceTable + sizeof(ULONG)*pNewListEntry->hookProcIndex;


	if (!MmIsAddressValid((PVOID)RestorePoint))
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	if (IsClock)
	{
		//撤掉时钟
		DelayDestroyTimer((PDELAYCLOCK)pNewListEntry->pDelayClock);
	}

	if (IsOldProc)
	{
		EnableWrite();
		RtlCopyMemory((PVOID)RestorePoint, &OldProc, sizeof(DWORD32));
		DisableWrite();
	}

	if (IsOldProc)
	{
		EnableWrite();
		RtlCopyMemory((PVOID)RestorePoint, &SourseProc, sizeof(DWORD32));
		DisableWrite();
	}

	return 1;
	
}




ULONG InstallHookEngine()
{

	if (MemServiceTable != 0 || FileServiceTable != 0)//已经被初始化过，则说明以前的没有被卸载
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}


	SERVICETABLE tServiceTable = { 0 };
	PSYSTEM_SERVICE_TABLE tpServiceTable = NULL;

	ULONG Value = 0;



	Value = NtEnumeServiceTable(&tServiceTable);


	if (Value == 0)
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	if (!MmIsAddressValid(tServiceTable.FileServiceTable))
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	if (!MmIsAddressValid(tServiceTable.MemServiceTable))
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}


	FileServiceTable = (ULONG)tServiceTable.FileServiceTable;
	

	Value = NtGetServiceDescriptor();

	if (Value == 0)
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	if (!MmIsAddressValid((PVOID)Value))
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	tpServiceTable = (PSYSTEM_SERVICE_TABLE)Value;

	MemServiceTable = (ULONG)tpServiceTable->ServiceTableBase;

	if (!MmIsAddressValid((PVOID)MemServiceTable))
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	ReleaseAnsiList(tServiceTable.NameList);
	ExFreePoolWithTag(tServiceTable.MemServiceTable, 1024);

	return 1;
	
}

ULONG UnInstallHookEngine()
{
	

	if (MemServiceTable == 0 || FileServiceTable == 0)
	{
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}
	

	ExFreePoolWithTag((PVOID)FileServiceTable, 1024);

	return 1;
}