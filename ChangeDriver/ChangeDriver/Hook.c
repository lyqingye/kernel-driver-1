#include <Hook.h>

//ȫ�ֱ��� 
ULONG MemServiceTable = 0; 
ULONG FileServiceTable = 0;


//
//��ʼ��Hook���
//
PSSDT_HOOK_LIST_HEADER InitializaHook(PHOOK_VALUE phookValue)

{


	//
	//�������
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


	//�߼����
	if (phookValue->Clock)
	{
		if (phookValue->Cycle_ns == 0 || phookValue->CallBackProc == NULL)
		{
			return NULL;
		}
	}

	//�ж��Ƿ���Ҫ��ʼ������
	if (phookValue->pListHeader == NULL)
	{
		//��ʼ������
		phookValue->pListHeader = InitializaHookList();

	}



	//�ɵ�Proc
	ULONG OldProc = 0;
	
	//������������HOOK����
	PSSDT_HOOK_LIST_ENTRY InserListEntry;

	//�µ�HOOK����
	SSDT_HOOK_LIST_ENTRY NewListEntry ; 
	


	//��ȡOldProc�Ա�ָ�hook
	RtlCopyMemory(&OldProc, (PVOID)(MemServiceTable + phookValue->ServicesIndex * sizeof(ULONG)), sizeof(ULONG));

	//Hook������Ϣ����
	NewListEntry.hookProcIndex = phookValue->ServicesIndex;
	NewListEntry.NewProc = phookValue->NewProc;
	NewListEntry.OldProc = OldProc;
	NewListEntry.pNextEntry = NULL;


	//�����ݲ���ȫ��HOOK����
	InserListEntry = IncreaseHookList(phookValue->pListHeader, &NewListEntry);


	phookValue->pNewListEntry = InserListEntry;

	//�ж��Ƿ���Ҫʱ��
	if (phookValue->Clock)
	{
		//��ʼ��ʱ��
		DelayTimerInit((PDELAYCLOCK)InserListEntry->pDelayClock, phookValue->CallBackProc);
		DelaySetTimer((PDELAYCLOCK)InserListEntry->pDelayClock, phookValue->Cycle_ns, NULL);
	}
	else{
		//����Ҫʱ��
		EnableHook(phookValue->pNewListEntry);
	}

	return phookValue->pListHeader;
}



//
//����Hook
//

ULONG EnableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry)

{	
	
	//
	//�������
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
		//û�а�װHook���
		RstatusPrint(HK_STATUS_RESULT_ERROR);
		return 0;
	}

	//��������


	//��ʼ�� HOOK����
	DWORD32 NewProc = 0;
	DWORD32 HookPoint = 0;

	NewProc = pNewListEntry->NewProc;

	//Hook��ַ
	HookPoint = MemServiceTable + sizeof(ULONG)*pNewListEntry->hookProcIndex;

	//�ҹ�SSDT
	EnableWrite();
	RtlCopyMemory((PVOID)HookPoint, &NewProc, sizeof(ULONG));
	DisableWrite();


	return 1;
}

//
//�ָ�Hook
//
ULONG DisableHook(IN PSSDT_HOOK_LIST_ENTRY pNewListEntry, BOOLEAN IsOldProc, BOOLEAN IsClock)
{
	if (FileServiceTable == 0 || MemServiceTable == 0)
	{
		//û�а�װHook����
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
		//OldProcInvalid,��ԭԭʼ��ַ
		IsOldProc = FALSE;
	}

	//��ʼ���ָ��ҹ�����
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
		//����ʱ��
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

	if (MemServiceTable != 0 || FileServiceTable != 0)//�Ѿ�����ʼ��������˵����ǰ��û�б�ж��
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