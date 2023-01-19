#include <DataOperation.h>


//
//�����ڴ���Ansi�ַ�������
//

ULONG DPeAnsiStrlen(PVOID pStr)
{
	//
	//�������
	//
	if (!MmIsAddressValid(pStr))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}


	ULONG result = 0;

	_asm{
		pushad
			lea eax, pStr
			mov eax, dword ptr[eax] //��ȡstrָ��ĵ�ַ
			mov ebx, eax  //����һ��

			xor ecx, ecx //ecx��Ϊ��������0 ��ʼ 

		Loopstar :

		mov eax, ebx //ԭʼ��ַ��eax ����Ϊ eax�ᱻ����Ĵ����޸�
			add eax, ecx //���ֽ�ָ��
			mov al, byte ptr[eax] //���ֽ�Ϊ��λȡ
			cmp al, 0x00 //�ж��Ƿ��ַ�β
			je LoopEnd  //��������β
			inc ecx		//�ֽڵ���
			jmp Loopstar

		LoopEnd :
		lea eax, result
			mov dword ptr[eax], ecx
			popad
	}
	return result;
}
//
//ȡָ���ַ
//

ULONG DPeTakeOutPoint(PVOID Point)
{
	ULONG result = 0;

	if (!Point)
	{
		DbgPrint("Invalide Point\n");
		return 0;
	}

	_asm{

		pushad
			lea eax, Point
			mov eax, dword ptr[eax]
			lea ebx, result
			mov dword ptr[ebx], eax
			popad
	}
	return result;
}

//
//��ʼ������ͷ
//

PANSI_STRING_LIST_HEADER InitializaAnsiList()
{
	
	//Ϊ��������������ͷ�ڴ�

	PANSI_STRING_LIST_HEADER NewListHead = NULL;

	//�����ڴ�
	NewListHead = (PANSI_STRING_LIST_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(ANSI_STRING_LIST_HEADER), 1024);

	//������
	if (NewListHead == NULL)
	{
		return NULL;
	}

	//�ڴ���0
	RtlZeroMemory((PVOID)NewListHead, sizeof(ANSI_STRING_LIST_HEADER));

	//�����³�Ա����
	NewListHead->NumberOfMerber = 0;
	NewListHead->pNextEntry = NULL;

	//����������ͷ
	return NewListHead;
}

//
//������β���ӳ�Ա
//

PANSI_STRING_LIST_ENTRY  IncreaseAnsiList(PANSI_STRING_LIST_HEADER pListHead,PANSI_STRING pData)
{

	//
	//�������
	//
	if (!MmIsAddressValid(pListHead))
	{
		
		return NULL;
	}
	if (!MmIsAddressValid(pData))
	{

		return NULL;
	}


	//Ϊ�³�Ա����ռ��ַ

	PANSI_STRING_LIST_ENTRY  NewListEntry = NULL;

	//�����ڴ�ռ�
	NewListEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(ANSI_STRING_LIST_ENTRY)+pData->MaximumLength, 1024);

	//�������
	if (NewListEntry == NULL)
	{
		return NULL;
	}


	//�ڴ���0
	RtlZeroMemory((PVOID)NewListEntry, sizeof(ANSI_STRING_LIST_ENTRY)+pData->MaximumLength);


	//����³�Ա

	NewListEntry->pNext_Entry = NULL;
	NewListEntry->Datainfo.Buffer = (PVOID)(DPeTakeOutPoint((PVOID)NewListEntry) + sizeof(ANSI_STRING_LIST_ENTRY));
	NewListEntry->Datainfo.Length = pData->Length;
	NewListEntry->Datainfo.MaximumLength = pData->MaximumLength;

	//��������

	RtlCopyMemory((PVOID)NewListEntry->Datainfo.Buffer, pData->Buffer, pData->MaximumLength);

	//��������ȷ��Ҫ�����λ�� 
	if (pListHead->NumberOfMerber == 0) //Ϊ�״β���,Ϊ������Դ�����ж�
	{

		//��������ָ��

		pListHead->NumberOfMerber++;
		pListHead->pNextEntry = NewListEntry;

		//��������
		return NewListEntry;

	}
	else{ //˵�������״β�����Ҫ����
		
		PANSI_STRING_LIST_ENTRY LastListEntry = pListHead->pNextEntry;
		
		for (ULONG tIndex = 0; tIndex < pListHead->NumberOfMerber; tIndex++)
		{
			if (LastListEntry->pNext_Entry == NULL) //�ҵ�����β
			{

				break;
			}

			else{ //�����������
				if (LastListEntry == NULL)
				{
					return NULL;
				}

				LastListEntry = LastListEntry->pNext_Entry;
				
			}
		}

		//��������ָ��
		pListHead->NumberOfMerber++;
		LastListEntry->pNext_Entry = NewListEntry;

		//��������
		return NewListEntry;
	}

		
}

//
//�ͷ�����ͷ����Ա��������
//

PANSI_STRING_LIST_ENTRY ReleaseAnsiList(PANSI_STRING_LIST_HEADER  pListHead)
{

	//
	//�������
	//
	if (!MmIsAddressValid(pListHead))
	{

		return NULL;
	}


	if (pListHead->NumberOfMerber == 0)//û��������Ա�ͷ�����ͷ����
	{
		//�����ڴ�
		RtlZeroMemory(pListHead, sizeof(ANSI_STRING_LIST_HEADER));

		//�ͷ��ڴ�
		ExFreePoolWithTag(pListHead, 1024);

		//����
		return (ANSI_STRING_LIST_ENTRY*)pListHead;
	}


	//��ȡLIST_ENTRY ����Ϳ��԰�����ͷ�ͷŵ�

	PANSI_STRING_LIST_ENTRY  Free_List_Entry = NULL;
	PANSI_STRING_LIST_ENTRY  Load_List_Entry = NULL;

	//�����Ա��
	ULONG NumberOfMerber = 0;

	//��ȡ��������,Ȼ��Ϳ����ͷ�����ͷ
	Free_List_Entry = pListHead->pNextEntry;

	//��ȡ�����Ա��
	NumberOfMerber = pListHead->NumberOfMerber;


	//�ͷ�����ͷ

	RtlZeroMemory(pListHead, sizeof(ANSI_STRING_LIST_HEADER));

	ExFreePoolWithTag(pListHead, 1024);
	

	//��ʼѭ���ͷ�����

	for (ULONG t_index = 0; NumberOfMerber; t_index++)

	{
		//�ж��Ƿ�Ϊβ��
		if (Free_List_Entry->pNext_Entry == NULL)
		{
			//���������ڴ�
			RtlZeroMemory(Free_List_Entry, sizeof(ANSI_STRING_LIST_ENTRY)+Free_List_Entry->Datainfo.MaximumLength);

			//�ͷ��ڴ�
			ExFreePoolWithTag(Free_List_Entry, 1024);

			//��������
			return Free_List_Entry;
		}

		//��ȡ��һ��List_Entry Ȼ�����һ�����ͷ�
		Load_List_Entry = Free_List_Entry->pNext_Entry;


		//�ͷŵ���һ��List_Entry
		RtlZeroMemory(Free_List_Entry, sizeof(ANSI_STRING_LIST_ENTRY)+Free_List_Entry->Datainfo.MaximumLength);
		ExFreePoolWithTag(Free_List_Entry, 1024);


		//����
		Free_List_Entry = Load_List_Entry;

	}

	//��������
	return Free_List_Entry;
}

//
//��ʼ������
//
PSSDT_HOOK_LIST_HEADER InitializaHookList()
{
	SSDT_HOOK_LIST_HEADER * NewListHeader = (SSDT_HOOK_LIST_HEADER*)ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDT_HOOK_LIST_HEADER), 1024);
	if (NewListHeader == NULL)
	{
		return NULL;
	}

	RtlZeroMemory((PVOID)NewListHeader, sizeof(SSDT_HOOK_LIST_HEADER));
	NewListHeader->NumberOfMerber = 0;
	NewListHeader->pNextEntry = NULL;
	return NewListHeader;
}

//
//�����Ա
//

PSSDT_HOOK_LIST_ENTRY IncreaseHookList(PSSDT_HOOK_LIST_HEADER pListHeader, PSSDT_HOOK_LIST_ENTRY pData)
{
	//Ϊ�³�Ա����ռ�
	SSDT_HOOK_LIST_ENTRY *NewListEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDT_HOOK_LIST_ENTRY), 1024);
	if (NewListEntry == NULL)
	{
		return NULL;
	}
	RtlZeroMemory((PVOID)NewListEntry, sizeof(SSDT_HOOK_LIST_ENTRY));

	//����³�Ա����
	if (pData == NULL)
	{
		return NULL;
	}

	RtlCopyMemory(NewListEntry, pData, sizeof(SSDT_HOOK_LIST_ENTRY));

	//��ʼ���³�Ա����ָ��
	NewListEntry->pNextEntry = NULL;
	NewListEntry->pDelayClock = DPeTakeOutPoint((PVOID)NewListEntry) + sizeof(PVOID);
	
	//����ȫ������
	if ((pListHeader->latelyListEntry == NULL && pListHeader->NumberOfMerber != 0) || (pListHeader->latelyListEntry != NULL && pListHeader->NumberOfMerber == 0))
	{
		return NULL; //�������ݱ��ƻ�
	}

	SSDT_HOOK_LIST_ENTRY * latelyListEntry = pListHeader->latelyListEntry;

	if (latelyListEntry == NULL)
	{
		//�״μ��룬������������ͷ����

		//��������ͷ

		pListHeader->latelyListEntry = NewListEntry;
		pListHeader->pNextEntry = NewListEntry;
		pListHeader->NumberOfMerber++;
	}
	else{
		//�����״μ���
		if (latelyListEntry->pNextEntry != NULL)
		{
			return NULL; // �Ƿ�����
		}

		//��������
		latelyListEntry->pNextEntry = NewListEntry;
		pListHeader->latelyListEntry = NewListEntry;
		pListHeader->NumberOfMerber++;
	}

	return NewListEntry;

}

//
//�ͷ�����
//

PSSDT_HOOK_LIST_ENTRY ReleaseHookList(PSSDT_HOOK_LIST_HEADER  pListHeader)
{
	if (pListHeader == NULL)
	{
		return NULL;
	}
	
	if (pListHeader->NumberOfMerber == 0)
	{
		//ֻ������ͷ �޳�Ա
		ExFreePoolWithTag((PVOID)pListHeader, 1024);
		return (SSDT_HOOK_LIST_ENTRY*)pListHeader;
	}

	//�г�Ա

	//��ȡLIST_ENTRY ����Ϳ��԰�����ͷ�ͷŵ�

	SSDT_HOOK_LIST_ENTRY * Free_List_Entry = pListHeader->pNextEntry;
	SSDT_HOOK_LIST_ENTRY * Load_List_Entry = NULL;
	ULONG NumberOfMerber = pListHeader->NumberOfMerber;
	//�ͷ�����ͷ
	RtlZeroMemory(pListHeader, sizeof(SSDT_HOOK_LIST_HEADER));
	ExFreePoolWithTag(pListHeader, 1024);



	for (ULONG t_index = 0; NumberOfMerber; t_index++)

	{
		//�ж��Ƿ�Ϊβ��
		if (Free_List_Entry->pNextEntry == NULL)
		{

			RtlZeroMemory(Free_List_Entry, sizeof(SSDT_HOOK_LIST_ENTRY));
			ExFreePoolWithTag(Free_List_Entry, 1024);
			return Free_List_Entry;
		}

		//��ȡ��һ��List_Entry Ȼ�����һ�����ͷ�
		Load_List_Entry = Free_List_Entry->pNextEntry;
		//�ͷŵ���һ��List_Entry
		RtlZeroMemory(Free_List_Entry, sizeof(SSDT_HOOK_LIST_ENTRY));
		ExFreePoolWithTag(Free_List_Entry, 1024);

		//����
		Free_List_Entry = Load_List_Entry;
	}

	return Free_List_Entry;
}



//---------------------------------------------------------------------------------------------------------
//
//��Ansi����ת��ΪMap
//

PVOID AnsiListToMapping(PANSI_STRING_LIST_HEADER ListHead, BOOLEAN Release,PULONG MapSize)
{

	//
	//�������
	//


	if (!MmIsAddressValid(ListHead))
	{
		return NULL;
	}
	if (!MmIsAddressValid(MapSize))
	{
		return NULL;
	}

	ULONG i = 0;
	ULONG Length = 0;
	ULONG Number = 0;
	ULONG MapCopyPoint = 0;

	PVOID Map = NULL;

	PANSI_STRING_LIST_ENTRY Entry = NULL;

	//��ʼ������
	Entry = ListHead->pNextEntry;
	Number = ListHead->NumberOfMerber;

	for (i = 0; i < Number; i++)
	{
		//ȷ���Ƿ��������

		if (Entry == NULL)
		{
			break;
		}

		//��ȡ�ַ�����MaxLength

		Length = Length + Entry->Datainfo.MaximumLength;

		Entry = Entry->pNext_Entry;
	}

	//�����ڴ�

	Map = (PVOID)ExAllocatePoolWithTag(NonPagedPool, Length, 1024);
	if (Map == NULL)
	{
		return NULL;
	}


	//��ʼ������
	Entry = ListHead->pNextEntry;
	Number = ListHead->NumberOfMerber;
	MapCopyPoint = DPeTakeOutPoint(Map);

	//���Map
	for (i = 0; i < Number; i++)
	{

		//ȷ���Ƿ��������

		if (Entry == NULL)
		{
			break;
		}

		//��������
		RtlCopyMemory((PVOID)MapCopyPoint, Entry->Datainfo.Buffer, Entry->Datainfo.MaximumLength);

		//��λMap

		MapCopyPoint = MapCopyPoint + Entry->Datainfo.MaximumLength;

		Entry = Entry->pNext_Entry;
	}

	if (Release)
	{
		ReleaseAnsiList(ListHead);
	}

	*MapSize = Length;


	return Map;
}


//
//��Mapת��ΪAnsi����
//

PANSI_STRING_LIST_HEADER MappingToAnsiList(PVOID Map,ULONG Number, BOOLEAN Release)
{

	//
	//�������
	//

	if (!MmIsAddressValid(Map))
	{
		return NULL;
	}


	ULONG i = 0;

	ULONG MapCopyPoint = 0;
	ULONG StringLength = 0;

	ANSI_STRING Str = {0};
	PANSI_STRING_LIST_HEADER ListHead = NULL;

	//��ʼ������

	ListHead = InitializaAnsiList();

	if (ListHead == NULL)
	{
		return NULL;
	}


	MapCopyPoint = DPeTakeOutPoint(Map);

	for (i = 0; i < Number; i++)
	{
		//��ʼ���ַ���Ϣ
		Str.Buffer = (PVOID)MapCopyPoint;
		Str.Length = (USHORT)DPeAnsiStrlen((PVOID)MapCopyPoint);
		Str.MaximumLength = Str.Length + 1;

		//��λ
		MapCopyPoint = MapCopyPoint + Str.MaximumLength;

		//��������
		IncreaseAnsiList(ListHead, &Str);
		 
	}


	if (Release)
	{
		ExFreePoolWithTag(Map, 1024);
	}

	return ListHead;

}