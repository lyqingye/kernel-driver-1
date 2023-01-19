#include <DataOperation.h>


//
//测量内存中Ansi字符串长度
//

ULONG DPeAnsiStrlen(PVOID pStr)
{
	//
	//参数检查
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
			mov eax, dword ptr[eax] //获取str指向的地址
			mov ebx, eax  //保存一份

			xor ecx, ecx //ecx作为计数器从0 开始 

		Loopstar :

		mov eax, ebx //原始地址给eax ，因为 eax会被下面的代码修改
			add eax, ecx //逐字节指向
			mov al, byte ptr[eax] //以字节为单位取
			cmp al, 0x00 //判断是否到字符尾
			je LoopEnd  //遍历到结尾
			inc ecx		//字节递增
			jmp Loopstar

		LoopEnd :
		lea eax, result
			mov dword ptr[eax], ecx
			popad
	}
	return result;
}
//
//取指针地址
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
//初始化链表头
//

PANSI_STRING_LIST_HEADER InitializaAnsiList()
{
	
	//为新链表神器链表头内存

	PANSI_STRING_LIST_HEADER NewListHead = NULL;

	//申请内存
	NewListHead = (PANSI_STRING_LIST_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(ANSI_STRING_LIST_HEADER), 1024);

	//检查参数
	if (NewListHead == NULL)
	{
		return NULL;
	}

	//内存置0
	RtlZeroMemory((PVOID)NewListHead, sizeof(ANSI_STRING_LIST_HEADER));

	//设置新成员属性
	NewListHead->NumberOfMerber = 0;
	NewListHead->pNextEntry = NULL;

	//返回新链表头
	return NewListHead;
}

//
//在链表尾增加成员
//

PANSI_STRING_LIST_ENTRY  IncreaseAnsiList(PANSI_STRING_LIST_HEADER pListHead,PANSI_STRING pData)
{

	//
	//参数检查
	//
	if (!MmIsAddressValid(pListHead))
	{
		
		return NULL;
	}
	if (!MmIsAddressValid(pData))
	{

		return NULL;
	}


	//为新成员分配空间地址

	PANSI_STRING_LIST_ENTRY  NewListEntry = NULL;

	//分配内存空间
	NewListEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(ANSI_STRING_LIST_ENTRY)+pData->MaximumLength, 1024);

	//参数检查
	if (NewListEntry == NULL)
	{
		return NULL;
	}


	//内存置0
	RtlZeroMemory((PVOID)NewListEntry, sizeof(ANSI_STRING_LIST_ENTRY)+pData->MaximumLength);


	//填充新成员

	NewListEntry->pNext_Entry = NULL;
	NewListEntry->Datainfo.Buffer = (PVOID)(DPeTakeOutPoint((PVOID)NewListEntry) + sizeof(ANSI_STRING_LIST_ENTRY));
	NewListEntry->Datainfo.Length = pData->Length;
	NewListEntry->Datainfo.MaximumLength = pData->MaximumLength;

	//拷贝数据

	RtlCopyMemory((PVOID)NewListEntry->Datainfo.Buffer, pData->Buffer, pData->MaximumLength);

	//遍历链表确定要插入的位置 
	if (pListHead->NumberOfMerber == 0) //为首次插入,为减少资源做此判断
	{

		//设置数据指向

		pListHead->NumberOfMerber++;
		pListHead->pNextEntry = NewListEntry;

		//返回数据
		return NewListEntry;

	}
	else{ //说明不是首次插入需要遍历
		
		PANSI_STRING_LIST_ENTRY LastListEntry = pListHead->pNextEntry;
		
		for (ULONG tIndex = 0; tIndex < pListHead->NumberOfMerber; tIndex++)
		{
			if (LastListEntry->pNext_Entry == NULL) //找到链表尾
			{

				break;
			}

			else{ //否则继续遍历
				if (LastListEntry == NULL)
				{
					return NULL;
				}

				LastListEntry = LastListEntry->pNext_Entry;
				
			}
		}

		//设置数据指向
		pListHead->NumberOfMerber++;
		LastListEntry->pNext_Entry = NewListEntry;

		//返回数据
		return NewListEntry;
	}

		
}

//
//释放链表头及成员所有数据
//

PANSI_STRING_LIST_ENTRY ReleaseAnsiList(PANSI_STRING_LIST_HEADER  pListHead)
{

	//
	//参数检查
	//
	if (!MmIsAddressValid(pListHead))
	{

		return NULL;
	}


	if (pListHead->NumberOfMerber == 0)//没有其他成员释放链表头即可
	{
		//清理内存
		RtlZeroMemory(pListHead, sizeof(ANSI_STRING_LIST_HEADER));

		//释放内存
		ExFreePoolWithTag(pListHead, 1024);

		//返回
		return (ANSI_STRING_LIST_ENTRY*)pListHead;
	}


	//获取LIST_ENTRY 下面就可以把链表头释放掉

	PANSI_STRING_LIST_ENTRY  Free_List_Entry = NULL;
	PANSI_STRING_LIST_ENTRY  Load_List_Entry = NULL;

	//链表成员数
	ULONG NumberOfMerber = 0;

	//获取链表子链,然后就可以释放链表头
	Free_List_Entry = pListHead->pNextEntry;

	//获取链表成员数
	NumberOfMerber = pListHead->NumberOfMerber;


	//释放链表头

	RtlZeroMemory(pListHead, sizeof(ANSI_STRING_LIST_HEADER));

	ExFreePoolWithTag(pListHead, 1024);
	

	//开始循环释放子链

	for (ULONG t_index = 0; NumberOfMerber; t_index++)

	{
		//判断是否为尾部
		if (Free_List_Entry->pNext_Entry == NULL)
		{
			//清理子链内存
			RtlZeroMemory(Free_List_Entry, sizeof(ANSI_STRING_LIST_ENTRY)+Free_List_Entry->Datainfo.MaximumLength);

			//释放内存
			ExFreePoolWithTag(Free_List_Entry, 1024);

			//结束遍历
			return Free_List_Entry;
		}

		//获取下一个List_Entry 然后把上一个给释放
		Load_List_Entry = Free_List_Entry->pNext_Entry;


		//释放掉上一个List_Entry
		RtlZeroMemory(Free_List_Entry, sizeof(ANSI_STRING_LIST_ENTRY)+Free_List_Entry->Datainfo.MaximumLength);
		ExFreePoolWithTag(Free_List_Entry, 1024);


		//遍历
		Free_List_Entry = Load_List_Entry;

	}

	//返回数据
	return Free_List_Entry;
}

//
//初始化链表
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
//插入成员
//

PSSDT_HOOK_LIST_ENTRY IncreaseHookList(PSSDT_HOOK_LIST_HEADER pListHeader, PSSDT_HOOK_LIST_ENTRY pData)
{
	//为新成员分配空间
	SSDT_HOOK_LIST_ENTRY *NewListEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDT_HOOK_LIST_ENTRY), 1024);
	if (NewListEntry == NULL)
	{
		return NULL;
	}
	RtlZeroMemory((PVOID)NewListEntry, sizeof(SSDT_HOOK_LIST_ENTRY));

	//填充新成员数据
	if (pData == NULL)
	{
		return NULL;
	}

	RtlCopyMemory(NewListEntry, pData, sizeof(SSDT_HOOK_LIST_ENTRY));

	//初始化新成员数据指向
	NewListEntry->pNextEntry = NULL;
	NewListEntry->pDelayClock = DPeTakeOutPoint((PVOID)NewListEntry) + sizeof(PVOID);
	
	//加入全局链表
	if ((pListHeader->latelyListEntry == NULL && pListHeader->NumberOfMerber != 0) || (pListHeader->latelyListEntry != NULL && pListHeader->NumberOfMerber == 0))
	{
		return NULL; //链表数据被破坏
	}

	SSDT_HOOK_LIST_ENTRY * latelyListEntry = pListHeader->latelyListEntry;

	if (latelyListEntry == NULL)
	{
		//首次加入，所以链接链表头即可

		//链接链表头

		pListHeader->latelyListEntry = NewListEntry;
		pListHeader->pNextEntry = NewListEntry;
		pListHeader->NumberOfMerber++;
	}
	else{
		//不是首次加入
		if (latelyListEntry->pNextEntry != NULL)
		{
			return NULL; // 非法链表
		}

		//链接链表
		latelyListEntry->pNextEntry = NewListEntry;
		pListHeader->latelyListEntry = NewListEntry;
		pListHeader->NumberOfMerber++;
	}

	return NewListEntry;

}

//
//释放链表
//

PSSDT_HOOK_LIST_ENTRY ReleaseHookList(PSSDT_HOOK_LIST_HEADER  pListHeader)
{
	if (pListHeader == NULL)
	{
		return NULL;
	}
	
	if (pListHeader->NumberOfMerber == 0)
	{
		//只有链表头 无成员
		ExFreePoolWithTag((PVOID)pListHeader, 1024);
		return (SSDT_HOOK_LIST_ENTRY*)pListHeader;
	}

	//有成员

	//获取LIST_ENTRY 下面就可以把链表头释放掉

	SSDT_HOOK_LIST_ENTRY * Free_List_Entry = pListHeader->pNextEntry;
	SSDT_HOOK_LIST_ENTRY * Load_List_Entry = NULL;
	ULONG NumberOfMerber = pListHeader->NumberOfMerber;
	//释放链表头
	RtlZeroMemory(pListHeader, sizeof(SSDT_HOOK_LIST_HEADER));
	ExFreePoolWithTag(pListHeader, 1024);



	for (ULONG t_index = 0; NumberOfMerber; t_index++)

	{
		//判断是否为尾部
		if (Free_List_Entry->pNextEntry == NULL)
		{

			RtlZeroMemory(Free_List_Entry, sizeof(SSDT_HOOK_LIST_ENTRY));
			ExFreePoolWithTag(Free_List_Entry, 1024);
			return Free_List_Entry;
		}

		//获取下一个List_Entry 然后把上一个给释放
		Load_List_Entry = Free_List_Entry->pNextEntry;
		//释放掉上一个List_Entry
		RtlZeroMemory(Free_List_Entry, sizeof(SSDT_HOOK_LIST_ENTRY));
		ExFreePoolWithTag(Free_List_Entry, 1024);

		//遍历
		Free_List_Entry = Load_List_Entry;
	}

	return Free_List_Entry;
}



//---------------------------------------------------------------------------------------------------------
//
//将Ansi链表转换为Map
//

PVOID AnsiListToMapping(PANSI_STRING_LIST_HEADER ListHead, BOOLEAN Release,PULONG MapSize)
{

	//
	//参数检查
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

	//初始化数据
	Entry = ListHead->pNextEntry;
	Number = ListHead->NumberOfMerber;

	for (i = 0; i < Number; i++)
	{
		//确认是否遍历结束

		if (Entry == NULL)
		{
			break;
		}

		//获取字符长度MaxLength

		Length = Length + Entry->Datainfo.MaximumLength;

		Entry = Entry->pNext_Entry;
	}

	//分配内存

	Map = (PVOID)ExAllocatePoolWithTag(NonPagedPool, Length, 1024);
	if (Map == NULL)
	{
		return NULL;
	}


	//初始化数据
	Entry = ListHead->pNextEntry;
	Number = ListHead->NumberOfMerber;
	MapCopyPoint = DPeTakeOutPoint(Map);

	//填充Map
	for (i = 0; i < Number; i++)
	{

		//确认是否遍历结束

		if (Entry == NULL)
		{
			break;
		}

		//拷贝数据
		RtlCopyMemory((PVOID)MapCopyPoint, Entry->Datainfo.Buffer, Entry->Datainfo.MaximumLength);

		//定位Map

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
//将Map转换为Ansi链表
//

PANSI_STRING_LIST_HEADER MappingToAnsiList(PVOID Map,ULONG Number, BOOLEAN Release)
{

	//
	//参数检查
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

	//初始化链表

	ListHead = InitializaAnsiList();

	if (ListHead == NULL)
	{
		return NULL;
	}


	MapCopyPoint = DPeTakeOutPoint(Map);

	for (i = 0; i < Number; i++)
	{
		//初始化字符信息
		Str.Buffer = (PVOID)MapCopyPoint;
		Str.Length = (USHORT)DPeAnsiStrlen((PVOID)MapCopyPoint);
		Str.MaximumLength = Str.Length + 1;

		//定位
		MapCopyPoint = MapCopyPoint + Str.MaximumLength;

		//插入链表
		IncreaseAnsiList(ListHead, &Str);
		 
	}


	if (Release)
	{
		ExFreePoolWithTag(Map, 1024);
	}

	return ListHead;

}