#include <NtProcess.h>






//
//枚举句柄表
//
/*
ULONG NpEnumeraHandleTable(PHANDLE_TABLE pHandleTable)
{


	//
	//参数检查
	//

	if (!MmIsAddressValid(pHandleTable))
	{
		return 0;
	}

	//分级句柄表索引
	ULONG i = 0;
	ULONG j = 0;
	ULONG k = 0;


	ULONG TableLevel = 0;
	ULONG CapturedTable = 0;

	//分级句柄表地址
	PVOID TableLevel1 = NULL;
	PVOID TableLevel2 = NULL;
	PVOID TableLevel3 = NULL;

	PHANDLE_TABLE_ENTRY Entry = NULL;


	//获取句柄表地址
	CapturedTable = pHandleTable->TableCode;
	//获取句柄表级数
	TableLevel = CapturedTable & LEVEL_CODE_MASK;
	//修正句柄表地址
	CapturedTable = CapturedTable - TableLevel;


	ULONG Object = 0;
	ULONG Handle = 0;

	switch (TableLevel)
	{
	case 0:
	{
			  //
			  //一级表
			  //

			  TableLevel1 = (PVOID)(CapturedTable + 0x8);

			  KdPrint(("Enter TableLevel1 \n"));

			  //Trace
			  for (i = 0; i < LEVEL1_COUNT - 1; i++)
			  {
				  //获得TableEntry

				  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

				  //获得对象

				  Object = (ULONG)Entry->Object;

				  //计算句柄值
				  Handle = i * 4 + 4;

				  KdPrint(("HANDLE : %X  OBJECT :%X \n", Handle, Object));

				  TableLevel1 = (PVOID)((ULONG)TableLevel1 + sizeof(HANDLE_TABLE_ENTRY));
			  }
			  return 1;
	}

	case 1:
	{
			  //
			  //二级表
			  //
			  TableLevel2 = (PVOID)CapturedTable;

			  KdPrint(("Enter TableLevel2 \n"));

			  //Trace  
			  for (i = 0; i < LEVEL2_COUNT; i++)
			  {
				  //定位二级表中,一级表位置
				  TableLevel1 = (PVOID)((ULONG)TableLevel2 + sizeof(PVOID)* i);
				  //获得一级表
				  TableLevel1 = *(PVOID *)TableLevel1;

				  if (TableLevel1 == NULL)
				  {
					  //遍历结束

					  return 1;
				  }


				  //第一项直接跨过
				  TableLevel1 = (PVOID)((ULONG)TableLevel1 + 0x8);

				  for (j = 0; j < LEVEL1_COUNT - 1; j++)
				  {
					  //获得TableEntry

					  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

					  //获得对象

					  Object = (ULONG)Entry->Object;

					  //计算句柄值
					  Handle = LEVEL1_MAX * i + j * 4 + 4;

					  //输出
					  DbgPrint("HANDLE : %X  OBJECT :%X \n", Handle, Object);


					  //Trace
					  TableLevel1 = (PVOID)((ULONG)TableLevel1 + sizeof(HANDLE_TABLE_ENTRY));
				  }



			  }
			  return 1;

	}

	case 2:
	{
			  //
			  //三级表
			  //

			  TableLevel3 = (PVOID)CapturedTable;

			  KdPrint(("Enter TableLevel3 \n"));


			  //Trace
			  for (i = 0; i < LEVEL2_COUNT; i++)
			  {
				  //定位二级表在二级表中的位置

				  TableLevel2 = (PVOID)((ULONG)TableLevel3 + sizeof(PVOID)* i);

				  //获得二级表指针

				  TableLevel2 = *(PVOID *)TableLevel2;

				  if (TableLevel2 == NULL)
				  {
					  //遍历结束

					  return 1;
				  }

				  //遍历二级表
				  for (j = 0; j < LEVEL2_COUNT; j++)
				  {
					  //确定一级表在二级表中的位置
					  TableLevel1 = (PVOID)((ULONG)TableLevel2 + sizeof(PVOID)* j);

					  //获得一级表指针

					  TableLevel1 = *(PVOID *)TableLevel1;

					  if (TableLevel1 == NULL)
					  {
						  //遍历结束

						  return 1;
					  }

					  //遍历一级表

					  //Trace
					  for (k = 0; k < LEVEL1_COUNT - 1; k++)
					  {
						  //获得TableEntry

						  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

						  //获得对象

						  Object = (ULONG)Entry->Object;

						  //计算句柄值
						  Handle = k * 4 + j * LEVEL1_MAX + i * LEVEL2_MAX + 4;

						  KdPrint(("HANDLE : %X  OBJECT :%X \n", Handle, Object));

						  TableLevel1 = (PVOID)((ULONG)TableLevel1 + sizeof(HANDLE_TABLE_ENTRY));
					  }

				  }


			  }



	}


	}

	return 0;
	
}*/


//
//进程名取EPROCESS,for XP
//
PEPROCESS NpLookupPorcessByName(CHAR* ProcessName)
{
	//
	//参数检查
	//

	if (!MmIsAddressValid((PVOID)ProcessName))
	{
		return NULL;
	}

	ULONG ListOffset = 0;
	ULONG NameOffset = 0;

	SYSTEM_VERSION OsVer;

	PVOID ImageFileName = NULL;

	PLIST_ENTRY Entry = NULL;
	PLIST_ENTRY pBink = NULL;

	PEPROCESS Eprocess = NULL;


	OsVer = NtGetSystemVerSion();
	if (OsVer == SYSTEM_VERSION_UNKONW)
	{
		return NULL;
	}

	if (OsVer == SYSTEM_VERSION_WINXP)
	{
		ListOffset = 0x88;
		NameOffset = 0x174;
	}

	if (OsVer == SYSTEM_VERSION_WIN7)
	{
		ListOffset = 0x0b8;
		NameOffset = 0x16c;
	}

	//缺省，待完善
	if (OsVer == SYSTEM_VERSION_WIN2K)
	{
		return NULL;
	}
	if (OsVer == SYSTEM_VERSION_WINVISTA)
	{
		return NULL;
	}
	if (OsVer == SYSTEM_VERSION_WINSERVER)
	{
		return NULL;
	}
	if (OsVer == SYSTEM_VERSION_WIN8)
	{
		return NULL;
	}
	if (OsVer == SYSTEM_VERSION_WIN8_1)
	{
		return NULL;
	}

	//获取EPROCESS
	Eprocess = PsGetCurrentProcess();

	if (Eprocess == NULL)
	{
		return NULL;
	}

	//获取Activity链表

	Entry = (PLIST_ENTRY)((ULONG)Eprocess + ListOffset);

	//开始遍历

	pBink = Entry->Blink;
	
	while (Entry != pBink)
	{

		//获取EPROCESS
		Eprocess = (PEPROCESS)((ULONG)pBink - ListOffset);

		//获取ImageName
		ImageFileName = (PVOID)((ULONG)Eprocess + NameOffset);

		//名称比较
		if (strcmp(ImageFileName, ProcessName) == 0)
		{
			return Eprocess;
		}

		pBink = pBink->Blink;
	}
	return NULL;
}