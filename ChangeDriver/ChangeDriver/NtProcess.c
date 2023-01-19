#include <NtProcess.h>






//
//ö�پ����
//
/*
ULONG NpEnumeraHandleTable(PHANDLE_TABLE pHandleTable)
{


	//
	//�������
	//

	if (!MmIsAddressValid(pHandleTable))
	{
		return 0;
	}

	//�ּ����������
	ULONG i = 0;
	ULONG j = 0;
	ULONG k = 0;


	ULONG TableLevel = 0;
	ULONG CapturedTable = 0;

	//�ּ�������ַ
	PVOID TableLevel1 = NULL;
	PVOID TableLevel2 = NULL;
	PVOID TableLevel3 = NULL;

	PHANDLE_TABLE_ENTRY Entry = NULL;


	//��ȡ������ַ
	CapturedTable = pHandleTable->TableCode;
	//��ȡ�������
	TableLevel = CapturedTable & LEVEL_CODE_MASK;
	//����������ַ
	CapturedTable = CapturedTable - TableLevel;


	ULONG Object = 0;
	ULONG Handle = 0;

	switch (TableLevel)
	{
	case 0:
	{
			  //
			  //һ����
			  //

			  TableLevel1 = (PVOID)(CapturedTable + 0x8);

			  KdPrint(("Enter TableLevel1 \n"));

			  //Trace
			  for (i = 0; i < LEVEL1_COUNT - 1; i++)
			  {
				  //���TableEntry

				  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

				  //��ö���

				  Object = (ULONG)Entry->Object;

				  //������ֵ
				  Handle = i * 4 + 4;

				  KdPrint(("HANDLE : %X  OBJECT :%X \n", Handle, Object));

				  TableLevel1 = (PVOID)((ULONG)TableLevel1 + sizeof(HANDLE_TABLE_ENTRY));
			  }
			  return 1;
	}

	case 1:
	{
			  //
			  //������
			  //
			  TableLevel2 = (PVOID)CapturedTable;

			  KdPrint(("Enter TableLevel2 \n"));

			  //Trace  
			  for (i = 0; i < LEVEL2_COUNT; i++)
			  {
				  //��λ��������,һ����λ��
				  TableLevel1 = (PVOID)((ULONG)TableLevel2 + sizeof(PVOID)* i);
				  //���һ����
				  TableLevel1 = *(PVOID *)TableLevel1;

				  if (TableLevel1 == NULL)
				  {
					  //��������

					  return 1;
				  }


				  //��һ��ֱ�ӿ��
				  TableLevel1 = (PVOID)((ULONG)TableLevel1 + 0x8);

				  for (j = 0; j < LEVEL1_COUNT - 1; j++)
				  {
					  //���TableEntry

					  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

					  //��ö���

					  Object = (ULONG)Entry->Object;

					  //������ֵ
					  Handle = LEVEL1_MAX * i + j * 4 + 4;

					  //���
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
			  //������
			  //

			  TableLevel3 = (PVOID)CapturedTable;

			  KdPrint(("Enter TableLevel3 \n"));


			  //Trace
			  for (i = 0; i < LEVEL2_COUNT; i++)
			  {
				  //��λ�������ڶ������е�λ��

				  TableLevel2 = (PVOID)((ULONG)TableLevel3 + sizeof(PVOID)* i);

				  //��ö�����ָ��

				  TableLevel2 = *(PVOID *)TableLevel2;

				  if (TableLevel2 == NULL)
				  {
					  //��������

					  return 1;
				  }

				  //����������
				  for (j = 0; j < LEVEL2_COUNT; j++)
				  {
					  //ȷ��һ�����ڶ������е�λ��
					  TableLevel1 = (PVOID)((ULONG)TableLevel2 + sizeof(PVOID)* j);

					  //���һ����ָ��

					  TableLevel1 = *(PVOID *)TableLevel1;

					  if (TableLevel1 == NULL)
					  {
						  //��������

						  return 1;
					  }

					  //����һ����

					  //Trace
					  for (k = 0; k < LEVEL1_COUNT - 1; k++)
					  {
						  //���TableEntry

						  Entry = (PHANDLE_TABLE_ENTRY)TableLevel1;

						  //��ö���

						  Object = (ULONG)Entry->Object;

						  //������ֵ
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
//������ȡEPROCESS,for XP
//
PEPROCESS NpLookupPorcessByName(CHAR* ProcessName)
{
	//
	//�������
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

	//ȱʡ��������
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

	//��ȡEPROCESS
	Eprocess = PsGetCurrentProcess();

	if (Eprocess == NULL)
	{
		return NULL;
	}

	//��ȡActivity����

	Entry = (PLIST_ENTRY)((ULONG)Eprocess + ListOffset);

	//��ʼ����

	pBink = Entry->Blink;
	
	while (Entry != pBink)
	{

		//��ȡEPROCESS
		Eprocess = (PEPROCESS)((ULONG)pBink - ListOffset);

		//��ȡImageName
		ImageFileName = (PVOID)((ULONG)Eprocess + NameOffset);

		//���ƱȽ�
		if (strcmp(ImageFileName, ProcessName) == 0)
		{
			return Eprocess;
		}

		pBink = pBink->Blink;
	}
	return NULL;
}