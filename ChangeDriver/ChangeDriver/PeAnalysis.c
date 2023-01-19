#include <PeAnalysis.h>




//
//���ָ������ĵ�ַ
//

ULONG PeTakeOutPoint(PVOID Point)
{

	//
	//�������
	//
	if (!MmIsAddressValid(Point))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}


	ULONG result = 0;

	_asm{

		pushad
			lea eax, Point
			mov eax, dword ptr[eax]
			lea ebx,result
			mov dword ptr[ebx],eax
		popad
	}
	return result;
}


//
//��ȡDosͷ
//

PIMAGE_DOS_HEADER PeGetDosHeader(IN PVOID FileBuffer)
{
	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}


	return (PIMAGE_DOS_HEADER)PeTakeOutPoint(FileBuffer);
}

//
//��ȡNTͷ
//

PIMAGE_NT_HEADER PeGetNtHeader(PVOID FileBuffer)
{
	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//��ȡƫ��
	ULONG elfanew = 0;

	//��ȡDosͷ
	PIMAGE_DOS_HEADER  tDosHead = (PIMAGE_DOS_HEADER)PeTakeOutPoint(FileBuffer);

	//��ȡNtͷƫ��
	elfanew = tDosHead->e_lfanew;

	//����Ntͷ
	return (PIMAGE_NT_HEADER)(elfanew + PeTakeOutPoint(FileBuffer));
}

//
//��ȡ����ͷ
//

PIMAGE_SECTION_HEADER PeGetSectionHeader(IN PVOID FileBuffer)
{
	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}


	ULONG Result = 0;

	//��ȡNtͷ
	IMAGE_NT_HEADER * tNtHead = PeGetNtHeader(FileBuffer);

	//�������ͷ 
	Result = PeTakeOutPoint((PVOID)tNtHead) + 0xF8;

	//��������ͷ
	return (PIMAGE_SECTION_HEADER)Result;
}

//
//�����ڴ���Ansi�ַ�������
//

ULONG PeAnsiStrlen(PVOID pStr)
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
			mov dword ptr[eax],ecx
		popad
	}
	return result;
}

//
// �����ַת�ļ�ƫ��
//

ULONG PeRvaToFileOffset(PVOID FileBuffer, ULONG Rva)
{

	//
	// FileBuffer ָ��PE�ļ�buffer
	// Rva	ָ��Ҫת���������ַ	
	// Result ����ת�����Foa
	//
	

	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (Rva == 0)
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	
	//��ʼת��

	ULONG SegRva = 0;  //Rva�������ε�����RVA
	ULONG SegFoa = 0;  //Rva�������ε�����FOA
	ULONG SegRvaOffset = 0; //Rva�������ε�RVA�����RVA��ƫ��
	ULONG Foa = 0;

	ULONG NumberOfSeg = 0; //������
	ULONG SegSize = 0;//���δ�С

	ULONG tPointSeg = 0; //����ÿһ������
	PIMAGE_SECTION_HEADER tSegHead = NULL;//ÿһ������,����ͷָ��


	//��ȡNtͷ������ͷ

	PIMAGE_SECTION_HEADER SegHead = PeGetSectionHeader(FileBuffer);
	PIMAGE_NT_HEADER tNtHead = PeGetNtHeader(FileBuffer);

	//��ȡ������Ŀ

	NumberOfSeg = tNtHead->FileHeader.NumberOfSections;


	//
	//�����ж�Rva��������
	//

	for (ULONG i = 0; i < NumberOfSeg; i++)

	{

		//����,����ÿһ������

		tPointSeg = (ULONG)(PeTakeOutPoint((PVOID)SegHead) + (0x28 * i));
		tSegHead = (PIMAGE_SECTION_HEADER)tPointSeg;


		//��ʼ��������Ϣ

		SegRva = tSegHead->VirtualAddress;
		SegFoa = tSegHead->PointerToRawData;
		SegSize = tSegHead->Misc.VirtualSize;


		//�ж��Ƿ���Rva��������

		if ((Rva >= SegRva) && (Rva <= SegRva + SegSize)) 
		{
			//����Foa

			SegRvaOffset = Rva - SegRva;
			Foa = SegRvaOffset + SegFoa;
			break;

		}
	}

	return Foa;
}

//
//�����ڴ����ֵ,���������ڴ��С,�Զ���ֵΪ��׼����NULL����
//

ULONG PeGetMemorySize(PVOID Buffer, ULONG Alignment)
{
	//
	//�������
	//
	if (!MmIsAddressValid(Buffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (Alignment == 0)
	{
		return 0;
	}

	//��ʼ����

	ULONG Count = 0;
	PVOID CmpBuffer = NULL;
	PVOID CmpBuffer2 = NULL;

	//����һ��յ��ڴ�,���ȡ���ڴ�����Ƚ�,ȷ�Ͻ���λ��
	CmpBuffer = ExAllocatePoolWithTag(NonPagedPool, Alignment, 1024);

	if (CmpBuffer == NULL)
	{
		RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}
		
	//�ڴ���0,���ڱȽϣ�ȷ�Ͻ���
	RtlZeroMemory(CmpBuffer, Alignment);

	//��ʼѭ��
	while (1)
	{
		//���ݶ���ֵ,��ȡҪ�Ƚϵ��ڴ��ַ

		CmpBuffer2 =(PVOID) (PeTakeOutPoint(Buffer) + Alignment*Count);

		//ȷ�Ͻ���
		if (RtlCompareMemory(CmpBuffer, CmpBuffer2, Alignment) == Alignment)
		{
			break;
		}

		//ռ�ÿ����
		Count++;
	}

	//release

	ExFreePoolWithTag(CmpBuffer, 1024);

	//����ռ���ڴ棬��������
	Count = Count*Alignment;

	return Count;
}

//
//��ȡPe������
//

ULONG PeGetExportTable(IN PVOID FileBuffer, OUT PEXPORT_DIRECTORY pExportDirectory)
{
	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pExportDirectory))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------


	//��ȡ�����������Ϣ

	//��ŵ��������Ա�����ļ�ƫ��
	ULONG ExporTable = 0;
	ULONG FncTable = 0;
	ULONG NameTable = 0;
	ULONG OrdinaTable = 0;

	//��Ÿ���Ա��Ŀ
	ULONG NumberOfFnc = 0;
	ULONG NumberOfNames = 0;
	ULONG OrdinalsBase = 0;

	//��ŷ�������
	PVOID  ResFncTable = NULL;
	PVOID  ResOrdnaTable = NULL;
	PANSI_STRING_LIST_HEADER  ResNameList = NULL;

	//���PE������Ϣ
	PIMAGE_NT_HEADER tNtHead = NULL;
	PIMAGE_EXPORT_DIRECTORY tExportDirect = NULL;

	//��ȡ������ƫ��
	tNtHead = PeGetNtHeader(FileBuffer);
	ExporTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[0].VirtualAddress);

	//��ȡ�������ַ
	tExportDirect = (PIMAGE_EXPORT_DIRECTORY)(PeTakeOutPoint(FileBuffer) + ExporTable);

	//��ʼ������Ա����,�����ǳ�Ա��Ŀ
	OrdinalsBase = tExportDirect->Base;
	NumberOfNames = tExportDirect->NumberOfNames;
	NumberOfFnc = tExportDirect->NumberOfFunctions;

	//��ȡ���������Ա�����ļ�λ��
	FncTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfFunctions) + PeTakeOutPoint(FileBuffer);
	NameTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfNames) + PeTakeOutPoint(FileBuffer);
	OrdinaTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfNameOrdinals) + PeTakeOutPoint(FileBuffer);



	//�����ڴ�,���ڴ�ŷ�������
	ResFncTable = ExAllocatePoolWithTag(NonPagedPool, NumberOfFnc*sizeof(ULONG), 1024);
	ResOrdnaTable = ExAllocatePoolWithTag(NonPagedPool, NumberOfFnc*sizeof(WORD16), 1024);
	ResNameList = InitializaAnsiList();

	//����ڴ����ʧ��
	if (ResFncTable == NULL || ResOrdnaTable == NULL)
	{
		return 0;
	}

	//�ڴ���0
	RtlZeroMemory(ResFncTable, NumberOfFnc*sizeof(ULONG));
	RtlZeroMemory(ResOrdnaTable, NumberOfFnc*sizeof(WORD16));

//--------------------------------------------------------------------------------------------------------------------------------------------

	//��ʼ����������


	//����Ա��Ϣ
	ULONG fncIndex = 0;
	ULONG onlIndex = 0;
	ULONG Ordinals = 0;
	ULONG fncAddress = 0;
	ULONG Namefoa = 0;
	ULONG NameStrlen = 0;

	//������Ϣ
	BOOLEAN IsName = FALSE;
	ANSI_STRING fncName ;
	ANSI_STRING fncNoName;

	//������Ϣ���õ���������ַ
	ULONG CopyPointfnc = 0;
	ULONG CopyPointonl = 0;


	//��ʼ�������ƺ�����
	RtlInitAnsiString(&fncNoName, "-"); //û�����ֵĺ���

	for (fncIndex = 0; fncIndex < NumberOfFnc; fncIndex++)
	{

		//����fncIndex �Ӻ�����ַ��ͷ ��ȡfncAddress
		RtlCopyMemory(&fncAddress, (PVOID)(FncTable + fncIndex*sizeof(ULONG)), sizeof(ULONG));

		//������ű��ҵ���Function_Index��ȵ����
		for (onlIndex = 0; onlIndex < NumberOfNames; onlIndex++)
		{
			//������,��Ҫ��ÿ����Ա2���ֽ�
			RtlCopyMemory(&Ordinals, (PVOID)(OrdinaTable + onlIndex*sizeof(WORD16)), sizeof(WORD16));

			//�������
			Ordinals = Ordinals + OrdinalsBase;

			//ȷ���ҵ���������,fncIndex��0��ʼ������+1
			if (Ordinals == (fncIndex + 1))
			{
				IsName = TRUE;
				break;
			}
		}


		//�жϺ����Ƿ�������
		if (IsName)
		{
			//��ȡ����
			RtlCopyMemory(&Namefoa, (PVOID)(NameTable + onlIndex*sizeof(ULONG)), sizeof(ULONG));

			//��ȡ����foa
			Namefoa = PeRvaToFileOffset(FileBuffer, Namefoa) + PeTakeOutPoint(FileBuffer);

			//�������ֳ��ȣ���������
			NameStrlen = PeAnsiStrlen((PVOID)Namefoa);

			//����������Ϣ
			fncName.Buffer = (PVOID)Namefoa;
			fncName.Length = (USHORT)NameStrlen;
			fncName.MaximumLength = (USHORT)NameStrlen + 1;

		}
		else{

			//�����ƣ����������ƺ�����Ϣ
			fncName.Buffer = fncNoName.Buffer;
			fncName.Length = fncNoName.Length;
			fncName.MaximumLength = fncNoName.MaximumLength;
		}

		//���㿽�������������ڴ��ĵ�ַ
		CopyPointfnc = (ULONG)(PeTakeOutPoint(ResFncTable) + sizeof(ULONG)*fncIndex);
		CopyPointonl = (ULONG)(PeTakeOutPoint(ResOrdnaTable) + sizeof(WORD16)*fncIndex);

		//�������ݵ����������ڴ��
		RtlCopyMemory((PVOID)CopyPointfnc, &fncAddress, sizeof(ULONG));
		RtlCopyMemory((PVOID)CopyPointonl, &Ordinals, sizeof(WORD16));

		//���������Ʋ��뷵���ַ�������
		IncreaseAnsiList(ResNameList, &fncName);

	}

	//���ݷ��ز���
	pExportDirectory->pfncNamelist = ResNameList;
	pExportDirectory->pfncRvaTable = ResFncTable;
	pExportDirectory->OrdlnalsTable = ResOrdnaTable;

	//���غ�������
	return NumberOfFnc;
}

//
//��ȡPe�����
//

ULONG PeGetImportTable(IN PVOID FileBuffer, OUT PIMPORT_DIRECTORY pImportDirectory)

{

	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(pImportDirectory))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}



	//--------------------------------------------------------------------------------------------------------------------------------------------

	//��ʼ������������Ϣ

	//�����λ��
	ULONG ImportTable = 0; //�ļ��е�����ƫ��

	ULONG dllNumber = 0; //����DLL������

	//���巵������
	PVOID ResListHeadArr = NULL;
	PVOID ResIatThunkArr = NULL;
	PVOID ResOnlOrHitArr = NULL;
	PVOID ResFirstThunkArr = NULL;

	PIMAGE_NT_HEADER tNtHead = NULL;

	//��λ�����λ��
	tNtHead = PeGetNtHeader(FileBuffer);
	ImportTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[1].VirtualAddress) + PeTakeOutPoint(FileBuffer);


	//���DLL�����������ڷ���Ҫ�������ݵĿռ�
	dllNumber = PeGetMemorySize((PVOID)ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	//���䷵�������ڴ�
	ResListHeadArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResIatThunkArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResOnlOrHitArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResFirstThunkArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);

	//������
	if (ResListHeadArr == NULL || ResIatThunkArr == NULL || ResOnlOrHitArr == NULL || ResFirstThunkArr== NULL)
	{
		RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	RtlZeroMemory(ResListHeadArr, sizeof(PVOID)*dllNumber);
	RtlZeroMemory(ResIatThunkArr, sizeof(PVOID)*dllNumber);
	RtlZeroMemory(ResOnlOrHitArr, sizeof(PVOID)*dllNumber);
	RtlZeroMemory(ResFirstThunkArr, sizeof(PVOID)*dllNumber);
	//----------------------------------------------------------------------------------------------------------------------------------------------

	//��ʼ��������������Ҫ���ڴ�ռ�


	//���ÿһ��DLL�� Thunk_Data_Array  �Լ� Iat_Thunk_Data_Array �����������ҷ����ڴ棬���ڴ��ַ���뷵�����ݵ�����

	//����������Ϣ
	ULONG tThunkOffset = 0;  //ÿһ��dll�е�Thunk_Data_Array��ַ
	ULONG tIatThunkOffset = 0;   //ÿһ��dll�е�Iatָ���Iat_Thunk_Data_Array��ַ

	ULONG tImportThunk = 0;  //Thunk_Data_Array ��Ա
	ULONG tIatThunk = 0;     //Iat_Thunk_Data_Array ��Ա

	ULONG tIatThunkNumber = 0; //Iat_Thunk_Data_Array ��Ա����
	ULONG tImportThunkNumber = 0; //Thunk_Data_Array��Ա����

	//ÿһ��dllӵ�еĽṹ
	PIMAGE_IMPORT_DESCRIPTOR tImportDescrt = NULL;

	for (ULONG i = 0; i < dllNumber; i++)
	{

		//��λҪ������Ŀ¼��ַ
		tImportDescrt = (PIMAGE_IMPORT_DESCRIPTOR)(ImportTable + i*sizeof(IMAGE_IMPORT_DESCRIPTOR));
		tThunkOffset = PeRvaToFileOffset(FileBuffer, tImportDescrt->OriginalFirstThunk) + PeTakeOutPoint(FileBuffer);

		//����ImportThunkArray ��Ա����
		tImportThunkNumber = PeGetMemorySize((PVOID)tThunkOffset, sizeof(ULONG)) / sizeof(ULONG);


		//��λ��Thunk_DataĿ¼��ַ
		tIatThunkOffset = PeRvaToFileOffset(FileBuffer, tImportDescrt->FirstThunk) + PeTakeOutPoint(FileBuffer);

		//����IatThunkArray ��Ա����
		tIatThunkNumber = PeGetMemorySize((PVOID)tIatThunkOffset, sizeof(ULONG)) / sizeof(ULONG);


		//ͳһ�����ڴ�,��ÿһ��DLL�еĺ������ƣ��Լ�Ordinals����HIT ��Iat �е�Thunk_Data ���з����ڴ�
		PVOID NewImportThunkTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*(tImportThunkNumber + 1), 1024);
		PVOID NewIatThunkTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*(tIatThunkNumber + 1), 1024);
		PANSI_STRING_LIST_HEADER  NewDllList = InitializaAnsiList();

		//�������
		if (NewImportThunkTable == NULL || NewIatThunkTable == NULL || NewDllList == NULL)
		{
			RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
			return 0;
		}

		//����ڴ棬��ʼ��������
		RtlZeroMemory(NewImportThunkTable, sizeof(ULONG)*(tImportThunkNumber + 1));
		RtlZeroMemory(NewIatThunkTable, sizeof(ULONG)*(tIatThunkNumber + 1));

		//���뷵������
		ULONG CopyPoint = PeTakeOutPoint(ResListHeadArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewDllList, sizeof(PVOID));

		CopyPoint = PeTakeOutPoint(ResIatThunkArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewIatThunkTable, sizeof(PVOID));

		CopyPoint = PeTakeOutPoint(ResOnlOrHitArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewImportThunkTable, sizeof(PVOID));
	}

	//-----------------------------------------------------------------------------------------------------------------------------------------------

	//���濪ʼ���������

	//�ļ��е�����ƫ��_�м���
	ULONG tImportDirect = 0;

	//��������ÿһ��dllָ���iat �� thunkdata
	ULONG tThunkTable1 = 0;
	ULONG tIatTable1 = 0;
	ULONG tFirstThunk = 0;

	//֮ǰ������ڴ��
	PVOID LoadImportThunkTable = NULL;
	PVOID LoadIatThunkTable = NULL;
	PANSI_STRING_LIST_HEADER  LoadNewDllList = NULL;

	//��������DLL
	ULONG dllIndex = 0;

	//��ȡ����dllName
	ANSI_STRING DllName;

	//��ʱֵ
	ULONG tCopyPoint = 0;


	for (dllIndex = 0; dllIndex < dllNumber; dllIndex++)
	{


		//------------------------------------------------------------------------------------------------------------------
		//��ʼ������������Ϣ->��ȡ֮ǰ������ڴ��

		tCopyPoint = PeTakeOutPoint(ResListHeadArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadNewDllList, (PVOID)tCopyPoint, sizeof(PVOID));

		tCopyPoint = PeTakeOutPoint(ResIatThunkArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadIatThunkTable, (PVOID)tCopyPoint, sizeof(PVOID));

		tCopyPoint = PeTakeOutPoint(ResOnlOrHitArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadImportThunkTable, (PVOID)tCopyPoint, sizeof(PVOID));

		//------------------------------------------------------------------------------------------------------------------

		//��λ�����
		tImportDirect = ImportTable + dllIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		tImportDescrt = (IMAGE_IMPORT_DESCRIPTOR *)tImportDirect;

		//��λ�����ThunkData �� Iat 
		tThunkTable1 = PeRvaToFileOffset(FileBuffer, tImportDescrt->OriginalFirstThunk) + PeTakeOutPoint(FileBuffer);
		tIatTable1 = PeRvaToFileOffset(FileBuffer, tImportDescrt->FirstThunk) + PeTakeOutPoint(FileBuffer);
		tFirstThunk = tImportDescrt->FirstThunk;
		//����FirstThunk
		RtlCopyMemory((PVOID)((ULONG)ResFirstThunkArr + sizeof(PVOID)*dllIndex), &tFirstThunk, sizeof(ULONG));

		//��ȡdll����
		DllName.Buffer = (PVOID)(PeRvaToFileOffset(FileBuffer, tImportDescrt->Name) + PeTakeOutPoint(FileBuffer));
		DllName.Length = (USHORT)PeAnsiStrlen(DllName.Buffer);
		DllName.MaximumLength = DllName.Length + 1;

		//���뷵������
		IncreaseAnsiList(LoadNewDllList, &DllName);

		//------------------------------------------------------------------------------------------------------------------

		//����������������
		ULONG OnlOrHit = 0;
		ULONG ThunkData = 0;

		ULONG tIndex = 0;

		ANSI_STRING  fncName;
		ANSI_STRING  fncNoName; //��ŵ���

		RtlInitAnsiString(&fncNoName, "-");

		while (TRUE)
		{
			//��ȡThunkData
			RtlCopyMemory(&ThunkData, (PVOID)(tThunkTable1 + tIndex*sizeof(ULONG)), sizeof(ULONG));

			//ȷ�ϱ�������
			if (ThunkData == 0) break;

			//ȷ���Ƿ�Ϊ��ŵ��뻹�����Ƶ���
			if ((0x80000000 & ThunkData) == 0x80000000)
			{
				//��ŵ���
				ThunkData = ThunkData << 1;
				ThunkData = ThunkData >> 1;
				OnlOrHit = ThunkData;

				//������
				fncName.Buffer = fncNoName.Buffer;
				fncName.Length = fncNoName.Length;
				fncName.MaximumLength = fncNoName.MaximumLength;
			}
			else{
				//���Ƶ���,��ȡ����
				fncName.Buffer = (PVOID)(PeRvaToFileOffset(FileBuffer, ThunkData) + PeTakeOutPoint(FileBuffer) + sizeof(WORD16));
				fncName.Length = (USHORT)PeAnsiStrlen(fncName.Buffer);
				fncName.MaximumLength = fncName.Length + 1;

				//��ȡ��Ż���HIT
				IMAGE_IMPORT_BY_NAME *tImportByName = (PIMAGE_IMPORT_BY_NAME)(PeRvaToFileOffset(FileBuffer, ThunkData) + PeTakeOutPoint(FileBuffer));
				OnlOrHit = tImportByName->Hint;

			}
			//��������

			//����ȡ���ĺ������Ʋ�������
			IncreaseAnsiList(LoadNewDllList, &fncName);

			//�������
			tCopyPoint = PeTakeOutPoint(LoadImportThunkTable) + sizeof(ULONG)*tIndex;
			RtlCopyMemory((PVOID)tCopyPoint, &OnlOrHit, sizeof(ULONG));

			// trace
			tIndex++;
		}



		//����ֱ�ӿ���Iat ��
		RtlCopyMemory(LoadIatThunkTable, (PVOID)tIatTable1, PeGetMemorySize((PVOID)tIatTable1, sizeof(ULONG)));

		//------------------------------------------------------------------------------------------------------------------
	}


	//���濽����������

	pImportDirectory->dllNumber = dllNumber;
	pImportDirectory->pArrPfncNameList = ResListHeadArr;
	pImportDirectory->pOrdinalsOrHit = ResOnlOrHitArr;
	pImportDirectory->pArrIatThunkTable = ResIatThunkArr;
	pImportDirectory->pArrIatFirstThunk = ResFirstThunkArr;
	return dllNumber;
}

//
//�ͷŻ�ȡ��Pe������
//
ULONG PeReleaseExportTable(IN PEXPORT_DIRECTORY pExportDirectory)
{
	//
	//�������
	//

	if (!MmIsAddressValid(pExportDirectory))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pExportDirectory->pfncNamelist))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pExportDirectory->pfncRvaTable))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(pExportDirectory->OrdlnalsTable))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	//�ͷ��ڴ�
	ExFreePoolWithTag(pExportDirectory->pfncRvaTable, 1024);
	ExFreePoolWithTag(pExportDirectory->OrdlnalsTable, 1024);
	ReleaseAnsiList(pExportDirectory->pfncNamelist);
	
	pExportDirectory->pfncRvaTable = NULL;
	pExportDirectory->pfncNamelist = NULL;
	pExportDirectory->OrdlnalsTable = NULL;

	return 1; 
}

//
//�ͷŻ�ȡ��Pe�����
//
ULONG PeReleaseImportTable(IN PIMPORT_DIRECTORY pImportDirect)
{
	//
	//�������
	//

	if (!MmIsAddressValid(pImportDirect))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pImportDirect->pArrPfncNameList))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pImportDirect->pArrIatThunkTable))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(pImportDirect->pOrdinalsOrHit))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	ULONG i = 0;
	ULONG tBuffer;

	ULONG dllNumber = pImportDirect->dllNumber;
	PVOID pOrdinalsOrHit = pImportDirect->pOrdinalsOrHit;
	PVOID pArrPfncNameList = pImportDirect->pArrPfncNameList;
	PVOID pArrIatThunkTable = pImportDirect->pArrIatThunkTable;
	

	for (i = 0; i < dllNumber; i++)
	{
		//�ͷ���������
		tBuffer = *(ULONG *)((ULONG)pArrPfncNameList + sizeof(PVOID)*i);
		ReleaseAnsiList((PANSI_STRING_LIST_HEADER)tBuffer);
		//�ͷ�Iat��
		tBuffer = *(ULONG *)((ULONG)pArrIatThunkTable + sizeof(PVOID)*i);
		ExFreePoolWithTag((PVOID)tBuffer, 1024);
		//�ͷ�Hit��
		tBuffer = *(ULONG *)((ULONG)pOrdinalsOrHit + sizeof(PVOID)*i);
		ExFreePoolWithTag((PVOID)tBuffer, 1024);
	}

	//�ͷ�����
	ExFreePoolWithTag(pOrdinalsOrHit, 1024);
	ExFreePoolWithTag(pArrPfncNameList, 1024);
	ExFreePoolWithTag(pArrIatThunkTable, 1024);
	ExFreePoolWithTag(pImportDirect->pArrIatFirstThunk, 1024);
	return 1;
}


//
//����������
//
ULONG PeSearchExportTable(IN PVOID FileBuffer,IN PANSI_STRING SearchName, OUT PEXPORT_SEARCH_VALUE pExoirtSearchValue)
{


	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(pExoirtSearchValue))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(SearchName))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

//------------------------------------------------------------------------------------------------------------------------------------------------


	
	

	//����������Ϣ
	EXPORT_DIRECTORY tExportDirect;

	//�����������Ϣ
	PVOID fncRvaTable = NULL;
	PVOID OrdinalTable = NULL;
	PANSI_STRING_LIST_HEADER pfncNamelist = NULL;


	//ö���õ�������
	ULONG i = 0;
	PANSI_STRING_LIST_ENTRY List_Entry = NULL;
	
	//���ص�����
	ULONG rva = 0;
	ULONG foa = 0;
	
	//��ȡ���ĺ�������,���ڱȽ��Ƿ�ΪҪѰ�ҵ�
	ANSI_STRING fncName;

	//��ȡ��������Ϣ
	PeGetExportTable(FileBuffer,&tExportDirect);

	//��ʼ���������Ա��Ϣ
	pfncNamelist = tExportDirect.pfncNamelist;
	fncRvaTable = tExportDirect.pfncRvaTable;
	OrdinalTable = tExportDirect.OrdlnalsTable;
	//��ʼ����,trace����
	List_Entry = pfncNamelist->pNextEntry;

	//���������
	for (i = 0; i < pfncNamelist->NumberOfMerber; i++)
	{
		//������ȡ��������
		fncName = List_Entry->Datainfo;

		//�ж��Ƿ�ΪѰ�ҵĺ�������
		if (RtlCompareString(&fncName, SearchName, FALSE) == 0)
		{
			break;
		}

		//��������
		List_Entry = List_Entry->pNext_Entry;
	}


	//ȷ���Ƿ������ȫ�����Ϊ��ȫ���Ҳ�������
	if (i == pfncNamelist->NumberOfMerber)
	{
		//�ͷ��ڴ�
		PeReleaseExportTable(&tExportDirect);
		return 0;
	}


	//��ȡ����
	
	RtlCopyMemory(&rva, (PVOID)(PeTakeOutPoint(fncRvaTable) + i*sizeof(ULONG)), sizeof(ULONG));
	foa = PeRvaToFileOffset(FileBuffer, rva);

	//��������
	pExoirtSearchValue->FileOffset = foa;
	pExoirtSearchValue->VirtualAddress = rva;

	//�ͷ��ڴ�
	PeReleaseExportTable(&tExportDirect);

	return foa;
}

//
//���������
//
ULONG PeSearchImportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PIMPORT_SEARCH_VALUE pImportSearchValue)
{
	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(pImportSearchValue))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}
	if (!MmIsAddressValid(SearchName))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	//------------------------------------------------------------------------------------------------------------------------------------------------

	//temp var
	ULONG i = 0;
	ULONG j = 0;
	ULONG tfncIatTable = 0;

	//����������Ϣ
	PVOID fncNameListArr = NULL;
	PVOID fncIatArr = NULL;

	IMPORT_DIRECTORY tImportDirect;

	ANSI_STRING fncName;
	PANSI_STRING_LIST_ENTRY Entry = NULL;
	PANSI_STRING_LIST_HEADER tListHead = NULL;

	//������Ϣ
	ULONG rva;
	ULONG foa;

	//��ȡ�������Ϣ
	if (PeGetImportTable(FileBuffer, &tImportDirect) == 0)
	{
		return 0;
	}

	//��ʼ������������Ϣ
	fncIatArr = tImportDirect.pArrIatThunkTable;
	fncNameListArr = tImportDirect.pArrPfncNameList;


	for (i = 0; i < tImportDirect.dllNumber; i++)
	{
		//��ȡNameList
		tListHead = (PANSI_STRING_LIST_HEADER)(*(ULONG*)((ULONG)fncNameListArr + sizeof(PVOID)*i));
		//��ȡIatTable
		tfncIatTable = *(ULONG*)((ULONG)fncIatArr + sizeof(PVOID)*i);

		Entry = tListHead->pNextEntry; 
		Entry = Entry->pNext_Entry; //����DllName

		for (j = 0; j < tListHead->NumberOfMerber - 1; j++)
		{
			if (Entry == NULL)
			{
				break;
			}

			fncName = Entry->Datainfo;

			//�ж��Ƿ�ΪѰ�ҵĺ�������
			if (RtlCompareString(&fncName, SearchName, FALSE) == 0)
			{
				//�Ѿ��ҵ�
				rva = (*(ULONG*)((ULONG)tImportDirect.pArrIatFirstThunk + sizeof(PVOID)*i)) + sizeof(ULONG)*j;
				foa = PeRvaToFileOffset(FileBuffer, rva);

				//��������
				pImportSearchValue->FileOffset = foa;
				pImportSearchValue->VirulAddress = rva;

				//�ͷ��ڴ�
				PeReleaseImportTable(&tImportDirect);
				return 1;

			}
			Entry = Entry->pNext_Entry;
		}

	}


	//�ͷ��ڴ�
	PeReleaseImportTable(&tImportDirect);
	return 0;
}



//
//��ȡ�ض�λ��
//

ULONG PeGetRelocaTable(PVOID FileBuffer, OUT PVOID pRvaTable)
{

	//
	//�������
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

	if (!MmIsAddressValid(pRvaTable))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return 0;
	}

//----------------------------------------------------------------------------------------------------------------------------------------------

//�����ض�λ��

	//�ض�λ���ַ
	ULONG fRelocaTable = 0;
	ULONG fRelocaBase = 0;

	//���������ض�λ��
	ULONG tIndex = 0;

	//��Ҫ�޸ĵĳ�Ա����
	ULONG Number = 0;

	//��Ҫ�޸ĵĵ�ַ
	ULONG CorrectRva = 0; 
	ULONG CorrectAddress = 0;

	//���������޸ĳ�Ա�����ָ��
	ULONG tCorrectPoint = 0;

	//ÿһ���С
	ULONG SizeOfBlock = 0;

	//������������Ҫ������ڴ��С
	ULONG NumberOfCourrect = 0;

	//����������������ָ��
	ULONG tCopyPoint = 0;
	ULONG tCopyCount = 0;


	//���ڼ��������ڴ��С
	PIMAGE_NT_HEADER tNtHead = NULL;
	PIMAGE_BASE_RELOCATION tRelocaTable = NULL;


	//��������
	PVOID ResRvaTable = NULL;


	//��λ�ض�λ��

	tNtHead = PeGetNtHeader(FileBuffer);
	fRelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	fRelocaBase = fRelocaTable;

	//���������ڴ��С

	while (TRUE)
	{

		//��ȡҪ�ض�λ
		tRelocaTable = (PIMAGE_BASE_RELOCATION)fRelocaBase;

		//��ȡ������Ϣ
		SizeOfBlock = tRelocaTable->SizeOfBlock;

		//�ж��Ƿ������β��
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//�������п��С 
		NumberOfCourrect = NumberOfCourrect + (SizeOfBlock-0x8) / 2 -1 ;

		//trace
		fRelocaBase = fRelocaBase + SizeOfBlock;
	}


	//�����ڴ�
	ResRvaTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfCourrect, 1024);

	//�������
	if (ResRvaTable == NULL)
	{
		RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//�ڴ���0
	RtlZeroMemory(ResRvaTable, sizeof(ULONG)*NumberOfCourrect);

	//��ʼ��������������ָ��
	tCopyPoint = PeTakeOutPoint(ResRvaTable);

	//��ʼ���ض�λ���ַ
	fRelocaBase = fRelocaTable;


	//------------------------------------------------------------------------------------------------------------------------------------------

	//��ʼ�����ض�λ��

	while (TRUE)
	{
		//��λ�ض�λ��
		tRelocaTable = (PIMAGE_BASE_RELOCATION)fRelocaBase;

		//ȷ���Ƿ������β��
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}


		//��ʼ����������
		SizeOfBlock = tRelocaTable->SizeOfBlock;

		//ÿһ���ض�λ��������Ա����
		Number = (SizeOfBlock - 0x8) / 2 - 1;

		//ÿһ���ض�λ����rvabase
		CorrectRva = tRelocaTable->VirtualAddress;

		//�����ض�λ���ÿһ����Ա����СΪ2�ֽ�
		for (tIndex = 0; tIndex < Number; tIndex++)
		{

			//��ʼ�����ݿ���λ��

			//Ҫ������ַCopyPoint
			tCorrectPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16) * tIndex;

			//��������CopyPoint
			tCopyPoint = PeTakeOutPoint(ResRvaTable) + tCopyCount * sizeof(ULONG);

			//���Ҫ�����ĵ�ַ
			RtlCopyMemory(&CorrectAddress, (PVOID)tCorrectPoint, sizeof(WORD16));

			//ȡ��12λΪƫ�� + Rva 
			CorrectAddress = CorrectAddress << 20;
			CorrectAddress = CorrectAddress >> 20;
			CorrectAddress = CorrectAddress + CorrectRva;

			//������������
			RtlCopyMemory((PVOID)tCopyPoint, &CorrectAddress, sizeof(ULONG));

			//trace
			tCopyCount++;
		}

		//trace
		fRelocaBase = fRelocaBase + SizeOfBlock;

	}
	
	//������������
	
	RtlCopyMemory(pRvaTable, ResRvaTable, sizeof(PVOID));

	return NumberOfCourrect;
}

