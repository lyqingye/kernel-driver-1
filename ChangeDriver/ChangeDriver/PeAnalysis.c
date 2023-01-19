#include <PeAnalysis.h>




//
//获得指针里面的地址
//

ULONG PeTakeOutPoint(PVOID Point)
{

	//
	//参数检查
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
//获取Dos头
//

PIMAGE_DOS_HEADER PeGetDosHeader(IN PVOID FileBuffer)
{
	//
	//参数检查
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}


	return (PIMAGE_DOS_HEADER)PeTakeOutPoint(FileBuffer);
}

//
//获取NT头
//

PIMAGE_NT_HEADER PeGetNtHeader(PVOID FileBuffer)
{
	//
	//参数检查
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//获取偏移
	ULONG elfanew = 0;

	//获取Dos头
	PIMAGE_DOS_HEADER  tDosHead = (PIMAGE_DOS_HEADER)PeTakeOutPoint(FileBuffer);

	//获取Nt头偏移
	elfanew = tDosHead->e_lfanew;

	//返回Nt头
	return (PIMAGE_NT_HEADER)(elfanew + PeTakeOutPoint(FileBuffer));
}

//
//获取区段头
//

PIMAGE_SECTION_HEADER PeGetSectionHeader(IN PVOID FileBuffer)
{
	//
	//参数检查
	//
	if (!MmIsAddressValid(FileBuffer))
	{
		RstatusPrint(PE_STATUS_INVALID_PARAMETE);
		return NULL;
	}


	ULONG Result = 0;

	//获取Nt头
	IMAGE_NT_HEADER * tNtHead = PeGetNtHeader(FileBuffer);

	//获得区段头 
	Result = PeTakeOutPoint((PVOID)tNtHead) + 0xF8;

	//返回区段头
	return (PIMAGE_SECTION_HEADER)Result;
}

//
//测量内存中Ansi字符串长度
//

ULONG PeAnsiStrlen(PVOID pStr)
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
			mov dword ptr[eax],ecx
		popad
	}
	return result;
}

//
// 虚拟地址转文件偏移
//

ULONG PeRvaToFileOffset(PVOID FileBuffer, ULONG Rva)
{

	//
	// FileBuffer 指定PE文件buffer
	// Rva	指定要转换的虚拟地址	
	// Result 返回转换后的Foa
	//
	

	//
	//参数检查
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

	
	//开始转换

	ULONG SegRva = 0;  //Rva所在区段的区段RVA
	ULONG SegFoa = 0;  //Rva所在区段的区段FOA
	ULONG SegRvaOffset = 0; //Rva所在区段的RVA相对于RVA的偏移
	ULONG Foa = 0;

	ULONG NumberOfSeg = 0; //区段数
	ULONG SegSize = 0;//区段大小

	ULONG tPointSeg = 0; //遍历每一个区段
	PIMAGE_SECTION_HEADER tSegHead = NULL;//每一个区段,区段头指针


	//获取Nt头与区段头

	PIMAGE_SECTION_HEADER SegHead = PeGetSectionHeader(FileBuffer);
	PIMAGE_NT_HEADER tNtHead = PeGetNtHeader(FileBuffer);

	//获取区段数目

	NumberOfSeg = tNtHead->FileHeader.NumberOfSections;


	//
	//遍历判断Rva所在区段
	//

	for (ULONG i = 0; i < NumberOfSeg; i++)

	{

		//计算,遍历每一个区段

		tPointSeg = (ULONG)(PeTakeOutPoint((PVOID)SegHead) + (0x28 * i));
		tSegHead = (PIMAGE_SECTION_HEADER)tPointSeg;


		//初始化区段信息

		SegRva = tSegHead->VirtualAddress;
		SegFoa = tSegHead->PointerToRawData;
		SegSize = tSegHead->Misc.VirtualSize;


		//判断是否在Rva所在区段

		if ((Rva >= SegRva) && (Rva <= SegRva + SegSize)) 
		{
			//计算Foa

			SegRvaOffset = Rva - SegRva;
			Foa = SegRvaOffset + SegFoa;
			break;

		}
	}

	return Foa;
}

//
//根据内存对齐值,计算所用内存大小,以对齐值为标准，以NULL结束
//

ULONG PeGetMemorySize(PVOID Buffer, ULONG Alignment)
{
	//
	//参数检查
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

	//开始计算

	ULONG Count = 0;
	PVOID CmpBuffer = NULL;
	PVOID CmpBuffer2 = NULL;

	//申请一块空的内存,与获取的内存块做比较,确认结束位置
	CmpBuffer = ExAllocatePoolWithTag(NonPagedPool, Alignment, 1024);

	if (CmpBuffer == NULL)
	{
		RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}
		
	//内存置0,用于比较，确认结束
	RtlZeroMemory(CmpBuffer, Alignment);

	//开始循环
	while (1)
	{
		//根据对齐值,获取要比较的内存地址

		CmpBuffer2 =(PVOID) (PeTakeOutPoint(Buffer) + Alignment*Count);

		//确认结束
		if (RtlCompareMemory(CmpBuffer, CmpBuffer2, Alignment) == Alignment)
		{
			break;
		}

		//占用块计数
		Count++;
	}

	//release

	ExFreePoolWithTag(CmpBuffer, 1024);

	//计算占用内存，返回数据
	Count = Count*Alignment;

	return Count;
}

//
//获取Pe导出表
//

ULONG PeGetExportTable(IN PVOID FileBuffer, OUT PEXPORT_DIRECTORY pExportDirectory)
{
	//
	//参数检查
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


	//获取导出表基本信息

	//存放导出表各成员所在文件偏移
	ULONG ExporTable = 0;
	ULONG FncTable = 0;
	ULONG NameTable = 0;
	ULONG OrdinaTable = 0;

	//存放各成员数目
	ULONG NumberOfFnc = 0;
	ULONG NumberOfNames = 0;
	ULONG OrdinalsBase = 0;

	//存放返回数据
	PVOID  ResFncTable = NULL;
	PVOID  ResOrdnaTable = NULL;
	PANSI_STRING_LIST_HEADER  ResNameList = NULL;

	//存放PE基本信息
	PIMAGE_NT_HEADER tNtHead = NULL;
	PIMAGE_EXPORT_DIRECTORY tExportDirect = NULL;

	//获取导出表偏移
	tNtHead = PeGetNtHeader(FileBuffer);
	ExporTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[0].VirtualAddress);

	//获取导出表地址
	tExportDirect = (PIMAGE_EXPORT_DIRECTORY)(PeTakeOutPoint(FileBuffer) + ExporTable);

	//初始化各成员数据,首先是成员数目
	OrdinalsBase = tExportDirect->Base;
	NumberOfNames = tExportDirect->NumberOfNames;
	NumberOfFnc = tExportDirect->NumberOfFunctions;

	//获取导出表各成员所在文件位置
	FncTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfFunctions) + PeTakeOutPoint(FileBuffer);
	NameTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfNames) + PeTakeOutPoint(FileBuffer);
	OrdinaTable = PeRvaToFileOffset(FileBuffer, tExportDirect->AddressOfNameOrdinals) + PeTakeOutPoint(FileBuffer);



	//申请内存,用于存放返回数据
	ResFncTable = ExAllocatePoolWithTag(NonPagedPool, NumberOfFnc*sizeof(ULONG), 1024);
	ResOrdnaTable = ExAllocatePoolWithTag(NonPagedPool, NumberOfFnc*sizeof(WORD16), 1024);
	ResNameList = InitializaAnsiList();

	//如果内存分配失败
	if (ResFncTable == NULL || ResOrdnaTable == NULL)
	{
		return 0;
	}

	//内存置0
	RtlZeroMemory(ResFncTable, NumberOfFnc*sizeof(ULONG));
	RtlZeroMemory(ResOrdnaTable, NumberOfFnc*sizeof(WORD16));

//--------------------------------------------------------------------------------------------------------------------------------------------

	//开始解析导出表


	//各成员信息
	ULONG fncIndex = 0;
	ULONG onlIndex = 0;
	ULONG Ordinals = 0;
	ULONG fncAddress = 0;
	ULONG Namefoa = 0;
	ULONG NameStrlen = 0;

	//名称信息
	BOOLEAN IsName = FALSE;
	ANSI_STRING fncName ;
	ANSI_STRING fncNoName;

	//拷贝信息所用到的索引地址
	ULONG CopyPointfnc = 0;
	ULONG CopyPointonl = 0;


	//初始化无名称函数名
	RtlInitAnsiString(&fncNoName, "-"); //没有名字的函数

	for (fncIndex = 0; fncIndex < NumberOfFnc; fncIndex++)
	{

		//根据fncIndex 从函数地址表开头 获取fncAddress
		RtlCopyMemory(&fncAddress, (PVOID)(FncTable + fncIndex*sizeof(ULONG)), sizeof(ULONG));

		//遍历序号表，找到与Function_Index相等的序号
		for (onlIndex = 0; onlIndex < NumberOfNames; onlIndex++)
		{
			//获得序号,需要表每个成员2个字节
			RtlCopyMemory(&Ordinals, (PVOID)(OrdinaTable + onlIndex*sizeof(WORD16)), sizeof(WORD16));

			//计算序号
			Ordinals = Ordinals + OrdinalsBase;

			//确认找到函数名称,fncIndex从0开始，所以+1
			if (Ordinals == (fncIndex + 1))
			{
				IsName = TRUE;
				break;
			}
		}


		//判断函数是否有名字
		if (IsName)
		{
			//获取名字
			RtlCopyMemory(&Namefoa, (PVOID)(NameTable + onlIndex*sizeof(ULONG)), sizeof(ULONG));

			//获取名字foa
			Namefoa = PeRvaToFileOffset(FileBuffer, Namefoa) + PeTakeOutPoint(FileBuffer);

			//测量名字长度，拷贝数据
			NameStrlen = PeAnsiStrlen((PVOID)Namefoa);

			//设置名字信息
			fncName.Buffer = (PVOID)Namefoa;
			fncName.Length = (USHORT)NameStrlen;
			fncName.MaximumLength = (USHORT)NameStrlen + 1;

		}
		else{

			//无名称，设置无名称函数信息
			fncName.Buffer = fncNoName.Buffer;
			fncName.Length = fncNoName.Length;
			fncName.MaximumLength = fncNoName.MaximumLength;
		}

		//计算拷贝到返回数据内存块的地址
		CopyPointfnc = (ULONG)(PeTakeOutPoint(ResFncTable) + sizeof(ULONG)*fncIndex);
		CopyPointonl = (ULONG)(PeTakeOutPoint(ResOrdnaTable) + sizeof(WORD16)*fncIndex);

		//拷贝数据到返回数据内存块
		RtlCopyMemory((PVOID)CopyPointfnc, &fncAddress, sizeof(ULONG));
		RtlCopyMemory((PVOID)CopyPointonl, &Ordinals, sizeof(WORD16));

		//将函数名称插入返回字符串链表
		IncreaseAnsiList(ResNameList, &fncName);

	}

	//传递返回参数
	pExportDirectory->pfncNamelist = ResNameList;
	pExportDirectory->pfncRvaTable = ResFncTable;
	pExportDirectory->OrdlnalsTable = ResOrdnaTable;

	//返回函数个数
	return NumberOfFnc;
}

//
//获取Pe导入表
//

ULONG PeGetImportTable(IN PVOID FileBuffer, OUT PIMPORT_DIRECTORY pImportDirectory)

{

	//
	//参数检查
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

	//初始化导入表基本信息

	//导入表位置
	ULONG ImportTable = 0; //文件中导入表的偏移

	ULONG dllNumber = 0; //导入DLL的总数

	//定义返回数据
	PVOID ResListHeadArr = NULL;
	PVOID ResIatThunkArr = NULL;
	PVOID ResOnlOrHitArr = NULL;
	PVOID ResFirstThunkArr = NULL;

	PIMAGE_NT_HEADER tNtHead = NULL;

	//定位导入表位置
	tNtHead = PeGetNtHeader(FileBuffer);
	ImportTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[1].VirtualAddress) + PeTakeOutPoint(FileBuffer);


	//获得DLL的总数，便于分配要返回数据的空间
	dllNumber = PeGetMemorySize((PVOID)ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	//分配返回数组内存
	ResListHeadArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResIatThunkArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResOnlOrHitArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);
	ResFirstThunkArr = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID)*dllNumber, 1024);

	//检查参数
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

	//初始化返回数据所需要的内存空间


	//获得每一个DLL中 Thunk_Data_Array  以及 Iat_Thunk_Data_Array 的数量，并且分配内存，将内存地址加入返回数据的数组

	//导入表基本信息
	ULONG tThunkOffset = 0;  //每一个dll中的Thunk_Data_Array地址
	ULONG tIatThunkOffset = 0;   //每一个dll中的Iat指向的Iat_Thunk_Data_Array地址

	ULONG tImportThunk = 0;  //Thunk_Data_Array 成员
	ULONG tIatThunk = 0;     //Iat_Thunk_Data_Array 成员

	ULONG tIatThunkNumber = 0; //Iat_Thunk_Data_Array 成员个数
	ULONG tImportThunkNumber = 0; //Thunk_Data_Array成员个数

	//每一个dll拥有的结构
	PIMAGE_IMPORT_DESCRIPTOR tImportDescrt = NULL;

	for (ULONG i = 0; i < dllNumber; i++)
	{

		//定位要解析的目录地址
		tImportDescrt = (PIMAGE_IMPORT_DESCRIPTOR)(ImportTable + i*sizeof(IMAGE_IMPORT_DESCRIPTOR));
		tThunkOffset = PeRvaToFileOffset(FileBuffer, tImportDescrt->OriginalFirstThunk) + PeTakeOutPoint(FileBuffer);

		//计算ImportThunkArray 成员数量
		tImportThunkNumber = PeGetMemorySize((PVOID)tThunkOffset, sizeof(ULONG)) / sizeof(ULONG);


		//定位中Thunk_Data目录地址
		tIatThunkOffset = PeRvaToFileOffset(FileBuffer, tImportDescrt->FirstThunk) + PeTakeOutPoint(FileBuffer);

		//计算IatThunkArray 成员数量
		tIatThunkNumber = PeGetMemorySize((PVOID)tIatThunkOffset, sizeof(ULONG)) / sizeof(ULONG);


		//统一分配内存,对每一个DLL中的函数名称，以及Ordinals或者HIT ，Iat 中的Thunk_Data 进行分配内存
		PVOID NewImportThunkTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*(tImportThunkNumber + 1), 1024);
		PVOID NewIatThunkTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*(tIatThunkNumber + 1), 1024);
		PANSI_STRING_LIST_HEADER  NewDllList = InitializaAnsiList();

		//参数检查
		if (NewImportThunkTable == NULL || NewIatThunkTable == NULL || NewDllList == NULL)
		{
			RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
			return 0;
		}

		//清空内存，开始拷贝数据
		RtlZeroMemory(NewImportThunkTable, sizeof(ULONG)*(tImportThunkNumber + 1));
		RtlZeroMemory(NewIatThunkTable, sizeof(ULONG)*(tIatThunkNumber + 1));

		//加入返回数据
		ULONG CopyPoint = PeTakeOutPoint(ResListHeadArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewDllList, sizeof(PVOID));

		CopyPoint = PeTakeOutPoint(ResIatThunkArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewIatThunkTable, sizeof(PVOID));

		CopyPoint = PeTakeOutPoint(ResOnlOrHitArr) + sizeof(PVOID)*i;
		RtlCopyMemory((PVOID)CopyPoint, &NewImportThunkTable, sizeof(PVOID));
	}

	//-----------------------------------------------------------------------------------------------------------------------------------------------

	//下面开始解析导入表

	//文件中导入表的偏移_中间者
	ULONG tImportDirect = 0;

	//用来索引每一个dll指向的iat 与 thunkdata
	ULONG tThunkTable1 = 0;
	ULONG tIatTable1 = 0;
	ULONG tFirstThunk = 0;

	//之前申请的内存块
	PVOID LoadImportThunkTable = NULL;
	PVOID LoadIatThunkTable = NULL;
	PANSI_STRING_LIST_HEADER  LoadNewDllList = NULL;

	//用来索引DLL
	ULONG dllIndex = 0;

	//获取到的dllName
	ANSI_STRING DllName;

	//临时值
	ULONG tCopyPoint = 0;


	for (dllIndex = 0; dllIndex < dllNumber; dllIndex++)
	{


		//------------------------------------------------------------------------------------------------------------------
		//初始化基本返回信息->获取之前申请的内存块

		tCopyPoint = PeTakeOutPoint(ResListHeadArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadNewDllList, (PVOID)tCopyPoint, sizeof(PVOID));

		tCopyPoint = PeTakeOutPoint(ResIatThunkArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadIatThunkTable, (PVOID)tCopyPoint, sizeof(PVOID));

		tCopyPoint = PeTakeOutPoint(ResOnlOrHitArr) + sizeof(PVOID)*dllIndex;
		RtlCopyMemory(&LoadImportThunkTable, (PVOID)tCopyPoint, sizeof(PVOID));

		//------------------------------------------------------------------------------------------------------------------

		//定位导入表
		tImportDirect = ImportTable + dllIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		tImportDescrt = (IMAGE_IMPORT_DESCRIPTOR *)tImportDirect;

		//定位导入表ThunkData 与 Iat 
		tThunkTable1 = PeRvaToFileOffset(FileBuffer, tImportDescrt->OriginalFirstThunk) + PeTakeOutPoint(FileBuffer);
		tIatTable1 = PeRvaToFileOffset(FileBuffer, tImportDescrt->FirstThunk) + PeTakeOutPoint(FileBuffer);
		tFirstThunk = tImportDescrt->FirstThunk;
		//拷贝FirstThunk
		RtlCopyMemory((PVOID)((ULONG)ResFirstThunkArr + sizeof(PVOID)*dllIndex), &tFirstThunk, sizeof(ULONG));

		//获取dll名称
		DllName.Buffer = (PVOID)(PeRvaToFileOffset(FileBuffer, tImportDescrt->Name) + PeTakeOutPoint(FileBuffer));
		DllName.Length = (USHORT)PeAnsiStrlen(DllName.Buffer);
		DllName.MaximumLength = DllName.Length + 1;

		//插入返回链表
		IncreaseAnsiList(LoadNewDllList, &DllName);

		//------------------------------------------------------------------------------------------------------------------

		//下面解析导入表函数名
		ULONG OnlOrHit = 0;
		ULONG ThunkData = 0;

		ULONG tIndex = 0;

		ANSI_STRING  fncName;
		ANSI_STRING  fncNoName; //序号导入

		RtlInitAnsiString(&fncNoName, "-");

		while (TRUE)
		{
			//获取ThunkData
			RtlCopyMemory(&ThunkData, (PVOID)(tThunkTable1 + tIndex*sizeof(ULONG)), sizeof(ULONG));

			//确认遍历结束
			if (ThunkData == 0) break;

			//确认是否为序号导入还是名称导入
			if ((0x80000000 & ThunkData) == 0x80000000)
			{
				//序号导入
				ThunkData = ThunkData << 1;
				ThunkData = ThunkData >> 1;
				OnlOrHit = ThunkData;

				//无名称
				fncName.Buffer = fncNoName.Buffer;
				fncName.Length = fncNoName.Length;
				fncName.MaximumLength = fncNoName.MaximumLength;
			}
			else{
				//名称导入,获取名称
				fncName.Buffer = (PVOID)(PeRvaToFileOffset(FileBuffer, ThunkData) + PeTakeOutPoint(FileBuffer) + sizeof(WORD16));
				fncName.Length = (USHORT)PeAnsiStrlen(fncName.Buffer);
				fncName.MaximumLength = fncName.Length + 1;

				//获取序号或者HIT
				IMAGE_IMPORT_BY_NAME *tImportByName = (PIMAGE_IMPORT_BY_NAME)(PeRvaToFileOffset(FileBuffer, ThunkData) + PeTakeOutPoint(FileBuffer));
				OnlOrHit = tImportByName->Hint;

			}
			//拷贝数据

			//将获取到的函数名称插入链表
			IncreaseAnsiList(LoadNewDllList, &fncName);

			//拷贝序号
			tCopyPoint = PeTakeOutPoint(LoadImportThunkTable) + sizeof(ULONG)*tIndex;
			RtlCopyMemory((PVOID)tCopyPoint, &OnlOrHit, sizeof(ULONG));

			// trace
			tIndex++;
		}



		//下面直接拷贝Iat 表
		RtlCopyMemory(LoadIatThunkTable, (PVOID)tIatTable1, PeGetMemorySize((PVOID)tIatTable1, sizeof(ULONG)));

		//------------------------------------------------------------------------------------------------------------------
	}


	//下面拷贝返回数据

	pImportDirectory->dllNumber = dllNumber;
	pImportDirectory->pArrPfncNameList = ResListHeadArr;
	pImportDirectory->pOrdinalsOrHit = ResOnlOrHitArr;
	pImportDirectory->pArrIatThunkTable = ResIatThunkArr;
	pImportDirectory->pArrIatFirstThunk = ResFirstThunkArr;
	return dllNumber;
}

//
//释放获取的Pe导出表
//
ULONG PeReleaseExportTable(IN PEXPORT_DIRECTORY pExportDirectory)
{
	//
	//参数检查
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

	//释放内存
	ExFreePoolWithTag(pExportDirectory->pfncRvaTable, 1024);
	ExFreePoolWithTag(pExportDirectory->OrdlnalsTable, 1024);
	ReleaseAnsiList(pExportDirectory->pfncNamelist);
	
	pExportDirectory->pfncRvaTable = NULL;
	pExportDirectory->pfncNamelist = NULL;
	pExportDirectory->OrdlnalsTable = NULL;

	return 1; 
}

//
//释放获取的Pe导入表
//
ULONG PeReleaseImportTable(IN PIMPORT_DIRECTORY pImportDirect)
{
	//
	//参数检查
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
		//释放名称链表
		tBuffer = *(ULONG *)((ULONG)pArrPfncNameList + sizeof(PVOID)*i);
		ReleaseAnsiList((PANSI_STRING_LIST_HEADER)tBuffer);
		//释放Iat表
		tBuffer = *(ULONG *)((ULONG)pArrIatThunkTable + sizeof(PVOID)*i);
		ExFreePoolWithTag((PVOID)tBuffer, 1024);
		//释放Hit表
		tBuffer = *(ULONG *)((ULONG)pOrdinalsOrHit + sizeof(PVOID)*i);
		ExFreePoolWithTag((PVOID)tBuffer, 1024);
	}

	//释放数组
	ExFreePoolWithTag(pOrdinalsOrHit, 1024);
	ExFreePoolWithTag(pArrPfncNameList, 1024);
	ExFreePoolWithTag(pArrIatThunkTable, 1024);
	ExFreePoolWithTag(pImportDirect->pArrIatFirstThunk, 1024);
	return 1;
}


//
//搜索导出表
//
ULONG PeSearchExportTable(IN PVOID FileBuffer,IN PANSI_STRING SearchName, OUT PEXPORT_SEARCH_VALUE pExoirtSearchValue)
{


	//
	//参数检查
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


	
	

	//导出表返回信息
	EXPORT_DIRECTORY tExportDirect;

	//导出表基本信息
	PVOID fncRvaTable = NULL;
	PVOID OrdinalTable = NULL;
	PANSI_STRING_LIST_HEADER pfncNamelist = NULL;


	//枚举用到的索引
	ULONG i = 0;
	PANSI_STRING_LIST_ENTRY List_Entry = NULL;
	
	//返回的数据
	ULONG rva = 0;
	ULONG foa = 0;
	
	//获取到的函数名称,用于比较是否为要寻找的
	ANSI_STRING fncName;

	//获取导出表信息
	PeGetExportTable(FileBuffer,&tExportDirect);

	//初始化导出表成员信息
	pfncNamelist = tExportDirect.pfncNamelist;
	fncRvaTable = tExportDirect.pfncRvaTable;
	OrdinalTable = tExportDirect.OrdlnalsTable;
	//开始搜索,trace链表
	List_Entry = pfncNamelist->pNextEntry;

	//搜索导入表
	for (i = 0; i < pfncNamelist->NumberOfMerber; i++)
	{
		//遍历获取函数名称
		fncName = List_Entry->Datainfo;

		//判断是否为寻找的函数名称
		if (RtlCompareString(&fncName, SearchName, FALSE) == 0)
		{
			break;
		}

		//遍历链表
		List_Entry = List_Entry->pNext_Entry;
	}


	//确认是否遍历完全，如果为完全则找不到函数
	if (i == pfncNamelist->NumberOfMerber)
	{
		//释放内存
		PeReleaseExportTable(&tExportDirect);
		return 0;
	}


	//获取数据
	
	RtlCopyMemory(&rva, (PVOID)(PeTakeOutPoint(fncRvaTable) + i*sizeof(ULONG)), sizeof(ULONG));
	foa = PeRvaToFileOffset(FileBuffer, rva);

	//返回数据
	pExoirtSearchValue->FileOffset = foa;
	pExoirtSearchValue->VirtualAddress = rva;

	//释放内存
	PeReleaseExportTable(&tExportDirect);

	return foa;
}

//
//搜索导入表
//
ULONG PeSearchImportTable(IN PVOID FileBuffer, IN PANSI_STRING SearchName, OUT PIMPORT_SEARCH_VALUE pImportSearchValue)
{
	//
	//参数检查
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

	//导入表基本信息
	PVOID fncNameListArr = NULL;
	PVOID fncIatArr = NULL;

	IMPORT_DIRECTORY tImportDirect;

	ANSI_STRING fncName;
	PANSI_STRING_LIST_ENTRY Entry = NULL;
	PANSI_STRING_LIST_HEADER tListHead = NULL;

	//返回信息
	ULONG rva;
	ULONG foa;

	//获取导入表信息
	if (PeGetImportTable(FileBuffer, &tImportDirect) == 0)
	{
		return 0;
	}

	//初始化导入表基本信息
	fncIatArr = tImportDirect.pArrIatThunkTable;
	fncNameListArr = tImportDirect.pArrPfncNameList;


	for (i = 0; i < tImportDirect.dllNumber; i++)
	{
		//获取NameList
		tListHead = (PANSI_STRING_LIST_HEADER)(*(ULONG*)((ULONG)fncNameListArr + sizeof(PVOID)*i));
		//获取IatTable
		tfncIatTable = *(ULONG*)((ULONG)fncIatArr + sizeof(PVOID)*i);

		Entry = tListHead->pNextEntry; 
		Entry = Entry->pNext_Entry; //跳过DllName

		for (j = 0; j < tListHead->NumberOfMerber - 1; j++)
		{
			if (Entry == NULL)
			{
				break;
			}

			fncName = Entry->Datainfo;

			//判断是否为寻找的函数名称
			if (RtlCompareString(&fncName, SearchName, FALSE) == 0)
			{
				//已经找到
				rva = (*(ULONG*)((ULONG)tImportDirect.pArrIatFirstThunk + sizeof(PVOID)*i)) + sizeof(ULONG)*j;
				foa = PeRvaToFileOffset(FileBuffer, rva);

				//返回数据
				pImportSearchValue->FileOffset = foa;
				pImportSearchValue->VirulAddress = rva;

				//释放内存
				PeReleaseImportTable(&tImportDirect);
				return 1;

			}
			Entry = Entry->pNext_Entry;
		}

	}


	//释放内存
	PeReleaseImportTable(&tImportDirect);
	return 0;
}



//
//获取重定位表
//

ULONG PeGetRelocaTable(PVOID FileBuffer, OUT PVOID pRvaTable)
{

	//
	//参数检查
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

//解析重定位表

	//重定位表地址
	ULONG fRelocaTable = 0;
	ULONG fRelocaBase = 0;

	//用于索引重定位表
	ULONG tIndex = 0;

	//需要修改的成员个数
	ULONG Number = 0;

	//需要修改的地址
	ULONG CorrectRva = 0; 
	ULONG CorrectAddress = 0;

	//用于索引修改成员数组的指针
	ULONG tCorrectPoint = 0;

	//每一块大小
	ULONG SizeOfBlock = 0;

	//返回数据所需要分配的内存大小
	ULONG NumberOfCourrect = 0;

	//索引拷贝返回数据指针
	ULONG tCopyPoint = 0;
	ULONG tCopyCount = 0;


	//用于计算所需内存大小
	PIMAGE_NT_HEADER tNtHead = NULL;
	PIMAGE_BASE_RELOCATION tRelocaTable = NULL;


	//返回数据
	PVOID ResRvaTable = NULL;


	//定位重定位表

	tNtHead = PeGetNtHeader(FileBuffer);
	fRelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	fRelocaBase = fRelocaTable;

	//计算所需内存大小

	while (TRUE)
	{

		//获取要重定位
		tRelocaTable = (PIMAGE_BASE_RELOCATION)fRelocaBase;

		//获取基本信息
		SizeOfBlock = tRelocaTable->SizeOfBlock;

		//判断是否遍历到尾部
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//计算所有块大小 
		NumberOfCourrect = NumberOfCourrect + (SizeOfBlock-0x8) / 2 -1 ;

		//trace
		fRelocaBase = fRelocaBase + SizeOfBlock;
	}


	//分配内存
	ResRvaTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfCourrect, 1024);

	//参数检查
	if (ResRvaTable == NULL)
	{
		RstatusPrint(PE_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//内存置0
	RtlZeroMemory(ResRvaTable, sizeof(ULONG)*NumberOfCourrect);

	//初始化拷贝返回数据指针
	tCopyPoint = PeTakeOutPoint(ResRvaTable);

	//初始化重定位表地址
	fRelocaBase = fRelocaTable;


	//------------------------------------------------------------------------------------------------------------------------------------------

	//开始遍历重定位表

	while (TRUE)
	{
		//定位重定位表
		tRelocaTable = (PIMAGE_BASE_RELOCATION)fRelocaBase;

		//确认是否遍历到尾部
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}


		//初始化基本数据
		SizeOfBlock = tRelocaTable->SizeOfBlock;

		//每一个重定位表项，数组成员个数
		Number = (SizeOfBlock - 0x8) / 2 - 1;

		//每一个重定位表项rvabase
		CorrectRva = tRelocaTable->VirtualAddress;

		//遍历重定位表项，每一个成员，大小为2字节
		for (tIndex = 0; tIndex < Number; tIndex++)
		{

			//初始化数据拷贝位置

			//要修正地址CopyPoint
			tCorrectPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16) * tIndex;

			//返回数据CopyPoint
			tCopyPoint = PeTakeOutPoint(ResRvaTable) + tCopyCount * sizeof(ULONG);

			//获得要修正的地址
			RtlCopyMemory(&CorrectAddress, (PVOID)tCorrectPoint, sizeof(WORD16));

			//取后12位为偏移 + Rva 
			CorrectAddress = CorrectAddress << 20;
			CorrectAddress = CorrectAddress >> 20;
			CorrectAddress = CorrectAddress + CorrectRva;

			//拷贝返回数据
			RtlCopyMemory((PVOID)tCopyPoint, &CorrectAddress, sizeof(ULONG));

			//trace
			tCopyCount++;
		}

		//trace
		fRelocaBase = fRelocaBase + SizeOfBlock;

	}
	
	//拷贝返回数据
	
	RtlCopyMemory(pRvaTable, ResRvaTable, sizeof(PVOID));

	return NumberOfCourrect;
}

