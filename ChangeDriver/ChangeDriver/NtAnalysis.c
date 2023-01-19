#include <NtAnalysis.h>
#include <NtProcess.h>


#pragma comment (lib,"ntdll.lib") 







//
//全局变量
//

KIRQL OldIrql;
KSPIN_LOCK Lock;
KAPC_STATE ApcState;


//内核重载相关变量--------------------------------------------
//-------------------------------------------------------------
//OldTable
PSYSTEM_SERVICE_TABLE g_OldTable = NULL;
PSYSTEM_SERVICE_TABLE g_OldTableShadow = NULL;

//NewTable
PSYSTEM_SERVICE_TABLE g_NewTable = NULL;
PSYSTEM_SERVICE_TABLE g_NewTableShadow = NULL;

//Hook地址
ULONG g_FastCallHookPointer = 0;

//保护->过滤内容
PVOID g_ProtectProcessName = NULL;

//Hook后的返回地址
ULONG Jmp_KiFastCall = 0;
//-------------------------------------------------------------



//
//获取系统版本
//
SYSTEM_VERSION NtGetSystemVerSion()
{

	NTSTATUS status;
	RTL_OSVERSIONINFOW OsVerSionInfo;

	RtlZeroMemory((PVOID)&OsVerSionInfo, sizeof(RTL_OSVERSIONINFOW));

	//获取系统版本信息
	status = RtlGetVersion(&OsVerSionInfo);

	//Check status
	if (!NT_SUCCESS(status))
	{
		//获取失败
		return SYSTEM_VERSION_UNKONW;
	}

	if ( OsVerSionInfo.dwMajorVersion == 5 && OsVerSionInfo.dwMinorVersion == 0)
	{
		//Win2K

		return SYSTEM_VERSION_WIN2K;
	}
	if ( OsVerSionInfo.dwMajorVersion == 5 && OsVerSionInfo.dwMinorVersion == 1)
	{
		//WinXP

		return SYSTEM_VERSION_WINXP;
	}
	if (OsVerSionInfo.dwMajorVersion == 5 && OsVerSionInfo.dwMinorVersion == 2)
	{
		//WinServer2003

		return SYSTEM_VERSION_WINSERVER;
	}
	if ( OsVerSionInfo.dwMajorVersion == 6 && OsVerSionInfo.dwMinorVersion == 0)
	{
		//WinVista
		
		return SYSTEM_VERSION_WINVISTA;
	}
	if (OsVerSionInfo.dwMajorVersion == 6 && OsVerSionInfo.dwMinorVersion == 1)
	{
		//Win7

		return SYSTEM_VERSION_WIN7;
	}
	if (OsVerSionInfo.dwMajorVersion == 6 && OsVerSionInfo.dwMinorVersion == 2)
	{
		//Win8

		return SYSTEM_VERSION_WIN8;
	}
	if ( OsVerSionInfo.dwMajorVersion == 6 && OsVerSionInfo.dwMinorVersion == 3)
	{
		//Win8.1

		return SYSTEM_VERSION_WIN8_1;
	}

	return SYSTEM_VERSION_UNKONW;
}


//
//设置ssdt可写
//

 VOID EnableWrite()
{
	__asm
	{
		push eax
			mov eax, CR0
			and eax, 0FFFEFFFFh
			mov CR0, eax
			pop eax
	}
}

//
//设置ssdt不可写
//

 VOID DisableWrite()
{
	__asm
	{
		push eax
			mov eax, CR0
			or eax, NOT 0FFFEFFFFh
			mov CR0, eax
			pop eax
	}
}

 void PageProtectOn()
 {
	 __asm{//恢复内存保护  
		 mov  eax, cr0
			 or   eax, 10000h
			 mov  cr0, eax
			 sti
	 }
 }

 void PageProtectOff()
 {
	 __asm{//去掉内存保护
		 cli
			 mov  eax, cr0
			 and  eax, not 10000h
			 mov  cr0, eax
	 }
 }

 //
 //字符搜索,长度支持256
 //
 char* _stristr(char* str1, char* str2)
 {

	 if (!MmIsAddressValid(str1))
	 {
		 return NULL;
	 }
	 if (!MmIsAddressValid(str2))
	 {
		 return NULL;
	 }

	 ULONG i = 0;
	 ULONG uStrlen1 = 0;
	 ULONG uStrlen2 = 0;

	 char Newstr1[256] ;
	 char Newstr2[256] ;

	 uStrlen1 = PeAnsiStrlen(str1);
	 uStrlen2 = PeAnsiStrlen(str2);

	 char * result = NULL;
	 PVOID Search = NULL;
	 if (uStrlen1 == 0 || uStrlen2 == 0)
	 {
		 return NULL;
	 }


	 RtlZeroMemory(&Newstr1,  256);
	 RtlZeroMemory(&Newstr2,  256);
	 RtlCopyMemory(&Newstr1, str1, uStrlen1+1);
	 RtlCopyMemory(&Newstr2, str2, uStrlen2+1);

	 //转换为小写
	 for (i = 0; i < uStrlen1; i++)
	 {
		 *(char*)((ULONG)Newstr1 + i) = (char)toupper((int)(*(char*)((ULONG)Newstr1 + i)));
	 }

	 for (i = 0; i < uStrlen2; i++)
	 {
		 *(char*)((ULONG)Newstr2 + i) = (char)toupper((int)(*(char*)((ULONG)Newstr2 + i)));
	 }

	 Search = strstr(Newstr1, Newstr2);
	 if (Search == NULL)
	 {

		 result =  NULL;
	 }

	 else
	 {
		 
		 result = (char*)((ULONG)Search - (ULONG)Newstr1 + (ULONG)str1); //New Search Offset + Old Str Address = Search Pointer
	 }
	 

	 return result;

 }

 //
 //判断结构是否为空
 //

 BOOLEAN IsStructEmpty(IN PVOID Struct, IN ULONG Size)
 {
	 BOOLEAN bIsEmpty = TRUE;
	 ULONG i = 0;

	 if (!MmIsAddressValid(Struct))
	 {
		 return FALSE;
	 }

	 for (i = 0; i < Size; i++)
	 {
		 if (*(PULONG)((ULONG)Struct + i) != 0x0)
		 {
			 bIsEmpty = FALSE;
			 break;
		 }
	 }

	 return bIsEmpty;
 }

 //
 //获取内核模块基质,根据模块名称
 //

 ULONG NtGetModulBase(PVOID ModulName)
 {
	 //
	 //参数检查
	 //
	 if (!MmIsAddressValid(ModulName))
	 {
		 return 0;
	 }

	

	 ULONG i = 0;
	 ULONG Result = 0;

	 ULONG NeedLen = 0;
	 PVOID InfoBuffer = NULL;


	 //获取需要的内存大小
	 ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	 //分配内存
	 InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	 if (InfoBuffer == NULL)
	 {
		 RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		 return 0;
	 }

	 //获取系统信息
	 ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	 PSYSTEM_MODULE_INFORMATION pModules;

	 //获取模块
	 pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;


	 if (strcmp(ModulName, "HAL.dll") == 0)
	 {
		 return (ULONG)pModules->Module[1].Base;
	 }

	 
	 //Trace
	 for (i = 0; i < pModules->Count; i++)
	 {
		 if (_stristr((char*)&pModules->Module[i].ImageName, ModulName) != NULL)
		 {
			 Result = (ULONG)pModules->Module[i].Base;
			 return Result;
		 }
	 }
	 

	 return 0;

 }

//
//在指定内核模块搜索导出表函数地址
//
 ULONG NtGetModulProcAddress(PVOID Modul,PVOID FncName) 
{


	 //
	 //参数检查
	 //

	 if (!MmIsAddressValid(Modul))
	 {
		 return 0;
	 }

	 if (!MmIsAddressValid(FncName))
	 {
		 return 0;
	 }


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
	 tNtHead = PeGetNtHeader(Modul);
	 ExporTable = tNtHead->OptionalHeader.DataDirectory[0].VirtualAddress;

	 //获取导出表地址
	 tExportDirect = (PIMAGE_EXPORT_DIRECTORY)(PeTakeOutPoint(Modul) + ExporTable);

	 //初始化各成员数据,首先是成员数目
	 OrdinalsBase = tExportDirect->Base;
	 NumberOfNames = tExportDirect->NumberOfNames;
	 NumberOfFnc = tExportDirect->NumberOfFunctions;

	 //获取导出表各成员地址
	 FncTable = tExportDirect->AddressOfFunctions + PeTakeOutPoint(Modul);
	 NameTable = tExportDirect->AddressOfNames + PeTakeOutPoint(Modul);
	 OrdinaTable = tExportDirect->AddressOfNameOrdinals + PeTakeOutPoint(Modul);


	 //--------------------------------------------------------------------------------------------------------------------------------------------

	 //开始解析导出表


	 //各成员信息
	 ULONG fncIndex = 0;
	 ULONG onlIndex = 0;
	 ULONG Ordinals = 0;
	 ULONG fncAddress = 0;
	 ULONG Namefoa = 0;


	 //名称信息
	 BOOLEAN IsName = FALSE;
	 

	 //拷贝信息所用到的索引地址


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

			 //获取名字地址
			 Namefoa = Namefoa + PeTakeOutPoint(Modul);
			
			 if (strcmp((PVOID)Namefoa, FncName) == 0)
			 {
				 return fncAddress;
			 }
		 }

	 }

	 return 0;
}



//
//获取内核基址
//

ULONG NtGetKernelBase()
{
	
	ULONG NeedLen = 0; //所需要的实际大小
	ULONG Result = 0; //返回值
	PVOID InfoBuffer = NULL; //返回信息的Buffer
	

	//获取需要的内存大小
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//分配内存
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//获取系统信息
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);
	
	PSYSTEM_MODULE_INFORMATION pModules;

	//获取模块
	pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;

	//获取基址
	Result = (DWORD32)pModules->Module[0].Base;

	if (Result == 0)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}
	
	//返回数据
	return Result;
}


//
//获取Win32K基址
//
ULONG NtGetWin32kBase()
{
	ULONG i = 0;
	ULONG Result = 0;

	ULONG NeedLen = 0; 
	PVOID InfoBuffer = NULL; 
	
	ANSI_STRING Win32k;

	RtlInitAnsiString(&Win32k, "\\SystemRoot\\System32\\win32k.sys");

	//获取需要的内存大小
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//分配内存
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//获取系统信息
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	PSYSTEM_MODULE_INFORMATION pModules;

	//获取模块
	pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;
	
	//Trace
	for (i = 0; i < pModules->Count; i++)
	{
		if (strcmp((char*)&pModules->Module[i].ImageName, (char*)Win32k.Buffer) == 0)
		{
			Result = (ULONG)pModules->Module[i].Base;
			return Result;
		}
	}


	return 0;

}


//
//获取内核文件名称
//
ULONG NtGetKernelName(IN OUT PANSI_STRING pKernelName)
{
	ULONG NeedLen = 0; //所需要的实际大小
	ULONG NameStrlen = 0;
	PVOID SearchPoint = 0;
	PVOID NameBuffer = NULL;
	PVOID InfoBuffer = NULL; //返回信息的Buffer
	ANSI_STRING SearName;
	//获取需要的内存大小
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//分配内存
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//获取系统信息
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	PSYSTEM_MODULE_INFORMATION pModules;

	//获取模块
	pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;

	//获取名称内存地址
	NameBuffer = &pModules->Module[0].ImageName;

	//切割字符串
	RtlInitAnsiString(&SearName, "system32");
	SearchPoint = strstr(NameBuffer, SearName.Buffer);

	//寻找字符串失败
	if (SearchPoint == NULL)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//计算buffer位置
	NameBuffer = (PVOID)(PeTakeOutPoint(SearchPoint) + 9);

	//获取名称长度
	NameStrlen = PeAnsiStrlen(NameBuffer);


	//拷贝名称
	pKernelName->Buffer = ExAllocatePoolWithTag(NonPagedPool, NameStrlen+1, 1024);

	if (pKernelName->Buffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//内存置0
	RtlZeroMemory(pKernelName->Buffer, NameStrlen+1);
	//拷贝字符串
	RtlCopyMemory(pKernelName->Buffer, NameBuffer, NameStrlen+1);

	//设置字符串信息
	pKernelName->Length =(USHORT) NameStrlen;
	pKernelName->MaximumLength =(USHORT) NameStrlen+1;


	//返回数据
	return 1;
}


//
//读取内核文件到内存
//
PVOID NtLoadKernelFile()
{
	//字符串信息
	ULONG tStrlen = 0;
	ULONG tStrlen2 = 0;
	ULONG tMaxlen = 0;
	PVOID tBuffer = 0;

	//内核文件名称
	ANSI_STRING KernelName;
	UNICODE_STRING	KernelPath;
	UNICODE_STRING  KernelPath1;
	
	//check value 

	NTSTATUS Status;

	//先获取内核文件名称

	if (!NtGetKernelName(&KernelName))
	{
		//获取失败

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return NULL;
	}

	//初始化字符串
	RtlInitUnicodeString(&KernelPath1, L"\\SystemRoot\\system32\\");

	//计算路径所需内存大小
	tStrlen = KernelPath1.Length + KernelName.Length * 2;
	tStrlen2 = KernelPath1.Length;
	tMaxlen = KernelPath1.MaximumLength + KernelName.Length * 2 + 2;

	//为新字符串申请内存
	tBuffer = ExAllocatePoolWithTag(NonPagedPool, tMaxlen, 1024);

	if (tBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return NULL;
	}

	//设置新字符串信息

	KernelPath.Buffer = tBuffer;
	KernelPath.Length = (USHORT)tStrlen;
	KernelPath.MaximumLength = (USHORT)tMaxlen;


	//拷贝字符串以便下面的链接
	RtlCopyMemory(KernelPath.Buffer, KernelPath1.Buffer, KernelPath1.Length);


	//字符串转换
	Status = RtlAnsiStringToUnicodeString(&KernelPath1, &KernelName, TRUE);

	if (Status != STATUS_SUCCESS)
	{
		//转换失败

		//可以释放之前的KernelName
		ExFreePoolWithTag(KernelName.Buffer, 1024);
		KernelName.Buffer = NULL;
		KernelName.Length = 0;
		KernelName.MaximumLength = 0;

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return NULL;
	}




	//可以释放之前的KernelName
	ExFreePoolWithTag(KernelName.Buffer, 1024);
	KernelName.Buffer = NULL;
	KernelName.Length = 0;
	KernelName.MaximumLength = 0;


	//链接
	RtlCopyMemory((PVOID)(PeTakeOutPoint(KernelPath.Buffer) + tStrlen2), KernelPath1.Buffer, KernelPath1.Length);


	//--------------------------------------------------------------------------------------------------------------------------

	//读取文件


	//文件句柄
	HANDLE hFile = NULL;
	//缓冲区
	PVOID  FileBuffer = NULL;
	//IO状态
	IO_STATUS_BLOCK ioStatus;
	//文件属性
	OBJECT_ATTRIBUTES fileInfo;
	//文件信息
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//初始化文件对象
	InitializeObjectAttributes(&fileInfo, &KernelPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//打开文件
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//确认是否打开失败
	if (ioStatus.Information != 1)
	{
		//文件打开失败
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//获取文件信息
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//确认是否获取失败
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//获取文件信息失败,关掉文件句柄

		ZwClose(hFile);

		return NULL;
	}

	//分配文件缓冲区,准备读取文件
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//分配内存失败,关掉句柄
		ZwClose(hFile);

		return NULL;
	}

	//内存置0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//读取文件
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//读取文件失败,关掉句柄

		ZwClose(hFile);
		return NULL;
	}



	//关掉句柄
	ZwClose(hFile);


	//释放内存
	ExFreePoolWithTag(KernelPath.Buffer, 1024);
	KernelPath.Buffer = NULL;
	KernelPath.Length = 0;
	KernelPath.MaximumLength = 0;

	RtlFreeUnicodeString(&KernelPath1);

	//返回数据
	return FileBuffer;
}


//
//从内存卸载内核文件
//
PVOID NtUnLoadKernelFile(PVOID pBuffer)
{

	//
	//参数检查
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//释放内存
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;
	return pBuffer;
}

//
//读取Ntdll到内存
//

PVOID NtLoadNativeFile()
{
	
	//文件路径
	UNICODE_STRING NativePath;

	//文件句柄
	HANDLE hFile = NULL;
	//缓冲区
	PVOID  FileBuffer = NULL;
	//IO状态
	IO_STATUS_BLOCK ioStatus;
	//文件属性
	OBJECT_ATTRIBUTES fileInfo;
	//文件信息
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//状态
	NTSTATUS Status;

	//初始化文件路径
	RtlInitUnicodeString(&NativePath, L"\\SystemRoot\\system32\\ntdll.dll");

	//初始化文件对象
	InitializeObjectAttributes(&fileInfo, &NativePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//打开文件
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//确认是否打开失败
	if (ioStatus.Information != 1)
	{
		//文件打开失败
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//获取文件信息
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//确认是否获取失败
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//获取文件信息失败,关掉文件句柄

		ZwClose(hFile);

		return NULL;
	}

	//分配文件缓冲区,准备读取文件
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//分配内存失败,关掉句柄
		ZwClose(hFile);

		return NULL;
	}

	//内存置0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//读取文件
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//读取文件失败,关掉句柄

		ZwClose(hFile);
		return NULL;
	}



	//关掉句柄
	ZwClose(hFile);


	//返回数据
	return FileBuffer;
}

//
//从内存卸载Ntdll
//
PVOID NtUnLoadNativeFile(PVOID pBuffer)
{
	//
	//参数检查
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//释放内存
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;

	return pBuffer;
}

//
//读取Win32K到内存
//

PVOID NtLoadWin32kFile()
{
	//文件路径
	UNICODE_STRING NativePath;

	//文件句柄
	HANDLE hFile = NULL;
	//缓冲区
	PVOID  FileBuffer = NULL;
	//IO状态
	IO_STATUS_BLOCK ioStatus;
	//文件属性
	OBJECT_ATTRIBUTES fileInfo;
	//文件信息
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//状态
	NTSTATUS Status;

	//初始化文件路径
	RtlInitUnicodeString(&NativePath, L"\\SystemRoot\\system32\\win32k.sys");

	//初始化文件对象
	InitializeObjectAttributes(&fileInfo, &NativePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//打开文件
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//确认是否打开失败
	if (ioStatus.Information != 1)
	{
		//文件打开失败
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//获取文件信息
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//确认是否获取失败
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//获取文件信息失败,关掉文件句柄

		ZwClose(hFile);

		return NULL;
	}

	//分配文件缓冲区,准备读取文件
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//分配内存失败,关掉句柄
		ZwClose(hFile);

		return NULL;
	}

	//内存置0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//读取文件
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//读取文件失败,关掉句柄

		ZwClose(hFile);
		return NULL;
	}



	//关掉句柄
	ZwClose(hFile);


	//返回数据
	return FileBuffer;
}

//
//从内存卸载Win32k
//
PVOID NtUnloadWin32kFile(PVOID pBuffer)

{
	//
	//参数检查
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//释放内存
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;

	return pBuffer;

}

//
//获取KeServiceDescriptorTable
//

ULONG NtGetServiceDescriptor()
{
	//内核文件缓冲区
	PVOID pFileBuffer = NULL;

	//内核基址
	ULONG tKernelBase = 0;

	//要搜索的字串
	ANSI_STRING tSearchName = { 0 };

	//返回获取到的地址信息
	EXPORT_SEARCH_VALUE tExportSearchValue;

	//返回状态
	ULONG Value = 0;

	//初始化字串
	RtlInitAnsiString(&tSearchName, "KeServiceDescriptorTable");

	//读取内核文件
	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		//读取内核文件失败
		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
			
	}

	//搜索导出表
	Value = PeSearchExportTable(pFileBuffer, &tSearchName, &tExportSearchValue);

	if (!Value)
	{
		//搜索导出表失败
		RstatusPrint(PE_STATUS_SEARCHEXPORT_ERROR);
		return 0;
	}

	//获取内核基址

	tKernelBase = NtGetKernelBase();

	if (tKernelBase == 0)
	{
		//获取内核基址失败
		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);
		return 0;
	}

	//计算KeServiceDescriptorTable地址

	Value = tExportSearchValue.VirtualAddress + tKernelBase;

	//释放内存

	NtUnLoadKernelFile(pFileBuffer);


	//返回数据

	return Value;
}

//
//获取ssdt起源地址表，从文件获取
//

ULONG NtGetServiceFormFile()
{
	
	//内核文件缓存
	PVOID pFileBuffer = NULL;

	//计算 KeServiceDescriptorTable 偏移用到的数据,便于重定位搜索
	ULONG tKernelBase = 0;
	ULONG tImageBase = 0;
	ULONG tpfncRva = 0;
	ULONG tpfncAddress = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;

	//返回数据
	ULONG Value = 0;


	//读取内核文件
	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		//读取内核文件失败
		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
	}

	//获取内核基址
	tKernelBase = NtGetKernelBase();

	if (tKernelBase == 0)
	{
		//获取内核基址 失败 

		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);

		return 0;
	}

	//获取Nt头
	tNtHead = PeGetNtHeader(pFileBuffer);

	//获取ImageBase

	tImageBase = tNtHead->OptionalHeader.ImageBase;

	//计算KeServiceDescriptorTable偏移,在重定位表项指向的数据
	tpfncAddress = NtGetServiceDescriptor();

	if (tpfncAddress == 0)
	{
		//失败

		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
	}

	//计算好要遍历重定位数据
	tpfncRva = tpfncAddress - tKernelBase + tImageBase;

	//----------------------------------------------------------------------------------------------------------------------------------------

	//遍历重定位表

	//重定位表地址
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//遍历索引
	ULONG tIndex = 0;

	//重定位表项信息

	ULONG MemberRva = 0; //每一个表项的RVA
	ULONG ChangeFoa = 0; //要修正的地址(FOA)
	ULONG ChangeData = 0; //要修正的内容
	ULONG ChangeRva = 0; //要修正的地址 (RVA)

	//数据拷贝位置
	ULONG CopyPoint = 0;


	//表项基本信息
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	//用于定位SSDT,特征码
	ULONG dwCode = 0x05c7;
	ULONG Code = 0;


	//定位重定位表

	RelocaTable = PeRvaToFileOffset(pFileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(pFileBuffer);
	RelocaBase = RelocaTable;


	//开始遍历


	while (1)
	{
		//定位重定位表项

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//确认是否遍历结束
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//初始化基本数据
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//每一个表项RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//每一个表项成员数
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//初始化数据拷贝位置

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//获得要修正的地址

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//取后12位为偏移 + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//计算要修正地址FOA
			ChangeFoa = PeRvaToFileOffset(pFileBuffer, ChangeRva);

			//获取要修正的内容
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa), sizeof(ULONG));

			//关键函数定位
			if (ChangeData == tpfncRva)
			{
				//如果定位成功，则取前字节，进行特征码确认
				RtlCopyMemory(&Code, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa - 2), sizeof(WORD16));

				//特征码定位
				if (Code == dwCode)
				{
					//如果定位成功,获取SSDT地址
					RtlCopyMemory(&Value, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa + 4), sizeof(ULONG));

					//定位文件SSDT
					Value = PeRvaToFileOffset(pFileBuffer, Value - tNtHead->OptionalHeader.ImageBase);

					//释放内存
					NtUnLoadKernelFile(pFileBuffer);

					//返回数据
					return Value;
				}

			}

		}

		//trace
		RelocaBase = RelocaBase + SizeOfBlock;

	}

	
	//释放内存
	NtUnLoadKernelFile(pFileBuffer);

	//返回数据
	return Value;
}


//
//枚举SSDT
//

ULONG NtEnumeServiceTable(IN OUT PSERVICETABLE pServiceTable)
{
	
	//
	//参数检查
	//

	if (!MmIsAddressValid(pServiceTable))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}


	//内核文件缓存
	PVOID pKernelBuffer = NULL; //内核文件
	PVOID pNativeBuffer = NULL; //内核DLL


	//全局协议描述符信息
	PSYSTEM_SERVICE_TABLE pServiceDescriptor = NULL;
	PVOID ServiceTableBase = NULL;
	ULONG NumberOfService = 0;
	ULONG ServiceDescriptor = 0;

	//基本信息
	ULONG FileOffsetTable = 0; // 文件中SSDT偏移

	//返回的数据
	PVOID MemServiceTable = NULL;
	PVOID FileServiceTable = NULL;
	PANSI_STRING_LIST_HEADER pfncListHead = NULL;

	
	//重定位用到的数据
	ULONG tIndex = 0;
	ULONG tImageBase = 0;
	ULONG tKernelBase = 0;
	ULONG tRelocaPoint = 0;
	ULONG tRelocaData = 0;
	PIMAGE_NT_HEADER tNtHead = NULL;




	//初始化基本信息

	//获取KeServiceDescriptor
	ServiceDescriptor = NtGetServiceDescriptor();

	if (ServiceDescriptor == 0)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//初始化信息
	pServiceDescriptor = (PSYSTEM_SERVICE_TABLE)ServiceDescriptor;
	//函数个数
	NumberOfService = pServiceDescriptor->NumberOfService;
	//表的地址
	ServiceTableBase = pServiceDescriptor->ServiceTableBase;


	//分配返回数据内存块

	//内存SSDT
	MemServiceTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfService, 1024);
	//文件SSDT
	FileServiceTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfService, 1024);
	//函数名称
	pfncListHead = InitializaAnsiList();

	//Check Result

	if (MemServiceTable == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	if (FileServiceTable == NULL)
	{

		ExFreePoolWithTag(MemServiceTable, 1024);

		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	

	if (pfncListHead == NULL)
	{
		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);

		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}



	//加载文件进内存

	//内核文件
	pKernelBuffer = NtLoadKernelFile();
	//Native文件
	pNativeBuffer = NtLoadNativeFile();

	//Check Result 
	if (pKernelBuffer == NULL)
	{
		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	if (pNativeBuffer == NULL)
	{
		NtUnLoadKernelFile(pKernelBuffer);

		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}


	//开始拷贝内存中的SSDT

	EnableWrite();

	//拷贝数据
	RtlCopyMemory(MemServiceTable, ServiceTableBase, sizeof(ULONG)*NumberOfService);

	DisableWrite();

	
	//开始拷贝文件中的SSDT

	//获取文件SSDT
	FileOffsetTable = NtGetServiceFormFile();

	if (FileOffsetTable == 0)
	{
		NtUnLoadKernelFile(pKernelBuffer);
		NtUnLoadNativeFile(pNativeBuffer);

		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//计算地址
	FileOffsetTable = FileOffsetTable + PeTakeOutPoint(pKernelBuffer);

	//拷贝文件SSDT数据

	RtlCopyMemory(FileServiceTable, (PVOID)FileOffsetTable, sizeof(ULONG)*NumberOfService);

	//重定位文件SSDT

	//获取基本信息

	tNtHead = PeGetNtHeader(pKernelBuffer);

	tImageBase = tNtHead->OptionalHeader.ImageBase;

	tKernelBase = NtGetKernelBase();

	//Check Result
	if (tKernelBase == 0)
	{
		NtUnLoadKernelFile(pKernelBuffer);
		NtUnLoadNativeFile(pNativeBuffer);

		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);
		return 0;
	}

	for (tIndex = 0; tIndex < NumberOfService; tIndex++)
	{
		//定位要重定位的地址
		tRelocaPoint = PeTakeOutPoint(FileServiceTable) + sizeof(ULONG) * tIndex;
		//获取要重定位的数据
		RtlCopyMemory(&tRelocaData, (PVOID)tRelocaPoint, sizeof(ULONG));
		//重定位数据
		tRelocaData = tRelocaData - tImageBase + tKernelBase;
		//写会返回数据
		RtlCopyMemory((PVOID)tRelocaPoint, &tRelocaData, sizeof(ULONG));
	}


	//将内核文件卸载
	NtUnLoadKernelFile(pKernelBuffer);



	//下面解析NTDLL.DLL 获取函数名字

	EXPORT_DIRECTORY ExportDirectory ;
	PANSI_STRING_LIST_HEADER pExportNameList = NULL;
	PANSI_STRING_LIST_ENTRY  pListEntry = NULL;

	//用于确认是否为Zw开头的函数，以便重复
	ANSI_STRING ZwFlag = { 0 };

	//导出表基本信息
	PVOID pfncRvaTable = NULL;
	PVOID pOrdlnalsTable = NULL;
	ULONG NumberOfFnc = 0;

	//导出函数地址
	ULONG fncRva = 0;
	ULONG fncFoa = 0;

	//用来确认,SSDT函数序号 ，与获取到的函数序号
	ULONG fncIndex = 0;
	ULONG tMachineCode = 0;

	//遍历用到的索引
	ULONG tGetCount = 0;
	//是否再次遍历
	BOOLEAN TraceEnd = TRUE;


	//初始化基本信息
	//Zw函数标志
	RtlInitAnsiString(&ZwFlag, "Zw");

	//获取导出表
	NumberOfFnc = PeGetExportTable(pNativeBuffer, &ExportDirectory);

	//Check Result
	if (NumberOfFnc == 0)
	{
		//失败,卸载Ntdll
		NtUnLoadNativeFile(pNativeBuffer);
		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//导出表基本信息

	pfncRvaTable = ExportDirectory.pfncRvaTable;
	pOrdlnalsTable = ExportDirectory.OrdlnalsTable;
	pExportNameList = ExportDirectory.pfncNamelist;
	
	//链接链表，开始遍历
	pListEntry = pExportNameList->pNextEntry;



	while (TraceEnd)
	{
		for (tIndex = 0; tIndex < NumberOfFnc; tIndex++)
		{
			//从导出表获取函数rva
			RtlCopyMemory(&fncRva, (PVOID)(PeTakeOutPoint(pfncRvaTable) + sizeof(ULONG)*tIndex), sizeof(ULONG));

			//转成foa
			fncFoa = PeRvaToFileOffset(pNativeBuffer, fncRva) + PeTakeOutPoint(pNativeBuffer) ;

			//获取函数索引与机器码
			RtlCopyMemory(&fncIndex, (PVOID)fncFoa, sizeof(ULONG));

			//分离机器码
			tMachineCode = fncIndex << 24;
			tMachineCode = tMachineCode >> 24;

			//特征码定位
			if ((strstr(pListEntry->Datainfo.Buffer, ZwFlag.Buffer)) == NULL)
			{
				if (tMachineCode == 0xB8 && fncIndex >> 8 == tGetCount)
				{
					//插入返回链表
					IncreaseAnsiList(pfncListHead, (PANSI_STRING)(&pListEntry->Datainfo));
					//获取函数计数
					tGetCount++;
				}
			}

			//Trace
			pListEntry = pListEntry->pNext_Entry;
		}

		//判断是否获取完
		if (pfncListHead->NumberOfMerber != NumberOfService)
		{
			//没有获取完,继续获取
			tIndex = 0;
			TraceEnd = TRUE;
			pListEntry = pExportNameList->pNextEntry;
		}
		else{
			//完毕
			break;
		}

	}

	
	//释放内存
	NtUnLoadNativeFile(pNativeBuffer);
	PeReleaseExportTable(&ExportDirectory);
	
	//返回数据
	pServiceTable->NameList = pfncListHead;
	pServiceTable->FileServiceTable = FileServiceTable;
	pServiceTable->MemServiceTable = MemServiceTable;
	pServiceTable->NumberOfService = NumberOfService;


	return NumberOfService;
}

//
//释放枚举信息
//

ULONG NtDeleteServiceTable(IN PSERVICETABLE pServiceTable)
{

	//
	//参数检查
	//

	if (!MmIsAddressValid(pServiceTable))
	{
		return 0;
	}

	if (MmIsAddressValid(pServiceTable->NameList))
	{
		ReleaseAnsiList(pServiceTable->NameList);
	}

	if (MmIsAddressValid(pServiceTable->MemServiceTable))
	{
		ExFreePoolWithTag(pServiceTable->MemServiceTable, 1024);
	}

	if (MmIsAddressValid(pServiceTable->FileServiceTable))
	{
		ExFreePoolWithTag(pServiceTable->FileServiceTable, 1024);
	}


	pServiceTable->NameList = NULL;
	pServiceTable->MemServiceTable = NULL;
	pServiceTable->FileServiceTable = NULL;
	pServiceTable->NumberOfService = 0;

	return 1;


}


//
//获取PspCidTable
//

ULONG NtGetPspCidTable()
{
	//内核文件缓冲区
	PVOID pFileBuffer = NULL;

	//PsLookupProcessByProcessId名称
	ANSI_STRING fncName = { 0 };

	//导出表搜索信息
	EXPORT_SEARCH_VALUE SearchValue = { 0 };

	//基本信息
	ULONG fncFoa = 0;
	ULONG KernelBase = 0;
	ULONG UnRelocaTable = 0;
	
	
	//返回数据
	ULONG Value = 0;
	ULONG PspCidTable = 0;


	//载入内核文件

	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//
	//先获取PsLookupProcessByProcessId文件偏移,搜索导出表
	//
	
	//初始化字符串
	RtlInitAnsiString(&fncName, "PsLookupProcessByProcessId");

	//搜索导出表
	Value = PeSearchExportTable(pFileBuffer, &fncName, &SearchValue);

	if (Value == 0)
	{
		//释放内存
		NtUnLoadKernelFile(pFileBuffer);
		RstatusPrint(PE_STATUS_SEARCHEXPORT_ERROR);
		return 0;
	}
	
	//获取信息
	fncFoa = SearchValue.FileOffset;
	//内核基址
	KernelBase = NtGetKernelBase();

	if (KernelBase == 0)
	{
		//释放内存
		NtUnLoadKernelFile(pFileBuffer);
		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);
		return 0;
	}


	//遍历重定位表

	//重定位表地址
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//遍历索引
	ULONG tIndex = 0;

	//重定位表项信息

	ULONG MemberRva = 0; //每一个表项的RVA
	ULONG ChangeFoa = 0; //要修正的地址(FOA)
	ULONG ChangeData = 0; //要修正的内容
	ULONG ChangeRva = 0; //要修正的地址 (RVA)

	//数据拷贝位置
	ULONG CopyPoint = 0;


	//表项基本信息
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;

	tNtHead = PeGetNtHeader(pFileBuffer);

	//定位重定位表
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(pFileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(pFileBuffer);
	RelocaBase = RelocaTable;


	//开始遍历


	while (1)
	{
		//定位重定位表项

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//确认是否遍历结束
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//初始化基本数据
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//每一个表项RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//每一个表项成员数
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//初始化数据拷贝位置

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//获得要修正的地址

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//取后12位为偏移 + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//计算要修正地址FOA
			ChangeFoa = PeRvaToFileOffset(pFileBuffer, ChangeRva);

			//获取要修正的内容
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa), sizeof(ULONG));

			//关键函数定位
			if (ChangeFoa > fncFoa)
			{
				//如果定位成功，获取PspCidTable
				UnRelocaTable = ChangeData;
				//重定位
				PspCidTable = UnRelocaTable - ImageBase + KernelBase;
				//释放内存
				NtUnLoadKernelFile(pFileBuffer);

				//返回数据
				return PspCidTable;
				
			}

		}

		//trace
		RelocaBase = RelocaBase + SizeOfBlock;

	}

	//释放内存
	NtUnLoadKernelFile(pFileBuffer);

	return 0;

}

//
//获取 Shadow Service Table Form File
//

PVOID NtGetShadowServiceFormFile(ULONG * Count)
{

	/*加载Win32k.sys到内存，在导出表搜索 KeAddSystemServiceTable ,获得函数地址.

	从Win32k.sys -> Entry Point 开始搜索，根据重定位信息,定位到调用 KeAddSystemServiceTable地址

	回溯重定位信息,获得Shadw ServiceTable 地址,重定位地址*/

	

	PVOID Table = NULL;
	ULONG TableRva = 0;
	ULONG TableFoa = 0;
	ULONG TableFoa2 = 0;
	ULONG TableValue = 0;
	ULONG TableCount = 0;

	PVOID FileBuffer = NULL;
	ULONG fncKeAddValue = 0;


	ANSI_STRING SearchName;
	PIMAGE_NT_HEADER NtHead;
	IMPORT_SEARCH_VALUE ImportSearchValue;
	
	//重定位表地址
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//遍历索引
	ULONG tIndex = 0;

	//重定位表项信息

	ULONG MemberRva = 0; //每一个表项的RVA
	ULONG ChangeFoa = 0; //要修正的地址(FOA)
	ULONG ChangeData = 0; //要修正的内容
	ULONG ChangeRva = 0; //要修正的地址 (RVA)

	//数据拷贝位置
	ULONG CopyPoint = 0;


	//表项基本信息
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;



	RtlInitAnsiString(&SearchName, "KeAddSystemServiceTable");

	//加载Win32k.sys
	FileBuffer = NtLoadWin32kFile();

	//搜索导入表
	if (PeSearchImportTable(FileBuffer, &SearchName, &ImportSearchValue) == 0)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);
	
	//获取KeAddSystemServiceTable 虚拟地址,以便定位特征码
	fncKeAddValue = ImportSearchValue.VirulAddress + NtHead->OptionalHeader.ImageBase;

	//遍历重定位表,找到调用KeAddSystemServiceTable 的位置,因为为stdcall调用

	//遍历重定位表


	tNtHead = PeGetNtHeader(FileBuffer);

	//定位重定位表
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	RelocaBase = RelocaTable;


	//开始遍历


	while (1)
	{
		//定位重定位表项

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//确认是否遍历结束
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//初始化基本数据
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//每一个表项RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//每一个表项成员数
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//初始化数据拷贝位置

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//获得要修正的地址

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//取后12位为偏移 + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//计算要修正地址FOA
			ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);

			//获取要修正的内容
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

			//-------------------------------------------------------------------------------------

		

			//特征码定位
			if (ChangeData == fncKeAddValue)
			{
				//成功定位

				CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*(tIndex - 1);

				RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));
				ChangeRva = ChangeRva << 20;
				ChangeRva = ChangeRva >> 20;
				ChangeRva = ChangeRva + MemberRva;
				ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);
				RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

				TableRva = ChangeData - NtHead->OptionalHeader.ImageBase;
				goto start;
			}

		}
		//trace
		RelocaBase = RelocaBase + SizeOfBlock;
	}

//获取Shadow Table
start:


	if (TableRva == 0)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	}

	//获取
	TableFoa = PeRvaToFileOffset(FileBuffer, TableRva) + PeTakeOutPoint(FileBuffer);
	TableFoa2 = TableFoa;

	//遍历整个Table,计算Count
	while (1)
	{

		TableValue = *(ULONG*)TableFoa;

		if (TableValue <= ImageBase)
		{
			break;
		}
		TableFoa = TableFoa + 0x4;
	}

	//计算服务函数个数
	TableCount = (TableFoa - TableFoa2) / 4;

	//分配内存
	Table = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*TableCount, 1024);

	if (Table == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	
	}

	//拷贝Table

	RtlCopyMemory(Table, (PVOID)TableFoa2, sizeof(ULONG)*TableCount);

	//释放内存
	NtUnloadWin32kFile(FileBuffer); 

	if (Count != NULL)
	{
		*Count = TableCount;
	}

	return Table;
}

//
//获取 Shardow Service Table Form Mem 
//
PVOID NtGetShadowServiceFormMem(ULONG* Count)
{
	//
	//参数检查
	//
	if (!MmIsAddressValid((PVOID)Count))
	{
		return NULL;
	}

	/*加载Win32k.sys到内存，在导出表搜索 KeAddSystemServiceTable ,获得函数地址.

	从Win32k.sys -> Entry Point 开始搜索，根据重定位信息,定位到调用 KeAddSystemServiceTable地址

	回溯重定位信息,获得Shadw ServiceTable 地址,重定位地址*/



	PVOID Table = NULL;
	ULONG TableRva = 0;
	ULONG TableFoa = 0;
	ULONG TableFoa2 = 0;
	ULONG TableValue = 0;
	ULONG TableCount = 0;

	PVOID FileBuffer = NULL;
	ULONG fncKeAddValue = 0;


	PEPROCESS Eprocess = NULL;

	ANSI_STRING SearchName;
	PIMAGE_NT_HEADER NtHead;
	IMPORT_SEARCH_VALUE ImportSearchValue;

	//重定位表地址
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//遍历索引
	ULONG tIndex = 0;

	//重定位表项信息

	ULONG MemberRva = 0; //每一个表项的RVA
	ULONG ChangeFoa = 0; //要修正的地址(FOA)
	ULONG ChangeData = 0; //要修正的内容
	ULONG ChangeRva = 0; //要修正的地址 (RVA)

	//数据拷贝位置
	ULONG CopyPoint = 0;


	//表项基本信息
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;


	PIMAGE_NT_HEADER tNtHead = NULL;



	RtlInitAnsiString(&SearchName, "KeAddSystemServiceTable");

	//加载Win32k.sys
	FileBuffer = NtLoadWin32kFile();

	//搜索导入表
	if (PeSearchImportTable(FileBuffer, &SearchName, &ImportSearchValue) == 0)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);

	//获取KeAddSystemServiceTable 虚拟地址,以便定位特征码
	fncKeAddValue = ImportSearchValue.VirulAddress + NtHead->OptionalHeader.ImageBase;

	//遍历重定位表,找到调用KeAddSystemServiceTable 的位置,因为为stdcall调用

	//遍历重定位表


	tNtHead = PeGetNtHeader(FileBuffer);

	//定位重定位表
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	RelocaBase = RelocaTable;


	//开始遍历


	while (1)
	{
		//定位重定位表项

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//确认是否遍历结束
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//初始化基本数据
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//每一个表项RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//每一个表项成员数
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//初始化数据拷贝位置

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//获得要修正的地址

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//取后12位为偏移 + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//计算要修正地址FOA
			ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);

			//获取要修正的内容
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

			//-------------------------------------------------------------------------------------



			//特征码定位
			if (ChangeData == fncKeAddValue)
			{
				//成功定位

				CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*(tIndex - 1);

				RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));
				ChangeRva = ChangeRva << 20;
				ChangeRva = ChangeRva >> 20;
				ChangeRva = ChangeRva + MemberRva;
				ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);
				RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

				TableRva = ChangeData - NtHead->OptionalHeader.ImageBase;
				goto start;
			}

		}
		//trace
		RelocaBase = RelocaBase + SizeOfBlock;
	}

	//获取Shadow Table
start:


	if (TableRva == 0)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	}

	//获取
	TableFoa = PeRvaToFileOffset(FileBuffer, TableRva) + PeTakeOutPoint(FileBuffer);
	TableFoa2 = TableFoa;

	//遍历整个Table,计算Count
	while (1)
	{

		TableValue = *(ULONG*)TableFoa;

		if (TableValue <= ImageBase)
		{
			break;
		}
		TableFoa = TableFoa + 0x4;
	}

	//计算服务函数个数
	TableCount = (TableFoa - TableFoa2) / 4;

	*Count = TableCount;

	//分配内存
	Table = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*TableCount, 1024);

	if (Table == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;

	}

	TableRva = TableRva + NtGetWin32kBase();




	//附加到gui进程

	Eprocess = NpLookupPorcessByName("explorer.exe");

	if (Eprocess == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		ExFreePoolWithTag(Table, 1024);
		return NULL;
	}

	//初始化锁
	KeInitializeSpinLock(&Lock);
	KeAcquireSpinLock(&Lock, &OldIrql);

	//附加进程
	KeStackAttachProcess(Eprocess, &ApcState);


	if (!MmIsAddressValid((PVOID)TableRva))
	{
		NtUnloadWin32kFile(FileBuffer);
		ExFreePoolWithTag(Table, 1024);
		return NULL;
	}


	//可以拷贝数据
	RtlCopyMemory(Table, (PVOID)TableRva, sizeof(ULONG)*TableCount);

	//分离进程
	KeUnstackDetachProcess(&ApcState);
	//释放锁
	KeReleaseSpinLock(&Lock, OldIrql);


	return Table;
}


//
//获取到的 Shadow Service Table 需要重定位
//
PVOID NtRelocaShadowServiceTable(PVOID Table, ULONG Count)
{
	//
	//参数检查
	//

	if (!MmIsAddressValid(Table))
	{
		return NULL;
	}

	if (Count == 0)
	{
		return 0;
	}


	ULONG i = 0;
	ULONG Value = 0;
	PVOID FileBuffer;
	ULONG Win32kImageBase;
	ULONG Win32kRelocaBase;

	PIMAGE_NT_HEADER NtHead = NULL;

	//加载内核文件
	FileBuffer = NtLoadWin32kFile();

	if (FileBuffer == NULL)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);


	//
	//获取Win32k基址
	//
	Win32kRelocaBase = NtGetWin32kBase(); 
	
	Win32kImageBase = NtHead->OptionalHeader.ImageBase;


	//Check result
	if (Win32kRelocaBase == 0)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	}

	for (i = 0; i < Count; i++)
	{
		Value = *(ULONG*)((ULONG)Table + i*sizeof(PVOID));
		Value = Value - Win32kImageBase + Win32kRelocaBase;
		*(ULONG*)((ULONG)Table + i*sizeof(PVOID)) = Value;
	}

	NtUnloadWin32kFile(FileBuffer);
	return Table;
}

//
//枚举Service Table Shaodw
//

ULONG NtEnumeServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow)
{

	//
	//参数检查
	//

	if (!MmIsAddressValid(pServiceTableShadow))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}

	PVOID FileTable = NULL;
	ULONG FncNumber = 0;

	FileTable = NtGetShadowServiceFormFile(&FncNumber);

	NtRelocaShadowServiceTable(FileTable, FncNumber);

	if (FileTable == NULL)
	{
		return 0;
	}


	pServiceTableShadow->FileServiceTable = FileTable;
	pServiceTableShadow->MemServiceTable = NULL;
	pServiceTableShadow->NumberOfService = FncNumber;

	return 1;
}

//
//删除 Service Table Shaodw
//

ULONG NtDelectServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow)
{
	//
	//参数检查
	//

	if (!MmIsAddressValid(pServiceTableShadow))
	{
		return 0;
	}



	if (MmIsAddressValid(pServiceTableShadow->MemServiceTable))
	{
		ExFreePoolWithTag(pServiceTableShadow->MemServiceTable, 1024);
	}

	if (MmIsAddressValid(pServiceTableShadow->FileServiceTable))
	{
		ExFreePoolWithTag(pServiceTableShadow->FileServiceTable, 1024);
	}


	pServiceTableShadow->MemServiceTable = NULL;
	pServiceTableShadow->FileServiceTable = NULL;
	pServiceTableShadow->NumberOfService = 0;

	return 1;
}

//----------------------------------------------------------------------------------------------------------------------------------

//
//重载导入表
//
BOOLEAN NtFixImportTable(IN PVOID NewKernel)
{

	//
	//参数检查
	//
	if (!MmIsAddressValid(NewKernel))
	{
		return FALSE;
	}


	//--------------------------------------------------------------------------------------------------------------------------------------------

	//初始化导入表基本信息

	//导入表位置
	ULONG ImportTable = 0; //文件中导入表的偏移

	ULONG dllNumber = 0; //导入DLL的总数



	PIMAGE_NT_HEADER tNtHead = NULL;

	//定位导入表位置
	tNtHead = PeGetNtHeader(NewKernel);
	ImportTable = tNtHead->OptionalHeader.DataDirectory[1].VirtualAddress + PeTakeOutPoint(NewKernel);


	//获得DLL的总数
	dllNumber = PeGetMemorySize((PVOID)ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);


	//----------------------------------------------------------------------------------------------------------------------------------------------



	//导入表基本信息
	ULONG tThunkOffset = 0;  //每一个dll中的Thunk_Data_Array地址
	ULONG tIatThunkOffset = 0;   //每一个dll中的Iat指向的Iat_Thunk_Data_Array地址

	ULONG tImportThunk = 0;  //Thunk_Data_Array 成员
	ULONG tIatThunk = 0;     //Iat_Thunk_Data_Array 成员

	ULONG tIatThunkNumber = 0; //Iat_Thunk_Data_Array 成员个数
	ULONG tImportThunkNumber = 0; //Thunk_Data_Array成员个数

	//每一个dll拥有的结构
	PIMAGE_IMPORT_DESCRIPTOR tImportDescrt = NULL;

	//-----------------------------------------

	//文件中导入表的偏移_中间者
	ULONG tImportDirect = 0;

	//用来索引每一个dll指向的iat 与 thunkdata
	ULONG tThunkTable1 = 0;
	ULONG tIatTable1 = 0;
	ULONG tFirstThunk = 0;


	//用来索引DLL
	ULONG dllIndex = 0;

	//获取到的dllName
	ANSI_STRING DllName;

	//临时值
	ULONG tCopyPoint = 0;

	ULONG ModulBase = 0;
	ULONG FncAddress = 0;
	for (dllIndex = 0; dllIndex < dllNumber; dllIndex++)
	{



		//定位导入表
		tImportDirect = ImportTable + dllIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		tImportDescrt = (IMAGE_IMPORT_DESCRIPTOR *)tImportDirect;

		//定位导入表ThunkData 与 Iat 
		tThunkTable1 = tImportDescrt->OriginalFirstThunk + PeTakeOutPoint(NewKernel);
		tIatTable1 = tImportDescrt->FirstThunk + PeTakeOutPoint(NewKernel);


		//获取dll名称
		DllName.Buffer = (PVOID)(tImportDescrt->Name + PeTakeOutPoint(NewKernel));

		ModulBase = NtGetModulBase(DllName.Buffer);

		//DbgPrint("Fix Modul Name :%s ,Modul Base :%X\n", DllName.Buffer,ModulBase);
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
			if ((0x80000000 & ThunkData) == 0x80000000) //内核文件都是名称导入了
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
				fncName.Buffer = (PCHAR)(ThunkData + PeTakeOutPoint(NewKernel) + sizeof(WORD16));
				//获取函数地址
				FncAddress = NtGetModulProcAddress((PVOID)ModulBase, fncName.Buffer) + ModulBase;

				//DbgPrint("Fix Fnc Name :%s , Fnc Address:%X \n", fncName.Buffer, FncAddress);

				//修复IAT
				RtlCopyMemory((PVOID)(tIatTable1 + sizeof(PVOID)*tIndex), &FncAddress, sizeof(PVOID));
			}


			// trace
			tIndex++;
		}


		//------------------------------------------------------------------------------------------------------------------
	}



	return TRUE;
}

//
//重载内核
//
BOOLEAN NtHeavyloadKernel(IN OUT PVOID *NewKernel)
{

	//
	//参数检查
	//
	if (!MmIsAddressValid(NewKernel))
	{
		return FALSE;
	}

	PVOID pLoadKernelbuf = NULL;
	PVOID pNewKernelbuf  = NULL;

	ULONG uIndex = 0;
	ULONG uSecNumber = 0;
	ULONG uBlockSize = 0;
	ULONG uImageBase = 0;
	ULONG uKernelBase = 0;
	ULONG uSizeOfImage = 0;
	
	
	PIMAGE_NT_HEADER	pNtHead = NULL;
	PIMAGE_DOS_HEADER	pDosHead = NULL;
	PIMAGE_SECTION_HEADER	pSecHead = NULL;
	PIMAGE_SECTION_HEADER	pSecHeadPoint = NULL;
	//加载内核文件
	pLoadKernelbuf = NtLoadKernelFile();

	if (pLoadKernelbuf == NULL)
	{
		return FALSE;
	}

	//初始化Pe信息
	pNtHead  =  PeGetNtHeader(pLoadKernelbuf);
	pDosHead =  PeGetDosHeader(pLoadKernelbuf);
	pSecHead =  PeGetSectionHeader(pLoadKernelbuf);
	
	uSecNumber = pNtHead->FileHeader.NumberOfSections;
	uImageBase = pNtHead->OptionalHeader.ImageBase;
	uSizeOfImage = pNtHead->OptionalHeader.SizeOfImage;

	//分配新内核内存
	pNewKernelbuf = ExAllocatePool(NonPagedPool, uSizeOfImage);

	if (pNewKernelbuf == NULL)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		return FALSE;
	}

	*NewKernel = pNewKernelbuf;

	//_Mem_Zero
	RtlZeroMemory(pNewKernelbuf, uSizeOfImage);

	//All _ Header
	RtlCopyMemory(pNewKernelbuf, pLoadKernelbuf, pNtHead->OptionalHeader.SizeOfHeaders);

	//拷贝区块
	for (uIndex = 0; uIndex < uSecNumber; uIndex++)
	{
		//
		//从LoadKernelbuf -> NewKernelbuf
		//

		pSecHeadPoint = (PIMAGE_SECTION_HEADER)((ULONG)pSecHead + sizeof(IMAGE_SECTION_HEADER)*uIndex);
		
		
		RtlCopyMemory((PVOID)((ULONG)pNewKernelbuf + pSecHeadPoint->VirtualAddress),	//拷贝到新内核地址
					  (PVOID)((ULONG)pLoadKernelbuf + pSecHeadPoint->PointerToRawData),	//从文件内核拷贝
					  /*max(*/pSecHeadPoint->SizeOfRawData/*, pSecHeadPoint->Misc.VirtualSize)*/); //拷贝最大数值	
	}

	//内核重定位
	if (NtFixRelocaKernelEx(pNewKernelbuf, NtGetKernelBase(), uImageBase) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}

	//ServiceTable重定位
	if (NtFixServiceTable(pNewKernelbuf, NtGetKernelBase()) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}
	//Iat修复
	if (NtFixImportTable(pNewKernelbuf) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}

	//释放
	NtUnLoadKernelFile(pLoadKernelbuf);
	return TRUE;
}



//
//内核重定位修复版
//
BOOLEAN NtFixRelocaKernelEx(PVOID NewKernel, ULONG OldBase, ULONG NewBase)
{

	//
	//参数检查
	//

	if (!MmIsAddressValid(NewKernel))
	{
		return FALSE;
	}

	
	ULONG ChangeAddress = 0;
	ULONG ChangeData = 0;
	ULONG ChangeOffset = OldBase - NewBase;

	WORD16* pHandleAddress = NULL;

	PIMAGE_NT_HEADER tNtHead = NULL;
	PIMAGE_BASE_RELOCATION	tRectable = NULL;

	

	tNtHead = PeGetNtHeader(NewKernel);

	//指向重定位表
	tRectable = (PIMAGE_BASE_RELOCATION)(tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress + (ULONG)NewKernel);

	for (tRectable;!IsStructEmpty(tRectable, sizeof(IMAGE_BASE_RELOCATION));tRectable = (PIMAGE_BASE_RELOCATION)((ULONG)tRectable + tRectable->SizeOfBlock))
	{

		//指向要修正的数据块表项
		pHandleAddress = (WORD16*)((DWORD32)tRectable + sizeof(IMAGE_BASE_RELOCATION));

		for (pHandleAddress; pHandleAddress < (WORD16*)((ULONG)tRectable + tRectable->SizeOfBlock); pHandleAddress++ /*每次2字节 sizeof(WORD16)*/)
		{
			//如果flag == IMAGE_REL_BASED_HIGHLOW-则需要修正4字节数据
			if ((*pHandleAddress & 0xf000) == IMAGE_REL_BASED_HIGHLOW * 0x1000)//x86重定位标记
			{
				//获取要修正的地址
				ChangeAddress = (*pHandleAddress & 0xfff) + tRectable->VirtualAddress + (ULONG)NewKernel;

				//获取要修正的内容
				ChangeData = *(PULONG)ChangeAddress;

				//写入修正后的数据
				*(PULONG)ChangeAddress = ChangeData + ChangeOffset;
			}
		}

	}


	return TRUE;
}



//
//内核重定位KeServiceTable
//
BOOLEAN NtFixServiceTable(IN PVOID NewKernel, ULONG OldBase/*老内核Mem镜像基址*/)
{

	//
	//参数检查
	//

	if (!MmIsAddressValid(NewKernel))
	{
		return FALSE;
	}
	if (OldBase == 0 )
	{
		return FALSE;
	}

	//
	//变量声明
	//
	
	ULONG i = 0;
	ULONG TableBase = 0;

	ULONG KeServiceTable = 0;
	ULONG KeServiceTableOffset = 0;

	PSYSTEM_SERVICE_TABLE OldServiceTable = NULL;
	PSYSTEM_SERVICE_TABLE NewServiceTable = NULL;

	//修正KeServiceTable 
	KeServiceTable = NtGetServiceDescriptor();

	if (KeServiceTable == 0)
	{
		return FALSE;
	}

	if (!MmIsAddressValid((PVOID)KeServiceTable))
	{
		return FALSE;
	}
	//__RELOCA__
	KeServiceTableOffset = KeServiceTable - OldBase;
	NewServiceTable = (PSYSTEM_SERVICE_TABLE)((ULONG)NewKernel + KeServiceTableOffset);
	OldServiceTable = (PSYSTEM_SERVICE_TABLE)KeServiceTable;


	//_CHECK_
	if (!MmIsAddressValid((PVOID)NewServiceTable))
	{
		return FALSE;
	}

	if (!MmIsAddressValid((PVOID)OldServiceTable))
	{
		return FALSE;
	}

	if (OldServiceTable->NumberOfService == 0)
	{
		return FALSE;
	}
	if (!MmIsAddressValid(OldServiceTable->ServiceTableBase))
	{
		return FALSE;
	}

	if (!MmIsAddressValid((PVOID)OldServiceTable->ParamTableBase))
	{
		return FALSE;
	}

	//Init g_NewTable Var
	g_NewTable = NewServiceTable;
	g_OldTable = OldServiceTable;


	//_RELOCA_TION_
	NewServiceTable->NumberOfService = OldServiceTable->NumberOfService;
	NewServiceTable->ServiceCounterTableBase = OldServiceTable->ServiceCounterTableBase;
	NewServiceTable->ParamTableBase = OldServiceTable->ParamTableBase - OldBase + (ULONG)NewKernel;
	NewServiceTable->ServiceTableBase = (PVOID)((ULONG)OldServiceTable->ServiceTableBase - OldBase + (ULONG)NewKernel);
	
	//_CHECK_
	if (!MmIsAddressValid((PVOID)NewServiceTable->ParamTableBase))
	{
		return FALSE;
	}
	if (!MmIsAddressValid(NewServiceTable->ServiceTableBase))
	{
		return FALSE;
	}

	//DbgPrint("------------------------Fix ServiceTable--------------------------------");
	//_RELOCA_TION_TABLE
	TableBase = (ULONG)NewServiceTable->ServiceTableBase;

	for (i = 0; i < NewServiceTable->NumberOfService; i++)
	{
		//DbgPrint("Index : %x OldAddress : %x", i, *(ULONG*)(TableBase + sizeof(PVOID)*i));
		*(ULONG*)(TableBase + sizeof(PVOID)*i) = *(ULONG*)(TableBase + sizeof(PVOID)*i) - OldBase + (ULONG)NewKernel;
		//DbgPrint("NewAddress : %x \n", *(ULONG*)(TableBase + sizeof(PVOID)*i));
	}

	//_COPY_PARAM_TABLE_NOTHING
	RtlCopyMemory((PVOID)NewServiceTable->ParamTableBase, (PVOID)OldServiceTable->ParamTableBase, NewServiceTable->NumberOfService);

	
	return TRUE;
}


//
//过滤KiFastCallEntry
//

ULONG  NtFilterKiFastCallEntry(ULONG TableBase, ULONG FucIndex, ULONG OrigFuncAddress)
{
	//eax -> Index
	//edi -> TableBase	
	//edx -> FncAddress
	//ecx -> Number of argument 



	

	if (TableBase == (ULONG)g_OldTable->ServiceTableBase)
	{

		
		if (PsGetCurrentProcessId() == (HANDLE)2636)
		{
			//
			//return New Table fnc Address
			//
			return *(ULONG*)((ULONG)g_NewTable->ServiceTableBase + sizeof(PVOID)*FucIndex);
		}
		else{

			//return OrigFuncAddress;
			return OrigFuncAddress;
		}

		
	}
	else{
		//
		//ServiceTable  Shadow
		//

		//NULL
		return OrigFuncAddress;
	}


}


//
//New KiFastCallEntry
//


__declspec(naked)VOID NtNewKiFastCallEntry()

{

	__asm{
			pushad
			pushfd
				
				push	edx	//OldAddress
				push	eax //Index
				push	edi //TableBase

				//StdCall
				call	NtFilterKiFastCallEntry
				//Result Eax -> FilterFncAddress

				mov[esp + 0x18], eax //Copy Eax -> Stack -> Edx

			popfd
			popad	


			sub     esp, ecx
			shr     ecx, 2

			//Jump Old Address
			jmp		Jmp_KiFastCall
	}
}


//
//Search KiFastCallEntry Hook Point 
//
ULONG NtGetKiFastCallEntryHookPointer()
{

	ULONG  i = 0;
	UCHAR *p = NULL;

	ULONG KiFastCallEntry = 0;

	//KeSetSystemAffinityThread(0);

	_asm{

		push eax
		push ebx
		push ecx
			
			xor eax,eax
			xor ebx,ebx
			xor ecx,ecx

			lea ebx, KiFastCallEntry

			mov ecx, 0x176 //IA32_SYSENTER_EIP
			rdmsr 

			mov dword ptr[ebx],eax

		pop ecx
		pop ebx
		pop eax
	}

	ASSERT(KiFastCallEntry);

	for (i = 0; i < PAGE_SIZE; i++)
	{
		p = (UCHAR *)(KiFastCallEntry + i);

		if (*p == 0x2B &&
			*(p + 1) == 0xE1 &&
			*(p + 2) == 0xC1 &&
			*(p + 3) == 0xE9 &&
			*(p + 4) == 0x02)
		{
			return (ULONG)p;
		}
	}

	return 0;
}


//
//Set Inline Hook KiFastCallEntry
//
BOOLEAN NtSethookKiFastCallEntry(ULONG HookPointer,PVOID Newfnc)
{

	//
	//Check Var 
	//

	if (!MmIsAddressValid((PVOID)HookPointer))
	{
		return FALSE;
	}

	if (!MmIsAddressValid(Newfnc))
	{
		return FALSE;
	}


	ULONG	temp;
	UCHAR	Jump[5];

	//Init Jump opcode
	Jump[0] = 0xE9;

	//Calc Jmp Offset
	temp = (ULONG)Newfnc - HookPointer - 5;

	//Load Code
	*(ULONG*)&Jump[1] = temp;

	//Write Code
	PageProtectOff();

	RtlCopyMemory((PVOID)HookPointer, Jump, 5);

	PageProtectOn();

	return TRUE;
}

//
//Cancel Inline Hook KiFastCallEntry
//
BOOLEAN NtCancelhookKiFastCallEntry()
{

	//
	//Check Var
	//

	if (!MmIsAddressValid((PVOID)g_FastCallHookPointer))
	{
		return FALSE;
	}
	
	//Init Old Code
	UCHAR	code[5] = { 0x2B, 0xE1, 0xC1, 0xE9, 0x02 };

	//Write Code
	EnableWrite();
	//PageProtectOff();

	RtlCopyMemory((PVOID)g_FastCallHookPointer, code, 5);

	//PageProtectOn();
	DisableWrite();
	return TRUE;
}



//
//内核重载KiFastCallEntry
//

BOOLEAN NtFixKiFastCallEntry(PVOID ProtectProcessName)
{


	//
	//Init Hook Data
	//

	g_FastCallHookPointer = NtGetKiFastCallEntryHookPointer();

	if (g_FastCallHookPointer == 0)
	{
		return FALSE;
	}

	Jmp_KiFastCall = g_FastCallHookPointer + 5;

	//Set Hook 
	
	if (NtSethookKiFastCallEntry(g_FastCallHookPointer, (PVOID)NtNewKiFastCallEntry) == FALSE)
	{
		return FALSE;
	}


	g_ProtectProcessName = ProtectProcessName;

	return TRUE;
}

//
//内核重载还原KiFastCallEntry
//
BOOLEAN NtRestoreKiFastCallEntry()
{


	if (g_FastCallHookPointer == 0)
	{
		return FALSE;
	}


	return NtCancelhookKiFastCallEntry();
}


