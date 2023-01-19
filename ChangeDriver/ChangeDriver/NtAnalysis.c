#include <NtAnalysis.h>
#include <NtProcess.h>


#pragma comment (lib,"ntdll.lib") 







//
//ȫ�ֱ���
//

KIRQL OldIrql;
KSPIN_LOCK Lock;
KAPC_STATE ApcState;


//�ں�������ر���--------------------------------------------
//-------------------------------------------------------------
//OldTable
PSYSTEM_SERVICE_TABLE g_OldTable = NULL;
PSYSTEM_SERVICE_TABLE g_OldTableShadow = NULL;

//NewTable
PSYSTEM_SERVICE_TABLE g_NewTable = NULL;
PSYSTEM_SERVICE_TABLE g_NewTableShadow = NULL;

//Hook��ַ
ULONG g_FastCallHookPointer = 0;

//����->��������
PVOID g_ProtectProcessName = NULL;

//Hook��ķ��ص�ַ
ULONG Jmp_KiFastCall = 0;
//-------------------------------------------------------------



//
//��ȡϵͳ�汾
//
SYSTEM_VERSION NtGetSystemVerSion()
{

	NTSTATUS status;
	RTL_OSVERSIONINFOW OsVerSionInfo;

	RtlZeroMemory((PVOID)&OsVerSionInfo, sizeof(RTL_OSVERSIONINFOW));

	//��ȡϵͳ�汾��Ϣ
	status = RtlGetVersion(&OsVerSionInfo);

	//Check status
	if (!NT_SUCCESS(status))
	{
		//��ȡʧ��
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
//����ssdt��д
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
//����ssdt����д
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
	 __asm{//�ָ��ڴ汣��  
		 mov  eax, cr0
			 or   eax, 10000h
			 mov  cr0, eax
			 sti
	 }
 }

 void PageProtectOff()
 {
	 __asm{//ȥ���ڴ汣��
		 cli
			 mov  eax, cr0
			 and  eax, not 10000h
			 mov  cr0, eax
	 }
 }

 //
 //�ַ�����,����֧��256
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

	 //ת��ΪСд
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
 //�жϽṹ�Ƿ�Ϊ��
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
 //��ȡ�ں�ģ�����,����ģ������
 //

 ULONG NtGetModulBase(PVOID ModulName)
 {
	 //
	 //�������
	 //
	 if (!MmIsAddressValid(ModulName))
	 {
		 return 0;
	 }

	

	 ULONG i = 0;
	 ULONG Result = 0;

	 ULONG NeedLen = 0;
	 PVOID InfoBuffer = NULL;


	 //��ȡ��Ҫ���ڴ��С
	 ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	 //�����ڴ�
	 InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	 if (InfoBuffer == NULL)
	 {
		 RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		 return 0;
	 }

	 //��ȡϵͳ��Ϣ
	 ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	 PSYSTEM_MODULE_INFORMATION pModules;

	 //��ȡģ��
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
//��ָ���ں�ģ����������������ַ
//
 ULONG NtGetModulProcAddress(PVOID Modul,PVOID FncName) 
{


	 //
	 //�������
	 //

	 if (!MmIsAddressValid(Modul))
	 {
		 return 0;
	 }

	 if (!MmIsAddressValid(FncName))
	 {
		 return 0;
	 }


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
	 tNtHead = PeGetNtHeader(Modul);
	 ExporTable = tNtHead->OptionalHeader.DataDirectory[0].VirtualAddress;

	 //��ȡ�������ַ
	 tExportDirect = (PIMAGE_EXPORT_DIRECTORY)(PeTakeOutPoint(Modul) + ExporTable);

	 //��ʼ������Ա����,�����ǳ�Ա��Ŀ
	 OrdinalsBase = tExportDirect->Base;
	 NumberOfNames = tExportDirect->NumberOfNames;
	 NumberOfFnc = tExportDirect->NumberOfFunctions;

	 //��ȡ���������Ա��ַ
	 FncTable = tExportDirect->AddressOfFunctions + PeTakeOutPoint(Modul);
	 NameTable = tExportDirect->AddressOfNames + PeTakeOutPoint(Modul);
	 OrdinaTable = tExportDirect->AddressOfNameOrdinals + PeTakeOutPoint(Modul);


	 //--------------------------------------------------------------------------------------------------------------------------------------------

	 //��ʼ����������


	 //����Ա��Ϣ
	 ULONG fncIndex = 0;
	 ULONG onlIndex = 0;
	 ULONG Ordinals = 0;
	 ULONG fncAddress = 0;
	 ULONG Namefoa = 0;


	 //������Ϣ
	 BOOLEAN IsName = FALSE;
	 

	 //������Ϣ���õ���������ַ


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

			 //��ȡ���ֵ�ַ
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
//��ȡ�ں˻�ַ
//

ULONG NtGetKernelBase()
{
	
	ULONG NeedLen = 0; //����Ҫ��ʵ�ʴ�С
	ULONG Result = 0; //����ֵ
	PVOID InfoBuffer = NULL; //������Ϣ��Buffer
	

	//��ȡ��Ҫ���ڴ��С
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//�����ڴ�
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//��ȡϵͳ��Ϣ
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);
	
	PSYSTEM_MODULE_INFORMATION pModules;

	//��ȡģ��
	pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;

	//��ȡ��ַ
	Result = (DWORD32)pModules->Module[0].Base;

	if (Result == 0)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}
	
	//��������
	return Result;
}


//
//��ȡWin32K��ַ
//
ULONG NtGetWin32kBase()
{
	ULONG i = 0;
	ULONG Result = 0;

	ULONG NeedLen = 0; 
	PVOID InfoBuffer = NULL; 
	
	ANSI_STRING Win32k;

	RtlInitAnsiString(&Win32k, "\\SystemRoot\\System32\\win32k.sys");

	//��ȡ��Ҫ���ڴ��С
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//�����ڴ�
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//��ȡϵͳ��Ϣ
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	PSYSTEM_MODULE_INFORMATION pModules;

	//��ȡģ��
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
//��ȡ�ں��ļ�����
//
ULONG NtGetKernelName(IN OUT PANSI_STRING pKernelName)
{
	ULONG NeedLen = 0; //����Ҫ��ʵ�ʴ�С
	ULONG NameStrlen = 0;
	PVOID SearchPoint = 0;
	PVOID NameBuffer = NULL;
	PVOID InfoBuffer = NULL; //������Ϣ��Buffer
	ANSI_STRING SearName;
	//��ȡ��Ҫ���ڴ��С
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &NeedLen);

	//�����ڴ�
	InfoBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, NeedLen, 1024);

	if (InfoBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//��ȡϵͳ��Ϣ
	ZwQuerySystemInformation(SystemModuleInformation, (PVOID)InfoBuffer, NeedLen, &NeedLen);

	PSYSTEM_MODULE_INFORMATION pModules;

	//��ȡģ��
	pModules = (PSYSTEM_MODULE_INFORMATION)InfoBuffer;

	//��ȡ�����ڴ��ַ
	NameBuffer = &pModules->Module[0].ImageName;

	//�и��ַ���
	RtlInitAnsiString(&SearName, "system32");
	SearchPoint = strstr(NameBuffer, SearName.Buffer);

	//Ѱ���ַ���ʧ��
	if (SearchPoint == NULL)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//����bufferλ��
	NameBuffer = (PVOID)(PeTakeOutPoint(SearchPoint) + 9);

	//��ȡ���Ƴ���
	NameStrlen = PeAnsiStrlen(NameBuffer);


	//��������
	pKernelName->Buffer = ExAllocatePoolWithTag(NonPagedPool, NameStrlen+1, 1024);

	if (pKernelName->Buffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return 0;
	}

	//�ڴ���0
	RtlZeroMemory(pKernelName->Buffer, NameStrlen+1);
	//�����ַ���
	RtlCopyMemory(pKernelName->Buffer, NameBuffer, NameStrlen+1);

	//�����ַ�����Ϣ
	pKernelName->Length =(USHORT) NameStrlen;
	pKernelName->MaximumLength =(USHORT) NameStrlen+1;


	//��������
	return 1;
}


//
//��ȡ�ں��ļ����ڴ�
//
PVOID NtLoadKernelFile()
{
	//�ַ�����Ϣ
	ULONG tStrlen = 0;
	ULONG tStrlen2 = 0;
	ULONG tMaxlen = 0;
	PVOID tBuffer = 0;

	//�ں��ļ�����
	ANSI_STRING KernelName;
	UNICODE_STRING	KernelPath;
	UNICODE_STRING  KernelPath1;
	
	//check value 

	NTSTATUS Status;

	//�Ȼ�ȡ�ں��ļ�����

	if (!NtGetKernelName(&KernelName))
	{
		//��ȡʧ��

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return NULL;
	}

	//��ʼ���ַ���
	RtlInitUnicodeString(&KernelPath1, L"\\SystemRoot\\system32\\");

	//����·�������ڴ��С
	tStrlen = KernelPath1.Length + KernelName.Length * 2;
	tStrlen2 = KernelPath1.Length;
	tMaxlen = KernelPath1.MaximumLength + KernelName.Length * 2 + 2;

	//Ϊ���ַ��������ڴ�
	tBuffer = ExAllocatePoolWithTag(NonPagedPool, tMaxlen, 1024);

	if (tBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);
		return NULL;
	}

	//�������ַ�����Ϣ

	KernelPath.Buffer = tBuffer;
	KernelPath.Length = (USHORT)tStrlen;
	KernelPath.MaximumLength = (USHORT)tMaxlen;


	//�����ַ����Ա����������
	RtlCopyMemory(KernelPath.Buffer, KernelPath1.Buffer, KernelPath1.Length);


	//�ַ���ת��
	Status = RtlAnsiStringToUnicodeString(&KernelPath1, &KernelName, TRUE);

	if (Status != STATUS_SUCCESS)
	{
		//ת��ʧ��

		//�����ͷ�֮ǰ��KernelName
		ExFreePoolWithTag(KernelName.Buffer, 1024);
		KernelName.Buffer = NULL;
		KernelName.Length = 0;
		KernelName.MaximumLength = 0;

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return NULL;
	}




	//�����ͷ�֮ǰ��KernelName
	ExFreePoolWithTag(KernelName.Buffer, 1024);
	KernelName.Buffer = NULL;
	KernelName.Length = 0;
	KernelName.MaximumLength = 0;


	//����
	RtlCopyMemory((PVOID)(PeTakeOutPoint(KernelPath.Buffer) + tStrlen2), KernelPath1.Buffer, KernelPath1.Length);


	//--------------------------------------------------------------------------------------------------------------------------

	//��ȡ�ļ�


	//�ļ����
	HANDLE hFile = NULL;
	//������
	PVOID  FileBuffer = NULL;
	//IO״̬
	IO_STATUS_BLOCK ioStatus;
	//�ļ�����
	OBJECT_ATTRIBUTES fileInfo;
	//�ļ���Ϣ
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//��ʼ���ļ�����
	InitializeObjectAttributes(&fileInfo, &KernelPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//���ļ�
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//ȷ���Ƿ��ʧ��
	if (ioStatus.Information != 1)
	{
		//�ļ���ʧ��
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//��ȡ�ļ���Ϣ
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//ȷ���Ƿ��ȡʧ��
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//��ȡ�ļ���Ϣʧ��,�ص��ļ����

		ZwClose(hFile);

		return NULL;
	}

	//�����ļ�������,׼����ȡ�ļ�
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//�����ڴ�ʧ��,�ص����
		ZwClose(hFile);

		return NULL;
	}

	//�ڴ���0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//��ȡ�ļ�
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//��ȡ�ļ�ʧ��,�ص����

		ZwClose(hFile);
		return NULL;
	}



	//�ص����
	ZwClose(hFile);


	//�ͷ��ڴ�
	ExFreePoolWithTag(KernelPath.Buffer, 1024);
	KernelPath.Buffer = NULL;
	KernelPath.Length = 0;
	KernelPath.MaximumLength = 0;

	RtlFreeUnicodeString(&KernelPath1);

	//��������
	return FileBuffer;
}


//
//���ڴ�ж���ں��ļ�
//
PVOID NtUnLoadKernelFile(PVOID pBuffer)
{

	//
	//�������
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//�ͷ��ڴ�
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;
	return pBuffer;
}

//
//��ȡNtdll���ڴ�
//

PVOID NtLoadNativeFile()
{
	
	//�ļ�·��
	UNICODE_STRING NativePath;

	//�ļ����
	HANDLE hFile = NULL;
	//������
	PVOID  FileBuffer = NULL;
	//IO״̬
	IO_STATUS_BLOCK ioStatus;
	//�ļ�����
	OBJECT_ATTRIBUTES fileInfo;
	//�ļ���Ϣ
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//״̬
	NTSTATUS Status;

	//��ʼ���ļ�·��
	RtlInitUnicodeString(&NativePath, L"\\SystemRoot\\system32\\ntdll.dll");

	//��ʼ���ļ�����
	InitializeObjectAttributes(&fileInfo, &NativePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//���ļ�
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//ȷ���Ƿ��ʧ��
	if (ioStatus.Information != 1)
	{
		//�ļ���ʧ��
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//��ȡ�ļ���Ϣ
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//ȷ���Ƿ��ȡʧ��
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//��ȡ�ļ���Ϣʧ��,�ص��ļ����

		ZwClose(hFile);

		return NULL;
	}

	//�����ļ�������,׼����ȡ�ļ�
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//�����ڴ�ʧ��,�ص����
		ZwClose(hFile);

		return NULL;
	}

	//�ڴ���0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//��ȡ�ļ�
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//��ȡ�ļ�ʧ��,�ص����

		ZwClose(hFile);
		return NULL;
	}



	//�ص����
	ZwClose(hFile);


	//��������
	return FileBuffer;
}

//
//���ڴ�ж��Ntdll
//
PVOID NtUnLoadNativeFile(PVOID pBuffer)
{
	//
	//�������
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//�ͷ��ڴ�
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;

	return pBuffer;
}

//
//��ȡWin32K���ڴ�
//

PVOID NtLoadWin32kFile()
{
	//�ļ�·��
	UNICODE_STRING NativePath;

	//�ļ����
	HANDLE hFile = NULL;
	//������
	PVOID  FileBuffer = NULL;
	//IO״̬
	IO_STATUS_BLOCK ioStatus;
	//�ļ�����
	OBJECT_ATTRIBUTES fileInfo;
	//�ļ���Ϣ
	FILE_STANDARD_INFORMATION fsi = { 0 };

	//״̬
	NTSTATUS Status;

	//��ʼ���ļ�·��
	RtlInitUnicodeString(&NativePath, L"\\SystemRoot\\system32\\win32k.sys");

	//��ʼ���ļ�����
	InitializeObjectAttributes(&fileInfo, &NativePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//���ļ�
	Status = ZwCreateFile(&hFile, GENERIC_READ, &fileInfo, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//ȷ���Ƿ��ʧ��
	if (ioStatus.Information != 1)
	{
		//�ļ���ʧ��
		RstatusPrint(NT_STATUS_OPENFILE_ERROR);
		return NULL;
	}

	//��ȡ�ļ���Ϣ
	ZwQueryInformationFile(hFile, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	//ȷ���Ƿ��ȡʧ��
	if ((LONG)fsi.EndOfFile.QuadPart == 0)
	{

		RstatusPrint(NT_STATUS_GETFILESIZE_ERROR);

		//��ȡ�ļ���Ϣʧ��,�ص��ļ����

		ZwClose(hFile);

		return NULL;
	}

	//�����ļ�������,׼����ȡ�ļ�
	FileBuffer = ExAllocatePoolWithTag(NonPagedPool, (size_t)fsi.EndOfFile.QuadPart, 1024);


	if (FileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_MALLOCPOOL_ERROR);

		//�����ڴ�ʧ��,�ص����
		ZwClose(hFile);

		return NULL;
	}

	//�ڴ���0
	RtlZeroMemory(FileBuffer, (size_t)fsi.EndOfFile.QuadPart);

	//��ȡ�ļ�
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, FileBuffer, (size_t)fsi.EndOfFile.QuadPart, 0, NULL);

	if (Status != STATUS_SUCCESS)
	{
		RstatusPrint(NT_STATUS_READFILE_ERROR);

		//��ȡ�ļ�ʧ��,�ص����

		ZwClose(hFile);
		return NULL;
	}



	//�ص����
	ZwClose(hFile);


	//��������
	return FileBuffer;
}

//
//���ڴ�ж��Win32k
//
PVOID NtUnloadWin32kFile(PVOID pBuffer)

{
	//
	//�������
	//

	if (!MmIsAddressValid(pBuffer))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return NULL;
	}

	//�ͷ��ڴ�
	ExFreePoolWithTag(pBuffer, 1024);
	pBuffer = NULL;

	return pBuffer;

}

//
//��ȡKeServiceDescriptorTable
//

ULONG NtGetServiceDescriptor()
{
	//�ں��ļ�������
	PVOID pFileBuffer = NULL;

	//�ں˻�ַ
	ULONG tKernelBase = 0;

	//Ҫ�������ִ�
	ANSI_STRING tSearchName = { 0 };

	//���ػ�ȡ���ĵ�ַ��Ϣ
	EXPORT_SEARCH_VALUE tExportSearchValue;

	//����״̬
	ULONG Value = 0;

	//��ʼ���ִ�
	RtlInitAnsiString(&tSearchName, "KeServiceDescriptorTable");

	//��ȡ�ں��ļ�
	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		//��ȡ�ں��ļ�ʧ��
		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
			
	}

	//����������
	Value = PeSearchExportTable(pFileBuffer, &tSearchName, &tExportSearchValue);

	if (!Value)
	{
		//����������ʧ��
		RstatusPrint(PE_STATUS_SEARCHEXPORT_ERROR);
		return 0;
	}

	//��ȡ�ں˻�ַ

	tKernelBase = NtGetKernelBase();

	if (tKernelBase == 0)
	{
		//��ȡ�ں˻�ַʧ��
		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);
		return 0;
	}

	//����KeServiceDescriptorTable��ַ

	Value = tExportSearchValue.VirtualAddress + tKernelBase;

	//�ͷ��ڴ�

	NtUnLoadKernelFile(pFileBuffer);


	//��������

	return Value;
}

//
//��ȡssdt��Դ��ַ�����ļ���ȡ
//

ULONG NtGetServiceFormFile()
{
	
	//�ں��ļ�����
	PVOID pFileBuffer = NULL;

	//���� KeServiceDescriptorTable ƫ���õ�������,�����ض�λ����
	ULONG tKernelBase = 0;
	ULONG tImageBase = 0;
	ULONG tpfncRva = 0;
	ULONG tpfncAddress = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;

	//��������
	ULONG Value = 0;


	//��ȡ�ں��ļ�
	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		//��ȡ�ں��ļ�ʧ��
		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
	}

	//��ȡ�ں˻�ַ
	tKernelBase = NtGetKernelBase();

	if (tKernelBase == 0)
	{
		//��ȡ�ں˻�ַ ʧ�� 

		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);

		return 0;
	}

	//��ȡNtͷ
	tNtHead = PeGetNtHeader(pFileBuffer);

	//��ȡImageBase

	tImageBase = tNtHead->OptionalHeader.ImageBase;

	//����KeServiceDescriptorTableƫ��,���ض�λ����ָ�������
	tpfncAddress = NtGetServiceDescriptor();

	if (tpfncAddress == 0)
	{
		//ʧ��

		RstatusPrint(NT_STATUS_RESULT_ERROR);

		return 0;
	}

	//�����Ҫ�����ض�λ����
	tpfncRva = tpfncAddress - tKernelBase + tImageBase;

	//----------------------------------------------------------------------------------------------------------------------------------------

	//�����ض�λ��

	//�ض�λ���ַ
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//��������
	ULONG tIndex = 0;

	//�ض�λ������Ϣ

	ULONG MemberRva = 0; //ÿһ�������RVA
	ULONG ChangeFoa = 0; //Ҫ�����ĵ�ַ(FOA)
	ULONG ChangeData = 0; //Ҫ����������
	ULONG ChangeRva = 0; //Ҫ�����ĵ�ַ (RVA)

	//���ݿ���λ��
	ULONG CopyPoint = 0;


	//���������Ϣ
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	//���ڶ�λSSDT,������
	ULONG dwCode = 0x05c7;
	ULONG Code = 0;


	//��λ�ض�λ��

	RelocaTable = PeRvaToFileOffset(pFileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(pFileBuffer);
	RelocaBase = RelocaTable;


	//��ʼ����


	while (1)
	{
		//��λ�ض�λ����

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//ȷ���Ƿ��������
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//��ʼ����������
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//ÿһ������RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//ÿһ�������Ա��
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//��ʼ�����ݿ���λ��

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//���Ҫ�����ĵ�ַ

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//ȡ��12λΪƫ�� + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//����Ҫ������ַFOA
			ChangeFoa = PeRvaToFileOffset(pFileBuffer, ChangeRva);

			//��ȡҪ����������
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa), sizeof(ULONG));

			//�ؼ�������λ
			if (ChangeData == tpfncRva)
			{
				//�����λ�ɹ�����ȡǰ�ֽڣ�����������ȷ��
				RtlCopyMemory(&Code, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa - 2), sizeof(WORD16));

				//�����붨λ
				if (Code == dwCode)
				{
					//�����λ�ɹ�,��ȡSSDT��ַ
					RtlCopyMemory(&Value, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa + 4), sizeof(ULONG));

					//��λ�ļ�SSDT
					Value = PeRvaToFileOffset(pFileBuffer, Value - tNtHead->OptionalHeader.ImageBase);

					//�ͷ��ڴ�
					NtUnLoadKernelFile(pFileBuffer);

					//��������
					return Value;
				}

			}

		}

		//trace
		RelocaBase = RelocaBase + SizeOfBlock;

	}

	
	//�ͷ��ڴ�
	NtUnLoadKernelFile(pFileBuffer);

	//��������
	return Value;
}


//
//ö��SSDT
//

ULONG NtEnumeServiceTable(IN OUT PSERVICETABLE pServiceTable)
{
	
	//
	//�������
	//

	if (!MmIsAddressValid(pServiceTable))
	{
		RstatusPrint(NT_STATUS_INVALID_PARAMETE);
		return 0;
	}


	//�ں��ļ�����
	PVOID pKernelBuffer = NULL; //�ں��ļ�
	PVOID pNativeBuffer = NULL; //�ں�DLL


	//ȫ��Э����������Ϣ
	PSYSTEM_SERVICE_TABLE pServiceDescriptor = NULL;
	PVOID ServiceTableBase = NULL;
	ULONG NumberOfService = 0;
	ULONG ServiceDescriptor = 0;

	//������Ϣ
	ULONG FileOffsetTable = 0; // �ļ���SSDTƫ��

	//���ص�����
	PVOID MemServiceTable = NULL;
	PVOID FileServiceTable = NULL;
	PANSI_STRING_LIST_HEADER pfncListHead = NULL;

	
	//�ض�λ�õ�������
	ULONG tIndex = 0;
	ULONG tImageBase = 0;
	ULONG tKernelBase = 0;
	ULONG tRelocaPoint = 0;
	ULONG tRelocaData = 0;
	PIMAGE_NT_HEADER tNtHead = NULL;




	//��ʼ��������Ϣ

	//��ȡKeServiceDescriptor
	ServiceDescriptor = NtGetServiceDescriptor();

	if (ServiceDescriptor == 0)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//��ʼ����Ϣ
	pServiceDescriptor = (PSYSTEM_SERVICE_TABLE)ServiceDescriptor;
	//��������
	NumberOfService = pServiceDescriptor->NumberOfService;
	//��ĵ�ַ
	ServiceTableBase = pServiceDescriptor->ServiceTableBase;


	//���䷵�������ڴ��

	//�ڴ�SSDT
	MemServiceTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfService, 1024);
	//�ļ�SSDT
	FileServiceTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*NumberOfService, 1024);
	//��������
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



	//�����ļ����ڴ�

	//�ں��ļ�
	pKernelBuffer = NtLoadKernelFile();
	//Native�ļ�
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


	//��ʼ�����ڴ��е�SSDT

	EnableWrite();

	//��������
	RtlCopyMemory(MemServiceTable, ServiceTableBase, sizeof(ULONG)*NumberOfService);

	DisableWrite();

	
	//��ʼ�����ļ��е�SSDT

	//��ȡ�ļ�SSDT
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

	//�����ַ
	FileOffsetTable = FileOffsetTable + PeTakeOutPoint(pKernelBuffer);

	//�����ļ�SSDT����

	RtlCopyMemory(FileServiceTable, (PVOID)FileOffsetTable, sizeof(ULONG)*NumberOfService);

	//�ض�λ�ļ�SSDT

	//��ȡ������Ϣ

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
		//��λҪ�ض�λ�ĵ�ַ
		tRelocaPoint = PeTakeOutPoint(FileServiceTable) + sizeof(ULONG) * tIndex;
		//��ȡҪ�ض�λ������
		RtlCopyMemory(&tRelocaData, (PVOID)tRelocaPoint, sizeof(ULONG));
		//�ض�λ����
		tRelocaData = tRelocaData - tImageBase + tKernelBase;
		//д�᷵������
		RtlCopyMemory((PVOID)tRelocaPoint, &tRelocaData, sizeof(ULONG));
	}


	//���ں��ļ�ж��
	NtUnLoadKernelFile(pKernelBuffer);



	//�������NTDLL.DLL ��ȡ��������

	EXPORT_DIRECTORY ExportDirectory ;
	PANSI_STRING_LIST_HEADER pExportNameList = NULL;
	PANSI_STRING_LIST_ENTRY  pListEntry = NULL;

	//����ȷ���Ƿ�ΪZw��ͷ�ĺ������Ա��ظ�
	ANSI_STRING ZwFlag = { 0 };

	//�����������Ϣ
	PVOID pfncRvaTable = NULL;
	PVOID pOrdlnalsTable = NULL;
	ULONG NumberOfFnc = 0;

	//����������ַ
	ULONG fncRva = 0;
	ULONG fncFoa = 0;

	//����ȷ��,SSDT������� �����ȡ���ĺ������
	ULONG fncIndex = 0;
	ULONG tMachineCode = 0;

	//�����õ�������
	ULONG tGetCount = 0;
	//�Ƿ��ٴα���
	BOOLEAN TraceEnd = TRUE;


	//��ʼ��������Ϣ
	//Zw������־
	RtlInitAnsiString(&ZwFlag, "Zw");

	//��ȡ������
	NumberOfFnc = PeGetExportTable(pNativeBuffer, &ExportDirectory);

	//Check Result
	if (NumberOfFnc == 0)
	{
		//ʧ��,ж��Ntdll
		NtUnLoadNativeFile(pNativeBuffer);
		ExFreePoolWithTag(MemServiceTable, 1024);
		ExFreePoolWithTag(FileServiceTable, 1024);
		ReleaseAnsiList(pfncListHead);

		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//�����������Ϣ

	pfncRvaTable = ExportDirectory.pfncRvaTable;
	pOrdlnalsTable = ExportDirectory.OrdlnalsTable;
	pExportNameList = ExportDirectory.pfncNamelist;
	
	//����������ʼ����
	pListEntry = pExportNameList->pNextEntry;



	while (TraceEnd)
	{
		for (tIndex = 0; tIndex < NumberOfFnc; tIndex++)
		{
			//�ӵ������ȡ����rva
			RtlCopyMemory(&fncRva, (PVOID)(PeTakeOutPoint(pfncRvaTable) + sizeof(ULONG)*tIndex), sizeof(ULONG));

			//ת��foa
			fncFoa = PeRvaToFileOffset(pNativeBuffer, fncRva) + PeTakeOutPoint(pNativeBuffer) ;

			//��ȡ���������������
			RtlCopyMemory(&fncIndex, (PVOID)fncFoa, sizeof(ULONG));

			//���������
			tMachineCode = fncIndex << 24;
			tMachineCode = tMachineCode >> 24;

			//�����붨λ
			if ((strstr(pListEntry->Datainfo.Buffer, ZwFlag.Buffer)) == NULL)
			{
				if (tMachineCode == 0xB8 && fncIndex >> 8 == tGetCount)
				{
					//���뷵������
					IncreaseAnsiList(pfncListHead, (PANSI_STRING)(&pListEntry->Datainfo));
					//��ȡ��������
					tGetCount++;
				}
			}

			//Trace
			pListEntry = pListEntry->pNext_Entry;
		}

		//�ж��Ƿ��ȡ��
		if (pfncListHead->NumberOfMerber != NumberOfService)
		{
			//û�л�ȡ��,������ȡ
			tIndex = 0;
			TraceEnd = TRUE;
			pListEntry = pExportNameList->pNextEntry;
		}
		else{
			//���
			break;
		}

	}

	
	//�ͷ��ڴ�
	NtUnLoadNativeFile(pNativeBuffer);
	PeReleaseExportTable(&ExportDirectory);
	
	//��������
	pServiceTable->NameList = pfncListHead;
	pServiceTable->FileServiceTable = FileServiceTable;
	pServiceTable->MemServiceTable = MemServiceTable;
	pServiceTable->NumberOfService = NumberOfService;


	return NumberOfService;
}

//
//�ͷ�ö����Ϣ
//

ULONG NtDeleteServiceTable(IN PSERVICETABLE pServiceTable)
{

	//
	//�������
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
//��ȡPspCidTable
//

ULONG NtGetPspCidTable()
{
	//�ں��ļ�������
	PVOID pFileBuffer = NULL;

	//PsLookupProcessByProcessId����
	ANSI_STRING fncName = { 0 };

	//������������Ϣ
	EXPORT_SEARCH_VALUE SearchValue = { 0 };

	//������Ϣ
	ULONG fncFoa = 0;
	ULONG KernelBase = 0;
	ULONG UnRelocaTable = 0;
	
	
	//��������
	ULONG Value = 0;
	ULONG PspCidTable = 0;


	//�����ں��ļ�

	pFileBuffer = NtLoadKernelFile();

	if (pFileBuffer == NULL)
	{
		RstatusPrint(NT_STATUS_RESULT_ERROR);
		return 0;
	}

	//
	//�Ȼ�ȡPsLookupProcessByProcessId�ļ�ƫ��,����������
	//
	
	//��ʼ���ַ���
	RtlInitAnsiString(&fncName, "PsLookupProcessByProcessId");

	//����������
	Value = PeSearchExportTable(pFileBuffer, &fncName, &SearchValue);

	if (Value == 0)
	{
		//�ͷ��ڴ�
		NtUnLoadKernelFile(pFileBuffer);
		RstatusPrint(PE_STATUS_SEARCHEXPORT_ERROR);
		return 0;
	}
	
	//��ȡ��Ϣ
	fncFoa = SearchValue.FileOffset;
	//�ں˻�ַ
	KernelBase = NtGetKernelBase();

	if (KernelBase == 0)
	{
		//�ͷ��ڴ�
		NtUnLoadKernelFile(pFileBuffer);
		RstatusPrint(NT_STATUS_GETKERNELBASE_ERROR);
		return 0;
	}


	//�����ض�λ��

	//�ض�λ���ַ
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//��������
	ULONG tIndex = 0;

	//�ض�λ������Ϣ

	ULONG MemberRva = 0; //ÿһ�������RVA
	ULONG ChangeFoa = 0; //Ҫ�����ĵ�ַ(FOA)
	ULONG ChangeData = 0; //Ҫ����������
	ULONG ChangeRva = 0; //Ҫ�����ĵ�ַ (RVA)

	//���ݿ���λ��
	ULONG CopyPoint = 0;


	//���������Ϣ
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;

	tNtHead = PeGetNtHeader(pFileBuffer);

	//��λ�ض�λ��
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(pFileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(pFileBuffer);
	RelocaBase = RelocaTable;


	//��ʼ����


	while (1)
	{
		//��λ�ض�λ����

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//ȷ���Ƿ��������
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//��ʼ����������
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//ÿһ������RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//ÿһ�������Ա��
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//��ʼ�����ݿ���λ��

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//���Ҫ�����ĵ�ַ

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//ȡ��12λΪƫ�� + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//����Ҫ������ַFOA
			ChangeFoa = PeRvaToFileOffset(pFileBuffer, ChangeRva);

			//��ȡҪ����������
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(pFileBuffer) + ChangeFoa), sizeof(ULONG));

			//�ؼ�������λ
			if (ChangeFoa > fncFoa)
			{
				//�����λ�ɹ�����ȡPspCidTable
				UnRelocaTable = ChangeData;
				//�ض�λ
				PspCidTable = UnRelocaTable - ImageBase + KernelBase;
				//�ͷ��ڴ�
				NtUnLoadKernelFile(pFileBuffer);

				//��������
				return PspCidTable;
				
			}

		}

		//trace
		RelocaBase = RelocaBase + SizeOfBlock;

	}

	//�ͷ��ڴ�
	NtUnLoadKernelFile(pFileBuffer);

	return 0;

}

//
//��ȡ Shadow Service Table Form File
//

PVOID NtGetShadowServiceFormFile(ULONG * Count)
{

	/*����Win32k.sys���ڴ棬�ڵ��������� KeAddSystemServiceTable ,��ú�����ַ.

	��Win32k.sys -> Entry Point ��ʼ�����������ض�λ��Ϣ,��λ������ KeAddSystemServiceTable��ַ

	�����ض�λ��Ϣ,���Shadw ServiceTable ��ַ,�ض�λ��ַ*/

	

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
	
	//�ض�λ���ַ
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//��������
	ULONG tIndex = 0;

	//�ض�λ������Ϣ

	ULONG MemberRva = 0; //ÿһ�������RVA
	ULONG ChangeFoa = 0; //Ҫ�����ĵ�ַ(FOA)
	ULONG ChangeData = 0; //Ҫ����������
	ULONG ChangeRva = 0; //Ҫ�����ĵ�ַ (RVA)

	//���ݿ���λ��
	ULONG CopyPoint = 0;


	//���������Ϣ
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;

	PIMAGE_NT_HEADER tNtHead = NULL;



	RtlInitAnsiString(&SearchName, "KeAddSystemServiceTable");

	//����Win32k.sys
	FileBuffer = NtLoadWin32kFile();

	//���������
	if (PeSearchImportTable(FileBuffer, &SearchName, &ImportSearchValue) == 0)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);
	
	//��ȡKeAddSystemServiceTable �����ַ,�Ա㶨λ������
	fncKeAddValue = ImportSearchValue.VirulAddress + NtHead->OptionalHeader.ImageBase;

	//�����ض�λ��,�ҵ�����KeAddSystemServiceTable ��λ��,��ΪΪstdcall����

	//�����ض�λ��


	tNtHead = PeGetNtHeader(FileBuffer);

	//��λ�ض�λ��
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	RelocaBase = RelocaTable;


	//��ʼ����


	while (1)
	{
		//��λ�ض�λ����

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//ȷ���Ƿ��������
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//��ʼ����������
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//ÿһ������RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//ÿһ�������Ա��
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//��ʼ�����ݿ���λ��

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//���Ҫ�����ĵ�ַ

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//ȡ��12λΪƫ�� + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//����Ҫ������ַFOA
			ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);

			//��ȡҪ����������
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

			//-------------------------------------------------------------------------------------

		

			//�����붨λ
			if (ChangeData == fncKeAddValue)
			{
				//�ɹ���λ

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

//��ȡShadow Table
start:


	if (TableRva == 0)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	}

	//��ȡ
	TableFoa = PeRvaToFileOffset(FileBuffer, TableRva) + PeTakeOutPoint(FileBuffer);
	TableFoa2 = TableFoa;

	//��������Table,����Count
	while (1)
	{

		TableValue = *(ULONG*)TableFoa;

		if (TableValue <= ImageBase)
		{
			break;
		}
		TableFoa = TableFoa + 0x4;
	}

	//�������������
	TableCount = (TableFoa - TableFoa2) / 4;

	//�����ڴ�
	Table = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*TableCount, 1024);

	if (Table == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	
	}

	//����Table

	RtlCopyMemory(Table, (PVOID)TableFoa2, sizeof(ULONG)*TableCount);

	//�ͷ��ڴ�
	NtUnloadWin32kFile(FileBuffer); 

	if (Count != NULL)
	{
		*Count = TableCount;
	}

	return Table;
}

//
//��ȡ Shardow Service Table Form Mem 
//
PVOID NtGetShadowServiceFormMem(ULONG* Count)
{
	//
	//�������
	//
	if (!MmIsAddressValid((PVOID)Count))
	{
		return NULL;
	}

	/*����Win32k.sys���ڴ棬�ڵ��������� KeAddSystemServiceTable ,��ú�����ַ.

	��Win32k.sys -> Entry Point ��ʼ�����������ض�λ��Ϣ,��λ������ KeAddSystemServiceTable��ַ

	�����ض�λ��Ϣ,���Shadw ServiceTable ��ַ,�ض�λ��ַ*/



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

	//�ض�λ���ַ
	ULONG RelocaTable = 0;
	ULONG RelocaBase = 0;

	//��������
	ULONG tIndex = 0;

	//�ض�λ������Ϣ

	ULONG MemberRva = 0; //ÿһ�������RVA
	ULONG ChangeFoa = 0; //Ҫ�����ĵ�ַ(FOA)
	ULONG ChangeData = 0; //Ҫ����������
	ULONG ChangeRva = 0; //Ҫ�����ĵ�ַ (RVA)

	//���ݿ���λ��
	ULONG CopyPoint = 0;


	//���������Ϣ
	ULONG SizeOfBlock = 0;
	ULONG Number = 0;

	ULONG ImageBase = 0;


	PIMAGE_NT_HEADER tNtHead = NULL;



	RtlInitAnsiString(&SearchName, "KeAddSystemServiceTable");

	//����Win32k.sys
	FileBuffer = NtLoadWin32kFile();

	//���������
	if (PeSearchImportTable(FileBuffer, &SearchName, &ImportSearchValue) == 0)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);

	//��ȡKeAddSystemServiceTable �����ַ,�Ա㶨λ������
	fncKeAddValue = ImportSearchValue.VirulAddress + NtHead->OptionalHeader.ImageBase;

	//�����ض�λ��,�ҵ�����KeAddSystemServiceTable ��λ��,��ΪΪstdcall����

	//�����ض�λ��


	tNtHead = PeGetNtHeader(FileBuffer);

	//��λ�ض�λ��
	ImageBase = tNtHead->OptionalHeader.ImageBase;
	RelocaTable = PeRvaToFileOffset(FileBuffer, tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress) + PeTakeOutPoint(FileBuffer);
	RelocaBase = RelocaTable;


	//��ʼ����


	while (1)
	{
		//��λ�ض�λ����

		PIMAGE_BASE_RELOCATION  tRelocaTable = (PIMAGE_BASE_RELOCATION)RelocaBase;

		//ȷ���Ƿ��������
		if (tRelocaTable->SizeOfBlock == 0 && tRelocaTable->VirtualAddress == 0)
		{
			//trace end
			break;
		}

		//��ʼ����������
		SizeOfBlock = tRelocaTable->SizeOfBlock;
		//ÿһ������RVA
		MemberRva = tRelocaTable->VirtualAddress;
		//ÿһ�������Ա��
		Number = (SizeOfBlock - 0x8) / 2 - 1;


		for (tIndex = 0; tIndex < Number; tIndex++)
		{
			//��ʼ�����ݿ���λ��

			CopyPoint = PeTakeOutPoint(tRelocaTable) + 0x8 + sizeof(WORD16)*tIndex;

			//���Ҫ�����ĵ�ַ

			RtlCopyMemory(&ChangeRva, (PVOID)CopyPoint, sizeof(WORD16));

			//ȡ��12λΪƫ�� + Rva 

			ChangeRva = ChangeRva << 20;
			ChangeRva = ChangeRva >> 20;
			ChangeRva = ChangeRva + MemberRva;

			//����Ҫ������ַFOA
			ChangeFoa = PeRvaToFileOffset(FileBuffer, ChangeRva);

			//��ȡҪ����������
			RtlCopyMemory(&ChangeData, (PVOID)(PeTakeOutPoint(FileBuffer) + ChangeFoa), sizeof(ULONG));

			//-------------------------------------------------------------------------------------



			//�����붨λ
			if (ChangeData == fncKeAddValue)
			{
				//�ɹ���λ

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

	//��ȡShadow Table
start:


	if (TableRva == 0)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;
	}

	//��ȡ
	TableFoa = PeRvaToFileOffset(FileBuffer, TableRva) + PeTakeOutPoint(FileBuffer);
	TableFoa2 = TableFoa;

	//��������Table,����Count
	while (1)
	{

		TableValue = *(ULONG*)TableFoa;

		if (TableValue <= ImageBase)
		{
			break;
		}
		TableFoa = TableFoa + 0x4;
	}

	//�������������
	TableCount = (TableFoa - TableFoa2) / 4;

	*Count = TableCount;

	//�����ڴ�
	Table = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG)*TableCount, 1024);

	if (Table == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		return NULL;

	}

	TableRva = TableRva + NtGetWin32kBase();




	//���ӵ�gui����

	Eprocess = NpLookupPorcessByName("explorer.exe");

	if (Eprocess == NULL)
	{
		NtUnloadWin32kFile(FileBuffer);
		ExFreePoolWithTag(Table, 1024);
		return NULL;
	}

	//��ʼ����
	KeInitializeSpinLock(&Lock);
	KeAcquireSpinLock(&Lock, &OldIrql);

	//���ӽ���
	KeStackAttachProcess(Eprocess, &ApcState);


	if (!MmIsAddressValid((PVOID)TableRva))
	{
		NtUnloadWin32kFile(FileBuffer);
		ExFreePoolWithTag(Table, 1024);
		return NULL;
	}


	//���Կ�������
	RtlCopyMemory(Table, (PVOID)TableRva, sizeof(ULONG)*TableCount);

	//�������
	KeUnstackDetachProcess(&ApcState);
	//�ͷ���
	KeReleaseSpinLock(&Lock, OldIrql);


	return Table;
}


//
//��ȡ���� Shadow Service Table ��Ҫ�ض�λ
//
PVOID NtRelocaShadowServiceTable(PVOID Table, ULONG Count)
{
	//
	//�������
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

	//�����ں��ļ�
	FileBuffer = NtLoadWin32kFile();

	if (FileBuffer == NULL)
	{
		return NULL;
	}

	NtHead = PeGetNtHeader(FileBuffer);


	//
	//��ȡWin32k��ַ
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
//ö��Service Table Shaodw
//

ULONG NtEnumeServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow)
{

	//
	//�������
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
//ɾ�� Service Table Shaodw
//

ULONG NtDelectServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow)
{
	//
	//�������
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
//���ص����
//
BOOLEAN NtFixImportTable(IN PVOID NewKernel)
{

	//
	//�������
	//
	if (!MmIsAddressValid(NewKernel))
	{
		return FALSE;
	}


	//--------------------------------------------------------------------------------------------------------------------------------------------

	//��ʼ������������Ϣ

	//�����λ��
	ULONG ImportTable = 0; //�ļ��е�����ƫ��

	ULONG dllNumber = 0; //����DLL������



	PIMAGE_NT_HEADER tNtHead = NULL;

	//��λ�����λ��
	tNtHead = PeGetNtHeader(NewKernel);
	ImportTable = tNtHead->OptionalHeader.DataDirectory[1].VirtualAddress + PeTakeOutPoint(NewKernel);


	//���DLL������
	dllNumber = PeGetMemorySize((PVOID)ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);


	//----------------------------------------------------------------------------------------------------------------------------------------------



	//����������Ϣ
	ULONG tThunkOffset = 0;  //ÿһ��dll�е�Thunk_Data_Array��ַ
	ULONG tIatThunkOffset = 0;   //ÿһ��dll�е�Iatָ���Iat_Thunk_Data_Array��ַ

	ULONG tImportThunk = 0;  //Thunk_Data_Array ��Ա
	ULONG tIatThunk = 0;     //Iat_Thunk_Data_Array ��Ա

	ULONG tIatThunkNumber = 0; //Iat_Thunk_Data_Array ��Ա����
	ULONG tImportThunkNumber = 0; //Thunk_Data_Array��Ա����

	//ÿһ��dllӵ�еĽṹ
	PIMAGE_IMPORT_DESCRIPTOR tImportDescrt = NULL;

	//-----------------------------------------

	//�ļ��е�����ƫ��_�м���
	ULONG tImportDirect = 0;

	//��������ÿһ��dllָ���iat �� thunkdata
	ULONG tThunkTable1 = 0;
	ULONG tIatTable1 = 0;
	ULONG tFirstThunk = 0;


	//��������DLL
	ULONG dllIndex = 0;

	//��ȡ����dllName
	ANSI_STRING DllName;

	//��ʱֵ
	ULONG tCopyPoint = 0;

	ULONG ModulBase = 0;
	ULONG FncAddress = 0;
	for (dllIndex = 0; dllIndex < dllNumber; dllIndex++)
	{



		//��λ�����
		tImportDirect = ImportTable + dllIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		tImportDescrt = (IMAGE_IMPORT_DESCRIPTOR *)tImportDirect;

		//��λ�����ThunkData �� Iat 
		tThunkTable1 = tImportDescrt->OriginalFirstThunk + PeTakeOutPoint(NewKernel);
		tIatTable1 = tImportDescrt->FirstThunk + PeTakeOutPoint(NewKernel);


		//��ȡdll����
		DllName.Buffer = (PVOID)(tImportDescrt->Name + PeTakeOutPoint(NewKernel));

		ModulBase = NtGetModulBase(DllName.Buffer);

		//DbgPrint("Fix Modul Name :%s ,Modul Base :%X\n", DllName.Buffer,ModulBase);
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
			if ((0x80000000 & ThunkData) == 0x80000000) //�ں��ļ��������Ƶ�����
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
				fncName.Buffer = (PCHAR)(ThunkData + PeTakeOutPoint(NewKernel) + sizeof(WORD16));
				//��ȡ������ַ
				FncAddress = NtGetModulProcAddress((PVOID)ModulBase, fncName.Buffer) + ModulBase;

				//DbgPrint("Fix Fnc Name :%s , Fnc Address:%X \n", fncName.Buffer, FncAddress);

				//�޸�IAT
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
//�����ں�
//
BOOLEAN NtHeavyloadKernel(IN OUT PVOID *NewKernel)
{

	//
	//�������
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
	//�����ں��ļ�
	pLoadKernelbuf = NtLoadKernelFile();

	if (pLoadKernelbuf == NULL)
	{
		return FALSE;
	}

	//��ʼ��Pe��Ϣ
	pNtHead  =  PeGetNtHeader(pLoadKernelbuf);
	pDosHead =  PeGetDosHeader(pLoadKernelbuf);
	pSecHead =  PeGetSectionHeader(pLoadKernelbuf);
	
	uSecNumber = pNtHead->FileHeader.NumberOfSections;
	uImageBase = pNtHead->OptionalHeader.ImageBase;
	uSizeOfImage = pNtHead->OptionalHeader.SizeOfImage;

	//�������ں��ڴ�
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

	//��������
	for (uIndex = 0; uIndex < uSecNumber; uIndex++)
	{
		//
		//��LoadKernelbuf -> NewKernelbuf
		//

		pSecHeadPoint = (PIMAGE_SECTION_HEADER)((ULONG)pSecHead + sizeof(IMAGE_SECTION_HEADER)*uIndex);
		
		
		RtlCopyMemory((PVOID)((ULONG)pNewKernelbuf + pSecHeadPoint->VirtualAddress),	//���������ں˵�ַ
					  (PVOID)((ULONG)pLoadKernelbuf + pSecHeadPoint->PointerToRawData),	//���ļ��ں˿���
					  /*max(*/pSecHeadPoint->SizeOfRawData/*, pSecHeadPoint->Misc.VirtualSize)*/); //���������ֵ	
	}

	//�ں��ض�λ
	if (NtFixRelocaKernelEx(pNewKernelbuf, NtGetKernelBase(), uImageBase) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}

	//ServiceTable�ض�λ
	if (NtFixServiceTable(pNewKernelbuf, NtGetKernelBase()) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}
	//Iat�޸�
	if (NtFixImportTable(pNewKernelbuf) == FALSE)
	{
		//_OLD_KERNEL
		NtUnLoadKernelFile(pLoadKernelbuf);
		//_NEW_KERNEL
		ExFreePool(pNewKernelbuf);
		return FALSE;
	}

	//�ͷ�
	NtUnLoadKernelFile(pLoadKernelbuf);
	return TRUE;
}



//
//�ں��ض�λ�޸���
//
BOOLEAN NtFixRelocaKernelEx(PVOID NewKernel, ULONG OldBase, ULONG NewBase)
{

	//
	//�������
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

	//ָ���ض�λ��
	tRectable = (PIMAGE_BASE_RELOCATION)(tNtHead->OptionalHeader.DataDirectory[5].VirtualAddress + (ULONG)NewKernel);

	for (tRectable;!IsStructEmpty(tRectable, sizeof(IMAGE_BASE_RELOCATION));tRectable = (PIMAGE_BASE_RELOCATION)((ULONG)tRectable + tRectable->SizeOfBlock))
	{

		//ָ��Ҫ���������ݿ����
		pHandleAddress = (WORD16*)((DWORD32)tRectable + sizeof(IMAGE_BASE_RELOCATION));

		for (pHandleAddress; pHandleAddress < (WORD16*)((ULONG)tRectable + tRectable->SizeOfBlock); pHandleAddress++ /*ÿ��2�ֽ� sizeof(WORD16)*/)
		{
			//���flag == IMAGE_REL_BASED_HIGHLOW-����Ҫ����4�ֽ�����
			if ((*pHandleAddress & 0xf000) == IMAGE_REL_BASED_HIGHLOW * 0x1000)//x86�ض�λ���
			{
				//��ȡҪ�����ĵ�ַ
				ChangeAddress = (*pHandleAddress & 0xfff) + tRectable->VirtualAddress + (ULONG)NewKernel;

				//��ȡҪ����������
				ChangeData = *(PULONG)ChangeAddress;

				//д�������������
				*(PULONG)ChangeAddress = ChangeData + ChangeOffset;
			}
		}

	}


	return TRUE;
}



//
//�ں��ض�λKeServiceTable
//
BOOLEAN NtFixServiceTable(IN PVOID NewKernel, ULONG OldBase/*���ں�Mem�����ַ*/)
{

	//
	//�������
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
	//��������
	//
	
	ULONG i = 0;
	ULONG TableBase = 0;

	ULONG KeServiceTable = 0;
	ULONG KeServiceTableOffset = 0;

	PSYSTEM_SERVICE_TABLE OldServiceTable = NULL;
	PSYSTEM_SERVICE_TABLE NewServiceTable = NULL;

	//����KeServiceTable 
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
//����KiFastCallEntry
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
//�ں�����KiFastCallEntry
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
//�ں����ػ�ԭKiFastCallEntry
//
BOOLEAN NtRestoreKiFastCallEntry()
{


	if (g_FastCallHookPointer == 0)
	{
		return FALSE;
	}


	return NtCancelhookKiFastCallEntry();
}


