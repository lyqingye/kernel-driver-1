#include <Ntifs.h>
#include <PeAnalysis.h>
#include <ResultStatus.h>



#pragma once 


//
//Modul define
//

//
//Ԥ�����
//

#define DBG 1

#define ASSERTRUN(exp)	exp
#define ASSERTEX (exp)  if(!ASSERTRUN(exp)) {if(DBG) { DbgPrint(#exp),DbgPrint("  Faild!\n")}else ASSERT(FALSE)}



//
//ϵͳ����
//


#define SystemModuleInformation 11

//
//�û����峣��
//

//ϵͳ�汾
#define SYSTEM_VERSION_UNKONW -1
#define SYSTEM_VERSION_WIN2K 0x0
#define SYSTEM_VERSION_WINSERVER 0x1
#define SYSTEM_VERSION_WINXP	0x2
#define SYSTEM_VERSION_WINVISTA 0x3
#define SYSTEM_VERSION_WIN7 0x4
#define SYSTEM_VERSION_WIN8 0x5
#define SYSTEM_VERSION_WIN8_1 0x6






//
//�ṹ����
//
typedef INT32 SYSTEM_VERSION;


//
//ϵͳ�ṹ
//

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG Unknow1;
	ULONG Unknow2;
#ifdef _WIN64
	ULONG Unknow3;
	ULONG Unknow4 :
#endif
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
}SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;//�ں����Լ��ص�ģ��ĸ���
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase; //���ָ��ϵͳ��������ַ��
	PULONG ServiceCounterTableBase; //NULL
	ULONG NumberOfService; //�������ĸ���
	ULONG ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;





//
//�û�����ṹ
//

typedef struct  _SERVICETABLE{
	ULONG NumberOfService;
	PVOID MemServiceTable;
	PVOID FileServiceTable;
	PANSI_STRING_LIST_HEADER NameList;
}SERVICETABLE, *PSERVICETABLE;


typedef struct _SERVICETABLE_SHADOW{
	ULONG NumberOfService;
	PVOID MemServiceTable;
	PVOID FileServiceTable;
}SERVICETABLE_SHADOW, *PSERVICETABLE_SHADOW;


//
//��������
//

//
//�ں˵�������
//

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass,
												 IN OUT PVOID SystemInformation,
												 IN ULONG SystemInformationLength,
												 OUT PULONG ReturnLength);


//
//�û�����
//





//
//����ssdt��д
//

VOID EnableWrite();

//
//����ssdt����д
//
VOID DisableWrite();


//
//��ȡϵͳ�汾
//

SYSTEM_VERSION NtGetSystemVerSion();


//
//��ȡ�ں��ļ����ڴ�
//
PVOID NtLoadKernelFile();

//
//���ڴ�ж���ں��ļ�
//
PVOID NtUnLoadKernelFile(PVOID pBuffer);


//
//��ȡWin32K���ڴ�
//

PVOID NtLoadWin32kFile();
//
//���ڴ�ж��Win32k
//
PVOID NtUnloadWin32kFile(PVOID pBuffer);

//
//��ȡ�ں��ļ�����
//
ULONG NtGetKernelName(IN OUT PANSI_STRING pKernelName);

//
//��ȡ�ں˻���
//
ULONG NtGetKernelBase();

//
//��ȡWin32K��ַ
//
ULONG NtGetWin32kBase();

//
//��ȡPspCidTable
//
ULONG NtGetPspCidTable();

//
//��ȡKeservicedeScriptorTable
//

ULONG NtGetServiceDescriptor();

//
//��ȡssdt��Դ��ַ�����ļ���ȡ
//
ULONG NtGetServiceFormFile();

//
//��ȡssdt,�����ڴ�,�����ļ�
//
ULONG NtEnumeServiceTable(IN OUT PSERVICETABLE pServiceTable);

//
//�ͷ�ö�ٺ��ssdt
//
ULONG NtDeleteServiceTable(IN PSERVICETABLE pServiceTable);

//
//��ȡ Shadow Service Table Form Mem
//

PVOID NtGetShadowServiceFormFile(ULONG * Count);

//
//��ȡ Shardow Service Table Form Mem 
//
PVOID NtGetShadowServiceFormMem(ULONG* Count);

//
//��ȡ���� Shadow Service Table ��Ҫ�ض�λ
//
PVOID NtRelocaShadowServiceTable(PVOID Table, ULONG Count);

//
//ö��Service Table Shaodw
//
ULONG NtEnumeServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow);

//
//ɾ�� Service Table Shaodw
//

ULONG NtDelectServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow);

//
//�����ں�
//
BOOLEAN NtHeavyloadKernel(IN OUT PVOID *NewKernel);

//
//�ں��ض�λ
//
BOOLEAN NtFixRelocaKernel(IN PVOID NewKernel, ULONG OldBase/*���ں�Mem�����ַ*/, ULONG NewBase/*���ں�File�����ַ*/);

//
//�ں��ض�λKeServiceTable
//
BOOLEAN NtFixServiceTable(IN PVOID NewKernel, ULONG OldBase/*���ں�Mem�����ַ*/);


//
//�ں�����KiFastCallEntry
//

BOOLEAN NtFixKiFastCallEntry(PVOID ProtectProcessName);



//
//�ں����ػ�ԭKiFastCallEntry
//
BOOLEAN NtRestoreKiFastCallEntry();

//
//�ں��ض�λ�޸���
//
BOOLEAN NtFixRelocaKernelEx(PVOID NewKernel, ULONG OldBase, ULONG NewBase);