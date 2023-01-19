#include <Ntifs.h>
#include <PeAnalysis.h>
#include <ResultStatus.h>



#pragma once 


//
//Modul define
//

//
//预编译块
//

#define DBG 1

#define ASSERTRUN(exp)	exp
#define ASSERTEX (exp)  if(!ASSERTRUN(exp)) {if(DBG) { DbgPrint(#exp),DbgPrint("  Faild!\n")}else ASSERT(FALSE)}



//
//系统常量
//


#define SystemModuleInformation 11

//
//用户定义常量
//

//系统版本
#define SYSTEM_VERSION_UNKONW -1
#define SYSTEM_VERSION_WIN2K 0x0
#define SYSTEM_VERSION_WINSERVER 0x1
#define SYSTEM_VERSION_WINXP	0x2
#define SYSTEM_VERSION_WINVISTA 0x3
#define SYSTEM_VERSION_WIN7 0x4
#define SYSTEM_VERSION_WIN8 0x5
#define SYSTEM_VERSION_WIN8_1 0x6






//
//结构定义
//
typedef INT32 SYSTEM_VERSION;


//
//系统结构
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
	ULONG Count;//内核中以加载的模块的个数
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase; //这个指向系统服务函数地址表
	PULONG ServiceCounterTableBase; //NULL
	ULONG NumberOfService; //服务函数的个数
	ULONG ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;





//
//用户定义结构
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
//函数声明
//

//
//内核导出函数
//

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass,
												 IN OUT PVOID SystemInformation,
												 IN ULONG SystemInformationLength,
												 OUT PULONG ReturnLength);


//
//用户函数
//





//
//设置ssdt可写
//

VOID EnableWrite();

//
//设置ssdt不可写
//
VOID DisableWrite();


//
//获取系统版本
//

SYSTEM_VERSION NtGetSystemVerSion();


//
//读取内核文件到内存
//
PVOID NtLoadKernelFile();

//
//从内存卸载内核文件
//
PVOID NtUnLoadKernelFile(PVOID pBuffer);


//
//读取Win32K到内存
//

PVOID NtLoadWin32kFile();
//
//从内存卸载Win32k
//
PVOID NtUnloadWin32kFile(PVOID pBuffer);

//
//获取内核文件名称
//
ULONG NtGetKernelName(IN OUT PANSI_STRING pKernelName);

//
//获取内核基质
//
ULONG NtGetKernelBase();

//
//获取Win32K基址
//
ULONG NtGetWin32kBase();

//
//获取PspCidTable
//
ULONG NtGetPspCidTable();

//
//获取KeservicedeScriptorTable
//

ULONG NtGetServiceDescriptor();

//
//获取ssdt起源地址表，从文件获取
//
ULONG NtGetServiceFormFile();

//
//获取ssdt,来自内存,来自文件
//
ULONG NtEnumeServiceTable(IN OUT PSERVICETABLE pServiceTable);

//
//释放枚举后的ssdt
//
ULONG NtDeleteServiceTable(IN PSERVICETABLE pServiceTable);

//
//获取 Shadow Service Table Form Mem
//

PVOID NtGetShadowServiceFormFile(ULONG * Count);

//
//获取 Shardow Service Table Form Mem 
//
PVOID NtGetShadowServiceFormMem(ULONG* Count);

//
//获取到的 Shadow Service Table 需要重定位
//
PVOID NtRelocaShadowServiceTable(PVOID Table, ULONG Count);

//
//枚举Service Table Shaodw
//
ULONG NtEnumeServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow);

//
//删除 Service Table Shaodw
//

ULONG NtDelectServiceTableShadow(IN OUT PSERVICETABLE_SHADOW pServiceTableShadow);

//
//重载内核
//
BOOLEAN NtHeavyloadKernel(IN OUT PVOID *NewKernel);

//
//内核重定位
//
BOOLEAN NtFixRelocaKernel(IN PVOID NewKernel, ULONG OldBase/*老内核Mem镜像基址*/, ULONG NewBase/*新内核File镜像基址*/);

//
//内核重定位KeServiceTable
//
BOOLEAN NtFixServiceTable(IN PVOID NewKernel, ULONG OldBase/*老内核Mem镜像基址*/);


//
//内核重载KiFastCallEntry
//

BOOLEAN NtFixKiFastCallEntry(PVOID ProtectProcessName);



//
//内核重载还原KiFastCallEntry
//
BOOLEAN NtRestoreKiFastCallEntry();

//
//内核重定位修复版
//
BOOLEAN NtFixRelocaKernelEx(PVOID NewKernel, ULONG OldBase, ULONG NewBase);