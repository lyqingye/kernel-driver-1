#include <Ntifs.h>
#include <NtAnalysis.h>
#include <NtProcess.h>

#pragma once 



//
//常量声明
//

//-------------------------------------------------------------------------------------------------------------
//获取MemServiceTable表函数名称
#define CTL_CODE_GET_SERVICETABLE_FNC_NAME  CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取MemServiceTable表函数地址 
#define CTL_CODE_GET_SERVICETABLE_MEM_FNC   CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取FileerviceTable表函数地址
#define CTL_CODE_GET_SERVICETABLE_FILE_FNC  CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取Fnc数目
#define CTL_CODE_GET_SERVICETABLE_NUMBER    CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)

//-------------------------------------------------------------------------------------------------------------
//获取FileServiceTableShadow表地址
#define CTL_CODE_GET_SERVICETABLE_SHADOW_FILE_FNC CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取MemServiceTableShadow表地址
#define CTL_CODE_GET_SERVICETABLE_SHADOW_MEM_FNC  CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)


//-------------------------------------------------------------------------------------------------------------
//获取进程名称
#define CTL_CODE_GET_PROCESS_NAME			CTL_CODE(FILE_DEVICE_UNKNOWN,0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取进程ID
#define CTL_CODE_GET_PROCESS_ID				CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取父进程ID
#define CTL_CODE_GET_PROCESS_PID		    CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
//获取进程路径
#define CTL_CODE_GET_PROCESS_PATH		    CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
//-------------------------------------------------------------------------------------------------------------

//
//函数声明
//

PVOID ExGetServiceTableFncName(OUT PULONG MapSize, IN PSERVICETABLE pServiceTable);
PVOID ExGetServiceTableMemFnc();
PVOID ExGetServiceTableFileFnc();
ULONG ExGetServiceTableNumber(IN PSERVICETABLE pServiceTable);


ULONG ExGetServiceTableShadowNumber();
PVOID ExGetServiceTableShadowFileFnc();
PVOID ExGetServiceTableShadowMemFnc();

PVOID ExGetProcessName();
PVOID ExGetProcessId();
PVOID ExGetProcessPid();
PVOID ExGetProcessPath();

