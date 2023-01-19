#include <Ntifs.h>
#include <NtAnalysis.h>
#include <NtProcess.h>

#pragma once 



//
//��������
//

//-------------------------------------------------------------------------------------------------------------
//��ȡMemServiceTable��������
#define CTL_CODE_GET_SERVICETABLE_FNC_NAME  CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡMemServiceTable������ַ 
#define CTL_CODE_GET_SERVICETABLE_MEM_FNC   CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡFileerviceTable������ַ
#define CTL_CODE_GET_SERVICETABLE_FILE_FNC  CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡFnc��Ŀ
#define CTL_CODE_GET_SERVICETABLE_NUMBER    CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)

//-------------------------------------------------------------------------------------------------------------
//��ȡFileServiceTableShadow���ַ
#define CTL_CODE_GET_SERVICETABLE_SHADOW_FILE_FNC CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡMemServiceTableShadow���ַ
#define CTL_CODE_GET_SERVICETABLE_SHADOW_MEM_FNC  CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)


//-------------------------------------------------------------------------------------------------------------
//��ȡ��������
#define CTL_CODE_GET_PROCESS_NAME			CTL_CODE(FILE_DEVICE_UNKNOWN,0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡ����ID
#define CTL_CODE_GET_PROCESS_ID				CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡ������ID
#define CTL_CODE_GET_PROCESS_PID		    CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
//��ȡ����·��
#define CTL_CODE_GET_PROCESS_PATH		    CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
//-------------------------------------------------------------------------------------------------------------

//
//��������
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

